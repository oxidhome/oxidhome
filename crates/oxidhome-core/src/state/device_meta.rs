//! Host-owned device metadata that outlives a registration (H6 slice 2):
//! the `device_meta` table.
//!
//! One row per device id the host has had to remember something about:
//!
//! - `sensitive_floor` — every sensitive category the host has ever
//!   derived from the device's capabilities. A plugin can replace a
//!   device's capability list with `update-device` or re-registration;
//!   the floor stops that from turning a known lock into a switch. The
//!   host only ever adds to it.
//! - `category_override` — a category the operator set
//!   (`oxidhome device set-category`, `PUT /api/v1/devices/{id}/category`).
//!   It can only raise: the effective class is the union of the
//!   derived class, the floor and the override, so an override below
//!   what the device already is changes nothing. Clearing it removes
//!   the operator's raise, never the floor.
//! - `owner_instance` — the instance that registered the device, so a
//!   camera plugin's blobs stay camera blobs after the plugin stops.
//!
//! Rows are written only for devices that are (or were) sensitive or
//! that the operator classified, so a household of lights writes
//! nothing. The table is small and loaded into memory at open; reads
//! (every authorization decision on a device) never touch `SQLite`.
//!
//! A failed write is logged and the in-memory floor still applies for
//! the life of the process: the floor only ever protects more.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::params;

use super::db::Db;
use super::event_log::now_unix_ms;
use crate::auth::{DeviceCategory, DeviceClass, SensitiveCategory, SensitiveSet};

/// One remembered device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceMetaRow {
    /// Instance that registered the device, when the host saw it.
    pub owner_instance: Option<String>,
    /// Sensitive categories the host has derived for the device.
    pub sensitive_floor: SensitiveSet,
    /// The operator's raise, if any.
    pub category_override: Option<DeviceCategory>,
}

impl DeviceMetaRow {
    /// `class` widened by this row's floor and override.
    #[must_use]
    pub fn apply(&self, class: DeviceClass) -> DeviceClass {
        let class = class.with_sensitive(self.sensitive_floor);
        match self.category_override {
            Some(c) => class.raised(c),
            None => class,
        }
    }
}

/// Most sensitive devices one instance can have remembered. Four times
/// the live per-instance device cap, so a plugin that replaces its
/// devices a few times never meets it.
pub const MAX_FLOOR_ROWS_PER_INSTANCE: usize = 4 * super::devices::MAX_DEVICES_PER_INSTANCE;

/// Most sensitive devices the host remembers in all. Instance ids are
/// cheap (every scripting sandbox has its own), so the per-instance cap
/// alone doesn't bound the table every startup loads.
pub const MAX_FLOOR_ROWS_TOTAL: usize = 16 * MAX_FLOOR_ROWS_PER_INSTANCE;

/// Why [`DeviceMetaStore::observe`] refused a registration.
#[derive(Debug, thiserror::Error)]
pub enum ObserveError {
    /// The instance already has [`MAX_FLOOR_ROWS_PER_INSTANCE`]
    /// sensitive devices on record.
    #[error("the instance has {MAX_FLOOR_ROWS_PER_INSTANCE} sensitive devices on record")]
    CapExceeded,
    /// The host already remembers [`MAX_FLOOR_ROWS_TOTAL`] sensitive
    /// devices.
    #[error("the host has {MAX_FLOOR_ROWS_TOTAL} sensitive devices on record")]
    TotalCapExceeded,
    /// The floor couldn't be stored.
    #[error("storing the device's sensitive categories failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Errors from the operator-facing writes.
#[derive(Debug, thiserror::Error)]
pub enum DeviceMetaError {
    /// `SQLite` failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The id isn't a host device id (`dev-` + 16 lowercase hex).
    #[error("`{0}` is not a device id (dev-<16 hex>)")]
    BadDeviceId(String),
    /// A raise to `camera` for a device whose owning instance the host
    /// can't find: the raise would protect the device but not the
    /// instance's other bytes, so it is refused.
    #[error(
        "`{0}` has no known owning instance (not registered, no stored state or events); \
         start its plugin and set the category again"
    )]
    UnknownOwner(String),
    /// A new row would pass [`MAX_FLOOR_ROWS_TOTAL`].
    #[error("the host has {MAX_FLOOR_ROWS_TOTAL} devices on record; clear an override first")]
    TooMany,
}

/// The `device_meta` table plus its in-memory copy. One per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct DeviceMetaStore {
    db: Option<Arc<Db>>,
    rows: RwLock<HashMap<String, DeviceMetaRow>>,
    /// Per-instance counts kept in step with `rows`, so the per-value
    /// byte check and the per-instance quota are one lookup each.
    index: RwLock<OwnerIndex>,
    /// Serializes writers through read → commit → publish, so the
    /// `rows` lock is held only to read and to publish, never across a
    /// `SQLite` commit: readers (every authorization) don't wait on an
    /// fsync.
    writer: Mutex<()>,
}

impl Default for DeviceMetaStore {
    fn default() -> Self {
        Self::detached()
    }
}

/// `true` for a host-minted device id: `dev-` plus 16 lowercase hex.
#[must_use]
pub fn is_device_id(id: &str) -> bool {
    id.strip_prefix("dev-").is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `true` when `pattern` is a device id or a `prefix*` of one (a
/// non-empty prefix shorter than an id): the device patterns a role
/// grant may name. Anything else would match no host-minted id.
#[must_use]
pub fn is_device_pattern(pattern: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => {
            !prefix.is_empty()
                && prefix.len() < "dev-0123456789abcdef".len()
                && could_prefix_device_id(prefix)
        }
        None => is_device_id(pattern),
    }
}

/// `true` when `prefix` could start a `dev-<16 lowercase hex>` id.
fn could_prefix_device_id(prefix: &str) -> bool {
    let template = "dev-";
    if prefix.len() <= template.len() {
        return template.starts_with(prefix);
    }
    prefix.starts_with(template)
        && prefix[template.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl DeviceMetaStore {
    /// A store with no database: the floor lives for the process only.
    /// For registries built outside an engine (tests).
    #[must_use]
    pub fn detached() -> Self {
        Self {
            db: None,
            rows: RwLock::new(HashMap::new()),
            index: RwLock::new(OwnerIndex::default()),
            writer: Mutex::new(()),
        }
    }

    /// Load every row from `db`.
    ///
    /// # Errors
    ///
    /// `SQLite` errors reading the table.
    pub fn open(db: Arc<Db>) -> Result<Self, rusqlite::Error> {
        let rows = db.read(|conn| -> Result<_, rusqlite::Error> {
            let mut stmt = conn.prepare(
                "SELECT device_id, owner_instance, sensitive_floor, category_override \
                 FROM device_meta",
            )?;
            let mut out = HashMap::new();
            let iter = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })?;
            for row in iter {
                let (id, owner, floor, over) = row?;
                out.insert(id.clone(), decode_row(&id, owner, &floor, over.as_deref()));
            }
            Ok(out)
        })?;
        Ok(Self {
            db: Some(db),
            index: RwLock::new(OwnerIndex::build(&rows)),
            rows: RwLock::new(rows),
            writer: Mutex::new(()),
        })
    }

    /// The remembered row for `device_id`, if any.
    #[must_use]
    pub fn get(&self, device_id: &str) -> Option<DeviceMetaRow> {
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(device_id)
            .cloned()
    }

    /// Every remembered row, keyed by device id.
    #[must_use]
    pub fn list(&self) -> Vec<(String, DeviceMetaRow)> {
        let mut rows: Vec<_> = self
            .rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// `true` when any device `instance_id` registered is (or was) a
    /// camera, by its floor or the operator's override.
    #[must_use]
    pub fn instance_is_camera(&self, instance_id: &str) -> bool {
        self.index
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .cameras
            .get(instance_id)
            .is_some_and(|n| *n > 0)
    }

    /// Move [`Self::index`] from `before` to `after` for one changed
    /// row (writers only, holding the `rows` write lock).
    fn reindex(&self, before: Option<&DeviceMetaRow>, after: Option<&DeviceMetaRow>) {
        let mut index = self.index.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(row) = before {
            index.remove(row);
        }
        if let Some(row) = after {
            index.add(row);
        }
    }

    /// Record that `device_id`, registered by `owner_instance`, was
    /// derived as `derived`. Raises the durable floor when `derived`
    /// has a sensitive category the floor lacks, and records the owner
    /// of a remembered device; otherwise does nothing (no write for
    /// non-sensitive devices). The `SQLite` write commits before the
    /// in-memory row changes; writers are serialized, so memory never
    /// runs ahead of (or behind) the table.
    ///
    /// # Errors
    ///
    /// [`ObserveError::CapExceeded`] when this would remember a new
    /// device for an instance that already has
    /// [`MAX_FLOOR_ROWS_PER_INSTANCE`] rows: the caller refuses the
    /// registration, so a plugin cycling `register-device` /
    /// `remove-device` through fresh ids can't grow the table without
    /// bound. [`ObserveError::Sqlite`] when the floor couldn't be
    /// stored: the caller refuses the registration too, and the next
    /// attempt writes again.
    pub fn observe(
        &self,
        device_id: &str,
        owner_instance: &str,
        derived: DeviceClass,
    ) -> Result<(), ObserveError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let floor = {
            let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
            let current = rows.get(device_id);
            let floor = current.map_or_else(SensitiveSet::empty, |r| r.sensitive_floor);
            let owner_known = current
                .and_then(|r| r.owner_instance.as_deref())
                .is_some_and(|o| o == owner_instance);
            if derived.sensitive().is_subset(floor) && (owner_known || current.is_none()) {
                return Ok(());
            }
            if current.is_none() && rows.len() >= MAX_FLOOR_ROWS_TOTAL {
                return Err(ObserveError::TotalCapExceeded);
            }
            if current.is_none() {
                let owned = self
                    .index
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .rows
                    .get(owner_instance)
                    .copied()
                    .unwrap_or(0);
                if owned >= MAX_FLOOR_ROWS_PER_INSTANCE {
                    return Err(ObserveError::CapExceeded);
                }
            }
            floor
        };
        let new_floor = floor.union(derived.sensitive());
        if let Some(db) = &self.db {
            let csv = new_floor.to_csv();
            durable_write(db, |conn| {
                conn.execute(
                    "INSERT INTO device_meta \
                       (device_id, owner_instance, sensitive_floor, category_override, updated_ms) \
                     VALUES (?1, ?2, ?3, NULL, ?4) \
                     ON CONFLICT(device_id) DO UPDATE SET \
                       owner_instance = excluded.owner_instance, \
                       sensitive_floor = excluded.sensitive_floor, \
                       updated_ms = excluded.updated_ms",
                    params![device_id, owner_instance, csv, now_unix_ms()],
                )
            })?;
        }
        let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
        let row = rows.entry(device_id.to_owned()).or_default();
        let before = row.clone();
        row.sensitive_floor = new_floor;
        row.owner_instance = Some(owner_instance.to_owned());
        self.reindex(Some(&before), Some(row));
        Ok(())
    }

    /// Set (or with `None` clear) the operator's category override for
    /// `device_id`. The device need not be registered right now;
    /// `owner_instance` is its owner when the host knows it, recorded so
    /// a raise to `camera` classes the instance's blobs too. Returns the
    /// row as stored. Writers are serialized through commit and
    /// publication, so concurrent overrides land in memory in the order
    /// they committed.
    ///
    /// # Errors
    ///
    /// [`DeviceMetaError::BadDeviceId`] for a malformed id; `SQLite`
    /// errors from the write (the in-memory row is left unchanged).
    pub fn set_override(
        &self,
        device_id: &str,
        category: Option<DeviceCategory>,
        owner_instance: Option<&str>,
    ) -> Result<DeviceMetaRow, DeviceMetaError> {
        if !is_device_id(device_id) {
            return Err(DeviceMetaError::BadDeviceId(device_id.to_owned()));
        }
        let name = category.map(DeviceCategory::as_str);
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if category.is_none() {
            // Clearing never leaves an empty row behind: an empty row
            // would count against the instance's floor-row cap.
            match self.get(device_id) {
                None => return Ok(DeviceMetaRow::default()),
                Some(row) if row.sensitive_floor.is_empty() => {
                    if let Some(db) = &self.db {
                        durable_write(db, |conn| {
                            conn.execute(
                                "DELETE FROM device_meta WHERE device_id = ?1",
                                params![device_id],
                            )
                        })?;
                    }
                    let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
                    let before = rows.remove(device_id);
                    self.reindex(before.as_ref(), None);
                    return Ok(DeviceMetaRow::default());
                }
                Some(_) => {}
            }
        }
        let mut owner = owner_instance
            .map(str::to_owned)
            .or_else(|| self.get(device_id).and_then(|r| r.owner_instance));
        if let Some(db) = &self.db
            && owner.is_none()
        {
            // Not registered right now (an offline CLI run, a stopped
            // plugin): the owner from what the host kept of the
            // device, so a raise to `camera` still classes its
            // instance's other data.
            owner = db.read(|conn| known_owner(conn, device_id))?;
        }
        if category == Some(DeviceCategory::Camera) && owner.is_none() {
            return Err(DeviceMetaError::UnknownOwner(device_id.to_owned()));
        }
        {
            let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
            if !rows.contains_key(device_id) && rows.len() >= MAX_FLOOR_ROWS_TOTAL {
                return Err(DeviceMetaError::TooMany);
            }
        }
        if let Some(db) = &self.db {
            durable_write(db, |conn| {
                conn.execute(
                    "INSERT INTO device_meta \
                       (device_id, owner_instance, sensitive_floor, category_override, updated_ms) \
                     VALUES (?1, ?2, '', ?3, ?4) \
                     ON CONFLICT(device_id) DO UPDATE SET \
                       owner_instance = COALESCE(excluded.owner_instance, owner_instance), \
                       category_override = excluded.category_override, \
                       updated_ms = excluded.updated_ms",
                    params![device_id, owner, name, now_unix_ms()],
                )?;
                Ok(())
            })?;
        }
        let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
        let row = rows.entry(device_id.to_owned()).or_default();
        let before = row.clone();
        row.category_override = category;
        if owner.is_some() {
            row.owner_instance = owner;
        }
        let row = row.clone();
        self.reindex(Some(&before), Some(&row));
        Ok(row)
    }
}

/// The instance that owns `device_id` according to its persisted state
/// or event history, if any.
fn known_owner(
    conn: &rusqlite::Connection,
    device_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT owner_instance FROM device_state WHERE device_id = ?1 \
         UNION ALL \
         SELECT instance_id FROM event_log WHERE device_id = ?1 \
         LIMIT 1",
        params![device_id],
        |r| r.get(0),
    )
    .optional()
}

/// One write at `synchronous = FULL`: a protection change the caller
/// acts on (a registration accepted, an override acknowledged) must
/// survive power loss. The token store's policy writes do the same.
fn durable_write<R: Send>(
    db: &Db,
    f: impl FnOnce(&rusqlite::Connection) -> Result<R, rusqlite::Error>,
) -> Result<R, rusqlite::Error> {
    db.write(move |conn| -> Result<R, rusqlite::Error> {
        conn.pragma_update(None, "synchronous", "FULL")?;
        let result = f(conn);
        if let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
            tracing::warn!(
                target: "auth.device_meta",
                error = %err,
                "failed to restore synchronous = NORMAL; connection stays at FULL",
            );
        }
        result
    })
}

/// Per-owner row counts and camera-row counts. An empty default row
/// (the `before` of an insert) has no owner and counts nowhere.
#[derive(Debug, Default)]
struct OwnerIndex {
    rows: HashMap<String, usize>,
    cameras: HashMap<String, usize>,
}

impl OwnerIndex {
    fn build(rows: &HashMap<String, DeviceMetaRow>) -> Self {
        let mut index = Self::default();
        for row in rows.values() {
            index.add(row);
        }
        index
    }

    fn add(&mut self, row: &DeviceMetaRow) {
        let Some(owner) = &row.owner_instance else {
            return;
        };
        *self.rows.entry(owner.clone()).or_default() += 1;
        if row.apply(DeviceClass::other()).is_camera() {
            *self.cameras.entry(owner.clone()).or_default() += 1;
        }
    }

    fn remove(&mut self, row: &DeviceMetaRow) {
        let Some(owner) = &row.owner_instance else {
            return;
        };
        let dec = |map: &mut HashMap<String, usize>| {
            if let Some(n) = map.get_mut(owner) {
                *n -= 1;
                if *n == 0 {
                    map.remove(owner);
                }
            }
        };
        dec(&mut self.rows);
        if row.apply(DeviceClass::other()).is_camera() {
            dec(&mut self.cameras);
        }
    }
}

fn decode_row(id: &str, owner: Option<String>, floor: &str, over: Option<&str>) -> DeviceMetaRow {
    // Rows are written only by this module, so a name it can't parse
    // comes from a newer binary (or a hand-edited file). Fail closed:
    // the device is then treated as every sensitive category until the
    // row is repaired, and the problem is logged at error.
    let mut unreadable = false;
    let mut sensitive_floor: SensitiveSet = floor
        .split(',')
        .filter(|n| !n.is_empty())
        .filter_map(|n| match n.parse() {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::error!(target: "auth.device_meta", device_id = id, %err, "unreadable floor entry");
                unreadable = true;
                None
            }
        })
        .collect();
    let category_override = over.and_then(|n| match n.parse() {
        Ok(c) => Some(c),
        Err(err) => {
            tracing::error!(target: "auth.device_meta", device_id = id, %err, "unreadable category override");
            unreadable = true;
            None
        }
    });
    if unreadable {
        sensitive_floor = SensitiveCategory::ALL.into_iter().collect();
    }
    DeviceMetaRow {
        owner_instance: owner,
        sensitive_floor,
        category_override,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SensitiveCategory;

    const DEV: &str = "dev-0123456789abcdef";

    #[test]
    fn floor_only_grows_and_survives_reopen() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = DeviceMetaStore::open(Arc::clone(&db)).expect("open");
        // A light writes nothing.
        store
            .observe(DEV, "inst", DeviceClass::of(DeviceCategory::Light))
            .unwrap();
        assert!(store.get(DEV).is_none());
        store
            .observe(DEV, "inst", DeviceClass::of(DeviceCategory::Lock))
            .unwrap();
        // Re-registered as a switch: the lock stays.
        store
            .observe(DEV, "inst", DeviceClass::of(DeviceCategory::Switch))
            .unwrap();
        let row = store.get(DEV).expect("row");
        assert!(row.sensitive_floor.contains(SensitiveCategory::Lock));
        assert_eq!(
            row.apply(DeviceClass::of(DeviceCategory::Switch))
                .category(),
            DeviceCategory::Lock
        );
        let reopened = DeviceMetaStore::open(db).expect("reopen");
        assert_eq!(reopened.get(DEV), Some(row));
    }

    #[test]
    fn override_raises_and_clears_without_touching_the_floor() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = DeviceMetaStore::open(Arc::clone(&db)).expect("open");
        let row = store
            .set_override(DEV, Some(DeviceCategory::Opener), None)
            .expect("set");
        let class = row.apply(DeviceClass::of(DeviceCategory::Switch));
        assert_eq!(class.category(), DeviceCategory::Opener);
        assert!(class.sensitive().contains(SensitiveCategory::Opener));
        // An override below what the device is changes nothing.
        store
            .observe(DEV, "inst", DeviceClass::of(DeviceCategory::Lock))
            .unwrap();
        let row = store
            .set_override(DEV, Some(DeviceCategory::Light), None)
            .expect("set");
        assert_eq!(
            row.apply(DeviceClass::of(DeviceCategory::Switch))
                .category(),
            DeviceCategory::Lock
        );
        let row = store.set_override(DEV, None, None).expect("clear");
        assert!(row.sensitive_floor.contains(SensitiveCategory::Lock));
        assert_eq!(row.category_override, None);
        assert_eq!(
            DeviceMetaStore::open(db).expect("reopen").get(DEV),
            Some(row)
        );
        assert!(matches!(
            store.set_override("dev-XYZ", Some(DeviceCategory::Lock), None),
            Err(DeviceMetaError::BadDeviceId(_))
        ));
    }

    #[test]
    fn camera_instances_are_remembered() {
        let store = DeviceMetaStore::detached();
        assert!(!store.instance_is_camera("cam"));
        store
            .observe(DEV, "cam", DeviceClass::of(DeviceCategory::Camera))
            .unwrap();
        assert!(store.instance_is_camera("cam"));
        assert!(!store.instance_is_camera("other"));
    }

    /// The per-instance camera index follows an override raised and
    /// cleared, and a row moving to another owner.
    #[test]
    fn the_camera_index_follows_overrides() {
        const LOCK_DEV: &str = "dev-00000000000000aa";
        let store = DeviceMetaStore::detached();
        store
            .set_override(LOCK_DEV, Some(DeviceCategory::Camera), Some("a"))
            .unwrap();
        assert!(store.instance_is_camera("a"));
        store.set_override(LOCK_DEV, None, None).unwrap();
        assert!(!store.instance_is_camera("a"), "the empty row is gone");
        store
            .observe(DEV, "a", DeviceClass::of(DeviceCategory::Camera))
            .unwrap();
        store
            .observe(DEV, "b", DeviceClass::of(DeviceCategory::Camera))
            .unwrap();
        assert!(!store.instance_is_camera("a"), "the row moved to b");
        assert!(store.instance_is_camera("b"));
    }

    #[test]
    fn floor_rows_are_capped_per_instance() {
        let store = DeviceMetaStore::detached();
        let lock = DeviceClass::of(DeviceCategory::Lock);
        for i in 0..MAX_FLOOR_ROWS_PER_INSTANCE {
            store
                .observe(&format!("dev-{i:016x}"), "p", lock)
                .expect("under the cap");
        }
        assert!(matches!(
            store.observe("dev-ffffffffffffffff", "p", lock),
            Err(ObserveError::CapExceeded)
        ));
        // A known device and another instance are unaffected.
        store.observe("dev-0000000000000000", "p", lock).unwrap();
        store.observe("dev-ffffffffffffffff", "q", lock).unwrap();
    }

    /// Clearing an override leaves no empty row (it would count
    /// against the per-instance floor-row cap).
    #[test]
    fn clearing_removes_an_empty_row() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = DeviceMetaStore::open(Arc::clone(&db)).unwrap();
        store
            .set_override(DEV, None, Some("inst"))
            .expect("no-op clear");
        assert_eq!(store.get(DEV), None);
        store
            .set_override(DEV, Some(DeviceCategory::Lock), Some("inst"))
            .expect("raise");
        store.set_override(DEV, None, None).expect("clear");
        assert_eq!(store.get(DEV), None);
        assert_eq!(DeviceMetaStore::open(db).unwrap().get(DEV), None);
    }

    /// A raise to `camera` needs the owning instance, so the whole
    /// instance is classed; other raises don't.
    #[test]
    fn camera_raise_needs_a_known_owner() {
        let store = DeviceMetaStore::open(Arc::new(Db::open_in_memory().unwrap())).unwrap();
        assert!(matches!(
            store.set_override(DEV, Some(DeviceCategory::Camera), None),
            Err(DeviceMetaError::UnknownOwner(_))
        ));
        store
            .set_override(DEV, Some(DeviceCategory::Lock), None)
            .expect("lock needs no owner");
        let row = store
            .set_override(DEV, Some(DeviceCategory::Camera), Some("inst"))
            .expect("owner given");
        assert_eq!(row.owner_instance.as_deref(), Some("inst"));
        assert!(store.instance_is_camera("inst"));
    }

    /// A row this binary can't read is treated as every sensitive
    /// category, not as none.
    #[test]
    fn an_unreadable_row_fails_closed() {
        let row = decode_row(DEV, Some("i".into()), "lock,teleporter", None);
        assert_eq!(
            row.sensitive_floor,
            SensitiveCategory::ALL.into_iter().collect()
        );
        let row = decode_row(DEV, Some("i".into()), "", Some("toaster"));
        assert!(row.sensitive_floor.contains(SensitiveCategory::Camera));
        let row = decode_row(DEV, None, "lock", Some("opener"));
        assert_eq!(
            row.sensitive_floor,
            [SensitiveCategory::Lock].into_iter().collect()
        );
    }

    #[test]
    fn device_id_shape() {
        assert!(is_device_id(DEV));
        assert!(!is_device_id("dev-0123456789ABCDEF"));
        assert!(!is_device_id("dev-0123"));
        assert!(!is_device_id("0123456789abcdef"));
    }
}
