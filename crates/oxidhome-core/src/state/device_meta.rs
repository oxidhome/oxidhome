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
use std::sync::{Arc, PoisonError, RwLock};

use rusqlite::params;

use super::db::Db;
use super::event_log::now_unix_ms;
use crate::auth::{DeviceCategory, DeviceClass, SensitiveSet};

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

/// Why [`DeviceMetaStore::observe`] refused a registration.
#[derive(Debug, thiserror::Error)]
pub enum ObserveError {
    /// The instance already has [`MAX_FLOOR_ROWS_PER_INSTANCE`]
    /// sensitive devices on record.
    #[error("the instance has {MAX_FLOOR_ROWS_PER_INSTANCE} sensitive devices on record")]
    CapExceeded,
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
}

/// The `device_meta` table plus its in-memory copy. One per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct DeviceMetaStore {
    db: Option<Arc<Db>>,
    rows: RwLock<HashMap<String, DeviceMetaRow>>,
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

impl DeviceMetaStore {
    /// A store with no database: the floor lives for the process only.
    /// For registries built outside an engine (tests).
    #[must_use]
    pub fn detached() -> Self {
        Self {
            db: None,
            rows: RwLock::new(HashMap::new()),
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
            rows: RwLock::new(rows),
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
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .any(|row| {
                row.owner_instance.as_deref() == Some(instance_id)
                    && row.apply(DeviceClass::other()).is_camera()
            })
    }

    /// Record that `device_id`, registered by `owner_instance`, was
    /// derived as `derived`. Raises the durable floor when `derived`
    /// has a sensitive category the floor lacks, and records the owner
    /// of a remembered device; otherwise does nothing (no write for
    /// non-sensitive devices). The `SQLite` write commits before the
    /// in-memory row changes, both under the store's lock, so memory
    /// never runs ahead of (or behind) the table.
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
        let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
        let current = rows.get(device_id);
        let floor = current.map_or_else(SensitiveSet::empty, |r| r.sensitive_floor);
        let owner_known = current
            .and_then(|r| r.owner_instance.as_deref())
            .is_some_and(|o| o == owner_instance);
        if derived.sensitive().is_subset(floor) && (owner_known || current.is_none()) {
            return Ok(());
        }
        if current.is_none() {
            let owned = rows
                .values()
                .filter(|r| r.owner_instance.as_deref() == Some(owner_instance))
                .count();
            if owned >= MAX_FLOOR_ROWS_PER_INSTANCE {
                return Err(ObserveError::CapExceeded);
            }
        }
        let new_floor = floor.union(derived.sensitive());
        if let Some(db) = &self.db {
            let csv = new_floor.to_csv();
            db.write(|conn| -> Result<usize, rusqlite::Error> {
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
        let row = rows.entry(device_id.to_owned()).or_default();
        row.sensitive_floor = new_floor;
        row.owner_instance = Some(owner_instance.to_owned());
        Ok(())
    }

    /// Set (or with `None` clear) the operator's category override for
    /// `device_id`. The device need not be registered right now;
    /// `owner_instance` is its owner when the host knows it, recorded so
    /// a raise to `camera` classes the instance's blobs too. Returns the
    /// row as stored. Commit and publication happen under one lock, so
    /// concurrent overrides land in memory in the order they committed.
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
        let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
        let owner = owner_instance
            .map(str::to_owned)
            .or_else(|| rows.get(device_id).and_then(|r| r.owner_instance.clone()));
        if let Some(db) = &self.db {
            db.write(|conn| -> Result<(), rusqlite::Error> {
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
        let row = rows.entry(device_id.to_owned()).or_default();
        row.category_override = category;
        if owner.is_some() {
            row.owner_instance = owner;
        }
        Ok(row.clone())
    }
}

fn decode_row(id: &str, owner: Option<String>, floor: &str, over: Option<&str>) -> DeviceMetaRow {
    // Rows are written only by this module, so a name it can't parse
    // comes from a newer binary. Keep what parses and say so; the
    // floor can only lose protection by being unreadable, which is
    // why it is logged at error.
    let sensitive_floor = floor
        .split(',')
        .filter(|n| !n.is_empty())
        .filter_map(|n| match n.parse() {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::error!(target: "auth.device_meta", device_id = id, %err, "unreadable floor entry");
                None
            }
        })
        .collect();
    let category_override = over.and_then(|n| match n.parse() {
        Ok(c) => Some(c),
        Err(err) => {
            tracing::error!(target: "auth.device_meta", device_id = id, %err, "unreadable category override");
            None
        }
    });
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

    #[test]
    fn device_id_shape() {
        assert!(is_device_id(DEV));
        assert!(!is_device_id("dev-0123456789ABCDEF"));
        assert!(!is_device_id("dev-0123"));
        assert!(!is_device_id("0123456789abcdef"));
    }
}
