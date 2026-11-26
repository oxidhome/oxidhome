//! The owner's deny lists over plugins (H6 slice 5): the `plugin_deny`
//! table.
//!
//! One row per plugin id the owner has restricted: a list of deny
//! entries ([`DenyRule`]) restricted to
//! [`crate::auth::PLUGIN_ACTIONS`]. [`crate::auth::authorize_plugin`]
//! applies the list of the acting plugin and of every plugin that made
//! a hop on the way to it, whatever the plugin's manifest grants. The
//! list is keyed by plugin id, not installation, so it can be set
//! before the plugin is installed; uninstalling the plugin deletes it,
//! so a reinstall starts with none. One more list, keyed
//! [`GLOBAL_PLUGIN_DENY`] (`*`), applies to every plugin, alongside
//! each plugin's own.
//!
//! The table is small and loaded into memory at open; reads (every
//! plugin decision) never touch `SQLite`, and a change applies to the
//! next decision of every running instance. A stored row that no longer
//! parses denies the plugin every plugin action (fail closed).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::params;

use super::db::Db;
use super::event_log::now_unix_ms;
use crate::auth::{DenyRule, PLUGIN_ACTIONS};

/// The key of the global list, which applies to every plugin.
pub const GLOBAL_PLUGIN_DENY: &str = "*";

/// `true` for a key a deny list may have: a plugin id, or
/// [`GLOBAL_PLUGIN_DENY`].
#[must_use]
pub fn is_deny_key(key: &str) -> bool {
    key == GLOBAL_PLUGIN_DENY || oxidhome_manifest::is_plugin_id(key)
}

/// Most deny entries one plugin's list may hold.
pub const MAX_PLUGIN_DENY_ENTRIES: usize = 32;

/// Most plugins with a deny list.
pub const MAX_PLUGIN_DENY_LISTS: usize = 1024;

/// Why a deny list change was refused.
#[derive(Debug, thiserror::Error)]
pub enum PluginDenyError {
    /// Not a plugin id (nor `*`).
    #[error("`{0}` is not a plugin id (reverse-DNS, e.g. `com.example.lights`) or `*`")]
    BadPluginId(String),
    /// Too many entries.
    #[error("a plugin deny list holds at most {MAX_PLUGIN_DENY_ENTRIES} entries")]
    TooManyEntries,
    /// Too many plugins with a list.
    #[error("at most {MAX_PLUGIN_DENY_LISTS} plugins can have a deny list; reset one first")]
    TooManyLists,
    /// `SQLite` failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// A plugin's deny list, shared with every decision that reads it.
pub type PluginDenyList = Arc<[DenyRule]>;

/// The `plugin_deny` table plus its in-memory copy. One per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct PluginDenyStore {
    db: Option<Arc<Db>>,
    rows: RwLock<HashMap<String, PluginDenyList>>,
    /// Serializes writers through commit → publish, so `rows` is held
    /// only to read and to publish, never across a `SQLite` commit.
    writer: Mutex<()>,
    /// Bumped on every change, under the `rows` write lock
    /// ([`Self::generation`]).
    generation: AtomicU64,
}

impl Default for PluginDenyStore {
    fn default() -> Self {
        Self::detached()
    }
}

/// Most items in each list of a stored deny entry, as an admin change
/// accepts.
const MAX_SELECTOR_LIST: usize = crate::api::token_admin::MAX_LIST;
/// Most device patterns in a stored deny entry, likewise.
const MAX_SELECTOR_DEVICES: usize = crate::api::sensitive_admin::MAX_DEVICE_PATTERNS;
/// Largest stored definition read: far above the largest list the
/// limits allow, so only a corrupt row is past it (and fails closed
/// without being copied or parsed).
const MAX_DEFINITION_BYTES: usize = 4 * 1024 * 1024;

/// The stored form of a list: a JSON array of deny entries.
fn encode(rules: &[DenyRule]) -> Vec<u8> {
    serde_json::Value::Array(rules.iter().map(DenyRule::to_json).collect())
        .to_string()
        .into_bytes()
}

/// Parse a stored list; `None` when any entry is malformed.
#[must_use]
pub fn decode_plugin_deny(definition: &[u8]) -> Option<Vec<DenyRule>> {
    let wire: Vec<crate::auth::role::SelectorWire> = serde_json::from_slice(definition).ok()?;
    // The admin surfaces' limits, so a stored list is never wider
    // than one they accept.
    if wire.len() > MAX_PLUGIN_DENY_ENTRIES
        || !wire
            .iter()
            .all(|w| w.within(MAX_SELECTOR_LIST, MAX_SELECTOR_DEVICES))
    {
        return None;
    }
    wire.into_iter()
        .map(crate::auth::role::SelectorWire::into_plugin_deny)
        .collect()
}

/// What a row that no longer parses means: every plugin action denied.
fn deny_everything() -> PluginDenyList {
    Arc::from(vec![DenyRule {
        actions: PLUGIN_ACTIONS,
        categories: None,
        devices: None,
        services: None,
    }])
}

/// The write a [`PluginDenyStore::change`] wraps; it runs at most once.
pub type Commit<'a> = Box<dyn FnOnce() -> Result<(), PluginDenyError> + 'a>;

impl PluginDenyStore {
    /// A store with no database, for states built outside an engine
    /// (tests).
    #[must_use]
    pub fn detached() -> Self {
        Self {
            db: None,
            rows: RwLock::new(HashMap::new()),
            writer: Mutex::new(()),
            generation: AtomicU64::new(0),
        }
    }

    /// Load every row from `db`.
    ///
    /// # Errors
    ///
    /// `SQLite` errors reading the table.
    pub fn open(db: Arc<Db>) -> Result<Self, rusqlite::Error> {
        let rows = db.read(|conn| -> Result<_, rusqlite::Error> {
            let mut stmt = conn.prepare("SELECT plugin_id, definition FROM plugin_deny")?;
            let iter = stmt.query_map([], |r| {
                // Any storage class: a value that isn't the JSON text
                // this module writes fails closed below, rather than
                // stopping the store from opening (or being reset).
                let definition = match r.get_ref(1)? {
                    rusqlite::types::ValueRef::Blob(b) | rusqlite::types::ValueRef::Text(b)
                        if b.len() <= MAX_DEFINITION_BYTES =>
                    {
                        b.to_vec()
                    }
                    _ => Vec::new(),
                };
                Ok((r.get::<_, String>(0)?, definition))
            })?;
            let mut out = HashMap::new();
            for row in iter {
                let (plugin_id, definition) = row?;
                let list = decode_plugin_deny(&definition).map_or_else(
                    || {
                        tracing::warn!(
                            target: "auth.plugin",
                            plugin_id = %plugin_id,
                            "stored plugin deny list does not parse; denying every plugin action",
                        );
                        deny_everything()
                    },
                    Arc::from,
                );
                out.insert(plugin_id, list);
            }
            Ok(out)
        })?;
        Ok(Self {
            db: Some(db),
            rows: RwLock::new(rows),
            writer: Mutex::new(()),
            generation: AtomicU64::new(0),
        })
    }

    /// The deny list of `plugin_id` (or the global one, `*`), if the
    /// owner set one.
    #[must_use]
    pub fn get(&self, plugin_id: &str) -> Option<PluginDenyList> {
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(plugin_id)
            .cloned()
    }

    /// The first list with an entry `refuses` accepts: the global
    /// list ([`GLOBAL_PLUGIN_DENY`]), then each of `plugins`'. All read
    /// under one lock, so a decision never mixes two states of the
    /// lists. `plugins` names at least the acting plugin, so the global
    /// list always counts.
    pub fn first_refusing<'a>(
        &self,
        plugins: impl IntoIterator<Item = &'a str>,
        refuses: impl Fn(&DenyRule) -> bool,
    ) -> Option<&'a str> {
        let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
        if rows.is_empty() {
            return None;
        }
        std::iter::once(GLOBAL_PLUGIN_DENY)
            .chain(plugins)
            .find(|id| rows.get(*id).is_some_and(|list| list.iter().any(&refuses)))
    }

    /// Changes so far. Two decisions that must agree on one policy
    /// (an entry's visibility and its bytes) compare it before and
    /// after: a change in between means they may have read two.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// `true` when no plugin has a deny list: the decision's fast path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// Every list, by plugin id.
    #[must_use]
    pub fn list(&self) -> Vec<(String, PluginDenyList)> {
        let mut rows: Vec<_> = self
            .rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// Replace the deny list of `plugin_id` with `rules` (an empty list
    /// removes it). Returns the list it replaced. Every entry must
    /// already be restricted to plugin actions.
    ///
    /// # Errors
    ///
    /// [`PluginDenyError`]: not a plugin id, too many entries or lists,
    /// or the write failed (the old list then still applies).
    pub fn set(
        &self,
        plugin_id: &str,
        rules: Vec<DenyRule>,
    ) -> Result<Option<PluginDenyList>, PluginDenyError> {
        self.change(plugin_id, rules, |old, commit| {
            let old = old.map(Arc::from);
            commit().map(|()| old)
        })?
    }

    /// [`Self::set`], with `wrap` around the write: it sees the list
    /// being replaced and calls `commit` to make the change, all under
    /// the writer lock, so what it records about the old list is what
    /// the change replaced (the audit row of an admin change). A change
    /// the limits refuse is refused before `wrap` runs.
    ///
    /// # Errors
    ///
    /// The change is refused ([`PluginDenyError`]: not a plugin id, too
    /// many entries or lists). Otherwise `wrap`'s result is returned,
    /// `commit` failing on a storage error.
    pub fn change<R>(
        &self,
        plugin_id: &str,
        rules: Vec<DenyRule>,
        wrap: impl FnOnce(Option<&[DenyRule]>, Commit<'_>) -> R,
    ) -> Result<R, PluginDenyError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.get(plugin_id);
        self.check(plugin_id, &rules, current.is_some())?;
        // Single-use: a second call can't turn the consumed list into
        // an empty one (a reset).
        let commit: Commit<'_> = Box::new(move || self.commit_locked(plugin_id, rules));
        Ok(wrap(current.as_deref(), commit))
    }

    /// The limits on a change; the writer lock is held.
    fn check(
        &self,
        plugin_id: &str,
        rules: &[DenyRule],
        exists: bool,
    ) -> Result<(), PluginDenyError> {
        if !is_deny_key(plugin_id) {
            return Err(PluginDenyError::BadPluginId(plugin_id.to_owned()));
        }
        if rules.len() > MAX_PLUGIN_DENY_ENTRIES {
            return Err(PluginDenyError::TooManyEntries);
        }
        if !rules.is_empty() && !exists && self.len() >= MAX_PLUGIN_DENY_LISTS {
            return Err(PluginDenyError::TooManyLists);
        }
        Ok(())
    }

    /// Store `rules`, [`Self::check`]ed; the writer lock is held.
    fn commit_locked(&self, plugin_id: &str, rules: Vec<DenyRule>) -> Result<(), PluginDenyError> {
        debug_assert!(rules.iter().all(|r| PLUGIN_ACTIONS.contains_all(r.actions)));
        if let Some(db) = &self.db {
            // `synchronous = FULL`: an acknowledged deny must survive
            // power loss, or the next start would load the wider
            // policy (like the network grant and TLS pin writes).
            db.write(|conn| -> Result<(), rusqlite::Error> {
                conn.pragma_update(None, "synchronous", "FULL")?;
                let result = if rules.is_empty() {
                    conn.execute("DELETE FROM plugin_deny WHERE plugin_id = ?1", [plugin_id])
                } else {
                    conn.execute(
                        "INSERT INTO plugin_deny (plugin_id, definition, updated_ms) \
                         VALUES (?1, ?2, ?3) \
                         ON CONFLICT(plugin_id) DO UPDATE SET \
                         definition = excluded.definition, updated_ms = excluded.updated_ms",
                        params![plugin_id, encode(&rules), now_unix_ms()],
                    )
                };
                if let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
                    tracing::warn!(
                        target: "auth.plugin",
                        error = %err,
                        "failed to restore synchronous = NORMAL; connection stays at FULL",
                    );
                }
                result.map(drop)
            })?;
        }
        let mut rows = self.rows.write().unwrap_or_else(PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::SeqCst);
        if rules.is_empty() {
            rows.remove(plugin_id);
        } else {
            rows.insert(plugin_id.to_owned(), Arc::from(rules));
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Action, ActionSet, DeviceCategory};

    fn rule() -> DenyRule {
        DenyRule {
            actions: ActionSet::of(&[Action::StateRead]),
            categories: Some(vec![DeviceCategory::Lock]),
            devices: None,
            services: None,
        }
    }

    #[test]
    fn lists_survive_a_reopen_and_reset_removes_them() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = PluginDenyStore::open(Arc::clone(&db)).expect("open");
        assert!(store.is_empty());
        assert!(
            store
                .set("com.example.lights", vec![rule()])
                .unwrap()
                .is_none()
        );
        let again = PluginDenyStore::open(Arc::clone(&db)).expect("reopen");
        assert_eq!(
            again.get("com.example.lights").as_deref(),
            Some(&[rule()][..])
        );
        let old = again.set("com.example.lights", Vec::new()).unwrap();
        assert_eq!(old.as_deref(), Some(&[rule()][..]));
        assert!(PluginDenyStore::open(db).expect("reopen").is_empty());
    }

    #[test]
    fn bad_ids_and_long_lists_are_refused() {
        let store = PluginDenyStore::detached();
        assert!(matches!(
            store.set("lights", vec![rule()]),
            Err(PluginDenyError::BadPluginId(_))
        ));
        assert!(matches!(
            store.set(
                "com.example.lights",
                vec![rule(); MAX_PLUGIN_DENY_ENTRIES + 1]
            ),
            Err(PluginDenyError::TooManyEntries)
        ));
    }

    /// The global list refuses for every plugin, ahead of the
    /// plugin's own, and survives a reopen like any other.
    #[test]
    fn the_global_list_applies_to_every_plugin() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = PluginDenyStore::open(Arc::clone(&db)).expect("open");
        let refuses = |d: &DenyRule| d.actions.contains(Action::StateRead);
        assert_eq!(store.first_refusing(["com.example.a"], refuses), None);
        store.set("com.example.a", vec![rule()]).expect("set");
        assert_eq!(
            store.first_refusing(["com.example.a"], refuses),
            Some("com.example.a")
        );
        store.set(GLOBAL_PLUGIN_DENY, vec![rule()]).expect("set");
        let store = PluginDenyStore::open(db).expect("reopen");
        assert_eq!(
            store.first_refusing(["com.example.a"], refuses),
            Some(GLOBAL_PLUGIN_DENY)
        );
        assert_eq!(
            store.first_refusing(["com.example.b"], refuses),
            Some(GLOBAL_PLUGIN_DENY)
        );
        assert!(matches!(
            store.set("**", vec![rule()]),
            Err(PluginDenyError::BadPluginId(_))
        ));
    }

    /// The generation moves with every stored change and only then,
    /// so decisions bracketing it see a change made between them.
    #[test]
    fn the_generation_moves_with_each_change() {
        let store = PluginDenyStore::detached();
        let g = store.generation();
        assert!(
            store
                .set("com.example.x", vec![rule(); MAX_PLUGIN_DENY_ENTRIES + 1])
                .is_err()
        );
        assert_eq!(store.generation(), g, "a refused change");
        store.set("com.example.x", vec![rule()]).expect("set");
        assert!(store.generation() > g);
        let g = store.generation();
        store.set("com.example.x", Vec::new()).expect("reset");
        assert!(store.generation() > g);
    }

    #[test]
    fn a_row_that_does_not_parse_denies_everything() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        db.write(|conn| {
            conn.execute(
                "INSERT INTO plugin_deny (plugin_id, definition, updated_ms) VALUES (?1, ?2, 0)",
                params!["com.example.x", br#"[{"actions":["host.logs"]}]"#.to_vec()],
            )
        })
        .expect("insert");
        let store = PluginDenyStore::open(db).expect("open");
        let list = store.get("com.example.x").expect("fail closed");
        assert_eq!(list[0].actions, PLUGIN_ACTIONS);
        // The widest device list an admin change takes survives a
        // reopen.
        let devices: Vec<String> = (0..crate::api::sensitive_admin::MAX_DEVICE_PATTERNS)
            .map(|i| format!("dev-{i:016x}"))
            .collect();
        let widest = serde_json::json!([{"actions": ["state.read"], "devices": devices}]);
        let widest = decode_plugin_deny(widest.to_string().as_bytes()).expect("within limits");
        let db = Arc::new(Db::open_in_memory().expect("db"));
        PluginDenyStore::open(Arc::clone(&db))
            .expect("open")
            .set("com.example.d", widest.clone())
            .expect("set");
        let store = PluginDenyStore::open(db).expect("reopen");
        assert_eq!(store.get("com.example.d").as_deref(), Some(&widest[..]));
        // A positional entry is malformed, not a narrower list.
        assert!(decode_plugin_deny(br#"[[["state.read"],null,null,null]]"#).is_none());
        // Text, a list wider than an admin change takes, and a
        // non-text value all fail closed too.
        let many: Vec<String> = (0..=MAX_SELECTOR_LIST)
            .map(|i| format!("com.example.p{i}/svc"))
            .collect();
        let wide = serde_json::json!([{"actions": ["service.call"], "services": many}]).to_string();
        let db = Arc::new(Db::open_in_memory().expect("db"));
        db.write(|conn| {
            conn.execute(
                "INSERT INTO plugin_deny (plugin_id, definition, updated_ms) VALUES \
                 ('com.example.a', ?1, 0), ('com.example.b', ?2, 0), ('com.example.c', 7, 0)",
                params![wide.clone(), wide.into_bytes()],
            )
        })
        .expect("insert");
        let store = PluginDenyStore::open(Arc::clone(&db)).expect("open");
        for id in ["com.example.a", "com.example.b", "com.example.c"] {
            assert_eq!(store.get(id).expect(id)[0].actions, PLUGIN_ACTIONS, "{id}");
        }
        store.set("com.example.a", Vec::new()).expect("reset");
        assert!(store.get("com.example.a").is_none());
        assert_eq!(
            PluginDenyStore::open(db).expect("reopen").len(),
            2,
            "the reset stuck"
        );
        assert_eq!(
            decode_plugin_deny(&encode(&[rule()])).as_deref(),
            Some(&[rule()][..])
        );
    }
}
