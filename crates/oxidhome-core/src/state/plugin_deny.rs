//! The owner's deny lists over plugins (H6 slice 5): the `plugin_deny`
//! table.
//!
//! One row per plugin id the owner has restricted: a list of deny
//! entries ([`DenyRule`]) restricted to
//! [`crate::auth::PLUGIN_ACTIONS`]. [`crate::auth::authorize_plugin`]
//! applies the list of the acting plugin and of every plugin that made
//! a hop on the way to it, whatever the plugin's manifest grants. The
//! list is keyed by plugin id, not installation: it outlives an
//! uninstall, so a reinstall can't shed it, and it can be set before
//! the plugin is installed.
//!
//! The table is small and loaded into memory at open; reads (every
//! plugin decision) never touch `SQLite`, and a change applies to the
//! next decision of every running instance. A stored row that no longer
//! parses denies the plugin every plugin action (fail closed).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::params;

use super::db::Db;
use super::event_log::now_unix_ms;
use crate::auth::{DenyRule, PLUGIN_ACTIONS};

/// Most deny entries one plugin's list may hold.
pub const MAX_PLUGIN_DENY_ENTRIES: usize = 32;

/// Most plugins with a deny list.
pub const MAX_PLUGIN_DENY_LISTS: usize = 1024;

/// Why a deny list change was refused.
#[derive(Debug, thiserror::Error)]
pub enum PluginDenyError {
    /// Not a plugin id.
    #[error("`{0}` is not a plugin id (reverse-DNS, e.g. `com.example.lights`)")]
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
}

impl Default for PluginDenyStore {
    fn default() -> Self {
        Self::detached()
    }
}

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
    if wire.len() > MAX_PLUGIN_DENY_ENTRIES {
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

impl PluginDenyStore {
    /// A store with no database, for states built outside an engine
    /// (tests).
    #[must_use]
    pub fn detached() -> Self {
        Self {
            db: None,
            rows: RwLock::new(HashMap::new()),
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
            let mut stmt = conn.prepare("SELECT plugin_id, definition FROM plugin_deny")?;
            let iter = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
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
        })
    }

    /// The deny list of `plugin_id`, if the owner set one.
    #[must_use]
    pub fn get(&self, plugin_id: &str) -> Option<PluginDenyList> {
        self.rows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(plugin_id)
            .cloned()
    }

    /// The first of `plugins` whose list has an entry `refuses`
    /// accepts, all read under one lock, so a decision never mixes two
    /// states of the lists.
    pub fn first_refusing<'a>(
        &self,
        plugins: impl IntoIterator<Item = &'a str>,
        refuses: impl Fn(&DenyRule) -> bool,
    ) -> Option<&'a str> {
        let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
        if rows.is_empty() {
            return None;
        }
        plugins
            .into_iter()
            .find(|id| rows.get(*id).is_some_and(|list| list.iter().any(&refuses)))
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
        wrap: impl FnOnce(Option<&[DenyRule]>, &mut dyn FnMut() -> Result<(), PluginDenyError>) -> R,
    ) -> Result<R, PluginDenyError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.get(plugin_id);
        self.check(plugin_id, &rules, current.is_some())?;
        let mut rules = Some(rules);
        let mut commit = || {
            let rules = rules.take().unwrap_or_default();
            self.commit_locked(plugin_id, rules)
        };
        Ok(wrap(current.as_deref(), &mut commit))
    }

    /// The limits on a change; the writer lock is held.
    fn check(
        &self,
        plugin_id: &str,
        rules: &[DenyRule],
        exists: bool,
    ) -> Result<(), PluginDenyError> {
        if !oxidhome_manifest::is_plugin_id(plugin_id) {
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
        assert_eq!(
            decode_plugin_deny(&encode(&[rule()])).as_deref(),
            Some(&[rule()][..])
        );
    }
}
