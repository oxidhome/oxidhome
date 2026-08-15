//! Phase 13 slice 3: persistent dashboard storage.
//!
//! A dashboard is a user-composed layout of widgets that
//! the shell renders. The host stores it as opaque JSON
//! (`layout_json`) plus a small envelope of metadata —
//! the shape of the layout is the shell's contract with
//! itself, versioned by `schema_version` so a future
//! widget-catalog change can drive a declarative
//! shell-side transform on load.
//!
//! Store mirrors the shape of the Phase-5 stores
//! (`Arc<Db>` handle, `spawn_blocking`-driven writes
//! from the async API layer, synchronous `impl` for the
//! store itself). Persistence lives in `dashboard` /
//! `dashboard_by_owner` per migration 15.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, params};

use crate::state::db::Db;

/// One dashboard row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dashboard {
    /// Server-minted primary key. `create` returns this;
    /// `upsert` / `update_layout` accept it.
    pub id: i64,
    /// Human-facing display name shown in the shell's
    /// dashboard picker. Not unique — two dashboards can
    /// share a name (they're addressed by `id`).
    pub name: String,
    /// Phase 12 actor id of the operator who created this
    /// dashboard. v1 is single-role "admin" so every row
    /// carries the admin actor's id; the column exists so
    /// the multi-user follow-up can route by owner
    /// without a migration.
    pub owner_user_id: String,
    /// Opaque bytes — the shell's serialized layout tree.
    /// The host doesn't parse it; the shell's own
    /// versioning + declarative migrations sit above.
    pub layout_json: Vec<u8>,
    /// Shell-side schema version bound to `layout_json`'s
    /// shape. Bumped by the shell when the widget-catalog
    /// contract changes.
    pub schema_version: i64,
    /// Host wall-clock (ms since Unix epoch) at row
    /// creation.
    pub created_ms: i64,
    /// Host wall-clock (ms since Unix epoch) of the last
    /// `upsert` / `update_layout`. Same as `created_ms`
    /// on a row that has never been updated.
    pub updated_ms: i64,
}

/// A new dashboard's fields — everything the caller
/// supplies at create time. The store fills in `id`,
/// `created_ms`, `updated_ms` on its own.
#[derive(Debug, Clone)]
pub struct DashboardInput {
    pub name: String,
    pub owner_user_id: String,
    pub layout_json: Vec<u8>,
    pub schema_version: i64,
}

/// Phase 13 slice 3: SQLite-backed dashboard store.
/// Cheap to clone — holds an `Arc<Db>`, no per-store
/// state.
#[derive(Debug)]
pub struct DashboardStore {
    db: Arc<Db>,
}

/// Errors surfaced from the store. The API layer maps
/// `NotFound` to `404` and `Persistence` to `500`
/// (host-side integrity / disk issue).
#[derive(Debug, thiserror::Error)]
pub enum DashboardError {
    #[error("dashboard {0} not found")]
    NotFound(i64),
    #[error(transparent)]
    Persistence(#[from] rusqlite::Error),
}

impl DashboardStore {
    /// Wrap a shared `Db` handle. Migrations are already
    /// applied by [`Db::open_file`] / [`Db::open_in_memory`]
    /// — the store expects table `dashboard` to exist.
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Insert a fresh dashboard. Returns the row as
    /// stored (with `id` filled in). `created_ms` and
    /// `updated_ms` are both set to the current host
    /// wall-clock.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn create(&self, input: DashboardInput) -> Result<Dashboard, DashboardError> {
        let now = now_ms();
        let id = self.db.write(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO dashboard \
                     (name, owner_user_id, layout_json, schema_version, created_ms, updated_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![
                    &input.name,
                    &input.owner_user_id,
                    &input.layout_json,
                    input.schema_version,
                    now,
                ],
            )?;
            let id = tx.last_insert_rowid();
            tx.commit()?;
            Ok::<_, rusqlite::Error>(id)
        })?;
        Ok(Dashboard {
            id,
            name: input.name,
            owner_user_id: input.owner_user_id,
            layout_json: input.layout_json,
            schema_version: input.schema_version,
            created_ms: now,
            updated_ms: now,
        })
    }

    /// Load one dashboard by id. Returns `Ok(None)` if the
    /// row doesn't exist — callers wanting `NotFound`
    /// semantics wrap with `.ok_or(...)`.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn get(&self, id: i64) -> Result<Option<Dashboard>, DashboardError> {
        let row = self.db.read(|conn| {
            conn.query_row(
                "SELECT id, name, owner_user_id, layout_json, schema_version, created_ms, updated_ms \
                 FROM dashboard WHERE id = ?1",
                params![id],
                Self::row_to_dashboard,
            )
            .optional()
        })?;
        Ok(row)
    }

    /// List every dashboard owned by `owner_user_id`,
    /// ordered by `updated_ms DESC` so the "most recently
    /// touched" bubble to the top of the shell's picker.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn list_by_owner(&self, owner_user_id: &str) -> Result<Vec<Dashboard>, DashboardError> {
        let rows = self.db.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, owner_user_id, layout_json, schema_version, created_ms, updated_ms \
                 FROM dashboard \
                 WHERE owner_user_id = ?1 \
                 ORDER BY updated_ms DESC",
            )?;
            stmt.query_map(params![owner_user_id], Self::row_to_dashboard)?
                .collect::<Result<Vec<_>, _>>()
        })?;
        Ok(rows)
    }

    /// Replace an existing dashboard's `name`, `layout_json`,
    /// and `schema_version`. Updates `updated_ms`; leaves
    /// `owner_user_id` and `created_ms` alone (the row's
    /// identity + creation time don't change on edit).
    ///
    /// # Errors
    /// - [`DashboardError::NotFound`] if no row has `id`.
    /// - [`DashboardError::Persistence`] on `SQLite` failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update(&self, id: i64, input: DashboardInput) -> Result<Dashboard, DashboardError> {
        let now = now_ms();
        let outcome = self.db.write(|conn| {
            let tx = conn.transaction()?;
            let rows = tx.execute(
                "UPDATE dashboard \
                    SET name = ?2, \
                        layout_json = ?3, \
                        schema_version = ?4, \
                        updated_ms = ?5 \
                  WHERE id = ?1",
                params![
                    id,
                    &input.name,
                    &input.layout_json,
                    input.schema_version,
                    now,
                ],
            )?;
            if rows == 0 {
                return Ok::<_, rusqlite::Error>(None);
            }
            tx.commit()?;
            Ok(Some(()))
        })?;
        match outcome {
            Some(()) => self.get(id)?.ok_or(DashboardError::NotFound(id)),
            None => Err(DashboardError::NotFound(id)),
        }
    }

    /// Delete a dashboard by id. Returns `Ok(true)` on
    /// success, `Ok(false)` if no row matched (idempotent
    /// — the caller can treat a repeat delete as a no-op).
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn delete(&self, id: i64) -> Result<bool, DashboardError> {
        let rows = self.db.write(|conn| {
            let tx = conn.transaction()?;
            let n = tx.execute("DELETE FROM dashboard WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok::<_, rusqlite::Error>(n)
        })?;
        Ok(rows > 0)
    }

    fn row_to_dashboard(row: &rusqlite::Row<'_>) -> rusqlite::Result<Dashboard> {
        Ok(Dashboard {
            id: row.get(0)?,
            name: row.get(1)?,
            owner_user_id: row.get(2)?,
            layout_json: row.get(3)?,
            schema_version: row.get(4)?,
            created_ms: row.get(5)?,
            updated_ms: row.get(6)?,
        })
    }
}

/// Shared `Arc` alias, parallel to `SharedKvStore` /
/// `SharedEventLog` etc.
pub type SharedDashboardStore = Arc<DashboardStore>;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> DashboardStore {
        let db = Db::open_in_memory().expect("open in-memory db");
        DashboardStore::new(Arc::new(db))
    }

    fn input(name: &str, owner: &str) -> DashboardInput {
        DashboardInput {
            name: name.into(),
            owner_user_id: owner.into(),
            layout_json: br#"{"rows":[]}"#.to_vec(),
            schema_version: 1,
        }
    }

    #[test]
    fn create_then_get_round_trips() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        assert!(created.id > 0);
        assert_eq!(created.name, "home");
        assert_eq!(created.owner_user_id, "admin");
        assert_eq!(created.schema_version, 1);
        assert_eq!(created.created_ms, created.updated_ms);
        let fetched = s.get(created.id).expect("get").expect("row");
        assert_eq!(fetched, created);
    }

    #[test]
    fn get_missing_returns_none() {
        let s = store();
        assert!(s.get(999).expect("get").is_none());
    }

    #[test]
    fn list_by_owner_orders_most_recent_first() {
        let s = store();
        // Two dashboards, first created earlier, second
        // touched later — `updated_ms DESC` must put the
        // second one first even though it has a higher id
        // that already implies later creation. Give them
        // deterministic timestamps by updating the second
        // one after creation.
        let a = s.create(input("a", "admin")).expect("a");
        let b = s.create(input("b", "admin")).expect("b");
        // Sleep a millisecond so the update's timestamp is
        // strictly greater than `a`'s.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b_updated = s
            .update(
                b.id,
                DashboardInput {
                    name: "b (renamed)".into(),
                    owner_user_id: "admin".into(),
                    layout_json: b.layout_json.clone(),
                    schema_version: b.schema_version,
                },
            )
            .expect("update b");
        let listed = s.list_by_owner("admin").expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, b_updated.id);
        assert_eq!(listed[1].id, a.id);
        // Different owner shouldn't see either.
        assert!(s.list_by_owner("someone-else").expect("list").is_empty());
    }

    #[test]
    fn update_touches_updated_ms_but_not_created_ms() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let updated = s
            .update(
                created.id,
                DashboardInput {
                    name: "home v2".into(),
                    owner_user_id: "admin".into(),
                    layout_json: br#"{"rows":[{"widgets":[]}]}"#.to_vec(),
                    schema_version: 2,
                },
            )
            .expect("update");
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.created_ms, created.created_ms);
        assert!(updated.updated_ms > created.updated_ms);
        assert_eq!(updated.name, "home v2");
        assert_eq!(updated.schema_version, 2);
    }

    #[test]
    fn update_missing_row_returns_not_found() {
        let s = store();
        let err = s.update(999, input("nope", "admin")).unwrap_err();
        assert!(matches!(err, DashboardError::NotFound(999)));
    }

    #[test]
    fn delete_reports_whether_a_row_was_removed() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        assert!(s.delete(created.id).expect("delete"));
        assert!(!s.delete(created.id).expect("re-delete is idempotent"));
        assert!(s.get(created.id).expect("get").is_none());
    }
}
