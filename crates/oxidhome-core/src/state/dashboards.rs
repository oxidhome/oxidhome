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

/// Round-2 finding 3: hard cap on dashboard `name`
/// length. Names are shown in the shell picker; huge
/// names make the picker unusable AND contribute
/// per-row to the list-endpoint response body.
pub const MAX_DASHBOARD_NAME_BYTES: usize = 256;

/// Round-2 finding 3: hard cap on a single dashboard's
/// serialized `layout_json`. Layouts are opaque bytes
/// (the shell owns the shape), but the byte cost is real
/// — the list endpoint reads every layout for the owner
/// into memory. 128 KiB is comfortable headroom for a
/// household-sized dashboard (dozens of widgets with
/// configs) and small enough that an owner filling their
/// count quota stays under a bounded memory footprint.
pub const MAX_DASHBOARD_LAYOUT_BYTES: usize = 128 * 1024;

/// Round-2 finding 3: cap on dashboards per owner.
/// Combined with the layout cap, one owner's total
/// projected bytes are bounded (`128 × 128 KiB = 16 MiB`).
/// The count itself keeps the list endpoint bounded and
/// prevents a scoped token from filling the database
/// through repeated creates.
pub const MAX_DASHBOARDS_PER_OWNER: usize = 128;

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
/// `NotFound` to `404`, cap violations to `400` /
/// `409`, and `Persistence` to `500` (host-side
/// integrity / disk issue).
#[derive(Debug, thiserror::Error)]
pub enum DashboardError {
    #[error("dashboard {0} not found")]
    NotFound(i64),
    /// Round-2 finding 3: request-time cap. `name` /
    /// `layout` came in over the allowed size.
    #[error("dashboard {field} exceeds the cap: {size} > {max}")]
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    /// Round-2 finding 3: this owner is at the
    /// [`MAX_DASHBOARDS_PER_OWNER`] cap. Delete an
    /// existing dashboard to free a slot.
    #[error("owner already has {existing} dashboards; cap is {max}")]
    QuotaExceeded { existing: usize, max: usize },
    #[error(transparent)]
    Persistence(#[from] rusqlite::Error),
}

/// Round-2 finding 3: metadata-only projection surfaced
/// by [`DashboardStore::list_metadata_by_owner`]. Omits
/// `layout_json` so the list endpoint response body is
/// bounded by `MAX_DASHBOARDS_PER_OWNER *
/// (MAX_DASHBOARD_NAME_BYTES + fixed metadata)` regardless
/// of layout size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardMetadata {
    pub id: i64,
    pub name: String,
    pub owner_user_id: String,
    pub schema_version: i64,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// Round-2 finding 3: byte size of `layout_json` on
    /// disk, so a client can render a size indicator
    /// without fetching every full row.
    pub layout_bytes: usize,
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
        check_caps(&input)?;
        let now = now_ms();
        // Round-2 finding 3: check the per-owner count
        // quota inside the same transaction as the insert
        // so a burst of concurrent creates can't slip past
        // by racing. `BEGIN IMMEDIATE` (SQLite's default
        // via rusqlite's `transaction()`) serializes
        // writers, so the count read is a valid pre-check.
        let owner_for_quota = input.owner_user_id.clone();
        let id = self
            .db
            .write(|conn| -> Result<Result<i64, DashboardError>, rusqlite::Error> {
                let tx = conn.transaction()?;
                let existing: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM dashboard WHERE owner_user_id = ?1",
                    params![&owner_for_quota],
                    |r| r.get(0),
                )?;
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let existing_usize = existing.max(0) as usize;
                if existing_usize >= MAX_DASHBOARDS_PER_OWNER {
                    return Ok(Err(DashboardError::QuotaExceeded {
                        existing: existing_usize,
                        max: MAX_DASHBOARDS_PER_OWNER,
                    }));
                }
                tx.execute(
                    "INSERT INTO dashboard \
                         (name, owner_user_id, layout_json, schema_version, created_ms, updated_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![
                        &input.name,
                        &owner_for_quota,
                        &input.layout_json,
                        input.schema_version,
                        now,
                    ],
                )?;
                let id = tx.last_insert_rowid();
                tx.commit()?;
                Ok(Ok(id))
            })??;
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

    /// Metadata-only projection of every dashboard owned by
    /// `owner_user_id`, ordered `updated_ms DESC` so the
    /// most-recently-touched surface first in the shell's
    /// picker. Round-2 finding 3: omits `layout_json` so the
    /// list response is bounded by
    /// `MAX_DASHBOARDS_PER_OWNER * (name + fixed metadata)`
    /// regardless of layout size; the caller fetches an
    /// individual layout with `get_owned` once the operator
    /// picks one. Pre-fix the endpoint surfaced every full
    /// row — an owner at the count quota with max-sized
    /// layouts would ship 16 MiB per list call.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn list_metadata_by_owner(
        &self,
        owner_user_id: &str,
    ) -> Result<Vec<DashboardMetadata>, DashboardError> {
        let rows = self.db.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, owner_user_id, schema_version, created_ms, updated_ms, \
                        length(layout_json) \
                 FROM dashboard \
                 WHERE owner_user_id = ?1 \
                 ORDER BY updated_ms DESC",
            )?;
            stmt.query_map(params![owner_user_id], |row| {
                let layout_bytes: i64 = row.get(6)?;
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let layout_bytes_usize = layout_bytes.max(0) as usize;
                Ok(DashboardMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    owner_user_id: row.get(2)?,
                    schema_version: row.get(3)?,
                    created_ms: row.get(4)?,
                    updated_ms: row.get(5)?,
                    layout_bytes: layout_bytes_usize,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
        })?;
        Ok(rows)
    }

    /// Replace an existing dashboard's `name`,
    /// `layout_json`, and `schema_version` — scoped to
    /// `owner_user_id` **inside the same statement** so a
    /// concurrent delete + create that recycles the
    /// `INTEGER PRIMARY KEY` value under a different owner
    /// can't be modified by a stale request that only
    /// remembers the id. Uses `RETURNING` so the response
    /// row is the one this statement actually wrote —
    /// eliminates the post-commit `get()` that pre-fix
    /// could observe a subsequent writer's row.
    ///
    /// Round-2 finding 1: pre-fix the handler did
    /// `get()`-then-`update-by-id` in two separate DB
    /// visits. `SQLite` reuses deleted `PRIMARY KEY` values,
    /// so a concurrent delete + create between the two
    /// visits could substitute a different owner's
    /// dashboard under the same id and the stale request
    /// would happily modify it.
    ///
    /// # Errors
    /// - [`DashboardError::NotFound`] if no row matches
    ///   `id AND owner_user_id`.
    /// - [`DashboardError::Persistence`] on `SQLite` failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_owned(
        &self,
        id: i64,
        owner_user_id: &str,
        input: DashboardInput,
    ) -> Result<Dashboard, DashboardError> {
        check_caps(&input)?;
        let now = now_ms();
        let row = self.db.write(|conn| {
            let tx = conn.transaction()?;
            let mut stmt = tx.prepare(
                "UPDATE dashboard \
                    SET name = ?2, \
                        layout_json = ?3, \
                        schema_version = ?4, \
                        updated_ms = ?5 \
                  WHERE id = ?1 AND owner_user_id = ?6 \
              RETURNING id, name, owner_user_id, layout_json, schema_version, created_ms, updated_ms",
            )?;
            let row = stmt
                .query_row(
                    params![
                        id,
                        &input.name,
                        &input.layout_json,
                        input.schema_version,
                        now,
                        owner_user_id,
                    ],
                    Self::row_to_dashboard,
                )
                .optional()?;
            drop(stmt);
            tx.commit()?;
            Ok::<_, rusqlite::Error>(row)
        })?;
        row.ok_or(DashboardError::NotFound(id))
    }

    /// Delete a dashboard by id, scoped to
    /// `owner_user_id` in the same statement (round-2
    /// finding 1 — see [`Self::update_owned`]). Returns
    /// `Ok(true)` on success, `Ok(false)` if no row
    /// matched.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn delete_owned(&self, id: i64, owner_user_id: &str) -> Result<bool, DashboardError> {
        let rows = self.db.write(|conn| {
            let tx = conn.transaction()?;
            let n = tx.execute(
                "DELETE FROM dashboard WHERE id = ?1 AND owner_user_id = ?2",
                params![id, owner_user_id],
            )?;
            tx.commit()?;
            Ok::<_, rusqlite::Error>(n)
        })?;
        Ok(rows > 0)
    }

    /// Owner-scoped point read — same shape as
    /// [`Self::update_owned`] / [`Self::delete_owned`] so
    /// the handler can uniformly enforce ownership in one
    /// statement without a post-fetch owner filter.
    ///
    /// # Errors
    /// [`DashboardError::Persistence`] on `SQLite` failure.
    pub fn get_owned(
        &self,
        id: i64,
        owner_user_id: &str,
    ) -> Result<Option<Dashboard>, DashboardError> {
        let row = self.db.read(|conn| {
            conn.query_row(
                "SELECT id, name, owner_user_id, layout_json, schema_version, created_ms, updated_ms \
                 FROM dashboard WHERE id = ?1 AND owner_user_id = ?2",
                params![id, owner_user_id],
                Self::row_to_dashboard,
            )
            .optional()
        })?;
        Ok(row)
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

/// Round-2 finding 3: name and layout size guards used by
/// both `create` and `update_owned`. Owner-quota check
/// lives inside `create`'s transaction (an owner at the
/// count cap can still update / delete existing rows).
fn check_caps(input: &DashboardInput) -> Result<(), DashboardError> {
    if input.name.len() > MAX_DASHBOARD_NAME_BYTES {
        return Err(DashboardError::TooLarge {
            field: "name",
            size: input.name.len(),
            max: MAX_DASHBOARD_NAME_BYTES,
        });
    }
    if input.layout_json.len() > MAX_DASHBOARD_LAYOUT_BYTES {
        return Err(DashboardError::TooLarge {
            field: "layout",
            size: input.layout_json.len(),
            max: MAX_DASHBOARD_LAYOUT_BYTES,
        });
    }
    Ok(())
}

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
        let fetched = s.get_owned(created.id, "admin").expect("get").expect("row");
        assert_eq!(fetched, created);
    }

    #[test]
    fn get_owned_scopes_to_owner() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        assert!(
            s.get_owned(created.id, "someone-else")
                .expect("get")
                .is_none()
        );
        assert!(s.get_owned(999, "admin").expect("get").is_none());
    }

    #[test]
    fn list_metadata_by_owner_orders_most_recent_first_and_omits_layout() {
        let s = store();
        let a = s.create(input("a", "admin")).expect("a");
        let b = s.create(input("b", "admin")).expect("b");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let _ = s
            .update_owned(
                b.id,
                "admin",
                DashboardInput {
                    name: "b (renamed)".into(),
                    owner_user_id: "admin".into(),
                    layout_json: b.layout_json.clone(),
                    schema_version: b.schema_version,
                },
            )
            .expect("update b");
        let listed = s.list_metadata_by_owner("admin").expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, b.id);
        assert_eq!(listed[1].id, a.id);
        // Metadata carries the size, not the bytes themselves.
        assert!(listed[0].layout_bytes > 0);
        assert!(s.list_metadata_by_owner("nobody").expect("list").is_empty());
    }

    #[test]
    fn update_owned_touches_updated_ms_but_not_created_ms() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let updated = s
            .update_owned(
                created.id,
                "admin",
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

    /// Round-2 finding 1: `update_owned` refuses to modify
    /// a row that isn't owned by the caller — even if the
    /// id matches. Regardless of a concurrent delete-plus-
    /// create sequence, the owner predicate travels
    /// *inside* the `UPDATE` statement.
    #[test]
    fn update_owned_refuses_cross_owner_id() {
        let s = store();
        let alice_row = s.create(input("alice-home", "alice")).expect("create");
        let err = s
            .update_owned(
                alice_row.id,
                "bob",
                DashboardInput {
                    name: "bob-was-here".into(),
                    owner_user_id: "bob".into(),
                    layout_json: b"{}".to_vec(),
                    schema_version: 1,
                },
            )
            .unwrap_err();
        assert!(matches!(err, DashboardError::NotFound(_)));
        // Alice's row is untouched.
        let refetched = s
            .get_owned(alice_row.id, "alice")
            .expect("get")
            .expect("row");
        assert_eq!(refetched.name, "alice-home");
    }

    #[test]
    fn update_owned_missing_row_returns_not_found() {
        let s = store();
        let err = s
            .update_owned(999, "admin", input("nope", "admin"))
            .unwrap_err();
        assert!(matches!(err, DashboardError::NotFound(999)));
    }

    #[test]
    fn delete_owned_reports_whether_a_row_was_removed_and_scopes_to_owner() {
        let s = store();
        let created = s.create(input("home", "admin")).expect("create");
        // Cross-owner attempt: no-op.
        assert!(!s.delete_owned(created.id, "not-admin").expect("delete"));
        // Owner delete: succeeds.
        assert!(s.delete_owned(created.id, "admin").expect("delete"));
        // Idempotent re-delete.
        assert!(!s.delete_owned(created.id, "admin").expect("re-delete"));
        assert!(s.get_owned(created.id, "admin").expect("get").is_none());
    }

    /// Round-2 finding 3: create refuses oversized name
    /// and oversized layout up front.
    #[test]
    fn create_refuses_oversized_name_and_layout() {
        let s = store();
        let big_name = "a".repeat(MAX_DASHBOARD_NAME_BYTES + 1);
        let err = s
            .create(DashboardInput {
                name: big_name,
                owner_user_id: "admin".into(),
                layout_json: b"{}".to_vec(),
                schema_version: 1,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            DashboardError::TooLarge { field: "name", .. }
        ));
        let big_layout = vec![b'a'; MAX_DASHBOARD_LAYOUT_BYTES + 1];
        let err = s
            .create(DashboardInput {
                name: "home".into(),
                owner_user_id: "admin".into(),
                layout_json: big_layout,
                schema_version: 1,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            DashboardError::TooLarge {
                field: "layout",
                ..
            }
        ));
    }

    /// Round-2 finding 3: per-owner count quota enforced
    /// inside the create transaction. Once at cap, a
    /// scoped token can't fill the DB through repeated
    /// creates.
    #[test]
    fn create_refuses_past_per_owner_count_quota() {
        let s = store();
        for i in 0..MAX_DASHBOARDS_PER_OWNER {
            s.create(input(&format!("d{i}"), "admin")).unwrap();
        }
        let err = s.create(input("overflow", "admin")).unwrap_err();
        assert!(matches!(err, DashboardError::QuotaExceeded { .. }));
        // Different owner still has room.
        s.create(input("theirs", "someone-else")).unwrap();
    }
}
