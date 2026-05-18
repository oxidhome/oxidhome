//! Per-instance blob store — Phase 5b.
//!
//! Filesystem-backed bytes (`<state_dir>/blobs/<instance_id>/<id>`)
//! plus a `SQLite` index in the same DB file as `kv` / `event_log` /
//! `log_event` (`blob` + `blob_usage` tables, migration 6). Splitting
//! bytes from index keeps multi-MB writes off the `SQLite` `BLOB` path
//! while keeping `(name → id)` lookup atomic with the quota check.
//!
//! ## Write atomicity
//!
//! `write` stages bytes into `<instance_dir>/.tmp/<id>`, fsyncs the
//! file, then opens a `BEGIN IMMEDIATE` transaction that:
//!
//! 1. Checks the projected `bytes_used` against
//!    `bytes_quota`. Over-quota → return `BlobError::QuotaExceeded`
//!    without committing or renaming.
//! 2. INSERTs or UPDATEs the `blob` row (the trigger updates
//!    `blob_usage.bytes_used`).
//! 3. Atomically renames `.tmp/<id>` → `<instance_dir>/<id>`.
//! 4. Commits the transaction.
//! 5. Best-effort deletes the *previous* blob file when the write
//!    overwrites an existing name.
//!
//! Rename-then-commit means a crash between rename and commit
//! leaves the new file in place but no DB row references it.
//! Acceptable — a Phase-12 retention sweep can drop FS orphans.
//! Commit-then-rename would be worse: a DB row pointing at a file
//! that doesn't exist would surface as `read_by_name → not-found`
//! after a previously-successful write, which is confusing for
//! operators.
//!
//! ## In-memory engine support
//!
//! `BlobStore::new(db, None)` is the "no filesystem available"
//! state — used by [`crate::Engine::new`] for in-memory tests. All
//! mutating ops return `BlobError::Unavailable`; reads return
//! `NotFound`. Tests that need to actually exercise blobs construct
//! `Engine::with_state_dir(...)`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::OptionalExtension;
use rusqlite::params;

use super::db::Db;

/// Errors returned by [`BlobStore`]. Map to WIT `error` variants in
/// `host_impl::blob_store`.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// No filesystem root configured — engine was constructed via
    /// [`crate::Engine::new`] (in-memory) rather than
    /// [`crate::Engine::with_state_dir`]. Writes / deletes can't
    /// complete; surface as `Error::Unavailable` from the WIT side.
    #[error("blob store unavailable: engine has no state directory configured")]
    Unavailable,

    /// Instance has no `blob_usage` row — host's loader didn't call
    /// `register_instance`. Host bug, never a plugin bug.
    #[error("instance `{instance_id}` is not registered with the blob store")]
    UnregisteredInstance { instance_id: String },

    /// Completing the write would push past the manifest-declared
    /// `blob_quota_mb`. Refused before any rename / commit.
    #[error(
        "blob quota exceeded for instance `{instance_id}`: \
         {would_use} bytes would be used / {allowed} allowed"
    )]
    QuotaExceeded {
        instance_id: String,
        would_use: u64,
        allowed: u64,
    },

    /// No blob with the given id / name for this instance.
    #[error("blob not found: {what}")]
    NotFound { what: String },

    /// Filesystem operation (mkdir / write / fsync / rename / read /
    /// remove) failed. The host's blob root is the same FS as the
    /// `SQLite` DB, so most causes (full disk, permission denied) are
    /// operator-visible already.
    #[error("blob filesystem error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// ``SQLite`` returned an error during the operation.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Decoded metadata for one stored blob — mirrors the WIT
/// `blob-info` record so the host trait impl can convert with a
/// trivial field-by-field move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    pub name: String,
    pub id: String,
    pub size_bytes: u64,
    pub created_ms: u64,
    pub mime: Option<String>,
}

/// Per-engine blob store. Cheap to clone — holds an `Arc<Db>` plus
/// an optional FS root + a tiny ID counter.
pub struct BlobStore {
    db: Arc<Db>,
    /// `<state_dir>/blobs` when the engine has a real state dir;
    /// `None` for `Engine::new()` (in-memory mode).
    blobs_root: Option<PathBuf>,
    /// Process-local counter that disambiguates blob IDs minted
    /// inside the same millisecond.
    id_counter: AtomicU64,
}

impl BlobStore {
    #[must_use]
    pub fn new(db: Arc<Db>, blobs_root: Option<PathBuf>) -> Self {
        Self {
            db,
            blobs_root,
            id_counter: AtomicU64::new(0),
        }
    }

    /// Reserve a `blob_usage` slot with the given quota. Idempotent
    /// — re-registering preserves `bytes_used` and only updates the
    /// quota (so a manifest edit + reload picks up the new value
    /// without wiping data). A quota of `0` is the manifest-default
    /// "blobs gated off" signal — every mutating call returns
    /// `permission-denied` via the host-side gate before reaching
    /// the store.
    ///
    /// # Errors
    ///
    /// ``SQLite`` errors surface as [`BlobError::Sql`].
    pub fn register_instance(&self, instance_id: &str, quota_bytes: u64) -> Result<(), BlobError> {
        let quota_i64 = i64::try_from(quota_bytes).unwrap_or(i64::MAX);
        self.db.write(|conn| -> Result<(), BlobError> {
            conn.execute(
                "INSERT INTO blob_usage(instance_id, bytes_used, bytes_quota) \
                 VALUES (?1, 0, ?2) \
                 ON CONFLICT(instance_id) DO UPDATE SET bytes_quota = excluded.bytes_quota",
                params![instance_id, quota_i64],
            )?;
            Ok(())
        })
    }

    /// Current `(bytes_used, bytes_quota)` for an instance. Returns
    /// `Ok(None)` when the instance isn't registered.
    ///
    /// # Errors
    ///
    /// Forwards SQL errors.
    pub fn usage(&self, instance_id: &str) -> Result<Option<(u64, u64)>, BlobError> {
        let row = self.db.read(|conn| -> Result<_, BlobError> {
            Ok(conn
                .query_row(
                    "SELECT bytes_used, bytes_quota FROM blob_usage WHERE instance_id = ?1",
                    params![instance_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?)
        })?;
        Ok(row.map(|(u, q)| (u.try_into().unwrap_or(0), q.try_into().unwrap_or(0))))
    }

    /// Write a blob in one shot. See module doc for atomicity.
    /// Returns the host-minted ID.
    ///
    /// # Errors
    ///
    /// - [`BlobError::Unavailable`] for in-memory engines.
    /// - [`BlobError::UnregisteredInstance`] if `register_instance`
    ///   was never called.
    /// - [`BlobError::QuotaExceeded`] if completing the write would
    ///   push past the quota.
    /// - [`BlobError::Io`] for filesystem failures.
    /// - [`BlobError::Sql`] for index transaction failures.
    ///
    /// # Panics
    /// Panics if `data.len()` doesn't fit in `i64`. A single blob
    /// past 8 EiB would have already broken every other accounting
    /// path; the cast is essentially an assertion against
    /// `usize::MAX` on 128-bit hypothetical targets.
    pub fn write(
        &self,
        instance_id: &str,
        name: &str,
        data: &[u8],
        mime: Option<&str>,
    ) -> Result<String, BlobError> {
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let instance_dir = blobs_root.join(instance_id);
        let tmp_dir = instance_dir.join(".tmp");
        let id = self.mint_id();
        let tmp_path = tmp_dir.join(&id);
        let final_path = instance_dir.join(&id);

        // 1. Make directories.
        std::fs::create_dir_all(&tmp_dir).map_err(|source| BlobError::Io {
            path: tmp_dir.clone(),
            source,
        })?;

        // 2. Stage write + fsync.
        write_and_fsync(&tmp_path, data)?;

        let new_size = i64::try_from(data.len()).expect("blob size fits in i64");
        let created_ms = i64::try_from(now_unix_ms()).unwrap_or(i64::MAX);
        let instance_id_owned = instance_id.to_owned();
        let name_owned = name.to_owned();
        let mime_owned = mime.map(str::to_owned);
        let id_owned = id.clone();
        let final_path_clone = final_path.clone();
        let tmp_path_clone = tmp_path.clone();
        let blobs_root_owned = blobs_root.to_path_buf();

        // 3-5. Transaction: quota check + UPSERT + rename. The
        // rename happens *inside* the transaction so a commit
        // failure leaves the file in place without a row pointing
        // at it (Phase-12 sweep recoverable) rather than a row
        // pointing at a missing file (read error visible to
        // plugins).
        let outcome = self
            .db
            .write(move |conn| -> Result<Option<PathBuf>, BlobError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

                let Some((bytes_used, bytes_quota)) = tx
                    .query_row(
                        "SELECT bytes_used, bytes_quota FROM blob_usage WHERE instance_id = ?1",
                        params![instance_id_owned],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?
                else {
                    return Err(BlobError::UnregisteredInstance {
                        instance_id: instance_id_owned,
                    });
                };

                // Existing row's bytes — refunded by the trigger when
                // we delete+insert. Capture for projected math + old-
                // file cleanup after commit.
                let old: Option<(String, i64)> = tx
                    .query_row(
                        "SELECT id, size_bytes FROM blob \
                         WHERE instance_id = ?1 AND name = ?2",
                        params![instance_id_owned, name_owned],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let old_size = old.as_ref().map_or(0, |(_, s)| *s);

                let projected = bytes_used - old_size + new_size;
                if projected > bytes_quota {
                    return Err(BlobError::QuotaExceeded {
                        instance_id: instance_id_owned,
                        would_use: projected.try_into().unwrap_or(u64::MAX),
                        allowed: bytes_quota.try_into().unwrap_or(0),
                    });
                }

                // INSERT-OR-REPLACE via DELETE+INSERT so the triggers
                // fire on both legs and `bytes_used` stays correct
                // (the UPDATE trigger only handles `size_bytes`
                // changes, not `id` / `name` changes).
                tx.execute(
                    "DELETE FROM blob WHERE instance_id = ?1 AND name = ?2",
                    params![instance_id_owned, name_owned],
                )?;
                tx.execute(
                    "INSERT INTO blob(instance_id, name, id, size_bytes, created_ms, mime) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        instance_id_owned,
                        name_owned,
                        id_owned,
                        new_size,
                        created_ms,
                        mime_owned,
                    ],
                )?;

                // Rename inside the tx so failure here aborts the
                // commit (and we clean tmp below).
                std::fs::rename(&tmp_path_clone, &final_path_clone).map_err(|source| {
                    BlobError::Io {
                        path: final_path_clone.clone(),
                        source,
                    }
                })?;

                tx.commit()?;
                // Old file path to clean up after the tx — only
                // returned if we actually overwrote. The old file
                // lives in the same instance dir.
                Ok(old.map(|(old_id, _)| blobs_root_owned.join(&instance_id_owned).join(old_id)))
            });

        match outcome {
            Ok(None) => Ok(id),
            Ok(Some(old_path)) => {
                // Best-effort cleanup; ignore failure (operator-
                // visible if `usage` reports drift, which it won't
                // — the trigger already accounted for the delete).
                let _ = std::fs::remove_file(&old_path);
                Ok(id)
            }
            Err(e) => {
                // Roll back the staged file so we don't leak it.
                let _ = std::fs::remove_file(&tmp_path);
                Err(e)
            }
        }
    }

    /// Read bytes by ULID.
    ///
    /// # Errors
    ///
    /// - [`BlobError::Unavailable`] for in-memory engines.
    /// - [`BlobError::NotFound`] if the id doesn't exist in this
    ///   instance.
    /// - [`BlobError::Io`] for filesystem failures.
    pub fn read(&self, instance_id: &str, id: &str) -> Result<Vec<u8>, BlobError> {
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        // Confirm the row exists for this instance — otherwise a
        // plugin could read another instance's blob by guessing the
        // id (filenames are predictable enough that we don't want
        // to rely on FS-only path scoping).
        let exists: bool = self.db.read(|conn| -> Result<_, BlobError> {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM blob WHERE instance_id = ?1 AND id = ?2",
                    params![instance_id, id],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false))
        })?;
        if !exists {
            return Err(BlobError::NotFound {
                what: format!("id `{id}` for instance `{instance_id}`"),
            });
        }
        let path = blobs_root.join(instance_id).join(id);
        std::fs::read(&path).map_err(|source| BlobError::Io { path, source })
    }

    /// Read bytes by user-chosen name.
    ///
    /// # Errors
    ///
    /// Same as [`Self::read`].
    pub fn read_by_name(&self, instance_id: &str, name: &str) -> Result<Vec<u8>, BlobError> {
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let id: String = self
            .db
            .read(|conn| -> Result<_, BlobError> {
                Ok(conn
                    .query_row(
                        "SELECT id FROM blob WHERE instance_id = ?1 AND name = ?2",
                        params![instance_id, name],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?)
            })?
            .ok_or_else(|| BlobError::NotFound {
                what: format!("name `{name}` for instance `{instance_id}`"),
            })?;
        let path = blobs_root.join(instance_id).join(&id);
        std::fs::read(&path).map_err(|source| BlobError::Io { path, source })
    }

    /// Look up metadata without fetching bytes.
    ///
    /// # Errors
    ///
    /// - [`BlobError::NotFound`] if no blob with that name.
    /// - [`BlobError::Sql`] for SQL errors.
    pub fn get_info(&self, instance_id: &str, name: &str) -> Result<BlobInfo, BlobError> {
        self.db
            .read(|conn| -> Result<_, BlobError> {
                conn.query_row(
                    "SELECT name, id, size_bytes, created_ms, mime FROM blob \
                     WHERE instance_id = ?1 AND name = ?2",
                    params![instance_id, name],
                    decode_blob_info,
                )
                .optional()
                .map_err(BlobError::from)
            })?
            .ok_or_else(|| BlobError::NotFound {
                what: format!("name `{name}` for instance `{instance_id}`"),
            })
    }

    /// Delete a blob by name. Returns `Ok(())` whether the blob
    /// existed or not — matches the WIT contract.
    ///
    /// # Errors
    ///
    /// - [`BlobError::Unavailable`] for in-memory engines.
    /// - [`BlobError::Io`] for filesystem failures (only when an
    ///   actual file is being removed).
    /// - [`BlobError::Sql`] for index transaction failures.
    pub fn delete(&self, instance_id: &str, name: &str) -> Result<(), BlobError> {
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let instance_id_owned = instance_id.to_owned();
        let name_owned = name.to_owned();
        // Get id first so we can rm the file, then drop the row.
        let id: Option<String> = self.db.write(move |conn| -> Result<_, BlobError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM blob WHERE instance_id = ?1 AND name = ?2",
                    params![instance_id_owned, name_owned],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if id.is_some() {
                tx.execute(
                    "DELETE FROM blob WHERE instance_id = ?1 AND name = ?2",
                    params![instance_id_owned, name_owned],
                )?;
            }
            tx.commit()?;
            Ok(id)
        })?;
        if let Some(id) = id {
            let path = blobs_root.join(instance_id).join(&id);
            // Best-effort: row already gone, FS orphan would be
            // cleaned by Phase-12 sweep.
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }

    /// List blobs whose name starts with `prefix`. Order is
    /// lexicographic by name. Empty prefix enumerates everything
    /// for the instance.
    ///
    /// # Errors
    ///
    /// Forwards SQL errors.
    pub fn list_blobs(&self, instance_id: &str, prefix: &str) -> Result<Vec<BlobInfo>, BlobError> {
        self.db.read(|conn| -> Result<_, BlobError> {
            let mut stmt = conn.prepare(
                "SELECT name, id, size_bytes, created_ms, mime FROM blob \
                 WHERE instance_id = ?1 AND substr(name, 1, length(?2)) = ?2 \
                 ORDER BY name",
            )?;
            let rows = stmt
                .query_map(params![instance_id, prefix], decode_blob_info)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Mint a new blob ID. Format: `<unix_ms_13hex>-<counter_8hex>-<nanos_8hex>`.
    /// Not a "real" ULID (no Crockford base32, no crypto RNG) but
    /// provides every property the store actually needs: unique
    /// within and across processes (timestamp+counter+nanos
    /// disambiguates), filesystem-safe, sortable by creation time.
    fn mint_id(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        // `as_millis` returns u128 (truly span-the-universe). Clamp
        // to u64 to keep the formatted ID width stable; 13 hex digits
        // covers wall-clock through year 10895 in unix-ms.
        let ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
        let nanos = now.subsec_nanos();
        let counter = self.id_counter.fetch_add(1, Ordering::Relaxed);
        format!("{ms:013x}-{counter:08x}-{nanos:08x}")
    }
}

fn write_and_fsync(path: &Path, data: &[u8]) -> Result<(), BlobError> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path).map_err(|source| BlobError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(data).map_err(|source| BlobError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| BlobError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn decode_blob_info(row: &rusqlite::Row<'_>) -> rusqlite::Result<BlobInfo> {
    let size: i64 = row.get(2)?;
    let created: i64 = row.get(3)?;
    Ok(BlobInfo {
        name: row.get(0)?,
        id: row.get(1)?,
        size_bytes: size.try_into().unwrap_or(0),
        created_ms: created.try_into().unwrap_or(0),
        mime: row.get(4)?,
    })
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_root() -> (BlobStore, TempDir) {
        let dir = tempdir();
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let blobs_root = Some(dir.path.clone());
        (BlobStore::new(db, blobs_root), dir)
    }

    #[test]
    fn write_then_read_round_trip() {
        let (store, _dir) = store_with_root();
        store
            .register_instance("alpha", 64 * 1024)
            .expect("register");
        let id = store
            .write("alpha", "snap.jpg", b"hello blob", Some("image/jpeg"))
            .expect("write");
        assert!(!id.is_empty());

        let by_id = store.read("alpha", &id).expect("read by id");
        assert_eq!(by_id, b"hello blob");

        let by_name = store
            .read_by_name("alpha", "snap.jpg")
            .expect("read by name");
        assert_eq!(by_name, b"hello blob");

        let info = store.get_info("alpha", "snap.jpg").expect("get_info");
        assert_eq!(info.name, "snap.jpg");
        assert_eq!(info.size_bytes, 10);
        assert_eq!(info.mime.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn overwrite_replaces_in_place_and_accounts_correctly() {
        let (store, _dir) = store_with_root();
        store
            .register_instance("alpha", 64 * 1024)
            .expect("register");
        store
            .write("alpha", "k", b"original-bytes", None)
            .expect("first");
        let (used1, _) = store.usage("alpha").expect("usage").expect("present");
        store
            .write("alpha", "k", b"replaced-with-longer-bytes", None)
            .expect("second");
        let (used2, _) = store.usage("alpha").expect("usage").expect("present");
        assert_eq!(used2, "replaced-with-longer-bytes".len() as u64);
        assert!(used2 > used1);

        let payload = store.read_by_name("alpha", "k").expect("read");
        assert_eq!(payload, b"replaced-with-longer-bytes");
    }

    #[test]
    fn quota_exceeded_refuses_write_and_keeps_old_value() {
        let (store, _dir) = store_with_root();
        store.register_instance("alpha", 32).expect("register");
        store
            .write("alpha", "a", b"first-bytes", None)
            .expect("write 1");
        let err = store
            .write("alpha", "b", &[0u8; 64], None)
            .expect_err("over quota");
        assert!(
            matches!(err, BlobError::QuotaExceeded { allowed: 32, .. }),
            "got {err:?}",
        );
        // Original still readable.
        assert_eq!(
            store.read_by_name("alpha", "a").expect("read"),
            b"first-bytes"
        );
    }

    #[test]
    fn delete_refunds_usage_and_removes_file() {
        let (store, dir) = store_with_root();
        store.register_instance("alpha", 4096).expect("register");
        let id = store.write("alpha", "snap", b"bytes", None).expect("write");
        let path = dir.path.join("alpha").join(&id);
        assert!(path.is_file());

        store.delete("alpha", "snap").expect("delete");
        let (used, _) = store.usage("alpha").expect("usage").expect("present");
        assert_eq!(used, 0);
        assert!(!path.exists(), "blob file should be gone after delete");

        // Reading after delete is NotFound.
        let err = store.read_by_name("alpha", "snap").expect_err("not found");
        assert!(matches!(err, BlobError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn list_blobs_returns_matching_prefix_in_order() {
        let (store, _dir) = store_with_root();
        store.register_instance("alpha", 4096).expect("register");
        for name in ["aa", "ab", "ba", "bb"] {
            store
                .write("alpha", name, name.as_bytes(), None)
                .expect("write");
        }
        let a = store.list_blobs("alpha", "a").expect("list");
        let names: Vec<_> = a.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["aa", "ab"]);

        let none = store.list_blobs("alpha", "z").expect("list");
        assert!(none.is_empty());
    }

    #[test]
    fn instances_isolated_from_each_other() {
        let (store, _dir) = store_with_root();
        store.register_instance("alpha", 4096).expect("register a");
        store.register_instance("beta", 4096).expect("register b");
        let id_a = store.write("alpha", "k", b"alpha-bytes", None).expect("a");
        let id_b = store.write("beta", "k", b"beta-bytes", None).expect("b");
        assert_ne!(id_a, id_b);

        assert_eq!(
            store.read_by_name("alpha", "k").expect("read a"),
            b"alpha-bytes",
        );
        assert_eq!(
            store.read_by_name("beta", "k").expect("read b"),
            b"beta-bytes",
        );
        // Cross-instance id read returns NotFound (the id is
        // namespaced to its instance — see `read`).
        let err = store.read("alpha", &id_b).expect_err("cross-id");
        assert!(matches!(err, BlobError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn in_memory_engine_blob_writes_return_unavailable() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = BlobStore::new(db, None);
        store.register_instance("alpha", 4096).expect("register");
        let err = store
            .write("alpha", "k", b"bytes", None)
            .expect_err("no fs");
        assert!(matches!(err, BlobError::Unavailable), "got {err:?}");
    }

    #[test]
    fn unregistered_instance_write_returns_unregistered() {
        let (store, _dir) = store_with_root();
        let err = store
            .write("ghost", "k", b"bytes", None)
            .expect_err("ghost");
        assert!(
            matches!(err, BlobError::UnregisteredInstance { ref instance_id } if instance_id == "ghost"),
            "got {err:?}",
        );
    }

    #[test]
    fn rows_survive_db_reopen() {
        let dir_db = tempdir();
        let dir_blobs = tempdir();
        let path = dir_db.path.clone();
        let id;
        {
            let db = Arc::new(Db::open_file(&path).expect("open"));
            let store = BlobStore::new(db, Some(dir_blobs.path.clone()));
            store.register_instance("alpha", 4096).expect("register");
            id = store
                .write("alpha", "persistent", b"survive", None)
                .expect("write");
        }
        let db = Arc::new(Db::open_file(&path).expect("reopen"));
        let store = BlobStore::new(db, Some(dir_blobs.path.clone()));
        assert_eq!(store.read("alpha", &id).expect("read"), b"survive");
        let info = store.get_info("alpha", "persistent").expect("get_info");
        assert_eq!(info.size_bytes, 7);
    }

    // Tiny tempdir helper.
    struct TempDir {
        path: PathBuf,
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn tempdir() -> TempDir {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "oxidhome-blobs-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&path).expect("mk tempdir");
        TempDir { path }
    }
}
