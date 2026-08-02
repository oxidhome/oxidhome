//! Per-instance blob store — Phase 5b.
//!
//! Filesystem-backed bytes
//! (`<state_dir>/blobs/<installation_uuid>/<instance_id>/<id>`) plus a
//! `SQLite` index in the same DB file as `kv` / `event_log` /
//! `log_event`. Splitting bytes from index keeps multi-MB writes off
//! the `SQLite` `BLOB` path while keeping `(name → id)` lookup atomic
//! with the quota check.
//!
//! ## H2 keying
//!
//! Every table row and every filesystem path is qualified by the
//! host-minted `installation_uuid` (see
//! [`crate::state::InstalledPluginRegistry`]). An uninstall + reinstall
//! of the same `plugin_id` mints a fresh uuid, so the reinstalled
//! plugin sees an empty blob namespace instead of inheriting the
//! previous install's data. `purge_installation` (called from
//! `uninstall`) wipes both the SQL rows and the on-disk directory tree
//! for a tombstoned install.
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
    #[error(
        "instance `{instance_id}` (installation `{installation_uuid}`) \
         is not registered with the blob store"
    )]
    UnregisteredInstance {
        installation_uuid: String,
        instance_id: String,
    },

    /// Follow-up review H1: the caller supplied an `instance_id`
    /// (or `installation_uuid`) that isn't safe to use as a
    /// filesystem segment (path traversal, absolute path, empty).
    /// The API's `start_plugin_instance` handler rejects unsafe
    /// `instance_id`s at the edge with a 400; this variant is the
    /// belt-and-suspenders check at the blob-store call site so a
    /// direct caller (host-side test harness bypassing the API)
    /// can't induce path escape either. The host mints
    /// `installation_uuid`, so it should never arrive malformed —
    /// the same check applies as defense-in-depth against a future
    /// refactor.
    #[error("blob path segment {segment:?} is unsafe for use as a filesystem segment")]
    UnsafeInstanceId { segment: String },

    /// Completing the write would push past the manifest-declared
    /// `blob_quota_mb`. Refused before any rename / commit.
    #[error(
        "blob quota exceeded for instance `{instance_id}` \
         (installation `{installation_uuid}`): \
         {would_use} bytes would be used / {allowed} allowed"
    )]
    QuotaExceeded {
        installation_uuid: String,
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

    /// `tx.commit()` failed *after* the in-transaction `rename`
    /// already moved bytes into place. Internal-only variant so the
    /// outer `write` matcher can remove `final_path` deterministically
    /// instead of leaving an FS orphan for the Phase-12 sweep to
    /// catch. Never surfaces outside `write` — the matcher
    /// downconverts it to `BlobError::Sql(source)` before returning
    /// to the caller.
    #[error("blob commit failed after rename at {final_path}: {source}")]
    CommitFailedAfterRename {
        final_path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
}

/// Follow-up review H1: reject `instance_id`s that aren't safe as
/// filesystem segments. Absolute paths would replace `blobs_root`
/// under `Path::join`; `..` escapes it; empty / leading-dot names
/// clobber the `.tmp` staging convention. Mirrors
/// `is_safe_plugin_id` in the installed-plugin registry — same
/// FS-segment rules apply everywhere the identity crosses the
/// filesystem boundary. Called by every blob-store entry point AND
/// at the API layer so a bad id is rejected before it ever reaches
/// path construction.
///
/// Review F1 (round-2): also cap the byte length at
/// [`MAX_INSTANCE_ID_BYTES`] (128) so an over-long id can't pass
/// validation and later `ENAMETOOLONG` at write time. `NAME_MAX`
/// on Linux/macOS is 255 bytes; 128 keeps well under it AND leaves
/// budget for the `.tmp/<blob-id>` sub-path names appended below
/// the instance dir (blob id ≈ 32 chars, `.tmp/` prefix 5 chars).
#[must_use]
pub fn is_safe_instance_id(instance_id: &str) -> bool {
    !instance_id.is_empty()
        && instance_id.len() <= MAX_INSTANCE_ID_BYTES
        && !instance_id.contains('/')
        && !instance_id.contains('\\')
        && !instance_id.contains("..")
        && !instance_id.starts_with('.')
        && !instance_id.contains('\0')
        // H10 round-3 finding 3: `"*"` is the reserved wildcard
        // sentinel in `ServiceGrant.instance` and
        // `ServiceGrant.caller_instance`. Refusing it here means a
        // real instance-id can never collide with the wildcard, so
        // a grant naming a specific instance is unambiguous.
        && instance_id != "*"
}

/// Maximum permitted byte length of an `instance_id` — see the
/// F1 comment on [`is_safe_instance_id`].
pub const MAX_INSTANCE_ID_BYTES: usize = 128;

fn check_instance_id(instance_id: &str) -> Result<(), BlobError> {
    if is_safe_instance_id(instance_id) {
        Ok(())
    } else {
        Err(BlobError::UnsafeInstanceId {
            segment: instance_id.to_owned(),
        })
    }
}

/// H2 defense-in-depth: mirror the `instance_id` shape check on the
/// host-minted `installation_uuid` too. The minter (`state::
/// installed_plugins::mint_installation_uuid`) always emits
/// `inst-<32 hex chars>`, so under normal wiring this can never fail
/// — but a future refactor that pipes a raw string through this API
/// shouldn't silently escape the blob root either.
fn check_installation_uuid(installation_uuid: &str) -> Result<(), BlobError> {
    if is_safe_instance_id(installation_uuid) {
        Ok(())
    } else {
        Err(BlobError::UnsafeInstanceId {
            segment: installation_uuid.to_owned(),
        })
    }
}

/// H1 defense-in-depth: the resolved path for any blob operation
/// MUST live under `blobs_root`. `is_safe_instance_id` above
/// guards the segment shape, but this containment check is the
/// last line: even if a future refactor bypasses the shape check,
/// nothing writes / reads outside the blob root.
fn ensure_contained(blobs_root: &Path, path: &Path) -> Result<(), BlobError> {
    if path.starts_with(blobs_root) {
        Ok(())
    } else {
        Err(BlobError::UnsafeInstanceId {
            segment: path.display().to_string(),
        })
    }
}

/// Compute the on-disk directory for one instance under one
/// installation. Encapsulates the H2 layout
/// (`<blobs_root>/<installation_uuid>/<instance_id>/`) so every
/// entry point shares the same shape.
fn instance_dir_for(blobs_root: &Path, installation_uuid: &str, instance_id: &str) -> PathBuf {
    blobs_root.join(installation_uuid).join(instance_id)
}

/// Outcome from a successful `write` transaction. Carries the path
/// to the *previous* file when an overwrite ran, so the outer
/// matcher can `remove_file` it post-commit.
struct WriteOutcome {
    old_file: Option<PathBuf>,
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
        // Seed the counter from pid + the construction-instant nanos
        // so two processes opening the same DB in the same wall-clock
        // millisecond don't both start at 0 and collide on `mint_id`.
        // The `(installation_uuid, instance_id, id)` UNIQUE constraint
        // (migration 14) catches any residual collision loudly inside
        // the writing transaction, but seeding makes the collision rate
        // vanish in practice.
        Self {
            db,
            blobs_root,
            id_counter: AtomicU64::new(id_counter_seed()),
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
    pub fn register_instance(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        quota_bytes: u64,
    ) -> Result<(), BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let quota_i64 = i64::try_from(quota_bytes).unwrap_or(i64::MAX);
        self.db.write(|conn| -> Result<(), BlobError> {
            conn.execute(
                "INSERT INTO blob_usage(installation_uuid, instance_id, bytes_used, bytes_quota) \
                 VALUES (?1, ?2, 0, ?3) \
                 ON CONFLICT(installation_uuid, instance_id) DO UPDATE \
                    SET bytes_quota = excluded.bytes_quota",
                params![installation_uuid, instance_id, quota_i64],
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
    pub fn usage(
        &self,
        installation_uuid: &str,
        instance_id: &str,
    ) -> Result<Option<(u64, u64)>, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let row = self.db.read(|conn| -> Result<_, BlobError> {
            Ok(conn
                .query_row(
                    "SELECT bytes_used, bytes_quota FROM blob_usage \
                     WHERE installation_uuid = ?1 AND instance_id = ?2",
                    params![installation_uuid, instance_id],
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
    // Length allow: H2's two-level directory layout added a second
    // fsync-guard pair on top of the pre-existing quota / rename /
    // commit dance. Splitting the transaction body out of the write
    // path would obscure the intra-transaction ordering invariants
    // (see the "3-5" comment inside) that the function's atomicity
    // contract depends on.
    #[allow(clippy::too_many_lines)]
    pub fn write(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        name: &str,
        data: &[u8],
        mime: Option<&str>,
    ) -> Result<String, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let install_dir = blobs_root.join(installation_uuid);
        let instance_dir = instance_dir_for(blobs_root, installation_uuid, instance_id);
        ensure_contained(blobs_root, &instance_dir)?;
        let tmp_dir = instance_dir.join(".tmp");
        let id = self.mint_id();
        let tmp_path = tmp_dir.join(&id);
        let final_path = instance_dir.join(&id);

        // 1. Make directories. Track whether `install_dir` /
        // `instance_dir` are new so we can fsync the *parent* of a
        // newly-created directory and make the entry durable —
        // without that, a crash after write can lose the directory
        // (and everything inside it) even after the SQLite commit is
        // durable.
        let install_dir_is_new = !install_dir.exists();
        let instance_dir_is_new = !instance_dir.exists();
        std::fs::create_dir_all(&tmp_dir).map_err(|source| BlobError::Io {
            path: tmp_dir.clone(),
            source,
        })?;
        if install_dir_is_new {
            fsync_dir(blobs_root)?;
        }
        if instance_dir_is_new {
            fsync_dir(&install_dir)?;
        }

        // 2. Stage write + fsync.
        write_and_fsync(&tmp_path, data)?;

        let new_size = i64::try_from(data.len()).expect("blob size fits in i64");
        let created_ms = i64::try_from(now_unix_ms()).unwrap_or(i64::MAX);
        let installation_uuid_owned = installation_uuid.to_owned();
        let instance_id_owned = instance_id.to_owned();
        let name_owned = name.to_owned();
        let mime_owned = mime.map(str::to_owned);
        let id_owned = id.clone();
        let final_path_clone = final_path.clone();
        let tmp_path_clone = tmp_path.clone();
        let instance_dir_clone = instance_dir.clone();
        let blobs_root_owned = blobs_root.to_path_buf();

        // 3-5. Transaction: quota check + UPSERT + rename + dir
        // fsync. The rename happens *inside* the transaction so a
        // commit failure leaves the file in place without a row
        // pointing at it (Phase-12 sweep recoverable) rather than a
        // row pointing at a missing file (read error visible to
        // plugins).
        //
        // Closure returns `Outcome` so the outer error handler can
        // tell whether the rename ran — that determines which path
        // (tmp or final) needs to be cleaned up on a failure between
        // rename and commit.
        let outcome = self
            .db
            .write(move |conn| -> Result<WriteOutcome, BlobError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

                let Some((bytes_used, bytes_quota)) = tx
                    .query_row(
                        "SELECT bytes_used, bytes_quota FROM blob_usage \
                         WHERE installation_uuid = ?1 AND instance_id = ?2",
                        params![installation_uuid_owned, instance_id_owned],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?
                else {
                    return Err(BlobError::UnregisteredInstance {
                        installation_uuid: installation_uuid_owned,
                        instance_id: instance_id_owned,
                    });
                };

                // Existing row's bytes — refunded by the trigger when
                // we delete+insert. Capture for projected math + old-
                // file cleanup after commit.
                let old: Option<(String, i64)> = tx
                    .query_row(
                        "SELECT id, size_bytes FROM blob \
                         WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                        params![installation_uuid_owned, instance_id_owned, name_owned],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let old_size = old.as_ref().map_or(0, |(_, s)| *s);

                let projected = bytes_used - old_size + new_size;
                if projected > bytes_quota {
                    return Err(BlobError::QuotaExceeded {
                        installation_uuid: installation_uuid_owned,
                        instance_id: instance_id_owned,
                        would_use: projected.try_into().unwrap_or(u64::MAX),
                        allowed: bytes_quota.try_into().unwrap_or(0),
                    });
                }

                // INSERT-OR-REPLACE via DELETE+INSERT so the triggers
                // fire on both legs and `bytes_used` stays correct
                // (the UPDATE trigger only handles `size_bytes`
                // changes, not `id` / `name` changes). Migration 14's
                // UNIQUE `(installation_uuid, instance_id, id)` index
                // makes a residual id collision fail the transaction
                // loudly here rather than silently overwriting the FS
                // file.
                tx.execute(
                    "DELETE FROM blob \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                    params![installation_uuid_owned, instance_id_owned, name_owned],
                )?;
                tx.execute(
                    "INSERT INTO blob(installation_uuid, instance_id, name, id, size_bytes, created_ms, mime) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        installation_uuid_owned,
                        instance_id_owned,
                        name_owned,
                        id_owned,
                        new_size,
                        created_ms,
                        mime_owned,
                    ],
                )?;

                // Rename + fsync the *parent directory*. Without the
                // directory fsync the rename can be undone after a
                // crash while the SQLite WAL commit is durable —
                // exactly the "DB row pointing at a missing file"
                // shape the module doc said we avoid. From this point
                // on the file lives at `final_path` durably; track
                // that so the outer error handler cleans the right
                // path if `tx.commit()` fails below.
                std::fs::rename(&tmp_path_clone, &final_path_clone).map_err(|source| {
                    BlobError::Io {
                        path: final_path_clone.clone(),
                        source,
                    }
                })?;
                fsync_dir(&instance_dir_clone)?;

                if let Err(e) = tx.commit() {
                    // Commit failure after a successful rename leaves
                    // bytes at `final_path` with no DB row. Surface
                    // that path so the outer match can clean it.
                    return Err(BlobError::CommitFailedAfterRename {
                        final_path: final_path_clone.clone(),
                        source: e,
                    });
                }
                Ok(WriteOutcome {
                    old_file: old.map(|(old_id, _)| {
                        instance_dir_for(&blobs_root_owned, &installation_uuid_owned, &instance_id_owned)
                            .join(old_id)
                    }),
                })
            });

        finalize_write_outcome(outcome, id, &tmp_path)
    }

    /// Read bytes by id.
    ///
    /// # Errors
    ///
    /// - [`BlobError::Unavailable`] for in-memory engines.
    /// - [`BlobError::NotFound`] if the id doesn't exist in this
    ///   instance.
    /// - [`BlobError::Io`] for filesystem failures.
    pub fn read(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        id: &str,
    ) -> Result<Vec<u8>, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        // Confirm the row exists for this instance — otherwise a
        // plugin could read another instance's blob by guessing the
        // id (filenames are predictable enough that we don't want
        // to rely on FS-only path scoping).
        let exists: bool = self.db.read(|conn| -> Result<_, BlobError> {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM blob \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND id = ?3",
                    params![installation_uuid, instance_id, id],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false))
        })?;
        if !exists {
            return Err(BlobError::NotFound {
                what: format!(
                    "id `{id}` for instance `{instance_id}` \
                     (installation `{installation_uuid}`)"
                ),
            });
        }
        let path = instance_dir_for(blobs_root, installation_uuid, instance_id).join(id);
        ensure_contained(blobs_root, &path)?;
        std::fs::read(&path).map_err(|source| BlobError::Io { path, source })
    }

    /// Read bytes by user-chosen name.
    ///
    /// # Errors
    ///
    /// Same as [`Self::read`].
    pub fn read_by_name(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<Vec<u8>, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let id: String = self
            .db
            .read(|conn| -> Result<_, BlobError> {
                Ok(conn
                    .query_row(
                        "SELECT id FROM blob \
                         WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                        params![installation_uuid, instance_id, name],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?)
            })?
            .ok_or_else(|| BlobError::NotFound {
                what: format!(
                    "name `{name}` for instance `{instance_id}` \
                     (installation `{installation_uuid}`)"
                ),
            })?;
        let path = instance_dir_for(blobs_root, installation_uuid, instance_id).join(&id);
        ensure_contained(blobs_root, &path)?;
        std::fs::read(&path).map_err(|source| BlobError::Io { path, source })
    }

    /// Look up metadata without fetching bytes.
    ///
    /// # Errors
    ///
    /// - [`BlobError::NotFound`] if no blob with that name.
    /// - [`BlobError::Sql`] for SQL errors.
    pub fn get_info(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<BlobInfo, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        self.db
            .read(|conn| -> Result<_, BlobError> {
                conn.query_row(
                    "SELECT name, id, size_bytes, created_ms, mime FROM blob \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                    params![installation_uuid, instance_id, name],
                    decode_blob_info,
                )
                .optional()
                .map_err(BlobError::from)
            })?
            .ok_or_else(|| BlobError::NotFound {
                what: format!(
                    "name `{name}` for instance `{instance_id}` \
                     (installation `{installation_uuid}`)"
                ),
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
    pub fn delete(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<(), BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        let blobs_root = self.blobs_root.as_deref().ok_or(BlobError::Unavailable)?;
        let installation_uuid_owned = installation_uuid.to_owned();
        let instance_id_owned = instance_id.to_owned();
        let name_owned = name.to_owned();
        // Get id first so we can rm the file, then drop the row.
        let id: Option<String> = self.db.write(move |conn| -> Result<_, BlobError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM blob \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                    params![installation_uuid_owned, instance_id_owned, name_owned],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if id.is_some() {
                tx.execute(
                    "DELETE FROM blob \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND name = ?3",
                    params![installation_uuid_owned, instance_id_owned, name_owned],
                )?;
            }
            tx.commit()?;
            Ok(id)
        })?;
        if let Some(id) = id {
            let instance_dir = instance_dir_for(blobs_root, installation_uuid, instance_id);
            ensure_contained(blobs_root, &instance_dir)?;
            let path = instance_dir.join(&id);
            // Best-effort: row already gone, FS orphan would be
            // cleaned by Phase-12 sweep. `fsync_dir` after the
            // unlink so the directory entry's removal is durable —
            // without it a crash could resurrect the file at the
            // path the DB no longer references.
            let _ = std::fs::remove_file(&path);
            let _ = fsync_dir(&instance_dir);
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
    pub fn list_blobs(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        prefix: &str,
    ) -> Result<Vec<BlobInfo>, BlobError> {
        check_installation_uuid(installation_uuid)?;
        check_instance_id(instance_id)?;
        self.db.read(|conn| -> Result<_, BlobError> {
            let mut stmt = conn.prepare(
                "SELECT name, id, size_bytes, created_ms, mime FROM blob \
                 WHERE installation_uuid = ?1 AND instance_id = ?2 \
                   AND substr(name, 1, length(?3)) = ?3 \
                 ORDER BY name",
            )?;
            let rows = stmt
                .query_map(
                    params![installation_uuid, instance_id, prefix],
                    decode_blob_info,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Wipe every SQL row (`blob` + `blob_usage`) AND the on-disk
    /// directory tree for the installation tombstoned at
    /// `installation_uuid`. Called from
    /// [`crate::state::InstalledPluginRegistry::uninstall`] so a
    /// subsequent reinstall of the same `plugin_id` sees an empty
    /// blob namespace — H2's central invariant.
    ///
    /// Order: SQL first, then FS. If the FS teardown fails partway,
    /// the DB is already consistent (no rows point at whatever is
    /// left) and the remaining files are orphans a Phase-12 sweep
    /// can reclaim. The reverse order would risk leaving DB rows
    /// pointing at deleted files, which is more disruptive to
    /// observability.
    ///
    /// Idempotent: purging an install that had no rows / no files
    /// is a no-op.
    ///
    /// # Errors
    ///
    /// - [`BlobError::Sql`] for SQL failures (nothing has been
    ///   touched on disk when this fires).
    /// - [`BlobError::Io`] wrapping any filesystem failure during
    ///   the directory removal. The SQL delete has already
    ///   committed at that point — retrying `purge_installation`
    ///   is safe and will just re-attempt the FS half.
    pub fn purge_installation(&self, installation_uuid: &str) -> Result<usize, BlobError> {
        check_installation_uuid(installation_uuid)?;
        let uuid_owned = installation_uuid.to_owned();
        let deleted = self.db.write(move |conn| -> Result<usize, BlobError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let usage_rows = tx.execute(
                "DELETE FROM blob_usage WHERE installation_uuid = ?1",
                params![uuid_owned],
            )?;
            let blob_rows = tx.execute(
                "DELETE FROM blob WHERE installation_uuid = ?1",
                params![uuid_owned],
            )?;
            tx.commit()?;
            Ok(usage_rows + blob_rows)
        })?;

        if let Some(blobs_root) = self.blobs_root.as_deref() {
            let install_dir = blobs_root.join(installation_uuid);
            ensure_contained(blobs_root, &install_dir)?;
            if install_dir.exists() {
                std::fs::remove_dir_all(&install_dir).map_err(|source| BlobError::Io {
                    path: install_dir.clone(),
                    source,
                })?;
                // Fsync the blobs root so the removal of the
                // installation dir is durable — otherwise a crash
                // after the SQL commit but before the directory
                // entry's removal is on disk would leave orphan
                // bytes behind that a subsequent (uuid-differing)
                // reinstall wouldn't touch.
                fsync_dir(blobs_root)?;
            }
        }
        Ok(deleted)
    }

    /// Mint a new blob id. Format:
    /// `<unix_ms_13hex>-<counter_8hex>-<nanos_8hex>` — host-minted,
    /// filesystem-safe, sortable by creation time. The counter is
    /// seeded per-`BlobStore` (see [`Self::new`]) so two processes
    /// don't both start at 0; migration 14's
    /// `UNIQUE (installation_uuid, instance_id, id)` index is the
    /// load-bearing collision check.
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

/// Per-`BlobStore` counter seed: `pid ^ construction-time subsec
/// nanos`, masked to 32 bits so `mint_id`'s `{counter:08x}` format
/// stays width-stable. `subsec_nanos()` only varies within a single
/// second — two processes starting in the same wall-clock second
/// share that range and only `pid` differentiates them (container
/// pid recycling shrinks that further). That's fine: migration 14's
/// `UNIQUE (installation_uuid, instance_id, id)` index is the
/// load-bearing collision check; the seed just keeps the practical
/// collision rate at zero.
fn id_counter_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    u64::from(pid ^ nanos)
}

/// Map the transaction outcome to the public `write` result, doing
/// the best-effort filesystem cleanup that depends on *where* the
/// write got to (post-commit overwrite, commit-after-rename failure,
/// or pre-rename failure).
fn finalize_write_outcome(
    outcome: Result<WriteOutcome, BlobError>,
    id: String,
    tmp_path: &Path,
) -> Result<String, BlobError> {
    match outcome {
        Ok(WriteOutcome { old_file: None }) => Ok(id),
        Ok(WriteOutcome {
            old_file: Some(old_path),
        }) => {
            // Best-effort cleanup; ignore failure (operator-visible
            // if `usage` reports drift, which it won't — the trigger
            // already accounted for the delete).
            let _ = std::fs::remove_file(&old_path);
            Ok(id)
        }
        Err(BlobError::CommitFailedAfterRename {
            final_path: orphan,
            source,
        }) => {
            // Bytes already at `final_path`, but the DB doesn't know
            // about them. Clean the orphan deterministically so we
            // don't have to wait for a Phase-12 sweep. The unlink
            // itself is best-effort — if it fails (permissions, FS
            // gone), the orphan persists and Phase-12 reclaims it,
            // same as the pre-fix behaviour.
            let _ = std::fs::remove_file(&orphan);
            Err(BlobError::Sql(source))
        }
        Err(e) => {
            // Rename hadn't happened yet — `final_path` is empty, the
            // staged file is still at `tmp_path`.
            let _ = std::fs::remove_file(tmp_path);
            Err(e)
        }
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

/// fsync the directory entry. `fsync` on the file alone (in
/// `write_and_fsync`) doesn't make the rename durable — POSIX
/// requires fsyncing the parent directory after a rename so the
/// new entry survives a crash. Without this, a crash between
/// `rename` and the next checkpoint can leave the file at its
/// pre-rename location while the `SQLite` WAL commit is durable, and
/// the next `read_by_name` fails with `Io { not found }`.
///
/// Unix-only — `std::fs::File::open` on a directory path fails on
/// Windows without `FILE_FLAG_BACKUP_SEMANTICS`, and `OxidHome` only
/// ships POSIX targets (Linux/macOS hub-class machines). The non-
/// unix arm is a deliberate no-op so the call sites stay uniform;
/// if Windows support is added later this needs a `BackupSemantics`
/// `OpenOptionsExt` path before re-enabling.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> Result<(), BlobError> {
    let dir_file = std::fs::File::open(dir).map_err(|source| BlobError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    dir_file.sync_all().map_err(|source| BlobError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> Result<(), BlobError> {
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

    /// Standing installation uuid used by every test that doesn't
    /// exercise multi-install isolation. Real code always passes the
    /// per-install uuid the registry minted.
    const INST_A: &str = "inst-test-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INST_B: &str = "inst-test-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
            .register_instance(INST_A, "alpha", 64 * 1024)
            .expect("register");
        let id = store
            .write(
                INST_A,
                "alpha",
                "snap.jpg",
                b"hello blob",
                Some("image/jpeg"),
            )
            .expect("write");
        assert!(!id.is_empty());

        let by_id = store.read(INST_A, "alpha", &id).expect("read by id");
        assert_eq!(by_id, b"hello blob");

        let by_name = store
            .read_by_name(INST_A, "alpha", "snap.jpg")
            .expect("read by name");
        assert_eq!(by_name, b"hello blob");

        let info = store
            .get_info(INST_A, "alpha", "snap.jpg")
            .expect("get_info");
        assert_eq!(info.name, "snap.jpg");
        assert_eq!(info.size_bytes, 10);
        assert_eq!(info.mime.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn overwrite_replaces_blob_and_accounts_correctly() {
        let (store, dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 64 * 1024)
            .expect("register");
        let first_id = store
            .write(INST_A, "alpha", "k", b"original-bytes", None)
            .expect("first");
        let first_path = dir.path.join(INST_A).join("alpha").join(&first_id);
        assert!(first_path.is_file(), "first write should land on disk");
        let (used1, _) = store
            .usage(INST_A, "alpha")
            .expect("usage")
            .expect("present");
        let second_id = store
            .write(INST_A, "alpha", "k", b"replaced-with-longer-bytes", None)
            .expect("second");
        assert_ne!(first_id, second_id, "overwrite should mint a fresh id");
        let (used2, _) = store
            .usage(INST_A, "alpha")
            .expect("usage")
            .expect("present");
        assert_eq!(used2, "replaced-with-longer-bytes".len() as u64);
        assert!(used2 > used1);

        let payload = store.read_by_name(INST_A, "alpha", "k").expect("read");
        assert_eq!(payload, b"replaced-with-longer-bytes");
        assert!(
            !first_path.exists(),
            "previous blob's FS file should be unlinked after overwrite",
        );
    }

    #[test]
    fn concurrent_writes_to_same_name_serialize() {
        // Assumes `Db::write` serializes via the single mutexed
        // connection (see `state::db::Db`). If `Db` ever moves to a
        // pool, `BEGIN IMMEDIATE` can return `SQLITE_BUSY` here and
        // the `.expect("concurrent write")` below would panic — that
        // change needs to teach this test to retry, not relax the
        // invariant (one row, no orphans).
        let (store, dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 64 * 1024)
            .expect("register");

        let store = Arc::new(store);
        let mut handles = Vec::new();
        for n in 0..8u32 {
            let s = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let payload = format!("payload-from-{n}");
                s.write(INST_A, "alpha", "k", payload.as_bytes(), None)
                    .expect("concurrent write")
            }));
        }
        let ids: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        // Every minted id is distinct — the UNIQUE index would have
        // failed the transaction otherwise.
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "id collision: {ids:?}");

        // Index has exactly one row for name "k".
        let rows = store.list_blobs(INST_A, "alpha", "k").expect("list");
        assert_eq!(rows.len(), 1, "expected single row, got {rows:?}");
        let winner_id = rows[0].id.clone();

        // On disk: only the winner's file remains; every other staged
        // id is gone (no orphans).
        let instance_dir = dir.path.join(INST_A).join("alpha");
        let mut files: Vec<String> = std::fs::read_dir(&instance_dir)
            .expect("read instance dir")
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_string_lossy().into_owned();
                if name == ".tmp" {
                    return None;
                }
                Some(name)
            })
            .collect();
        files.sort();
        assert_eq!(
            files,
            vec![winner_id],
            "orphan files left behind: {files:?}"
        );
    }

    #[test]
    fn quota_exceeded_refuses_write_and_keeps_old_value() {
        let (store, _dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 32)
            .expect("register");
        store
            .write(INST_A, "alpha", "a", b"first-bytes", None)
            .expect("write 1");
        let err = store
            .write(INST_A, "alpha", "b", &[0u8; 64], None)
            .expect_err("over quota");
        assert!(
            matches!(err, BlobError::QuotaExceeded { allowed: 32, .. }),
            "got {err:?}",
        );
        // Original still readable.
        assert_eq!(
            store.read_by_name(INST_A, "alpha", "a").expect("read"),
            b"first-bytes"
        );
    }

    #[test]
    fn delete_refunds_usage_and_removes_file() {
        let (store, dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 4096)
            .expect("register");
        let id = store
            .write(INST_A, "alpha", "snap", b"bytes", None)
            .expect("write");
        let path = dir.path.join(INST_A).join("alpha").join(&id);
        assert!(path.is_file());

        store.delete(INST_A, "alpha", "snap").expect("delete");
        let (used, _) = store
            .usage(INST_A, "alpha")
            .expect("usage")
            .expect("present");
        assert_eq!(used, 0);
        assert!(!path.exists(), "blob file should be gone after delete");

        // Reading after delete is NotFound.
        let err = store
            .read_by_name(INST_A, "alpha", "snap")
            .expect_err("not found");
        assert!(matches!(err, BlobError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn list_blobs_returns_matching_prefix_in_order() {
        let (store, _dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 4096)
            .expect("register");
        for name in ["aa", "ab", "ba", "bb"] {
            store
                .write(INST_A, "alpha", name, name.as_bytes(), None)
                .expect("write");
        }
        let a = store.list_blobs(INST_A, "alpha", "a").expect("list");
        let names: Vec<_> = a.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["aa", "ab"]);

        let none = store.list_blobs(INST_A, "alpha", "z").expect("list");
        assert!(none.is_empty());
    }

    #[test]
    fn instances_isolated_from_each_other() {
        let (store, _dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 4096)
            .expect("register a");
        store
            .register_instance(INST_A, "beta", 4096)
            .expect("register b");
        let id_a = store
            .write(INST_A, "alpha", "k", b"alpha-bytes", None)
            .expect("a");
        let id_b = store
            .write(INST_A, "beta", "k", b"beta-bytes", None)
            .expect("b");
        assert_ne!(id_a, id_b);

        assert_eq!(
            store.read_by_name(INST_A, "alpha", "k").expect("read a"),
            b"alpha-bytes",
        );
        assert_eq!(
            store.read_by_name(INST_A, "beta", "k").expect("read b"),
            b"beta-bytes",
        );
        // Cross-instance id read returns NotFound (the id is
        // namespaced to its instance — see `read`).
        let err = store.read(INST_A, "alpha", &id_b).expect_err("cross-id");
        assert!(matches!(err, BlobError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn in_memory_engine_blob_writes_return_unavailable() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let store = BlobStore::new(db, None);
        store
            .register_instance(INST_A, "alpha", 4096)
            .expect("register");
        let err = store
            .write(INST_A, "alpha", "k", b"bytes", None)
            .expect_err("no fs");
        assert!(matches!(err, BlobError::Unavailable), "got {err:?}");
    }

    #[test]
    fn unregistered_instance_write_returns_unregistered() {
        let (store, _dir) = store_with_root();
        let err = store
            .write(INST_A, "ghost", "k", b"bytes", None)
            .expect_err("ghost");
        assert!(
            matches!(
                err,
                BlobError::UnregisteredInstance { ref instance_id, .. } if instance_id == "ghost"
            ),
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
            store
                .register_instance(INST_A, "alpha", 4096)
                .expect("register");
            id = store
                .write(INST_A, "alpha", "persistent", b"survive", None)
                .expect("write");
        }
        let db = Arc::new(Db::open_file(&path).expect("reopen"));
        let store = BlobStore::new(db, Some(dir_blobs.path.clone()));
        assert_eq!(store.read(INST_A, "alpha", &id).expect("read"), b"survive");
        let info = store
            .get_info(INST_A, "alpha", "persistent")
            .expect("get_info");
        assert_eq!(info.size_bytes, 7);
    }

    /// H2: two installations of the same `plugin_id` (same `instance_id`
    /// string, different `installation_uuid`) must not share blob
    /// state or FS bytes. Writes under one uuid are invisible to
    /// the other, and each has its own directory tree under
    /// `<blobs_root>/<installation_uuid>/`.
    #[test]
    fn installation_uuid_isolates_state_from_same_instance_id() {
        let (store, dir) = store_with_root();
        store
            .register_instance(INST_A, "shared-id", 4096)
            .expect("register a");
        store
            .register_instance(INST_B, "shared-id", 4096)
            .expect("register b");
        let _id_a = store
            .write(INST_A, "shared-id", "name", b"payload-a", None)
            .expect("write a");
        let id_b = store
            .write(INST_B, "shared-id", "name", b"payload-b", None)
            .expect("write b");

        assert_eq!(
            store
                .read_by_name(INST_A, "shared-id", "name")
                .expect("read a"),
            b"payload-a"
        );
        assert_eq!(
            store
                .read_by_name(INST_B, "shared-id", "name")
                .expect("read b"),
            b"payload-b"
        );
        // Cross-uuid id read is NotFound — filenames don't collide
        // because the two uuids live in disjoint directory subtrees.
        assert!(matches!(
            store.read(INST_A, "shared-id", &id_b),
            Err(BlobError::NotFound { .. })
        ));
        assert!(dir.path.join(INST_A).join("shared-id").is_dir());
        assert!(dir.path.join(INST_B).join("shared-id").is_dir());
    }

    /// H2: `purge_installation` wipes SQL rows + on-disk directory
    /// tree for the tombstoned install and leaves other installs
    /// intact.
    #[test]
    fn purge_installation_wipes_sql_and_fs_for_only_that_install() {
        let (store, dir) = store_with_root();
        store
            .register_instance(INST_A, "alpha", 4096)
            .expect("register a");
        store
            .register_instance(INST_B, "alpha", 4096)
            .expect("register b");
        store
            .write(INST_A, "alpha", "x", b"aaa", None)
            .expect("write a");
        store
            .write(INST_B, "alpha", "x", b"bbb", None)
            .expect("write b");
        let a_dir = dir.path.join(INST_A);
        let b_dir = dir.path.join(INST_B);
        assert!(a_dir.is_dir());
        assert!(b_dir.is_dir());

        let removed = store.purge_installation(INST_A).expect("purge");
        assert!(removed >= 2, "expected ≥ 2 rows removed, got {removed}");
        assert!(!a_dir.exists(), "install A dir should be gone");
        assert!(b_dir.is_dir(), "install B dir must survive purge of A");
        assert!(store.usage(INST_A, "alpha").expect("usage a").is_none());
        assert_eq!(
            store.read_by_name(INST_B, "alpha", "x").expect("read b"),
            b"bbb"
        );
    }

    /// `purge_installation` on an install that never wrote is a
    /// no-op — safe to call from the uninstall path unconditionally.
    #[test]
    fn purge_installation_is_idempotent() {
        let (store, _dir) = store_with_root();
        assert_eq!(store.purge_installation(INST_A).expect("first"), 0);
        assert_eq!(store.purge_installation(INST_A).expect("second"), 0);
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

    /// Follow-up review H1: every blob-store entry point must
    /// refuse an unsafe `instance_id` — path traversal, absolute
    /// path, empty, leading dot, NUL byte. The check runs before
    /// any path construction so the FS never sees the malicious
    /// segment.
    #[test]
    fn all_entry_points_refuse_unsafe_instance_id() {
        let dir = tempdir();
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let blobs = BlobStore::new(db, Some(dir.path.clone()));
        // Length + traversal + control-char coverage.
        // Review F1: an id at exactly MAX_INSTANCE_ID_BYTES + 1
        // must refuse; boundary (== MAX) is exercised by the
        // positive-control test below.
        let too_long = "a".repeat(MAX_INSTANCE_ID_BYTES + 1);
        // 5-char multibyte string (kanji) that would be 15 bytes,
        // repeated to just past the byte limit.
        let too_long_multibyte = "日本語".repeat(30); // 30 * 9 bytes = 270 > 128
        let unsafe_ids: [&str; 10] = [
            "",
            "..",
            "../etc/passwd",
            "foo/bar",
            "foo\\bar",
            "/absolute",
            ".hidden",
            "with\0nul",
            too_long.as_str(),
            too_long_multibyte.as_str(),
        ];
        for id in unsafe_ids {
            assert!(
                matches!(
                    blobs.register_instance(INST_A, id, 4096),
                    Err(BlobError::UnsafeInstanceId { .. })
                ),
                "register_instance({id:?}) must refuse"
            );
            assert!(matches!(
                blobs.write(INST_A, id, "name", b"data", None),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.read(INST_A, id, "any-id"),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.read_by_name(INST_A, id, "name"),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.get_info(INST_A, id, "name"),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.delete(INST_A, id, "name"),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.list_blobs(INST_A, id, ""),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
            assert!(matches!(
                blobs.usage(INST_A, id),
                Err(BlobError::UnsafeInstanceId { .. })
            ));
        }
    }

    /// Positive control: safe ids continue to work.
    #[test]
    fn safe_instance_id_write_read_roundtrips() {
        let dir = tempdir();
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let blobs = BlobStore::new(db, Some(dir.path.clone()));
        blobs
            .register_instance(INST_A, "example.inst-1", 4096)
            .expect("register");
        let id = blobs
            .write(
                INST_A,
                "example.inst-1",
                "readme.txt",
                b"hello",
                Some("text/plain"),
            )
            .expect("write");
        let bytes = blobs.read(INST_A, "example.inst-1", &id).expect("read");
        assert_eq!(bytes, b"hello");
    }

    /// Review F1 boundary: an id at exactly [`MAX_INSTANCE_ID_BYTES`]
    /// is accepted; one byte over is refused. Verified by walking
    /// the boundary on both sides.
    #[test]
    fn instance_id_length_boundary() {
        assert!(
            is_safe_instance_id(&"a".repeat(MAX_INSTANCE_ID_BYTES)),
            "id of exactly MAX_INSTANCE_ID_BYTES must be accepted",
        );
        assert!(
            !is_safe_instance_id(&"a".repeat(MAX_INSTANCE_ID_BYTES + 1)),
            "id of MAX_INSTANCE_ID_BYTES + 1 must be refused",
        );
        // A short multibyte id is fine — byte length, not char
        // count, is what NAME_MAX cares about.
        assert!(
            is_safe_instance_id("日本語"),
            "short multibyte id must be accepted",
        );
    }

    /// H10 round-3 finding 3: `"*"` is reserved as the wildcard
    /// sentinel in `ServiceGrant.instance` /
    /// `ServiceGrant.caller_instance`, so a real instance-id must
    /// never equal `"*"`. Otherwise a grant naming a specific
    /// instance could not be distinguished from "any instance".
    #[test]
    fn wildcard_sentinel_instance_id_is_reserved() {
        assert!(
            !is_safe_instance_id("*"),
            "`*` is the reserved wildcard sentinel and must be refused as an instance-id",
        );
        // Only the exact `"*"` string — a name containing `*` as
        // one of several chars is fine.
        assert!(
            is_safe_instance_id("prod*"),
            "`prod*` is a normal identifier (only exact `*` is reserved)",
        );
        assert!(is_safe_instance_id("a*b"), "`a*b` is a normal identifier");
    }
}
