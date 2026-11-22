//! Backup, restore, and migration preflight (architecture-review M3).
//!
//! The persistent state is one `SQLite` database plus two
//! filesystem trees the database indexes:
//!
//! - `<state_dir>/oxidhome.db` (WAL mode, so `-wal` / `-shm` files
//!   ride along with it while a connection is open);
//! - `<state_dir>/blobs/<installation_uuid>/<instance_id>/<id>` —
//!   one file per `blob` row;
//! - `<state_dir>/plugins/<plugin_id>/` — one installed package per
//!   live `plugin_installation` row.
//!
//! Copying those three independently can capture an index that
//! points at files the copy doesn't contain (or the reverse), and a
//! naive copy of `oxidhome.db` without its WAL silently loses the
//! newest commits. This module defines the snapshot protocol.
//!
//! ## Backup (online)
//!
//! [`create_backup`] never takes the state-dir lock, so it runs
//! while the daemon is up. It holds the backup lock
//! ([`crate::exclusive_lock::acquire_backup_lock`]) *shared*, which
//! only excludes a restore:
//!
//! 1. `VACUUM INTO` from a fresh connection: one read transaction,
//!    so the copy is a point-in-time snapshot including every
//!    committed WAL frame. The snapshot is switched to a rollback
//!    journal so the archive is a single self-contained file.
//! 2. The blob and plugin file lists come from **the snapshot**, not
//!    the live tables. Blob files are immutable once their row
//!    commits (an overwrite mints a new id; the old file is removed
//!    only after the row is gone), so copying exactly the files the
//!    snapshot references reproduces the snapshot's view. Orphan
//!    files (crash leftovers no row points at) are skipped.
//! 3. Plugin packages are copied from `plugins/<plugin_id>/` and
//!    must hash to their row's `content_digest`. A referenced file
//!    that vanished mid-copy, a package that doesn't match its
//!    digest, or a live plugin set that changed between the snapshot
//!    and the end of the copy means the daemon raced the backup: the attempt is discarded
//!    and retried (up to [`BACKUP_ATTEMPTS`] times).
//! 4. A `manifest.json` lists every file with its size and SHA-256.
//!    The archive is built in a hidden sibling directory, verified
//!    with [`verify_backup`], fsynced, then renamed into place — a
//!    crash never leaves a half-written archive at the target path.
//!
//! The archive is a plain directory (tar / rsync it as you like);
//! it holds token *hashes* and audit rows but never the plaintext
//! `admin-token` file. It is not encrypted — see M7.
//!
//! ## Restore (offline)
//!
//! [`restore_offline`] holds the exclusive state-dir lock (so it
//! refuses while the daemon or an `mcp-stdio` session runs) plus the
//! backup lock *exclusively*, and:
//!
//! 1. verifies the whole archive (checksums, no extra / missing
//!    files, `PRAGMA integrity_check`, schema version, every blob
//!    row has its file and vice versa, every live plugin row has a
//!    package matching its digest) **before touching the state
//!    dir**;
//! 2. copies it into `<state_dir>/.restore-staging/`, re-checking
//!    every checksum on the way in, and re-runs the database /
//!    index / package checks on the staged copy;
//! 3. writes a durable `<state_dir>/.restore-journal`, then moves
//!    the current `oxidhome.db` (with its `-wal` / `-shm`), `blobs/`
//!    and `plugins/` into `<state_dir>/pre-restore-<unix_ms>/` and
//!    the staged copies into place;
//! 4. renames the journal to `.restore-audit-pending` and boots an
//!    [`crate::Engine`] on the restored state (applying any pending
//!    migrations) to record a `cli.state.restore` audit row, then
//!    removes the marker. If that fails, `--resume` retries it.
//!
//! The swap is a handful of renames, not one. A crash in the middle
//! leaves the journal behind; [`crate::state::Db::open_file`] then
//! refuses to open the state dir until `oxidhome restore --resume`
//! ([`resume_restore_offline`]) rolls the swap forward. Every step
//! of that roll-forward is idempotent. The previous state is never
//! deleted — the operator removes `pre-restore-*` once satisfied.
//!
//! ## Migration preflight
//!
//! Before [`crate::state::Db`] applies pending migrations to an
//! existing file it runs `PRAGMA quick_check` and writes a
//! `VACUUM INTO` snapshot to
//! `<state_dir>/pre-migration/<unix_ms>-v<from>-to-v<to>.db`
//! ([`snapshot_before_migration`]); the newest
//! [`PRE_MIGRATION_KEEP`] are kept. Either failing refuses the
//! migration. Migrations don't touch blob or plugin files, so the
//! database snapshot plus the untouched trees is the pre-upgrade
//! state.
//!
//! **Recovery policy is forward-first.** Each migration commits in
//! its own transaction, so a failing migration leaves the database
//! at the last good version and the daemon refuses to start; the fix
//! is a binary with a corrected migration. A database whose schema is
//! newer than the binary is refused outright (no silent downgrade).
//! Rolling back to the old binary means swapping the pre-migration
//! snapshot in by hand while the daemon is stopped, which discards
//! every write since the upgrade — see `ARCHITECTURE.md`. Rolling
//! back across migration 14 additionally loses the legacy blob
//! files, which [`crate::Engine::with_state_dir`] sweeps on the
//! boot that applies it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::db::{DB_FILE_NAME, schema_version};

/// `format` field of every backup manifest.
pub const BACKUP_FORMAT: &str = "oxidhome-backup";
/// Archive layout version. Bumped on any incompatible change to the
/// manifest or the directory layout.
pub const BACKUP_FORMAT_VERSION: u32 = 1;
/// Manifest file name at the archive root.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Blob tree, relative to both the state dir and the archive root.
pub const BLOBS_DIR: &str = "blobs";
/// Installed-plugin tree, relative to both the state dir and the
/// archive root.
pub const PLUGINS_DIR: &str = "plugins";
/// Present while a restore swap is in flight. Its presence makes
/// [`crate::state::Db::open_file`] refuse the state dir.
pub const RESTORE_JOURNAL_FILE: &str = ".restore-journal";
/// Present after the swap until the restore's audit row is recorded;
/// `oxidhome restore --resume` retries the audit while it exists.
pub const RESTORE_AUDIT_PENDING_FILE: &str = ".restore-audit-pending";
/// Where a restore stages the archive before the swap.
pub const RESTORE_STAGING_DIR: &str = ".restore-staging";
/// Prefix of the directory a restore moves the previous state into.
pub const PRE_RESTORE_PREFIX: &str = "pre-restore-";
/// Pre-migration snapshots, relative to the state dir.
pub const PRE_MIGRATION_DIR: &str = "pre-migration";
/// How many pre-migration snapshots to keep.
pub const PRE_MIGRATION_KEEP: usize = 3;
/// Oldest schema version a backup may carry. Archives can only be
/// produced by binaries at or past this version, and the
/// verification queries depend on its `blob` / `plugin_installation`
/// shape.
pub const MIN_RESTORABLE_SCHEMA_VERSION: i64 = 16;
/// Audit `path` for a completed restore.
pub const AUDIT_PATH_RESTORE: &str = "cli.state.restore";
/// Audit `method` of local (non-network) actions; matches the M4
/// admin-token recovery rows.
const AUDIT_METHOD_LOCAL: &str = "LOCAL";
/// Attempts before an online backup gives up on a busy daemon.
pub const BACKUP_ATTEMPTS: u32 = 3;

const MAX_MANIFEST_BYTES: u64 = 64 << 20;
const SOURCE_BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// `manifest.json` at the root of a backup archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Always [`BACKUP_FORMAT`].
    pub format: String,
    /// [`BACKUP_FORMAT_VERSION`] of the writer.
    pub format_version: u32,
    /// Wall-clock time the snapshot was taken (unix ms).
    pub created_ms: u64,
    /// `oxidhome-core` version that wrote the archive.
    pub oxidhome_version: String,
    /// `PRAGMA user_version` of the archived database.
    pub schema_version: i64,
    /// Every file in the archive except the manifest itself, sorted
    /// by path.
    pub files: Vec<FileEntry>,
}

/// One archived file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// `/`-separated path relative to the archive root.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Lower-case hex SHA-256 of the contents.
    pub sha256: String,
}

/// Result of [`create_backup`].
#[derive(Debug, Clone)]
pub struct BackupReport {
    /// The finished archive directory.
    pub path: PathBuf,
    /// Its manifest.
    pub manifest: BackupManifest,
    /// Blob files archived.
    pub blobs: usize,
    /// Installed plugins archived.
    pub plugins: usize,
    /// Attempts it took (more than one when the daemon raced it).
    pub attempts: u32,
}

/// Result of [`verify_backup`].
#[derive(Debug, Clone)]
pub struct VerifiedBackup {
    /// The archive's manifest.
    pub manifest: BackupManifest,
    /// Blob files in the archive.
    pub blobs: usize,
    /// Live plugin installations in the archive.
    pub plugins: usize,
}

/// Result of [`restore_offline`] / [`resume_restore_offline`].
#[derive(Debug, Clone)]
pub struct RestoreReport {
    /// Where the replaced state now lives.
    pub previous: PathBuf,
    /// `created_ms` of the restored archive.
    pub archive_created_ms: u64,
}

// ── backup ───────────────────────────────────────────────────────

/// Write a consistent backup of `state_dir` to the new directory
/// `out`. Safe while the daemon runs — see the module doc.
///
/// # Errors
///
/// - `out` already exists, or its parent doesn't.
/// - The state dir has no database or an interrupted restore.
/// - The daemon kept changing the indexed files across
///   [`BACKUP_ATTEMPTS`] attempts.
/// - The live state is inconsistent (a blob file whose size
///   disagrees with its row, a symlink inside a plugin package).
/// - Any I/O or `SQLite` failure. Nothing is left at `out`.
pub fn create_backup(state_dir: &Path, out: &Path) -> anyhow::Result<BackupReport> {
    ensure_no_interrupted_restore(state_dir)?;
    let db_path = state_dir.join(DB_FILE_NAME);
    ensure!(
        db_path.is_file(),
        "no oxidhome database at {} — nothing to back up \
         (set $OXIDHOME_STATE_DIR to the daemon's state dir)",
        db_path.display(),
    );
    ensure!(
        fs::symlink_metadata(out).is_err(),
        "backup target {} already exists",
        out.display(),
    );
    // Shared: concurrent backups are fine, a restore is not — it
    // would rename the database under our open connection.
    let _backup_lock = crate::exclusive_lock::acquire_backup_lock(state_dir, false)?;
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("backup target {} needs a UTF-8 file name", out.display()))?;
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    ensure!(
        parent.is_dir(),
        "parent directory of the backup target {} does not exist",
        out.display(),
    );
    let partial = parent.join(format!(".{name}.partial-{}", std::process::id()));

    let mut last_race = String::new();
    for attempt in 1..=BACKUP_ATTEMPTS {
        remove_dir_if_exists(&partial)?;
        match backup_attempt(state_dir, &partial) {
            Ok((manifest, blobs, plugins)) => {
                // Self-check with the same verifier restore uses.
                if let Err(err) = verify_backup(&partial) {
                    let _ = fs::remove_dir_all(&partial);
                    return Err(err.context("the freshly written backup failed verification"));
                }
                if fs::symlink_metadata(out).is_ok() {
                    let _ = fs::remove_dir_all(&partial);
                    bail!("backup target {} appeared during the backup", out.display());
                }
                if let Err(err) = fs::rename(&partial, out) {
                    let _ = fs::remove_dir_all(&partial);
                    return Err(anyhow::Error::new(err).context(format!(
                        "renaming {} to {}",
                        partial.display(),
                        out.display()
                    )));
                }
                sync_dir(&parent).with_context(|| format!("syncing {}", parent.display()))?;
                return Ok(BackupReport {
                    path: out.to_path_buf(),
                    manifest,
                    blobs,
                    plugins,
                    attempts: attempt,
                });
            }
            Err(AttemptError::Raced(reason)) => {
                tracing::warn!(attempt, reason = %reason, "backup raced a state change; retrying");
                last_race = reason;
            }
            Err(AttemptError::Fatal(err)) => {
                let _ = fs::remove_dir_all(&partial);
                return Err(err);
            }
        }
    }
    let _ = fs::remove_dir_all(&partial);
    bail!(
        "state kept changing during the backup ({BACKUP_ATTEMPTS} attempts; last: {last_race}) \
         — retry when the hub is quieter, or stop the daemon first"
    )
}

enum AttemptError {
    /// The daemon changed indexed files mid-copy; retry.
    Raced(String),
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for AttemptError {
    fn from(err: anyhow::Error) -> Self {
        Self::Fatal(err)
    }
}

/// What a database snapshot says the filesystem trees must contain.
#[derive(Debug, PartialEq, Eq)]
struct SnapshotIndex {
    /// Archive-relative blob path → recorded size.
    blobs: BTreeMap<String, u64>,
    plugins: BTreeSet<LivePlugin>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LivePlugin {
    plugin_id: String,
    installation_uuid: String,
    content_digest: Option<String>,
}

fn backup_attempt(
    state_dir: &Path,
    dest: &Path,
) -> Result<(BackupManifest, usize, usize), AttemptError> {
    ensure_no_interrupted_restore(state_dir)?;
    create_private_dir(dest)?;
    let created_ms = now_unix_ms();
    let source = open_live_db(&state_dir.join(DB_FILE_NAME))?;
    let snapshot_path = dest.join(DB_FILE_NAME);
    vacuum_into(&source, &snapshot_path)?;
    let (schema, index) = {
        let snap = Connection::open_with_flags(
            &snapshot_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .context("opening the database snapshot")?;
        set_rollback_journal(&snap)?;
        let schema = user_version(&snap)?;
        if schema < MIN_RESTORABLE_SCHEMA_VERSION {
            return Err(anyhow::anyhow!(
                "database schema v{schema} predates backup support \
                 (v{MIN_RESTORABLE_SCHEMA_VERSION}); start the daemon once to migrate it"
            )
            .into());
        }
        (schema, read_index(&snap)?)
    };
    File::open(&snapshot_path)
        .and_then(|f| f.sync_all())
        .context("syncing the database snapshot")?;

    let mut files = vec![file_entry(DB_FILE_NAME, &snapshot_path)?];
    create_private_dir(&dest.join(BLOBS_DIR))?;
    create_private_dir(&dest.join(PLUGINS_DIR))?;

    copy_indexed_blobs(state_dir, dest, &index, &mut files)?;
    copy_live_plugins(state_dir, dest, &index, &mut files)?;

    // The snapshot only pins the blob list; plugin trees are copied
    // from the live dir. An install / uninstall that committed after
    // the snapshot shows up as a different live set here.
    let live_now = read_live_plugins(&source)?;
    if live_now != index.plugins {
        return Err(AttemptError::Raced(
            "plugin installations changed during the backup".into(),
        ));
    }
    drop(source);
    // A restore that started swapping while we copied moves files
    // under us; never hand out an archive straddling the swap.
    ensure_no_interrupted_restore(state_dir)?;

    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = BackupManifest {
        format: BACKUP_FORMAT.into(),
        format_version: BACKUP_FORMAT_VERSION,
        created_ms,
        oxidhome_version: env!("CARGO_PKG_VERSION").into(),
        schema_version: schema,
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest).context("encoding the manifest")?;
    write_new_file(&dest.join(MANIFEST_FILE), &bytes).context("writing the manifest")?;
    sync_tree_dirs(dest)?;
    Ok((manifest, index.blobs.len(), index.plugins.len()))
}

/// Copy every blob file the snapshot indexes. Blob files are
/// immutable, so a missing file means a delete raced the backup.
fn copy_indexed_blobs(
    state_dir: &Path,
    dest: &Path,
    index: &SnapshotIndex,
    files: &mut Vec<FileEntry>,
) -> Result<(), AttemptError> {
    for (rel, size) in &index.blobs {
        let src = match open_no_follow(&state_dir.join(rel)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(AttemptError::Raced(format!("blob file {rel} disappeared")));
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("opening blob file {rel}"))
                    .into());
            }
        };
        let target = dest.join(rel);
        if let Some(p) = target.parent() {
            create_private_dir_all(p)?;
        }
        let (n, sha256) = copy_hashed(src, &target).with_context(|| format!("copying {rel}"))?;
        if n != *size {
            return Err(anyhow::anyhow!(
                "blob file {rel} is {n} bytes but its index row records {size} — \
                 the live state is inconsistent"
            )
            .into());
        }
        files.push(FileEntry {
            path: rel.clone(),
            size: n,
            sha256,
        });
    }

    Ok(())
}

/// Copy the package directory of every live installation in the
/// snapshot.
fn copy_live_plugins(
    state_dir: &Path,
    dest: &Path,
    index: &SnapshotIndex,
    files: &mut Vec<FileEntry>,
) -> Result<(), AttemptError> {
    for plugin in &index.plugins {
        let rel = format!("{PLUGINS_DIR}/{}", plugin.plugin_id);
        let src = state_dir.join(&rel);
        match fs::symlink_metadata(&src) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(
                    anyhow::anyhow!("installed plugin path {rel} is not a directory").into(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // An install renames its package into place after the
                // row commits; an uninstall removes it before the
                // tombstone. Both are transient. A package hand-placed
                // under another directory name is not, and fails once
                // the retries run out.
                return Err(AttemptError::Raced(format!(
                    "installed plugin directory {rel} is missing (install / uninstall in \
                     progress, or the package is not at plugins/<plugin_id>)"
                )));
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("reading {rel}"))
                    .into());
            }
        }
        copy_tree_hashed(&src, dest, &rel, files)?;
        // A package mid-uninstall (or replaced) still has a live row
        // for a moment; the digest catches the torn copy.
        check_package(&dest.join(&rel), plugin).map_err(|reason| {
            AttemptError::Raced(format!(
                "package of plugin {} changed during the copy or does not match its \
                 installation row ({reason}); if this persists, reinstall the plugin",
                plugin.plugin_id
            ))
        })?;
    }

    Ok(())
}

fn copy_tree_hashed(
    src_dir: &Path,
    dest_root: &Path,
    rel_dir: &str,
    files: &mut Vec<FileEntry>,
) -> Result<(), AttemptError> {
    create_private_dir_all(&dest_root.join(rel_dir))?;
    let entries = match fs::read_dir(src_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AttemptError::Raced(format!("{rel_dir} disappeared")));
        }
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("listing {rel_dir}"))
                .into());
        }
    };
    let mut children = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {rel_dir}"))?;
        children.push(entry);
    }
    children.sort_by_key(std::fs::DirEntry::file_name);
    for entry in children {
        let name = entry.file_name();
        let name = name
            .to_str()
            .filter(|n| is_safe_segment(n) || is_dot_file(n))
            .with_context(|| {
                format!(
                    "{rel_dir} contains an entry whose name can't be archived: {}",
                    entry.file_name().to_string_lossy()
                )
            })?
            .to_owned();
        let rel = format!("{rel_dir}/{name}");
        let ty = entry
            .file_type()
            .with_context(|| format!("reading {rel}"))?;
        if ty.is_dir() {
            copy_tree_hashed(&entry.path(), dest_root, &rel, files)?;
        } else if ty.is_file() {
            let src = match open_no_follow(&entry.path()) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AttemptError::Raced(format!("{rel} disappeared")));
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("opening {rel}"))
                        .into());
                }
            };
            let (size, sha256) = copy_hashed(src, &dest_root.join(&rel))
                .with_context(|| format!("copying {rel}"))?;
            files.push(FileEntry {
                path: rel,
                size,
                sha256,
            });
        } else {
            return Err(anyhow::anyhow!(
                "{rel} is a symlink or special file; installed packages may only hold \
                 regular files and directories"
            )
            .into());
        }
    }
    Ok(())
}

// ── verification ─────────────────────────────────────────────────

/// Verify a backup archive without modifying it. Checks:
///
/// - the manifest's format / version and path safety;
/// - the archive holds exactly the listed files (no extras, no
///   symlinks) with matching sizes and SHA-256s;
/// - the database is a self-contained rollback-journal file that
///   passes `PRAGMA integrity_check`, whose schema version matches
///   the manifest and that this binary can open;
/// - the blob files are exactly the ones the `blob` table indexes,
///   at the recorded sizes;
/// - every live `plugin_installation` row has its package, and no
///   package lacks a live row.
///
/// # Errors
///
/// The first failed check, naming the offending file.
pub fn verify_backup(archive: &Path) -> anyhow::Result<VerifiedBackup> {
    let meta = fs::symlink_metadata(archive)
        .with_context(|| format!("reading backup {}", archive.display()))?;
    ensure!(
        meta.is_dir(),
        "{} is not a backup directory",
        archive.display()
    );
    let manifest = read_manifest(archive)?;
    ensure!(
        manifest.format == BACKUP_FORMAT,
        "{} is not an oxidhome backup (format {:?})",
        archive.display(),
        manifest.format,
    );
    ensure!(
        manifest.format_version == BACKUP_FORMAT_VERSION,
        "unsupported backup format version {} (this binary reads {BACKUP_FORMAT_VERSION})",
        manifest.format_version,
    );

    check_archive_files(archive, &manifest)?;
    let index = check_tree(archive, &manifest)?;

    Ok(VerifiedBackup {
        blobs: index.blobs.len(),
        plugins: index.plugins.len(),
        manifest,
    })
}

/// Manifest entries are well-formed and the archive holds exactly
/// those files with matching sizes and checksums. Returns the
/// entries keyed by path.
fn check_archive_files<'m>(
    archive: &Path,
    manifest: &'m BackupManifest,
) -> anyhow::Result<BTreeMap<&'m str, &'m FileEntry>> {
    let mut listed: BTreeMap<&str, &FileEntry> = BTreeMap::new();
    for entry in &manifest.files {
        check_manifest_path(&entry.path)?;
        ensure!(
            entry.sha256.len() == 64
                && entry
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "manifest entry {} has a malformed sha256",
            entry.path,
        );
        ensure!(
            listed.insert(&entry.path, entry).is_none(),
            "manifest lists {} twice",
            entry.path,
        );
    }
    ensure!(
        listed.contains_key(DB_FILE_NAME),
        "manifest does not list {DB_FILE_NAME}"
    );

    let mut present = BTreeSet::new();
    walk_files(archive, "", &mut present)?;
    let mut expected: BTreeSet<String> = listed.keys().map(|k| (*k).to_owned()).collect();
    expected.insert(MANIFEST_FILE.to_owned());
    if let Some(extra) = present.difference(&expected).next() {
        bail!("archive contains {extra}, which the manifest does not list");
    }
    if let Some(missing) = expected.difference(&present).next() {
        bail!("archive is missing {missing}");
    }
    for entry in listed.values() {
        let path = archive.join(&entry.path);
        let file = open_no_follow(&path).with_context(|| format!("opening {}", entry.path))?;
        let (size, sha256) =
            hash_reader(file).with_context(|| format!("reading {}", entry.path))?;
        ensure!(
            size == entry.size && sha256 == entry.sha256,
            "checksum mismatch for {} — the archive is corrupt or was modified",
            entry.path,
        );
    }

    Ok(listed)
}

/// Open the archived database read-only and check it before reading
/// its index.
/// Database, index and package checks over a tree whose files
/// already match `manifest` (the archive, or the restore staging
/// dir). Returns the database's index.
fn check_tree(root: &Path, manifest: &BackupManifest) -> anyhow::Result<SnapshotIndex> {
    let listed: BTreeMap<&str, &FileEntry> = manifest
        .files
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let index = read_archived_index(root, manifest.schema_version)?;
    check_index_matches(&listed, &index)?;
    for plugin in &index.plugins {
        check_package(&root.join(PLUGINS_DIR).join(&plugin.plugin_id), plugin).map_err(
            |reason| anyhow::anyhow!("package of plugin {}: {reason}", plugin.plugin_id),
        )?;
    }
    Ok(index)
}

/// The package at `dir` is the one `plugin`'s row was granted for:
/// its manifest declares the same id and, unless the row is
/// quarantined (no digest), its content digest matches.
fn check_package(dir: &Path, plugin: &LivePlugin) -> Result<(), String> {
    let Some(expected) = &plugin.content_digest else {
        return Ok(());
    };
    let (digest, manifest) =
        crate::state::recompute_digest_and_manifest(dir).map_err(|e| format!("{e:#}"))?;
    if manifest.plugin.id != plugin.plugin_id {
        return Err(format!("manifest declares id {}", manifest.plugin.id));
    }
    if digest != *expected {
        return Err("content digest does not match its installation row".into());
    }
    Ok(())
}

fn read_archived_index(archive: &Path, manifest_schema: i64) -> anyhow::Result<SnapshotIndex> {
    let db_path = archive.join(DB_FILE_NAME);
    check_rollback_journal_header(&db_path)?;
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("opening the archived database")?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .context("running integrity_check on the archived database")?;
    ensure!(
        integrity == "ok",
        "archived database fails integrity_check: {integrity}"
    );
    let schema = user_version(&conn)?;
    ensure!(
        schema == manifest_schema,
        "archived database is schema v{schema} but the manifest says v{manifest_schema}",
    );
    ensure_schema_restorable(schema)?;
    read_index(&conn)
}

/// The blob files are exactly those the `blob` table indexes, and
/// the plugin packages exactly those with a live installation row.
fn check_index_matches(
    listed: &BTreeMap<&str, &FileEntry>,
    index: &SnapshotIndex,
) -> anyhow::Result<()> {
    let archived_blobs: BTreeMap<&str, u64> = listed
        .iter()
        .filter(|(p, _)| p.starts_with("blobs/"))
        .map(|(p, e)| (*p, e.size))
        .collect();
    for (rel, size) in &index.blobs {
        match archived_blobs.get(rel.as_str()) {
            Some(s) if s == size => {}
            Some(s) => bail!("blob {rel} is {s} bytes but its index row records {size}"),
            None => bail!("archive is missing blob {rel}, which the database indexes"),
        }
    }
    if let Some(extra) = archived_blobs
        .keys()
        .find(|p| !index.blobs.contains_key(**p))
    {
        bail!("archive contains blob {extra}, which no database row references");
    }

    let live_ids: BTreeSet<&str> = index.plugins.iter().map(|p| p.plugin_id.as_str()).collect();
    for path in listed.keys() {
        if let Some(rest) = path.strip_prefix("plugins/") {
            let id = rest.split('/').next().unwrap_or_default();
            ensure!(
                live_ids.contains(id),
                "archive contains {path}, but plugin {id} has no live installation row",
            );
        }
    }
    for id in &live_ids {
        ensure!(
            listed.contains_key(format!("plugins/{id}/manifest.toml").as_str()),
            "archive is missing the package of installed plugin {id}",
        );
    }

    Ok(())
}

fn read_manifest(archive: &Path) -> anyhow::Result<BackupManifest> {
    let path = archive.join(MANIFEST_FILE);
    let file = open_no_follow(&path).with_context(|| format!("opening {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "{} is larger than {MAX_MANIFEST_BYTES} bytes",
        path.display(),
    );
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Manifest paths: `oxidhome.db`, `blobs/<uuid>/<instance>/<id>`, or
/// `plugins/<plugin_id>/<…>`, every segment plain.
fn check_manifest_path(path: &str) -> anyhow::Result<()> {
    let segments: Vec<&str> = path.split('/').collect();
    let ok = match segments.as_slice() {
        [single] => *single == DB_FILE_NAME,
        [BLOBS_DIR, uuid, instance, id] => {
            is_safe_segment(uuid) && is_safe_segment(instance) && is_safe_segment(id)
        }
        [PLUGINS_DIR, id, rest @ ..] if !rest.is_empty() => {
            is_safe_segment(id) && rest.iter().all(|s| is_safe_segment(s) || is_dot_file(s))
        }
        _ => false,
    };
    ensure!(ok, "manifest lists an invalid path: {path:?}");
    Ok(())
}

/// Collect every regular file under `dir` as an archive-relative
/// path. Symlinks and special files are refused.
fn walk_files(dir: &Path, rel: &str, out: &mut BTreeSet<String>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("archive contains a non-UTF-8 name under {}", dir.display());
        };
        let child = if rel.is_empty() {
            name.to_owned()
        } else {
            format!("{rel}/{name}")
        };
        let ty = entry
            .file_type()
            .with_context(|| format!("reading {child}"))?;
        if ty.is_dir() {
            walk_files(&entry.path(), &child, out)?;
        } else if ty.is_file() {
            out.insert(child);
        } else {
            bail!("archive contains {child}, which is a symlink or special file");
        }
    }
    Ok(())
}

fn ensure_schema_restorable(schema: i64) -> anyhow::Result<()> {
    let current = schema_version();
    ensure!(
        schema <= current,
        "backup is schema v{schema}, newer than this binary supports (v{current}) — \
         restore it with a newer oxidhome",
    );
    ensure!(
        schema >= MIN_RESTORABLE_SCHEMA_VERSION,
        "backup is schema v{schema}, older than the oldest restorable \
         v{MIN_RESTORABLE_SCHEMA_VERSION}",
    );
    Ok(())
}

/// A WAL-mode database file needs its `-wal` to be complete, and a
/// read-only open of one may create `-shm` next to it. Archives must
/// hold rollback-journal databases (file format bytes 18/19 = 1).
fn check_rollback_journal_header(path: &Path) -> anyhow::Result<()> {
    let mut header = [0u8; 100];
    open_no_follow(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .with_context(|| format!("reading the header of {}", path.display()))?;
    ensure!(
        header.starts_with(b"SQLite format 3\0"),
        "{} is not a SQLite database",
        path.display()
    );
    ensure!(
        header[18] == 1 && header[19] == 1,
        "{} is a WAL-mode database; backups must be self-contained",
        path.display(),
    );
    Ok(())
}

// ── restore ──────────────────────────────────────────────────────

/// Replace the state in `state_dir` with the verified archive at
/// `archive`. Offline: takes the exclusive state-dir lock. See the
/// module doc for the protocol.
///
/// # Errors
///
/// - The state dir is locked (daemon running) or has an interrupted
///   restore (run [`resume_restore_offline`]).
/// - The archive fails [`verify_backup`] or changes while being
///   staged. The state dir is untouched in both cases.
/// - I/O errors during the swap: the journal stays behind and
///   [`resume_restore_offline`] finishes the job.
/// - The restored state fails to open (e.g. a migration fails); the
///   error names the directory holding the previous state.
pub fn restore_offline(state_dir: &Path, archive: &Path) -> anyhow::Result<RestoreReport> {
    let _lock = crate::exclusive_lock::acquire_state_dir_lock(state_dir)
        .context("restore needs exclusive access — stop the daemon first")?;
    let _backup_lock = crate::exclusive_lock::acquire_backup_lock(state_dir, true)?;
    ensure_no_interrupted_restore(state_dir)?;
    let verified =
        verify_backup(archive).with_context(|| format!("verifying {}", archive.display()))?;

    let staging = state_dir.join(RESTORE_STAGING_DIR);
    remove_dir_if_exists(&staging)?;
    // The database / index / package checks run again on the staged
    // bytes: verification read the archive, and a mutable archive
    // could have shown different bytes to each pass.
    stage_archive(archive, &verified.manifest, &staging)
        .and_then(|()| check_tree(&staging, &verified.manifest).map(|_| ()))
        .with_context(|| format!("staging {}", archive.display()))
        .inspect_err(|_| {
            let _ = fs::remove_dir_all(&staging);
        })?;

    let previous_name = format!("{PRE_RESTORE_PREFIX}{}", now_unix_ms());
    let previous = state_dir.join(&previous_name);
    create_private_dir(&previous).with_context(|| format!("creating {}", previous.display()))?;
    sync_dir(state_dir)?;
    let journal = RestoreJournal {
        previous: previous_name,
        archive_created_ms: verified.manifest.created_ms,
    };
    let journal_bytes = serde_json::to_vec(&journal).context("encoding the restore journal")?;
    write_file_atomic(&state_dir.join(RESTORE_JOURNAL_FILE), &journal_bytes)
        .context("writing the restore journal")?;

    finish_restore(state_dir, &journal)
}

/// Finish a restore that crashed mid-swap (the journal is present).
/// Offline: takes the exclusive state-dir lock. Returns `Ok(None)`
/// when there is nothing to resume.
///
/// # Errors
///
/// Lock contention, an unreadable journal, or I/O errors while
/// rolling the swap forward (safe to retry).
pub fn resume_restore_offline(state_dir: &Path) -> anyhow::Result<Option<RestoreReport>> {
    let _lock = crate::exclusive_lock::acquire_state_dir_lock(state_dir)
        .context("restore needs exclusive access — stop the daemon first")?;
    let _backup_lock = crate::exclusive_lock::acquire_backup_lock(state_dir, true)?;
    if let Some(journal) = read_journal(&state_dir.join(RESTORE_JOURNAL_FILE))? {
        return finish_restore(state_dir, &journal).map(Some);
    }
    if let Some(journal) = read_journal(&state_dir.join(RESTORE_AUDIT_PENDING_FILE))? {
        return complete_restore_audit(state_dir, &journal).map(Some);
    }
    Ok(None)
}

fn read_journal(path: &Path) -> anyhow::Result<Option<RestoreJournal>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    };
    let journal: RestoreJournal =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    ensure!(
        journal.previous.starts_with(PRE_RESTORE_PREFIX) && is_safe_segment(&journal.previous),
        "{} names an invalid previous-state directory {:?}",
        path.display(),
        journal.previous,
    );
    Ok(Some(journal))
}

/// Refuse to touch a state dir whose restore swap was interrupted.
/// Called by [`crate::state::Db::open_file`] and [`create_backup`].
///
/// # Errors
///
/// When `<state_dir>/.restore-journal` exists.
pub fn ensure_no_interrupted_restore(state_dir: &Path) -> anyhow::Result<()> {
    let journal = state_dir.join(RESTORE_JOURNAL_FILE);
    ensure!(
        fs::symlink_metadata(&journal).is_err(),
        "{} has an interrupted restore ({} exists) — run `oxidhome restore --resume` \
         with the daemon stopped",
        state_dir.display(),
        journal.display(),
    );
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct RestoreJournal {
    /// Directory name (under the state dir) receiving the old state.
    previous: String,
    archive_created_ms: u64,
}

/// Copy every manifest file into `staging`, re-hashing on the way in
/// so a file changed after verification can't slip through.
fn stage_archive(archive: &Path, manifest: &BackupManifest, staging: &Path) -> anyhow::Result<()> {
    create_private_dir(staging)?;
    create_private_dir(&staging.join(BLOBS_DIR))?;
    create_private_dir(&staging.join(PLUGINS_DIR))?;
    for entry in &manifest.files {
        let src = open_no_follow(&archive.join(&entry.path))
            .with_context(|| format!("opening {}", entry.path))?;
        let dst = staging.join(&entry.path);
        if let Some(p) = dst.parent() {
            create_private_dir_all(p)?;
        }
        let (size, sha256) =
            copy_hashed(src, &dst).with_context(|| format!("staging {}", entry.path))?;
        ensure!(
            size == entry.size && sha256 == entry.sha256,
            "{} changed after verification — aborting the restore",
            entry.path,
        );
    }
    sync_tree_dirs(staging)
}

/// Roll the swap forward. Idempotent: each item moves only while
/// its staged copy is still waiting in the staging dir.
fn finish_restore(state_dir: &Path, journal: &RestoreJournal) -> anyhow::Result<RestoreReport> {
    let staging = state_dir.join(RESTORE_STAGING_DIR);
    let previous = state_dir.join(&journal.previous);
    if !previous.is_dir() {
        create_private_dir(&previous)?;
    }

    if staging.join(DB_FILE_NAME).exists() {
        // The old WAL must leave before the new database arrives —
        // SQLite would otherwise replay its frames onto the restored
        // file.
        for suffix in ["-wal", "-shm", ""] {
            let name = format!("{DB_FILE_NAME}{suffix}");
            move_aside(&state_dir.join(&name), &previous.join(&name))?;
        }
        sync_dir(&previous)?;
        sync_dir(state_dir)?;
        rename_synced(
            &staging.join(DB_FILE_NAME),
            &state_dir.join(DB_FILE_NAME),
            &staging,
            state_dir,
        )?;
    }
    for dir in [BLOBS_DIR, PLUGINS_DIR] {
        if staging.join(dir).exists() {
            move_aside(&state_dir.join(dir), &previous.join(dir))?;
            sync_dir(&previous)?;
            rename_synced(
                &staging.join(dir),
                &state_dir.join(dir),
                &staging,
                state_dir,
            )?;
        }
    }
    remove_dir_if_exists(&staging)?;
    // The swap is done: the journal becomes the audit-pending marker
    // (one atomic rename), which no longer blocks `Db::open_file`.
    fs::rename(
        state_dir.join(RESTORE_JOURNAL_FILE),
        state_dir.join(RESTORE_AUDIT_PENDING_FILE),
    )
    .context("retiring the restore journal")?;
    sync_dir(state_dir)?;
    complete_restore_audit(state_dir, journal)
}

/// Record the restore's audit row, then drop the audit-pending
/// marker. A crash in between records a duplicate row on resume —
/// never a missing one.
fn complete_restore_audit(
    state_dir: &Path,
    journal: &RestoreJournal,
) -> anyhow::Result<RestoreReport> {
    let previous = state_dir.join(&journal.previous);
    record_restore(state_dir, journal.archive_created_ms).with_context(|| {
        format!(
            "the backup was swapped in, but opening the restored state or recording its \
             audit row failed (retry with `oxidhome restore --resume`); the previous state \
             is in {}",
            previous.display()
        )
    })?;
    remove_file_if_exists(&state_dir.join(RESTORE_AUDIT_PENDING_FILE))?;
    sync_dir(state_dir)?;
    Ok(RestoreReport {
        previous,
        archive_created_ms: journal.archive_created_ms,
    })
}

/// Boot an engine on the restored state (proves it opens, applies
/// pending migrations) and record the restore in its audit ledger.
fn record_restore(state_dir: &Path, archive_created_ms: u64) -> anyhow::Result<()> {
    let engine = crate::Engine::with_state_dir(state_dir)
        .with_context(|| format!("opening engine state at {}", state_dir.display()))?;
    let entry = crate::state::AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: format!("backup-{archive_created_ms}"),
        actor_kind: crate::ActorKind::Cli.as_str().into(),
        method: AUDIT_METHOD_LOCAL.into(),
        path: AUDIT_PATH_RESTORE.into(),
        status: 200,
        decision: "allow".into(),
        required_scope: None,
        execution_outcome: Some("success".into()),
        domain_error: None,
        credential_fp: None,
    };
    let result = engine
        .audit_log()
        .record_completed(&entry)
        .map(|_| ())
        .context("recording the restore audit row");
    let _ = engine.log_store().flush(Duration::from_secs(5));
    result
}

/// Move `from` to `to` if `from` exists. Refuses to overwrite.
fn move_aside(from: &Path, to: &Path) -> anyhow::Result<()> {
    if fs::symlink_metadata(from).is_err() {
        return Ok(());
    }
    ensure!(
        fs::symlink_metadata(to).is_err(),
        "cannot move {} aside: {} already exists",
        from.display(),
        to.display(),
    );
    fs::rename(from, to).with_context(|| format!("moving {} to {}", from.display(), to.display()))
}

/// Rename across two directories and sync both: resume uses the
/// entry's absence from `from_dir` as its progress marker, so that
/// removal must be as durable as the arrival in `to_dir`.
fn rename_synced(from: &Path, to: &Path, from_dir: &Path, to_dir: &Path) -> anyhow::Result<()> {
    fs::rename(from, to)
        .with_context(|| format!("moving {} to {}", from.display(), to.display()))?;
    sync_dir(to_dir)?;
    sync_dir(from_dir)
}

// ── migration preflight ──────────────────────────────────────────

/// Preflight for [`crate::state::Db`] before it applies migrations
/// `from + 1 ..= to` to the file-backed database `conn`: run
/// `PRAGMA quick_check`, then write a `VACUUM INTO` snapshot to
/// `<state_dir>/pre-migration/` and prune all but the newest
/// [`PRE_MIGRATION_KEEP`]. Returns the snapshot path.
///
/// # Errors
///
/// A failed quick check or any snapshot I/O error — the caller
/// refuses to migrate.
pub fn snapshot_before_migration(
    conn: &Connection,
    state_dir: &Path,
    from: i64,
    to: i64,
) -> anyhow::Result<PathBuf> {
    let check: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .context("running quick_check before migrating")?;
    ensure!(
        check == "ok",
        "database fails quick_check ({check}); refusing to migrate — restore a backup",
    );
    let dir = state_dir.join(PRE_MIGRATION_DIR);
    let dir_is_new = fs::symlink_metadata(&dir).is_err();
    create_private_dir_all(&dir)
        .and_then(|()| {
            if dir_is_new {
                sync_dir(state_dir)
            } else {
                Ok(())
            }
        })
        .with_context(|| format!("writing the pre-migration snapshot under {}", dir.display()))?;
    let name = format!("{:013}-v{from}-to-v{to}.db", now_unix_ms());
    let partial = dir.join(format!("{name}.partial"));
    let target = dir.join(&name);
    remove_file_if_exists(&partial)?;
    let result = (|| {
        vacuum_into(conn, &partial)?;
        {
            let snap = Connection::open(&partial).context("opening the snapshot")?;
            set_rollback_journal(&snap)?;
        }
        File::open(&partial)
            .and_then(|f| f.sync_all())
            .context("syncing the snapshot")?;
        fs::rename(&partial, &target).context("renaming the snapshot into place")?;
        sync_dir(&dir)
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&partial);
        return Err(err.context(format!(
            "writing the pre-migration snapshot under {}",
            dir.display()
        )));
    }
    prune_pre_migration(&dir);
    Ok(target)
}

/// Keep the newest [`PRE_MIGRATION_KEEP`] snapshots (names sort
/// chronologically) and drop stray `.partial` files. Best-effort.
fn prune_pre_migration(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut snapshots = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.ends_with(".partial") {
            let _ = fs::remove_file(entry.path());
        } else if Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
        {
            snapshots.push(name);
        }
    }
    snapshots.sort();
    let excess = snapshots.len().saturating_sub(PRE_MIGRATION_KEEP);
    for name in &snapshots[..excess] {
        if let Err(e) = fs::remove_file(dir.join(name)) {
            tracing::warn!(snapshot = %name, error = %e, "failed to prune pre-migration snapshot");
        }
    }
}

// ── SQLite helpers ───────────────────────────────────────────────

/// Open the live database without creating it or running
/// migrations. Read-write flags only so WAL readers can attach to
/// the `-shm` index; nothing is written.
fn open_live_db(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(SOURCE_BUSY_TIMEOUT)
        .context("setting busy_timeout")?;
    Ok(conn)
}

/// `VACUUM INTO` a new file. The target is pre-created empty with
/// mode `0o600` (`SQLite` accepts an empty target) so the snapshot —
/// token hashes, audit rows — is never readable by other users.
fn vacuum_into(conn: &Connection, target: &Path) -> anyhow::Result<()> {
    let target_str = target
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", target.display()))?;
    new_private_file(target).with_context(|| format!("creating {}", target.display()))?;
    conn.execute("VACUUM INTO ?1", [target_str])
        .with_context(|| format!("snapshotting the database into {}", target.display()))?;
    Ok(())
}

fn set_rollback_journal(conn: &Connection) -> anyhow::Result<()> {
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .context("switching the snapshot to a rollback journal")?;
    ensure!(
        mode.eq_ignore_ascii_case("delete"),
        "snapshot journal mode is {mode}, expected delete"
    );
    Ok(())
}

fn user_version(conn: &Connection) -> anyhow::Result<i64> {
    conn.pragma_query_value(None, "user_version", |r| r.get(0))
        .context("reading user_version")
}

fn read_index(conn: &Connection) -> anyhow::Result<SnapshotIndex> {
    let mut stmt = conn
        .prepare("SELECT installation_uuid, instance_id, id, size_bytes FROM blob")
        .context("reading the blob index")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .context("reading the blob index")?;
    let mut blobs = BTreeMap::new();
    for row in rows {
        let (uuid, instance, id, size) = row.context("reading the blob index")?;
        ensure!(
            is_safe_segment(&uuid) && is_safe_segment(&instance) && is_safe_segment(&id),
            "blob row ({uuid:?}, {instance:?}, {id:?}) has an unsafe path segment",
        );
        let size = u64::try_from(size)
            .with_context(|| format!("blob {uuid}/{instance}/{id} has a negative size"))?;
        blobs.insert(format!("{BLOBS_DIR}/{uuid}/{instance}/{id}"), size);
    }
    Ok(SnapshotIndex {
        blobs,
        plugins: read_live_plugins(conn)?,
    })
}

fn read_live_plugins(conn: &Connection) -> anyhow::Result<BTreeSet<LivePlugin>> {
    let mut stmt = conn
        .prepare(
            "SELECT plugin_id, installation_uuid, content_digest FROM plugin_installation \
             WHERE uninstalled_ms IS NULL",
        )
        .context("reading plugin installations")?;
    let rows = stmt
        .query_map([], |r| {
            Ok(LivePlugin {
                plugin_id: r.get(0)?,
                installation_uuid: r.get(1)?,
                content_digest: r.get(2)?,
            })
        })
        .context("reading plugin installations")?;
    let mut out = BTreeSet::new();
    for row in rows {
        let row = row.context("reading plugin installations")?;
        ensure!(
            is_safe_segment(&row.plugin_id),
            "plugin_installation row has an unsafe plugin_id {:?}",
            row.plugin_id,
        );
        out.insert(row);
    }
    Ok(out)
}

// ── filesystem helpers ───────────────────────────────────────────

/// A single path segment that can't escape or alias its parent.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.starts_with('.') && !s.contains(['/', '\\', '\0'])
}

/// Dot-files inside plugin packages (`.gitignore`, …) are archived;
/// `.` / `..` never are.
fn is_dot_file(s: &str) -> bool {
    s.len() > 1
        && s != ".."
        && s.len() <= 255
        && s.starts_with('.')
        && !s.contains(['/', '\\', '\0'])
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn file_entry(rel: &str, path: &Path) -> anyhow::Result<FileEntry> {
    let file = open_no_follow(path).with_context(|| format!("opening {rel}"))?;
    let (size, sha256) = hash_reader(file).with_context(|| format!("hashing {rel}"))?;
    Ok(FileEntry {
        path: rel.into(),
        size,
        sha256,
    })
}

/// Open a regular file without following a symlink at the leaf.
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: opening a FIFO planted in an archive must not
        // hang; the regular-file check below then rejects it.
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn hash_reader(mut reader: impl Read) -> std::io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex(&hasher.finalize())))
}

/// Copy `src` into the new file `dst` (mode `0o600`), fsync it, and
/// return its size and SHA-256.
fn copy_hashed(mut src: File, dst: &Path) -> anyhow::Result<(u64, String)> {
    let mut out = new_private_file(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).context("reading")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .with_context(|| format!("writing {}", dst.display()))?;
        total += n as u64;
    }
    out.sync_all()
        .with_context(|| format!("syncing {}", dst.display()))?;
    Ok((total, hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn new_private_file(path: &Path) -> std::io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = new_private_file(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}

/// Write `path` via a temp sibling + rename, fsyncing the file and
/// its directory.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    remove_file_if_exists(&tmp)?;
    write_new_file(&tmp, bytes)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    match path.parent() {
        Some(dir) => sync_dir(dir),
        None => Ok(()),
    }
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn create_private_dir_all(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn remove_dir_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
    }
}

fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
    }
}

fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|f| f.sync_all())
            .with_context(|| format!("syncing {}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Fsync every directory under (and including) `root`, children
/// first, so every new entry is durable before its parent.
fn sync_tree_dirs(root: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("listing {}", root.display()))? {
        let entry = entry.with_context(|| format!("listing {}", root.display()))?;
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            sync_tree_dirs(&entry.path())?;
        }
    }
    sync_dir(root)
}
