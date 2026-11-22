//! M3 — backup / verify / restore end to end, plus the failure
//! paths that must leave the state dir untouched.

#[path = "support.rs"]
mod support;

use std::path::{Path, PathBuf};

use oxidhome_core::Engine;
use oxidhome_core::backup::{
    self, AUDIT_PATH_RESTORE, BackupManifest, MANIFEST_FILE, RESTORE_JOURNAL_FILE,
    RESTORE_STAGING_DIR,
};
use oxidhome_core::state::{AuditQuery, Db};
use sha2::{Digest, Sha256};

const PLUGIN_ID: &str = "example.backup-fixture";
const INSTANCE: &str = "fixture-1";

/// Install a fixture plugin (install never compiles the wasm, so
/// placeholder bytes are enough) and return its installation uuid.
fn install_fixture(engine: &Engine) -> String {
    let manifest = format!(
        r#"manifest_version = 1

[plugin]
id = "{PLUGIN_ID}"
name = "Backup Fixture"
version = "0.1.0"
authors = ["The OxidHome Contributors"]
description = "M3 test fixture."
license = "MIT OR Apache-2.0"
world = "plugin"
sdk_version = "0.1.0"

[runtime]
wasm = "plugin.wasm"

[capabilities]
blob_quota_mb = 4
"#
    );
    let src = support::tempdir("backup-src");
    std::fs::write(src.path().join("manifest.toml"), manifest).unwrap();
    std::fs::write(src.path().join("plugin.wasm"), b"\0asm\x0d\0\x01\0").unwrap();
    std::fs::create_dir(src.path().join("assets")).unwrap();
    std::fs::write(src.path().join("assets").join(".keep"), b"").unwrap();
    engine
        .installed_plugins()
        .install(src.path())
        .expect("install fixture")
        .installation_uuid
        .to_string()
}

/// A state dir with one installed plugin and two blobs.
struct Fixture {
    state: support::TempDir,
    uuid: String,
}

fn fixture() -> Fixture {
    let state = support::tempdir("backup-state");
    let uuid = {
        let engine = Engine::with_state_dir(state.path()).unwrap();
        let uuid = install_fixture(&engine);
        let blobs = engine.blobs();
        blobs.register_instance(&uuid, INSTANCE, 1 << 20).unwrap();
        blobs
            .write(&uuid, INSTANCE, "keep", b"keep-bytes", Some("text/plain"))
            .unwrap();
        blobs
            .write(&uuid, INSTANCE, "doomed", b"doomed-bytes", None)
            .unwrap();
        uuid
    };
    Fixture { state, uuid }
}

fn out_path(dir: &support::TempDir) -> PathBuf {
    dir.path().join("backup")
}

fn read_manifest(archive: &Path) -> BackupManifest {
    serde_json::from_slice(&std::fs::read(archive.join(MANIFEST_FILE)).unwrap()).unwrap()
}

fn write_manifest(archive: &Path, manifest: &BackupManifest) {
    std::fs::write(
        archive.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Everything restore may touch, so a failed restore can prove it
/// changed nothing.
fn state_fingerprint(state: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if rel == ".oxidhome.lock" || rel == ".oxidhome-backup.lock" {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                out.push((rel, Vec::new()));
                walk(root, &e.path(), out);
            } else {
                out.push((rel, std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(state, state, &mut out);
    out
}

#[test]
fn online_backup_then_restore_round_trips_db_blobs_and_plugins() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);

    // Online: the engine (and its SQLite connection) stays open.
    let engine = Engine::with_state_dir(fx.state.path()).unwrap();
    let report = backup::create_backup(fx.state.path(), &archive).expect("backup");
    assert_eq!(report.blobs, 2);
    assert_eq!(report.plugins, 1);
    assert_eq!(report.attempts, 1);
    assert_eq!(
        report.manifest.schema_version,
        oxidhome_core::state::db::schema_version()
    );
    let verified = backup::verify_backup(&archive).expect("verify");
    assert_eq!(verified.manifest, report.manifest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [archive.clone(), archive.join("oxidhome.db")] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} is mode {mode:o}", path.display());
        }
    }
    // Self-contained: no WAL side files, no plaintext admin token.
    for name in ["oxidhome.db-wal", "oxidhome.db-shm", "admin-token"] {
        assert!(!archive.join(name).exists(), "{name} in archive");
    }
    assert!(
        report
            .manifest
            .files
            .iter()
            .any(|f| f.path == format!("plugins/{PLUGIN_ID}/assets/.keep"))
    );

    // Diverge after the backup: delete one blob, add another,
    // uninstall the plugin.
    let blobs = engine.blobs();
    blobs.delete(&fx.uuid, INSTANCE, "doomed").unwrap();
    blobs
        .write(&fx.uuid, INSTANCE, "late", b"late-bytes", None)
        .unwrap();
    engine.uninstall_plugin(PLUGIN_ID).unwrap();
    drop(blobs);
    drop(engine);

    let restored = backup::restore_offline(fx.state.path(), &archive).expect("restore");
    assert_eq!(restored.archive_created_ms, report.manifest.created_ms);
    assert!(restored.previous.join("oxidhome.db").is_file());
    assert!(!fx.state.path().join(RESTORE_JOURNAL_FILE).exists());
    assert!(!fx.state.path().join(RESTORE_STAGING_DIR).exists());

    let engine = Engine::with_state_dir(fx.state.path()).unwrap();
    let installed = engine
        .installed_plugins()
        .get(PLUGIN_ID)
        .expect("plugin restored");
    assert_eq!(&*installed.installation_uuid, fx.uuid);
    let blobs = engine.blobs();
    assert_eq!(
        blobs.read_by_name(&fx.uuid, INSTANCE, "keep").unwrap(),
        b"keep-bytes"
    );
    assert_eq!(
        blobs.read_by_name(&fx.uuid, INSTANCE, "doomed").unwrap(),
        b"doomed-bytes"
    );
    assert!(blobs.read_by_name(&fx.uuid, INSTANCE, "late").is_err());
    let rows = engine
        .audit_log()
        .query(
            &AuditQuery {
                path: Some(AUDIT_PATH_RESTORE.into()),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_kind, "cli");
    assert_eq!(rows[0].decision, "allow");
    drop(blobs);
    drop(engine);

    // The previous state is intact and openable on its own.
    let prev = Db::open_file(&restored.previous).expect("previous db opens");
    let tombstoned: i64 = prev
        .read(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM plugin_installation WHERE uninstalled_ms IS NOT NULL",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        tombstoned, 1,
        "previous state keeps the post-backup uninstall"
    );
}

/// Disaster recovery: restore onto a machine with no state yet.
#[test]
fn restore_into_an_empty_state_dir() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    backup::create_backup(fx.state.path(), &archive).unwrap();

    let fresh = support::tempdir("backup-fresh");
    let state = fresh.path().join("state");
    backup::restore_offline(&state, &archive).expect("restore into empty dir");
    let engine = Engine::with_state_dir(&state).unwrap();
    assert!(engine.installed_plugins().get(PLUGIN_ID).is_some());
    assert_eq!(
        engine
            .blobs()
            .read_by_name(&fx.uuid, INSTANCE, "keep")
            .unwrap(),
        b"keep-bytes"
    );
}

#[test]
fn backup_refuses_existing_target_and_missing_database() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let err = backup::create_backup(fx.state.path(), out_dir.path()).unwrap_err();
    assert!(format!("{err:#}").contains("already exists"), "{err:#}");

    let empty = support::tempdir("backup-empty");
    let err = backup::create_backup(empty.path(), &out_path(&out_dir)).unwrap_err();
    assert!(format!("{err:#}").contains("nothing to back up"), "{err:#}");
    assert!(!out_path(&out_dir).exists());
}

/// A blob row whose file is gone looks like a delete racing the
/// backup; after the retries the backup fails and leaves nothing.
#[test]
fn backup_gives_up_when_an_indexed_blob_file_is_missing() {
    let fx = fixture();
    let blob_dir = fx.state.path().join("blobs").join(&fx.uuid).join(INSTANCE);
    for entry in std::fs::read_dir(&blob_dir).unwrap().flatten() {
        if entry.file_type().unwrap().is_file() {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    let out_dir = support::tempdir("backup-out");
    let err = backup::create_backup(fx.state.path(), &out_path(&out_dir)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("disappeared") && msg.contains("stop the daemon"),
        "{msg}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(out_dir.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// A live installation whose package directory is missing looks
/// like an install / uninstall in flight; when it persists the
/// backup fails with an error naming the expected location.
#[test]
fn backup_fails_when_a_live_plugin_has_no_package_dir() {
    let fx = fixture();
    std::fs::rename(
        fx.state.path().join("plugins").join(PLUGIN_ID),
        fx.state.path().join("plugins").join("renamed"),
    )
    .unwrap();
    let out_dir = support::tempdir("backup-out");
    let err = backup::create_backup(fx.state.path(), &out_path(&out_dir)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("not at plugins/<plugin_id>"), "{msg}");
    assert!(std::fs::read_dir(out_dir.path()).unwrap().next().is_none());
}

/// Orphan blob files (crash leftovers no row references) are not
/// archived.
#[test]
fn backup_skips_orphan_blob_files() {
    let fx = fixture();
    let blob_dir = fx.state.path().join("blobs").join(&fx.uuid).join(INSTANCE);
    std::fs::write(blob_dir.join("orphan"), b"orphan").unwrap();
    let out_dir = support::tempdir("backup-out");
    let report = backup::create_backup(fx.state.path(), &out_path(&out_dir)).unwrap();
    assert!(
        !report
            .manifest
            .files
            .iter()
            .any(|f| f.path.ends_with("/orphan"))
    );
}

/// Build a valid archive, apply `tamper`, and assert that both
/// verify and restore refuse it with `needle` while the state dir
/// stays byte-for-byte unchanged.
fn assert_restore_refuses(tamper: impl FnOnce(&Path), needle: &str) {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    backup::create_backup(fx.state.path(), &archive).unwrap();
    tamper(&archive);
    let err = backup::verify_backup(&archive).unwrap_err();
    assert!(format!("{err:#}").contains(needle), "{err:#}");

    let before = state_fingerprint(fx.state.path());
    let err = backup::restore_offline(fx.state.path(), &archive).unwrap_err();
    assert!(format!("{err:#}").contains(needle), "{err:#}");
    assert_eq!(state_fingerprint(fx.state.path()), before);
}

fn first_blob(archive: &Path) -> PathBuf {
    let manifest = read_manifest(archive);
    let entry = manifest
        .files
        .iter()
        .find(|f| f.path.starts_with("blobs/"))
        .unwrap();
    archive.join(&entry.path)
}

#[test]
fn restore_refuses_a_modified_blob() {
    assert_restore_refuses(
        |archive| std::fs::write(first_blob(archive), b"tampered!!").unwrap(),
        "checksum mismatch",
    );
}

#[test]
fn restore_refuses_a_missing_file() {
    assert_restore_refuses(
        |archive| std::fs::remove_file(first_blob(archive)).unwrap(),
        "archive is missing",
    );
}

#[test]
fn restore_refuses_an_unlisted_file() {
    assert_restore_refuses(
        |archive| std::fs::write(archive.join("stray"), b"x").unwrap(),
        "does not list",
    );
}

#[test]
fn restore_refuses_a_missing_manifest() {
    assert_restore_refuses(
        |archive| std::fs::remove_file(archive.join(MANIFEST_FILE)).unwrap(),
        "manifest.json",
    );
}

/// A blob file the manifest vouches for but no row references —
/// the index/file mismatch M3 is about.
#[test]
fn restore_refuses_an_unreferenced_blob() {
    assert_restore_refuses(
        |archive| {
            let blob = first_blob(archive);
            let extra = blob.with_file_name("extra-blob");
            std::fs::write(&extra, b"extra").unwrap();
            let mut manifest = read_manifest(archive);
            manifest.files.push(backup::FileEntry {
                path: extra
                    .strip_prefix(archive)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                size: 5,
                sha256: sha256_hex(b"extra"),
            });
            write_manifest(archive, &manifest);
        },
        "no database row references",
    );
}

#[test]
fn restore_refuses_a_path_traversal_entry() {
    assert_restore_refuses(
        |archive| {
            let mut manifest = read_manifest(archive);
            manifest.files.push(backup::FileEntry {
                path: "blobs/../../escape".into(),
                size: 0,
                sha256: sha256_hex(b""),
            });
            write_manifest(archive, &manifest);
        },
        "invalid path",
    );
}

#[test]
fn restore_refuses_a_newer_schema() {
    assert_restore_refuses(
        |archive| {
            let db = archive.join("oxidhome.db");
            {
                let conn = rusqlite::Connection::open(&db).unwrap();
                let next = oxidhome_core::state::db::schema_version() + 1;
                conn.execute_batch(&format!("PRAGMA user_version = {next}"))
                    .unwrap();
            }
            let bytes = std::fs::read(&db).unwrap();
            let mut manifest = read_manifest(archive);
            manifest.schema_version += 1;
            let entry = manifest
                .files
                .iter_mut()
                .find(|f| f.path == "oxidhome.db")
                .unwrap();
            entry.size = bytes.len() as u64;
            entry.sha256 = sha256_hex(&bytes);
            write_manifest(archive, &manifest);
        },
        "newer than this binary",
    );
}

/// A package whose bytes no longer match its installation row's
/// content digest (even with a consistent manifest) is refused.
#[test]
fn restore_refuses_a_package_that_does_not_match_its_digest() {
    assert_restore_refuses(
        |archive| {
            let rel = format!("plugins/{PLUGIN_ID}/plugin.wasm");
            let bytes = b"\0asm\x0d\0\x01\0swapped";
            std::fs::write(archive.join(&rel), bytes).unwrap();
            let mut manifest = read_manifest(archive);
            let entry = manifest.files.iter_mut().find(|f| f.path == rel).unwrap();
            entry.size = bytes.len() as u64;
            entry.sha256 = sha256_hex(bytes);
            write_manifest(archive, &manifest);
        },
        "content digest",
    );
}

/// Backups (shared) and restores (exclusive) exclude each other
/// even with the daemon stopped.
#[cfg(unix)]
#[test]
fn backup_and_restore_exclude_each_other() {
    use oxidhome_core::exclusive_lock::acquire_backup_lock;
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    backup::create_backup(fx.state.path(), &archive).unwrap();

    let shared = acquire_backup_lock(fx.state.path(), false).unwrap();
    let before = state_fingerprint(fx.state.path());
    let err = backup::restore_offline(fx.state.path(), &archive).unwrap_err();
    assert!(
        format!("{err:#}").contains("backup or restore is running"),
        "{err:#}"
    );
    assert_eq!(state_fingerprint(fx.state.path()), before);
    drop(shared);

    let _exclusive = acquire_backup_lock(fx.state.path(), true).unwrap();
    let err = backup::create_backup(fx.state.path(), &out_dir.path().join("second")).unwrap_err();
    assert!(
        format!("{err:#}").contains("a restore is running"),
        "{err:#}"
    );
    assert!(!out_dir.path().join("second").exists());
}

#[cfg(unix)]
#[test]
fn restore_refuses_a_symlink_in_the_archive() {
    assert_restore_refuses(
        |archive| {
            std::os::unix::fs::symlink("/etc/passwd", archive.join("blobs").join("link")).unwrap();
        },
        "symlink",
    );
}

#[cfg(unix)]
#[test]
fn restore_refuses_while_the_state_dir_is_locked() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    backup::create_backup(fx.state.path(), &archive).unwrap();
    let _held = oxidhome_core::exclusive_lock::acquire_state_dir_lock(fx.state.path()).unwrap();
    let before = state_fingerprint(fx.state.path());
    let err = backup::restore_offline(fx.state.path(), &archive).unwrap_err();
    assert!(format!("{err:#}").contains("stop the daemon"), "{err:#}");
    assert_eq!(state_fingerprint(fx.state.path()), before);
}

/// A crash mid-swap leaves the journal: the database refuses to
/// open, backup refuses, and `--resume` rolls the swap forward.
#[test]
fn interrupted_restore_blocks_startup_until_resumed() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    let report = backup::create_backup(fx.state.path(), &archive).unwrap();
    {
        let engine = Engine::with_state_dir(fx.state.path()).unwrap();
        engine
            .blobs()
            .write(&fx.uuid, INSTANCE, "late", b"late-bytes", None)
            .unwrap();
    }

    // Reproduce the on-disk state of a crash right after the old
    // database moved aside: staging populated, journal written,
    // live `oxidhome.db` gone, blobs/plugins not yet swapped.
    let state = fx.state.path();
    let staging = state.join(RESTORE_STAGING_DIR);
    copy_tree(&archive, &staging);
    std::fs::remove_file(staging.join(MANIFEST_FILE)).unwrap();
    let previous = state.join("pre-restore-1");
    std::fs::create_dir(&previous).unwrap();
    std::fs::write(
        state.join(RESTORE_JOURNAL_FILE),
        format!(
            r#"{{"previous":"pre-restore-1","archive_created_ms":{}}}"#,
            report.manifest.created_ms
        ),
    )
    .unwrap();
    for name in ["oxidhome.db", "oxidhome.db-wal", "oxidhome.db-shm"] {
        if state.join(name).exists() {
            std::fs::rename(state.join(name), previous.join(name)).unwrap();
        }
    }

    let err = Db::open_file(state).unwrap_err();
    assert!(format!("{err:#}").contains("restore --resume"), "{err:#}");
    let err = backup::create_backup(state, &out_dir.path().join("second")).unwrap_err();
    assert!(
        format!("{err:#}").contains("interrupted restore"),
        "{err:#}"
    );
    let err = backup::restore_offline(state, &archive).unwrap_err();
    assert!(
        format!("{err:#}").contains("interrupted restore"),
        "{err:#}"
    );

    let resumed = backup::resume_restore_offline(state)
        .unwrap()
        .expect("something to resume");
    assert_eq!(resumed.previous, previous);
    assert!(previous.join("blobs").is_dir());
    assert!(previous.join("plugins").is_dir());
    assert!(backup::resume_restore_offline(state).unwrap().is_none());

    let engine = Engine::with_state_dir(state).unwrap();
    assert!(
        engine
            .blobs()
            .read_by_name(&fx.uuid, INSTANCE, "late")
            .is_err()
    );
    assert_eq!(
        engine
            .blobs()
            .read_by_name(&fx.uuid, INSTANCE, "keep")
            .unwrap(),
        b"keep-bytes"
    );
}

/// A crash between the swap and the audit row leaves
/// `.restore-audit-pending`; the daemon can start, and `--resume`
/// records the missing row.
#[test]
fn resume_records_a_missing_restore_audit_row() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    let report = backup::create_backup(fx.state.path(), &archive).unwrap();
    let restored = backup::restore_offline(fx.state.path(), &archive).unwrap();
    let previous = restored
        .previous
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    std::fs::write(
        fx.state.path().join(backup::RESTORE_AUDIT_PENDING_FILE),
        format!(
            r#"{{"previous":"{previous}","archive_created_ms":{}}}"#,
            report.manifest.created_ms
        ),
    )
    .unwrap();
    drop(Db::open_file(fx.state.path()).expect("audit-pending does not block startup"));

    let resumed = backup::resume_restore_offline(fx.state.path()).unwrap();
    assert_eq!(resumed.unwrap().previous, restored.previous);
    assert!(
        !fx.state
            .path()
            .join(backup::RESTORE_AUDIT_PENDING_FILE)
            .exists()
    );
    let engine = Engine::with_state_dir(fx.state.path()).unwrap();
    let rows = engine
        .audit_log()
        .query(
            &AuditQuery {
                path: Some(AUDIT_PATH_RESTORE.into()),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert_eq!(rows.len(), 2);
}

/// A FIFO planted as the manifest is rejected, not waited on.
#[cfg(unix)]
#[test]
fn verify_rejects_a_fifo_manifest_without_hanging() {
    let fx = fixture();
    let out_dir = support::tempdir("backup-out");
    let archive = out_path(&out_dir);
    backup::create_backup(fx.state.path(), &archive).unwrap();
    std::fs::remove_file(archive.join(MANIFEST_FILE)).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(archive.join(MANIFEST_FILE))
        .status()
        .unwrap();
    assert!(status.success());
    let err = backup::verify_backup(&archive).unwrap_err();
    assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), dst).unwrap();
        }
    }
}
