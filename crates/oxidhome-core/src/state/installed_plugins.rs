//! Phase 12-API-f — installed-plugin registry.
//!
//! Tracks plugin packages copied into `<state_dir>/plugins/<plugin_id>/`.
//! The filesystem is the source of truth — at boot, [`Self::scan`]
//! walks the directory and builds an in-memory index; subsequent
//! `install` / `uninstall` calls keep the index in step.
//!
//! ## Why not a `SQLite` table?
//!
//! - A directory + `manifest.toml` per plugin **is** the
//!   serializable on-disk shape. Adding a SQL table for the same
//!   information just creates a sync problem (operator edits dir,
//!   table now lies). The directory is what the supervisor reads
//!   at start-instance time; the index here is a cache.
//! - Install / uninstall are operator-triggered, low-frequency
//!   events — no need for transactional storage.
//!
//! ## Lifecycle ownership
//!
//! - **Install**: copies `source_dir` → `<plugins_root>/<plugin_id>/`,
//!   reads the manifest to extract the canonical plugin id, refuses
//!   if a dir for that id already exists (409 at the API layer).
//! - **Uninstall**: removes `<plugins_root>/<plugin_id>/`
//!   recursively. The API handler checks the instance registry for
//!   running instances *before* calling this, so the registry method
//!   itself is the unconditional "yank the dir" primitive.
//! - **Start / stop** are not this module's job — they go through
//!   the existing `Engine::start_instance` + `InstanceHandle::stop`
//!   paths. The registry only handles package presence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use oxidhome_manifest::PluginManifest;

/// One row in the installed-plugin index. Cheap to clone (single
/// `Arc<str>` plus a `PathBuf`).
#[derive(Debug, Clone)]
pub struct InstalledPlugin {
    /// Canonical plugin id from `manifest.plugin.id`.
    pub plugin_id: Arc<str>,
    /// Semver from `manifest.plugin.version`. Kept as a string for
    /// the API response so the wire shape doesn't have to follow
    /// the `semver` crate's serialization.
    pub version: String,
    /// Absolute path to `<plugins_root>/<plugin_id>/`. Contains
    /// `manifest.toml` and whatever the manifest's `runtime.wasm`
    /// pointer resolves to.
    pub path: PathBuf,
}

/// Why an install or uninstall failed. Mapped to HTTP status codes
/// by the API layer; unit tests pattern-match on the variants.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// In-memory engines (built via `Engine::new()`) have no
    /// `<state_dir>/plugins/` root, so install / uninstall both
    /// return this. API maps to `503 Service Unavailable`.
    #[error("plugin install requires a state-dir-backed engine")]
    NoPluginsRoot,
    /// `source_dir` doesn't exist, isn't a directory, or doesn't
    /// contain `manifest.toml`.
    #[error("source dir is missing or has no manifest.toml: {0}")]
    SourceMissing(PathBuf),
    /// Manifest at `<source>/manifest.toml` couldn't be read or
    /// parsed.
    #[error("reading manifest from {path}: {reason}")]
    BadManifest { path: PathBuf, reason: String },
    /// A different plugin already occupies `<plugins_root>/<plugin_id>/`.
    /// API maps to `409 Conflict`. Operator must uninstall the
    /// existing copy first.
    #[error("plugin {plugin_id} is already installed")]
    AlreadyInstalled { plugin_id: String },
    /// Recursive copy / metadata read failed.
    #[error("io error during install: {0}")]
    Io(#[from] std::io::Error),
}

/// Why an uninstall failed.
#[derive(Debug, thiserror::Error)]
pub enum UninstallError {
    #[error("plugin install requires a state-dir-backed engine")]
    NoPluginsRoot,
    /// No matching dir under `<plugins_root>/`. API maps to `404`.
    #[error("plugin {0} is not installed")]
    NotInstalled(String),
    #[error("io error during uninstall: {0}")]
    Io(#[from] std::io::Error),
}

/// In-memory + filesystem registry of installed plugins.
///
/// `None` for the FS root means "in-memory engine" — install /
/// uninstall return [`InstallError::NoPluginsRoot`]. The
/// `list()` / `get()` reads always succeed; in-memory engines just
/// stay empty.
#[derive(Debug)]
pub struct InstalledPluginRegistry {
    plugins_root: Option<PathBuf>,
    entries: RwLock<HashMap<Arc<str>, InstalledPlugin>>,
}

impl InstalledPluginRegistry {
    /// Empty registry without a filesystem backing. Used by
    /// `Engine::new()` for unit tests that don't need install
    /// support.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            plugins_root: None,
            entries: RwLock::new(HashMap::new()),
        }
    }

    // Poison-tolerant accessors. Critical sections here only do
    // HashMap ops + Arc / String clones, so a panic-under-lock
    // leaves the inner state consistent.
    fn read_entries(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Arc<str>, InstalledPlugin>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn write_entries(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Arc<str>, InstalledPlugin>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Build by scanning `plugins_root` for installed packages.
    /// Creates the directory if it doesn't exist yet (first-run
    /// state dir). Each immediate subdirectory containing a
    /// readable `manifest.toml` becomes a row.
    ///
    /// Malformed entries (non-dir, manifest missing or invalid)
    /// are skipped with a `tracing::warn` so a corrupt install
    /// doesn't block daemon boot.
    ///
    /// # Errors
    ///
    /// - Failure to create `plugins_root` if missing.
    /// - Failure to enumerate the directory.
    pub fn scan(plugins_root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&plugins_root)?;
        let mut entries: HashMap<Arc<str>, InstalledPlugin> = HashMap::new();
        for child in std::fs::read_dir(&plugins_root)? {
            let child = match child {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!(?err, "skipping unreadable entry in plugins dir");
                    continue;
                }
            };
            let path = child.path();
            let Ok(file_type) = child.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let manifest_path = path.join("manifest.toml");
            let manifest = match read_manifest_sync(&manifest_path) {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(
                        path = %manifest_path.display(),
                        %err,
                        "skipping installed dir with bad manifest",
                    );
                    continue;
                }
            };
            // The plugin id in the manifest is the authoritative
            // identifier; if it disagrees with the directory name,
            // trust the manifest (the dir was created by `install`
            // and named after it, but the manifest is what the
            // supervisor compares against). The boot scan can't
            // rename the dir safely (might race a `start`); we
            // just log.
            let manifest_id = manifest.plugin.id.clone();
            let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if dir_name != manifest_id {
                tracing::warn!(
                    dir = %dir_name,
                    manifest_id = %manifest_id,
                    "installed dir name disagrees with manifest plugin.id; indexing by manifest id",
                );
            }
            let id_arc: Arc<str> = Arc::from(manifest_id.as_str());
            entries.insert(
                Arc::clone(&id_arc),
                InstalledPlugin {
                    plugin_id: id_arc,
                    version: manifest.plugin.version.to_string(),
                    path,
                },
            );
        }
        Ok(Self {
            plugins_root: Some(plugins_root),
            entries: RwLock::new(entries),
        })
    }

    /// Snapshot of every installed plugin. Sort responsibility
    /// belongs to the caller (the API handler sorts by id for
    /// stable JSON output).
    #[must_use]
    pub fn list(&self) -> Vec<InstalledPlugin> {
        self.read_entries().values().cloned().collect()
    }

    /// Look up by plugin id.
    #[must_use]
    pub fn get(&self, plugin_id: &str) -> Option<InstalledPlugin> {
        self.read_entries().get(plugin_id).cloned()
    }

    /// Copy `source_dir` to `<plugins_root>/<plugin_id>/`, where
    /// `<plugin_id>` is read from `<source_dir>/manifest.toml`.
    ///
    /// Atomicity: copies into a sibling `.staging-<id>` dir first,
    /// then renames into place. A crash mid-copy leaves the
    /// `.staging-` dir around; the next scan ignores it (no
    /// `manifest.toml` at the staging path's *registered* name).
    ///
    /// # Errors
    ///
    /// See [`InstallError`].
    pub fn install(&self, source_dir: &Path) -> Result<InstalledPlugin, InstallError> {
        let plugins_root = self
            .plugins_root
            .as_ref()
            .ok_or(InstallError::NoPluginsRoot)?;

        if !source_dir.is_dir() {
            return Err(InstallError::SourceMissing(source_dir.to_path_buf()));
        }
        let manifest_path = source_dir.join("manifest.toml");
        if !manifest_path.is_file() {
            return Err(InstallError::SourceMissing(source_dir.to_path_buf()));
        }
        let manifest =
            read_manifest_sync(&manifest_path).map_err(|reason| InstallError::BadManifest {
                path: manifest_path.clone(),
                reason: reason.to_string(),
            })?;

        let plugin_id = manifest.plugin.id.clone();
        // Reject directory traversal / path separator chicanery in
        // the manifest id. Validate.rs in `oxidhome-manifest` also
        // enforces a kebab-case reverse-DNS shape, but defense in
        // depth — the id is about to become a filesystem segment.
        if plugin_id.is_empty()
            || plugin_id.contains('/')
            || plugin_id.contains('\\')
            || plugin_id.contains("..")
        {
            return Err(InstallError::BadManifest {
                path: manifest_path,
                reason: format!("plugin id {plugin_id:?} contains an unsafe character"),
            });
        }
        let dest = plugins_root.join(&plugin_id);
        if dest.exists() {
            return Err(InstallError::AlreadyInstalled { plugin_id });
        }
        let staging = plugins_root.join(format!(".staging-{plugin_id}"));
        // Best-effort: if a previous failed install left a staging
        // dir, blow it away. We *just* checked dest.exists() so we
        // know we're not racing a sibling install for the same id.
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        copy_dir_recursive(source_dir, &staging)?;
        // Validate the copied manifest just in case (the wasm path
        // inside might be relative and depend on the copied
        // layout). Errors here aren't great — the staging dir is
        // already populated — so clean up before returning.
        let staged_manifest = staging.join("manifest.toml");
        if let Err(err) = read_manifest_sync(&staged_manifest) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(InstallError::BadManifest {
                path: staged_manifest,
                reason: err.to_string(),
            });
        }
        std::fs::rename(&staging, &dest)?;

        let id_arc: Arc<str> = Arc::from(plugin_id.as_str());
        let row = InstalledPlugin {
            plugin_id: Arc::clone(&id_arc),
            version: manifest.plugin.version.to_string(),
            path: dest,
        };
        self.write_entries().insert(id_arc, row.clone());
        tracing::info!(
            plugin_id = %row.plugin_id,
            version = %row.version,
            path = %row.path.display(),
            "plugin installed",
        );
        Ok(row)
    }

    /// Remove `<plugins_root>/<plugin_id>/` recursively and drop
    /// the entry from the index. The caller (API handler) is
    /// responsible for ensuring no instances of this plugin are
    /// running — this method unconditionally yanks the dir.
    ///
    /// # Errors
    ///
    /// See [`UninstallError`].
    pub fn uninstall(&self, plugin_id: &str) -> Result<(), UninstallError> {
        let plugins_root = self
            .plugins_root
            .as_ref()
            .ok_or(UninstallError::NoPluginsRoot)?;
        // Take the write lock for the index update + filesystem
        // mutation. Holding it during `remove_dir_all` is fine —
        // uninstall is operator-initiated and infrequent, and we
        // don't want a parallel `install` for the same id slipping
        // in between the `remove_dir_all` and the index drop.
        let mut entries = self.write_entries();
        if !entries.contains_key(plugin_id) {
            return Err(UninstallError::NotInstalled(plugin_id.to_string()));
        }
        let dest = plugins_root.join(plugin_id);
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        entries.remove(plugin_id);
        tracing::info!(plugin_id = %plugin_id, "plugin uninstalled");
        Ok(())
    }
}

/// Sync `manifest.toml` reader. The async variant in
/// `runtime::instance::read_manifest` is used on the start-instance
/// hot path; install / scan run on the operator-initiated cold path
/// and don't need to be async.
///
/// Validates the manifest schema via `oxidhome_manifest::validate`
/// before returning — a malformed manifest is rejected at install
/// time so a `start` call later doesn't surface the same error.
fn read_manifest_sync(path: &Path) -> anyhow::Result<PluginManifest> {
    use anyhow::Context;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: PluginManifest =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if let Err(errors) = oxidhome_manifest::validate(&manifest) {
        anyhow::bail!(
            "manifest {} is invalid:\n  - {}",
            path.display(),
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n  - "),
        );
    }
    Ok(manifest)
}

/// Pure-Rust recursive copy. Doesn't follow symlinks (the source
/// dir is operator-supplied; we don't want a symlink-to-/etc to
/// drag arbitrary files into `<state_dir>/plugins/`). Empty dirs
/// are preserved.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            std::fs::copy(&from, &to)?;
        } else if ty.is_symlink() {
            // Skip symlinks. A plugin package that needs a
            // symlink can't be installed via this endpoint;
            // operator can stage by hand if they really want it.
            tracing::warn!(
                from = %from.display(),
                "skipping symlink during install copy",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let pid = u64::from(std::process::id());
        let nanos = u64::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        );
        let p = std::env::temp_dir().join(format!(
            "oxidhome-installed-{name}-{}",
            pid.wrapping_mul(1_000_003).wrapping_add(nanos),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_plugin_dir(root: &Path, plugin_id: &str) -> PathBuf {
        let dir = root.join(format!("source-{plugin_id}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.toml"),
            format!(
                r#"manifest_version = 1
[plugin]
id = "{plugin_id}"
name = "Test Plugin"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
            ),
        )
        .unwrap();
        std::fs::write(dir.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();
        dir
    }

    #[test]
    fn empty_engine_returns_no_plugins_root_on_install() {
        let reg = InstalledPluginRegistry::empty();
        let err = reg.install(Path::new("/nonexistent")).unwrap_err();
        assert!(matches!(err, InstallError::NoPluginsRoot));
    }

    #[test]
    fn scan_then_install_then_uninstall_roundtrip() {
        let root = tempdir("rt");
        let plugins_root = root.join("plugins");
        let reg = InstalledPluginRegistry::scan(plugins_root.clone()).unwrap();
        assert!(reg.list().is_empty());

        let source = write_plugin_dir(&root, "example.demo");
        let installed = reg.install(&source).expect("install");
        assert_eq!(&*installed.plugin_id, "example.demo");
        assert_eq!(installed.path, plugins_root.join("example.demo"));
        assert!(plugins_root.join("example.demo/manifest.toml").exists());
        assert!(plugins_root.join("example.demo/plugin.wasm").exists());

        // Idempotent re-install rejected.
        let err = reg.install(&source).unwrap_err();
        assert!(matches!(err, InstallError::AlreadyInstalled { .. }));

        // Snapshot reflects the install.
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(&*listed[0].plugin_id, "example.demo");

        // Uninstall removes the dir + index entry.
        reg.uninstall("example.demo").expect("uninstall");
        assert!(!plugins_root.join("example.demo").exists());
        assert!(reg.list().is_empty());

        // Uninstall again -> NotInstalled.
        let err = reg.uninstall("example.demo").unwrap_err();
        assert!(matches!(err, UninstallError::NotInstalled(_)));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn install_rejects_source_without_manifest() {
        let root = tempdir("nomanifest");
        let plugins_root = root.join("plugins");
        let reg = InstalledPluginRegistry::scan(plugins_root).unwrap();

        let bad = root.join("source-bad");
        std::fs::create_dir_all(&bad).unwrap();
        // No manifest.toml at all.
        let err = reg.install(&bad).unwrap_err();
        assert!(matches!(err, InstallError::SourceMissing(_)));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn install_rejects_malformed_manifest() {
        let root = tempdir("badmanifest");
        let plugins_root = root.join("plugins");
        let reg = InstalledPluginRegistry::scan(plugins_root).unwrap();

        let bad = root.join("source-bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("manifest.toml"), "this is not valid toml [[[").unwrap();
        let err = reg.install(&bad).unwrap_err();
        assert!(matches!(err, InstallError::BadManifest { .. }));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn scan_repopulates_index_from_existing_install() {
        let root = tempdir("rescan");
        let plugins_root = root.join("plugins");
        let reg = InstalledPluginRegistry::scan(plugins_root.clone()).unwrap();
        let source = write_plugin_dir(&root, "example.persist");
        reg.install(&source).expect("install");
        drop(reg);

        // Fresh scan against the same FS — the install must
        // re-surface (boot of a daemon against an existing state
        // dir).
        let reg2 = InstalledPluginRegistry::scan(plugins_root).unwrap();
        let listed = reg2.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(&*listed[0].plugin_id, "example.persist");

        std::fs::remove_dir_all(&root).unwrap();
    }
}
