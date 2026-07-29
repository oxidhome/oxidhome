//! Phase 12-API-f — installed-plugin registry.
//!
//! Tracks plugin packages copied into `<state_dir>/plugins/<plugin_id>/`.
//! The filesystem is the source of truth for package *contents* —
//! at boot, [`Self::scan`] walks the directory and builds an
//! in-memory index; subsequent `install` / `uninstall` calls keep
//! the index in step.
//!
//! ## Persistent installation identity (C1b)
//!
//! Architecture-review C1b: every install mints a
//! **`installation_uuid`** that is persisted to the `SQLite`
//! `plugin_installation` table (migration 11). This UUID feeds
//! [`crate::state::stable_device_id`] so that uninstalling a plugin
//! and installing a fresh copy with the same `plugin_id` mints
//! different device ids — the new install can't inherit the old
//! install's audit / API surface.
//!
//! Uninstall **tombstones** the row (sets `uninstalled_ms`) rather
//! than deleting it: historical audit rows referencing the retired
//! UUID stay traceable to "that particular install," and a
//! subsequent `install` of the same `plugin_id` inserts a fresh
//! row with a distinct UUID. A partial unique index constrains
//! *live* rows to one-per-`plugin_id`.
//!
//! ## Filesystem vs. SQL — who owns what
//!
//! - Package **contents** (`manifest.toml`, `<runtime.wasm>`, static
//!   assets) live on disk; the daemon copies them into
//!   `<plugins_root>/<plugin_id>/` at install time and reads them
//!   from there at start-instance time.
//! - Package **identity** (the `installation_uuid`) lives in SQL.
//!   Without SQL access (in-memory engines via `Engine::new()`) the
//!   registry is a plain in-memory cache; install / uninstall
//!   return [`InstallError::NoPluginsRoot`].
//! - `scan` reconciles the two on boot: any FS entry without a live
//!   SQL row gets a fresh UUID backfilled (pre-C1b installs; a hand
//!   -placed dir; a crash between the FS copy and the SQL insert).
//!
//! ## Lifecycle ownership
//!
//! - **Install**: mints a `installation_uuid`, INSERTs the SQL row,
//!   copies `source_dir` → `<plugins_root>/<plugin_id>/`. If the FS
//!   copy fails the SQL row is rolled back so a retry doesn't fail
//!   the `plugin_installation_live` unique index. Refuses if a live
//!   row for `plugin_id` already exists (409 at the API layer).
//! - **Uninstall**: tombstones the SQL row, then removes
//!   `<plugins_root>/<plugin_id>/` recursively. The API handler
//!   checks the instance registry for running instances *before*
//!   calling this, so the registry method itself is the
//!   unconditional "yank the dir + tombstone" primitive.
//! - **Start / stop** are not this module's job — they go through
//!   the existing `Engine::start_instance` + `InstanceHandle::stop`
//!   paths. The registry only handles package presence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use oxidhome_manifest::PluginManifest;
use rand::TryRng;
use rusqlite::OptionalExtension;

use crate::state::Db;

/// One row in the installed-plugin index. Cheap to clone (two
/// `Arc<str>`s plus a `PathBuf`).
#[derive(Debug, Clone)]
pub struct InstalledPlugin {
    /// Canonical plugin id from `manifest.plugin.id`. A reusable
    /// name — safe to expose to plugin authors and API callers, but
    /// **not** stable identity: uninstall + reinstall reuses it. Use
    /// [`Self::installation_uuid`] for stable identity.
    pub plugin_id: Arc<str>,
    /// C1b: host-minted per-install UUID (`inst-<32 hex>`).
    /// Persisted in the `plugin_installation` SQL table; feeds
    /// [`crate::state::stable_device_id`] so that reinstalling the
    /// same `plugin_id` produces different device ids. For
    /// in-memory registries (`Engine::new()` / dev loads without
    /// install) the fallback is the `plugin_id` itself — see
    /// [`InstalledPluginRegistry::empty`].
    pub installation_uuid: Arc<str>,
    /// Semver from `manifest.plugin.version`. Kept as a string for
    /// the API response so the wire shape doesn't have to follow
    /// the `semver` crate's serialization.
    pub version: String,
    /// Absolute path to `<plugins_root>/<plugin_id>/`. Contains
    /// `manifest.toml` and whatever the manifest's `runtime.wasm`
    /// pointer resolves to.
    pub path: PathBuf,
}

/// Mint a fresh installation UUID. Format: `inst-<32 lowercase hex>`
/// — 16 random bytes = 128 bits of entropy, matching a `UUIDv4`'s
/// shape without pulling in the `uuid` crate. The `inst-` prefix
/// is a readability cue in audit logs / API responses.
fn mint_installation_uuid() -> Arc<str> {
    let mut bytes = [0u8; 16];
    // Match the pattern already used by `auth_token::random_token`
    // for consistency: `SysRng::try_fill_bytes` returns a
    // `Result<(), _>` whose `Err` variant is `Infallible` on this
    // platform. `.expect` documents the operational contract.
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG must be available");
    let mut hex = String::with_capacity(5 + 32);
    hex.push_str("inst-");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Arc::from(hex.as_str())
}

/// Host wall-clock in milliseconds since the Unix epoch. Used for
/// `plugin_installation.installed_ms` / `uninstalled_ms`. Nanos
/// aren't needed — install / uninstall are operator-triggered, ms
/// resolution is plenty and matches the `audit_event` shape.
fn now_ms() -> i64 {
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        // `as i64` truncates from `u128`, but a `u128` millisecond
        // count doesn't overflow `i64` until year ~292M — an
        // absurd horizon for `installed_ms`.
        Ok(d) => d.as_millis() as i64,
        // Clock before the epoch (pathological, e.g. wildly wrong
        // BIOS clock). Fall back to 0 so a row still lands; audit
        // shows it as "impossibly early" but doesn't crash the install.
        Err(_) => 0,
    }
}

/// Validates a `plugin_id` for use as a filesystem segment.
/// Shared between [`InstalledPluginRegistry::install`] (which
/// rejects on entry to the registry) and
/// [`InstalledPluginRegistry::scan`] (which skips with a warn so
/// a corrupt hand-placed manifest doesn't poison the index).
///
/// 12-API-f review surfaced this as defense-in-depth — the
/// destructive `uninstall` path relies on "all registry ids are
/// FS-safe," and without a check in both insertion sites that
/// invariant rests on an undocumented assumption. Now enforced.
fn is_safe_plugin_id(plugin_id: &str) -> bool {
    !plugin_id.is_empty()
        && !plugin_id.contains('/')
        && !plugin_id.contains('\\')
        && !plugin_id.contains("..")
        && !plugin_id.starts_with('.')
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
    /// C1b: `plugin_installation` INSERT or backfill failed.
    /// Distinct from `Io` so the API can classify it as a host
    /// internal error rather than an operator-fixable I/O issue.
    #[error("persisting installation identity: {0}")]
    Persistence(#[from] rusqlite::Error),
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
    /// C1b: `plugin_installation` tombstone UPDATE failed.
    #[error("persisting uninstall tombstone: {0}")]
    Persistence(#[from] rusqlite::Error),
}

/// In-memory + filesystem + SQL registry of installed plugins.
///
/// - `plugins_root: None` → "in-memory engine": install / uninstall
///   return [`InstallError::NoPluginsRoot`]. The `list()` / `get()`
///   reads always succeed; in-memory engines just stay empty.
/// - `db: None` → no persistent installation UUIDs. The `plugin_id`
///   is used as the synthetic UUID (see [`Self::empty`]); reinstall
///   aliases into the previous identity. Only used by `Engine::new()`
///   and pure-in-memory test loads.
/// - Both `Some` → C1b persistent identity. Each install mints a
///   UUID stored in the `plugin_installation` SQL table; uninstall
///   tombstones the row; reinstall mints a fresh UUID.
#[derive(Debug)]
pub struct InstalledPluginRegistry {
    plugins_root: Option<PathBuf>,
    db: Option<Arc<Db>>,
    entries: RwLock<HashMap<Arc<str>, InstalledPlugin>>,
}

impl InstalledPluginRegistry {
    /// Empty registry without a filesystem or SQL backing. Used by
    /// `Engine::new()` for unit tests that don't need install
    /// support. No `installation_uuid` persistence — the fallback
    /// UUID at device-registration time is `manifest.plugin.id`
    /// itself (see the loader path in
    /// [`crate::PluginInstance::instantiate`]).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            plugins_root: None,
            db: None,
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

    /// Build by scanning `plugins_root` for installed packages and
    /// reconciling against the `plugin_installation` SQL table for
    /// installation UUIDs (C1b). Creates the directory if it doesn't
    /// exist yet (first-run state dir). Each immediate subdirectory
    /// containing a readable `manifest.toml` becomes a row.
    ///
    /// Reconciliation rules:
    /// - FS entry with a **live** SQL row (`uninstalled_ms IS NULL`)
    ///   → reuse the stored `installation_uuid` (identity survives
    ///   process restart).
    /// - FS entry with no live SQL row → mint a fresh UUID + INSERT
    ///   (backfill for pre-C1b installs or a crash between the FS
    ///   copy and the SQL insert).
    /// - Live SQL row with no FS entry → the row is stranded; log
    ///   and leave it — a subsequent `install` for that
    ///   `plugin_id` will refuse (unique index), matching operator
    ///   expectations. Operator can manually tombstone via
    ///   maintenance tooling if the FS was wiped externally.
    ///
    /// Malformed FS entries (non-dir, manifest missing or invalid)
    /// are skipped with a `tracing::warn` so a corrupt install
    /// doesn't block daemon boot.
    ///
    /// # Errors
    ///
    /// - Failure to create `plugins_root` if missing.
    /// - Failure to enumerate the directory.
    /// - Failure to load or backfill the `plugin_installation` table.
    pub fn scan(plugins_root: PathBuf, db: Arc<Db>) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&plugins_root)?;
        // Pull live installation rows keyed by plugin_id so the scan
        // loop can look up (and mint-if-missing) in one pass.
        let live_uuids = load_live_installation_uuids(&db)?;

        let mut entries: HashMap<Arc<str>, InstalledPlugin> = HashMap::new();
        let mut backfills: Vec<InstalledPlugin> = Vec::new();
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
            // Defense in depth: refuse to index an unsafe id, even
            // if it was placed on disk by hand. Without this an
            // attacker with `<state_dir>/plugins/` write access
            // could plant a manifest with `id = "../../..."` and
            // make the API's `DELETE` path escape the plugins root.
            // (The API gate is install's `is_safe_plugin_id` check;
            // this closes the second insertion path.)
            if !is_safe_plugin_id(&manifest_id) {
                tracing::warn!(
                    path = %path.display(),
                    manifest_id = %manifest_id,
                    "skipping installed dir whose manifest plugin.id is unsafe for use as a filesystem segment",
                );
                continue;
            }
            let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if dir_name != manifest_id {
                tracing::warn!(
                    dir = %dir_name,
                    manifest_id = %manifest_id,
                    "installed dir name disagrees with manifest plugin.id; indexing by manifest id",
                );
            }
            let id_arc: Arc<str> = Arc::from(manifest_id.as_str());
            let installation_uuid = if let Some(uuid) = live_uuids.get(&*id_arc) {
                Arc::clone(uuid)
            } else {
                // FS entry with no live SQL row — mint one.
                // Recorded in `backfills` for post-scan INSERT
                // so the in-memory map and the DB agree even
                // if the INSERT itself races with a concurrent
                // reader (which doesn't happen — scan runs at
                // Engine construction only, before any handler
                // has an `Arc<Engine>` reference).
                let uuid = mint_installation_uuid();
                backfills.push(InstalledPlugin {
                    plugin_id: Arc::clone(&id_arc),
                    installation_uuid: Arc::clone(&uuid),
                    version: manifest.plugin.version.to_string(),
                    path: path.clone(),
                });
                uuid
            };
            entries.insert(
                Arc::clone(&id_arc),
                InstalledPlugin {
                    plugin_id: id_arc,
                    installation_uuid,
                    version: manifest.plugin.version.to_string(),
                    path,
                },
            );
        }

        // Warn about live SQL rows without an FS entry — an
        // operational alarm-bell shape. Doesn't block boot.
        for (plugin_id, uuid) in &live_uuids {
            if !entries.contains_key(plugin_id.as_str()) {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    installation_uuid = %uuid,
                    "plugin_installation row is live but its plugin dir is missing; \
                     leaving the row in place (operator should tombstone via \
                     maintenance tooling if the FS state is authoritative)",
                );
            }
        }

        // Persist backfilled UUIDs so the identity survives the
        // next restart. If any fail we return the error — a
        // half-persisted registry would be worse than refusing to
        // boot and letting the operator investigate.
        for row in &backfills {
            insert_installation_row(&db, row)?;
            tracing::info!(
                plugin_id = %row.plugin_id,
                installation_uuid = %row.installation_uuid,
                "backfilled installation UUID for pre-existing plugin dir",
            );
        }

        Ok(Self {
            plugins_root: Some(plugins_root),
            db: Some(db),
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
        // the manifest id. `validate.rs` in `oxidhome-manifest` also
        // enforces a kebab-case reverse-DNS shape, but defense in
        // depth — the id is about to become a filesystem segment.
        // Same check fires in `scan` so a hand-placed dir with an
        // unsafe `manifest.plugin.id` doesn't enter the registry.
        if !is_safe_plugin_id(&plugin_id) {
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
        // `copy_dir_recursive` returns `InvalidInput` specifically
        // when the source dir contains a symlink — that's a fixable
        // operator-side mistake, not a host internal failure, so we
        // surface it as `BadManifest` (→ 422 BadInstall at the API)
        // rather than `Io` (→ 500). Other IO errors stay as `Io`.
        // Either way, a partial copy left in `staging` is cleaned
        // up so a subsequent install attempt doesn't see (or have
        // to skip over) the half-baked tree.
        if let Err(err) = copy_dir_recursive(source_dir, &staging) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(if err.kind() == std::io::ErrorKind::InvalidInput {
                InstallError::BadManifest {
                    path: source_dir.to_path_buf(),
                    reason: err.to_string(),
                }
            } else {
                InstallError::Io(err)
            });
        }
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
        // C1b: mint a fresh installation UUID and persist before
        // returning. If the INSERT fails (unique index — another
        // live row exists for this plugin_id, which should have
        // been caught by the `dest.exists()` check above, or a
        // real DB error), roll back the FS copy so a retry doesn't
        // hit "already installed" on disk while the SQL side is
        // clean.
        let row = InstalledPlugin {
            plugin_id: Arc::clone(&id_arc),
            installation_uuid: mint_installation_uuid(),
            version: manifest.plugin.version.to_string(),
            path: dest,
        };
        if let Some(db) = &self.db
            && let Err(err) = insert_installation_row(db, &row)
        {
            let _ = std::fs::remove_dir_all(&row.path);
            return Err(InstallError::Persistence(err));
        }
        self.write_entries().insert(id_arc, row.clone());
        tracing::info!(
            plugin_id = %row.plugin_id,
            installation_uuid = %row.installation_uuid,
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
        let Some(entry) = entries.get(plugin_id) else {
            return Err(UninstallError::NotInstalled(plugin_id.to_string()));
        };
        // **Path safety: use the stored path, not a recomputed
        // `plugins_root.join(plugin_id)`.** `install` validates ids
        // before they enter the registry, and `scan` skips
        // unsafe ones — but defense in depth, deleting the path
        // we observed and recorded keeps the destructive operation
        // safe-by-construction. Belt + suspenders: re-verify
        // containment against `plugins_root` before yanking. A
        // safe id's stored path is always under `plugins_root`;
        // any divergence is a sign of registry corruption and
        // we'd rather refuse than `remove_dir_all` outside it.
        let dest = entry.path.clone();
        if !dest.starts_with(plugins_root) {
            tracing::error!(
                plugin_id = %plugin_id,
                path = %dest.display(),
                root = %plugins_root.display(),
                "uninstall refused: registry path escapes plugins root",
            );
            // Treat as "not installed" from the caller's POV —
            // the on-disk state is inconsistent and we won't act
            // on it. Operator must clean up manually.
            return Err(UninstallError::NotInstalled(plugin_id.to_string()));
        }
        // C1b: tombstone the SQL row before yanking the FS. If
        // `remove_dir_all` fails after this, the row is already
        // tombstoned — the next `install` will insert a fresh
        // row with a new UUID (the leaked FS dir is a maintenance
        // problem, not an identity problem). If the tombstone
        // itself fails, refuse the uninstall — the operator
        // needs the SQL row gone (identity-wise) before the FS
        // dir disappears, otherwise a subsequent install would
        // hit the live-row unique index and 409.
        let installation_uuid = Arc::clone(&entry.installation_uuid);
        if let Some(db) = &self.db {
            tombstone_installation_row(db, &installation_uuid)?;
        }
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        entries.remove(plugin_id);
        tracing::info!(
            plugin_id = %plugin_id,
            path = %dest.display(),
            "plugin uninstalled",
        );
        Ok(())
    }
}

// ── SQL helpers (C1b) ───────────────────────────────────────────────

/// Load every live `plugin_installation` row (i.e. `uninstalled_ms IS
/// NULL`), returning a `plugin_id → installation_uuid` map. Used by
/// [`InstalledPluginRegistry::scan`] to reconcile FS entries against
/// stored identity.
fn load_live_installation_uuids(db: &Db) -> Result<HashMap<String, Arc<str>>, rusqlite::Error> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT plugin_id, installation_uuid
             FROM plugin_installation
             WHERE uninstalled_ms IS NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            let plugin_id: String = row.get(0)?;
            let uuid: String = row.get(1)?;
            Ok((plugin_id, Arc::<str>::from(uuid)))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (plugin_id, uuid) = row?;
            out.insert(plugin_id, uuid);
        }
        Ok(out)
    })
}

/// INSERT a fresh installation row. Fails with a unique-constraint
/// error if a live row already exists for `row.plugin_id` — callers
/// (both `install` and the scan backfill) must have ruled out that
/// case beforehand.
fn insert_installation_row(db: &Db, row: &InstalledPlugin) -> Result<(), rusqlite::Error> {
    db.write(|conn| {
        conn.execute(
            "INSERT INTO plugin_installation
                 (installation_uuid, plugin_id, version, installed_ms, uninstalled_ms)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            rusqlite::params![
                &*row.installation_uuid,
                &*row.plugin_id,
                &row.version,
                now_ms(),
            ],
        )?;
        Ok(())
    })
}

/// Mark an installation row as uninstalled. Idempotent — a
/// subsequent tombstone of the same UUID is a no-op (0 rows
/// affected). The row remains for historical trace-back.
fn tombstone_installation_row(db: &Db, installation_uuid: &str) -> Result<(), rusqlite::Error> {
    db.write(|conn| {
        conn.execute(
            "UPDATE plugin_installation
                SET uninstalled_ms = ?2
              WHERE installation_uuid = ?1
                AND uninstalled_ms IS NULL",
            rusqlite::params![installation_uuid, now_ms()],
        )?;
        Ok(())
    })
}

/// Look up the current live installation UUID for a given
/// `plugin_id`, or `None` if no live row exists. Used by the
/// runtime start path so a freshly-installed plugin picks up its
/// UUID without a scan round-trip.
#[allow(dead_code)] // reserved for future direct-lookup callsites
fn load_live_installation_uuid_for(
    db: &Db,
    plugin_id: &str,
) -> Result<Option<Arc<str>>, rusqlite::Error> {
    db.read(|conn| {
        conn.query_row(
            "SELECT installation_uuid
             FROM plugin_installation
             WHERE plugin_id = ?1 AND uninstalled_ms IS NULL",
            [plugin_id],
            |row| row.get::<_, String>(0).map(Arc::<str>::from),
        )
        .optional()
    })
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

/// Pure-Rust recursive copy. **Refuses symlinks** rather than
/// silently skipping them: an operator who points install at a
/// dir whose `.wasm` is a `ln -s` (common in `nix develop` /
/// shared-target-dir dev flows) would otherwise end up with a
/// broken install (no `.wasm` at the installed path) and a
/// confusing failure at first `start`. A hard error surfaces the
/// problem here instead. The "don't follow symlinks to /etc"
/// safety property is preserved — we never traverse one.
/// Empty dirs are preserved.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to install: source contains a symlink at {} — \
                     resolve it before install (the daemon does not follow \
                     symlinks during the copy)",
                    from.display(),
                ),
            ));
        }
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Arc<Db> {
        Arc::new(Db::open_in_memory().expect("in-memory db"))
    }

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
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), fresh_db()).unwrap();
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
        let reg = InstalledPluginRegistry::scan(plugins_root, fresh_db()).unwrap();

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
        let reg = InstalledPluginRegistry::scan(plugins_root, fresh_db()).unwrap();

        let bad = root.join("source-bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("manifest.toml"), "this is not valid toml [[[").unwrap();
        let err = reg.install(&bad).unwrap_err();
        assert!(matches!(err, InstallError::BadManifest { .. }));

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Pins the PR #48 review hardening: an install whose source
    /// dir contains a symlink (even just dangling) is refused
    /// with `BadManifest` (→ 422 at the API) rather than
    /// `Io` (→ 500) or a silent skip that produces a broken
    /// install. Common in `nix develop` / shared-target-dir dev
    /// workflows where `.wasm` artifacts are symlinks.
    #[cfg(unix)]
    #[test]
    fn install_rejects_source_containing_symlink() {
        use std::os::unix::fs::symlink;
        let root = tempdir("symlink");
        let plugins_root = root.join("plugins");
        let reg = InstalledPluginRegistry::scan(plugins_root, fresh_db()).unwrap();

        let source = write_plugin_dir(&root, "example.with-symlink");
        // Replace `plugin.wasm` with a symlink pointing to a real
        // file outside the source dir.
        let real_file = root.join("elsewhere.wasm");
        std::fs::write(&real_file, b"\0asm\x01\x00\x00\x00").unwrap();
        std::fs::remove_file(source.join("plugin.wasm")).unwrap();
        symlink(&real_file, source.join("plugin.wasm")).unwrap();

        let err = reg.install(&source).unwrap_err();
        assert!(
            matches!(err, InstallError::BadManifest { .. }),
            "got {err:?}"
        );
        // Staging dir was cleaned up — no `.staging-...` left around.
        assert!(!root.join("plugins/.staging-example.with-symlink").exists());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Pins the PR #48 review hardening: `scan` refuses to index
    /// a hand-placed dir whose `manifest.toml` declares an unsafe
    /// `plugin.id` (`..`, slashes, etc.). Without this check,
    /// `uninstall(id)` could pass `contains_key` and the stored
    /// `path` validation would be the only guard against
    /// `remove_dir_all` escaping the plugins root.
    #[test]
    fn scan_skips_unsafe_manifest_id() {
        let root = tempdir("unsafe-id-scan");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();

        // Hand-place a dir whose manifest claims a traversal id.
        let bad_dir = plugins_root.join("legit-looking-dirname");
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(
            bad_dir.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "../../../etc/cron.d"
name = "Evil"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "x.wasm"
"#,
        )
        .unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root, fresh_db()).unwrap();
        assert!(
            reg.list().is_empty(),
            "scan must skip unsafe ids, got {:?}",
            reg.list(),
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn scan_repopulates_index_from_existing_install() {
        let root = tempdir("rescan");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let source = write_plugin_dir(&root, "example.persist");
        let installed = reg.install(&source).expect("install");
        let first_uuid = Arc::clone(&installed.installation_uuid);
        drop(reg);

        // Fresh scan against the same FS + DB — the install must
        // re-surface (boot of a daemon against an existing state
        // dir) and the UUID must survive (C1b identity persistence).
        let reg2 = InstalledPluginRegistry::scan(plugins_root, db).unwrap();
        let listed = reg2.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(&*listed[0].plugin_id, "example.persist");
        assert_eq!(
            &*listed[0].installation_uuid, &*first_uuid,
            "installation UUID must survive a scan+restart",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b: uninstall + reinstall of the same `plugin_id` must
    /// yield a **different** installation UUID. Ensures the
    /// reviewer's identity-reuse concern from PR #84 is closed —
    /// the new install can't inherit the old install's audit /
    /// API surface even though `plugin_id` is unchanged.
    #[test]
    fn reinstall_after_uninstall_mints_fresh_installation_uuid() {
        let root = tempdir("reinstall-uuid");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root, db).unwrap();

        let source = write_plugin_dir(&root, "example.rotate");
        let first = reg.install(&source).expect("first install");
        let first_uuid = Arc::clone(&first.installation_uuid);
        assert!(first_uuid.starts_with("inst-"));

        reg.uninstall("example.rotate").expect("uninstall");
        let second = reg.install(&source).expect("second install");
        assert_eq!(&*second.plugin_id, "example.rotate");
        assert_ne!(
            &*second.installation_uuid, &*first_uuid,
            "reinstall must mint a fresh installation UUID",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b: a live SQL row is preserved as a tombstone after
    /// uninstall — historical audit rows keep resolving back to
    /// the retired install. A follow-up install for the same
    /// `plugin_id` inserts a fresh row.
    #[test]
    fn uninstall_tombstones_row_and_reinstall_inserts_fresh() {
        let root = tempdir("tombstone");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();

        let source = write_plugin_dir(&root, "example.tomb");
        let first = reg.install(&source).expect("first install");
        reg.uninstall("example.tomb").expect("uninstall");
        let second = reg.install(&source).expect("second install");

        // The DB has two rows for this plugin_id: one tombstoned
        // (first UUID), one live (second UUID).
        let rows: Vec<(String, Option<i64>)> = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT installation_uuid, uninstalled_ms
                     FROM plugin_installation
                     WHERE plugin_id = ?1
                     ORDER BY installed_ms",
                )?;
                let rows = stmt.query_map(["example.tomb"], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(rows.len(), 2, "expected tombstone + live row");
        assert_eq!(rows[0].0, *first.installation_uuid);
        assert!(rows[0].1.is_some(), "first row must be tombstoned");
        assert_eq!(rows[1].0, *second.installation_uuid);
        assert!(rows[1].1.is_none(), "second row must be live");

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b: a pre-existing plugin dir with no SQL row (upgrade
    /// from pre-C1b, or a hand-placed dir) gets a fresh UUID
    /// backfilled on scan and persists across restart.
    #[test]
    fn scan_backfills_installation_uuid_for_pre_c1b_dirs() {
        let root = tempdir("backfill");
        let plugins_root = root.join("plugins");
        // Hand-place a plugin dir directly under plugins_root
        // (skipping install), simulating an upgrade from before
        // the plugin_installation table existed.
        let plugin_dir = plugins_root.join("example.legacy");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.legacy"
name = "Legacy"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        let backfilled_uuid = Arc::clone(&listed[0].installation_uuid);
        assert!(backfilled_uuid.starts_with("inst-"));

        // A follow-up scan against the same DB reuses the UUID —
        // the backfill is one-time, not a source of drift on every
        // boot.
        drop(reg);
        let reg2 = InstalledPluginRegistry::scan(plugins_root, db).unwrap();
        assert_eq!(
            &*reg2.list()[0].installation_uuid,
            &*backfilled_uuid,
            "backfilled UUID must persist across scans",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
