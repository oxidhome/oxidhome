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
//! than deleting it, so an operator can audit *when* identity
//! rotated for a given `plugin_id` (query
//! `SELECT * FROM plugin_installation WHERE plugin_id = ?`). Note
//! that the table stores only `(installation_uuid, plugin_id,
//! version, timestamps)` — it does **not** persist a mapping from
//! `device_id`s back to their originating installation, so an audit
//! row written against a retired install's device id can't be
//! resolved back through this table alone. Adding a `plugin_device`
//! mapping is a C1c follow-up if the back-reference becomes
//! load-bearing. A partial unique index constrains *live* rows to
//! one-per-`plugin_id`.
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

use oxidhome_manifest::{CapabilitiesSection, PluginManifest, ServiceGrant};
use rand::TryRng;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use crate::state::Db;

/// One row in the installed-plugin index. Cheap to clone (two
/// `Arc<str>`s, an `Arc<CapabilitiesSection>`, plus a `PathBuf`).
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
    /// C5 — host-owned **granted** capabilities. Persisted in the
    /// `plugin_installation.granted_capabilities_json` column at
    /// install time (defaults to a verbatim copy of the manifest's
    /// requested `[capabilities]` block). Runtime host-import
    /// gates consult **this** value, not the manifest's — so a
    /// future PR can add an operator API that narrows the grant
    /// (or fails the install altogether) without editing the
    /// plugin's manifest.
    ///
    /// The split establishes the request/grant boundary; v1
    /// intentionally has no operator-override endpoint, so
    /// grant == request for every fresh install. Pre-C5 rows
    /// (NULL grant JSON) and rows whose grant JSON refuses to
    /// deserialize are **quarantined** by scan — they never
    /// surface through the registry — so an operator's reinstall
    /// re-issues the boundary. C5 review F1 (fail-closed).
    pub granted_capabilities: Arc<CapabilitiesSection>,
    /// C5 review F3: SHA-256 hex of the installed plugin's
    /// contents (manifest + wasm + assets). Computed at install
    /// time and stored in `plugin_installation.content_digest`;
    /// the loader recomputes and refuses to apply
    /// [`Self::granted_capabilities`] to a load whose bytes
    /// disagree with the stored digest.
    pub content_digest: Arc<str>,
}

/// C5 review F3 + round-4 F2: compute a stable content digest
/// binding a plugin's `manifest.toml` bytes and the component's
/// wasm bytes. Install captures this over the staged package
/// (in-memory bytes); the loader recomputes it from the exact
/// bytes it reads into memory for parse + instantiate, so there
/// is no TOCTOU window between the digest walk and the bytes
/// wasmtime actually executes.
///
/// Format: SHA-256 with a domain-separation tag + `u32`
/// length-prefix framing over `(manifest_bytes, wasm_bytes)`.
/// Assets under the plugin dir are intentionally excluded — they
/// aren't executed and can drift without affecting the grant
/// boundary; only manifest + component determine what runs.
#[must_use]
pub fn content_digest(manifest_bytes: &[u8], wasm_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    let tag = b"oxidhome:plugin-content:v2";
    #[allow(clippy::cast_possible_truncation)]
    hasher.update((tag.len() as u32).to_be_bytes());
    hasher.update(tag);
    #[allow(clippy::cast_possible_truncation)]
    hasher.update((manifest_bytes.len() as u32).to_be_bytes());
    hasher.update(manifest_bytes);
    #[allow(clippy::cast_possible_truncation)]
    hasher.update((wasm_bytes.len() as u32).to_be_bytes());
    hasher.update(wasm_bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in &digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Read the manifest.toml and referenced wasm bytes from an
/// installed plugin dir into memory, returning them alongside the
/// computed digest. The caller controls what happens with the
/// bytes — the loader uses them to instantiate wasmtime directly
/// so hash + parse + compile are all bound to the same in-memory
/// snapshot (C5 review F3 codex round-4 F2 TOCTOU fix).
///
/// `runtime_wasm_rel` is the manifest's `[runtime].wasm` relative
/// path (already validated to live under `plugin_dir` by
/// `resolve_wasm_path` at load time; scan re-does the join).
///
/// # Errors
///
/// Any `std::io::Error` from the two file reads.
pub fn read_installed_bytes(
    plugin_dir: &Path,
    runtime_wasm_rel: &Path,
) -> std::io::Result<(String, Vec<u8>, Vec<u8>)> {
    let manifest_bytes = read_no_follow_within(plugin_dir, &plugin_dir.join("manifest.toml"))?;
    let wasm_bytes = read_no_follow_within(plugin_dir, &plugin_dir.join(runtime_wasm_rel))?;
    let digest = content_digest(&manifest_bytes, &wasm_bytes);
    Ok((digest, manifest_bytes, wasm_bytes))
}

/// Read `path` into a `Vec<u8>` after refusing to follow a
/// symlink AND after verifying the canonicalized path lives
/// under `root`. Used by [`read_installed_bytes`] so a
/// hand-placed plugin dir can't smuggle in an out-of-tree wasm
/// via a symlink (which `std::fs::read` would silently follow),
/// nor point at `/dev/zero` or a fifo that would hang / OOM the
/// scan.
///
/// C5 round-6 review F1 refinement: on Unix, opens with
/// `O_NOFOLLOW` so the symlink refusal happens **atomically at
/// open time**, and reads via the returned file handle (not a
/// second pathname lookup) so a check-then-open race can't slip
/// a symlink or FIFO in after the check. On Windows (no
/// `O_NOFOLLOW`), falls back to the `symlink_metadata` + `open`
/// pattern; Windows symlinks require admin/dev-mode to create,
/// so the race is a lower-priority concern.
fn read_no_follow_within(root: &Path, path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        // `O_NOFOLLOW` returns `ELOOP` on Linux if the last
        // path component is a symlink. On macOS, POSIX-compliant.
        // Reading via the returned fd (not re-resolving `path`)
        // is what closes the TOCTOU on the file bytes themselves.
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to follow symlink at {}", path.display()),
            ));
        }
        std::fs::File::open(path)?
    };
    // Verify what we actually opened is a regular file. On Unix
    // with `O_NOFOLLOW`, symlinks would have failed at open; this
    // catches FIFOs, sockets, block/char devices whose paths can
    // still resolve to something openable. `metadata()` here
    // queries via the fd (`fstat`), not via a fresh path lookup.
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to read non-file entry at {} (type: {:?})",
                path.display(),
                meta.file_type()
            ),
        ));
    }
    // Canonical-containment guards against a plugin dir whose
    // contents include a hardlink or mount point that resolves
    // elsewhere. The main TOCTOU protection is `O_NOFOLLOW` +
    // reading via the fd; this containment check is a static
    // "did the operator legitimately install us here" guard.
    let canonical_path = std::fs::canonicalize(path)?;
    let canonical_root = std::fs::canonicalize(root)?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to read {} (canonical path {} escapes plugin root {})",
                path.display(),
                canonical_path.display(),
                canonical_root.display()
            ),
        ));
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// C5 review F2: compute the **effective** capability set at
/// load time. A stale grant broader than the current manifest's
/// request must not authorize permissions the manifest no longer
/// asks for — a plugin author removing a capability shouldn't
/// leave the operator holding a broader grant on a package that
/// no longer needs it.
///
/// Set-shaped fields (`network`, `declares_devices`,
/// `declares_services`) intersect on equality; quotas take the
/// minimum; `subscribes_events` is a boolean AND.
///
/// **`consumes_services` is NOT intersected here** (H10 round-4).
/// The requested × granted cross-product grows O(N²) in narrowed
/// selectors, and per-record dedup work on that N² output
/// approaches quadratic. The dispatcher instead checks both lists
/// **independently** at call time: a call is authorized iff at
/// least one requested selector matches AND at least one granted
/// selector matches. Semantically equivalent to intersection,
/// bounded per-call at O(|requested|) + O(|granted|), and each
/// list is bounded by the manifest-validation cap in
/// `oxidhome-manifest`. `effective_capabilities` therefore leaves
/// `consumes_services` set to the **granted** list only; the
/// requested list rides separately on `PluginState` through
/// `PluginInstance::instantiate`.
#[must_use]
pub fn effective_capabilities(
    requested: &CapabilitiesSection,
    granted: &CapabilitiesSection,
) -> CapabilitiesSection {
    CapabilitiesSection {
        network: intersect_by_eq(&requested.network, &granted.network),
        storage_quota_kb: requested.storage_quota_kb.min(granted.storage_quota_kb),
        blob_quota_mb: requested.blob_quota_mb.min(granted.blob_quota_mb),
        declares_devices: intersect_by_eq(&requested.declares_devices, &granted.declares_devices),
        declares_services: intersect_by_eq(
            &requested.declares_services,
            &granted.declares_services,
        ),
        // See doc comment — carry the granted list through, the
        // requested list is applied separately at dispatch time.
        consumes_services: granted.consumes_services.clone(),
        subscribes_events: requested.subscribes_events && granted.subscribes_events,
    }
}

fn intersect_by_eq<T: Clone + PartialEq>(a: &[T], b: &[T]) -> Vec<T> {
    a.iter().filter(|x| b.contains(x)).cloned().collect()
}

/// H10 round-4: dispatcher-side "any-selector matches" predicate.
/// The service registry's authorization check runs this once
/// against the caller's *requested* list and once against the
/// operator's *granted* list; both must return true for the call
/// to be authorized. This is the intersection semantics without
/// materializing the intersection.
#[must_use]
pub fn any_grant_matches(
    grants: &[ServiceGrant],
    caller_instance: &str,
    target_plugin: &str,
    target_instance: &str,
    target_service_local_id: &str,
    command: &str,
) -> bool {
    grants.iter().any(|g| {
        g.matches(
            caller_instance,
            target_plugin,
            target_instance,
            target_service_local_id,
            command,
        )
    })
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
    /// C5 review F1/F3 codex-fixup + round-6 F1: `plugin_id` →
    /// `(installation_uuid, path)` for live SQL rows that scan
    /// quarantined (NULL / malformed grant, NULL digest). Held
    /// in a separate map from `entries` because runtime callers
    /// must NOT resolve them as live installations, but the
    /// API's `uninstall` needs a way to address them so an
    /// operator's upgrade-then-reinstall recovery path works
    /// without hand-editing `SQLite`. `path` is `Option<PathBuf>`
    /// so a quarantined row whose FS dir went missing (or is
    /// unreadable / has an unsafe id) still appears in
    /// [`Self::is_quarantined`] and is uninstallable — with the
    /// SQL-tombstone-only branch of [`Self::uninstall`].
    quarantined: RwLock<std::collections::HashMap<Arc<str>, QuarantineEntry>>,
}

#[derive(Debug, Clone)]
struct QuarantineEntry {
    installation_uuid: Arc<str>,
    /// C5 round-5 review F1 + H8 review F1: every filesystem
    /// path scan found for this quarantined `plugin_id`.
    ///
    /// - Empty vec = the SQL row is quarantined but no matching
    ///   directory exists on disk (missing / unreadable / unsafe
    ///   id). `uninstall` still tombstones the SQL row so the
    ///   identity boundary clears.
    /// - One path = ordinary quarantine (single dir, broken
    ///   grant/digest).
    /// - Multiple paths = H8 duplicate manifest ids across
    ///   sibling dirs. Follow-up review flagged that storing
    ///   only the last-seen path let the OTHER duplicate
    ///   directory survive uninstall + get backfilled with a
    ///   fresh UUID on the next scan — the exact H8 reactivation
    ///   the first cut of this fix was meant to close. Storing
    ///   every path means `uninstall` yanks all of them in one
    ///   call, deterministically.
    paths: Vec<PathBuf>,
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
            quarantined: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// C5 review F1/F3 codex-fixup: true if `plugin_id` matches a
    /// live installation row that scan quarantined. The runtime
    /// loader consults this before falling back to dev-load
    /// semantics — direct-start (argv or `Engine::start_instance`
    /// with a raw path) whose loaded manifest declares a
    /// quarantined `plugin_id` must refuse to run, not shadow the
    /// quarantine with a manifest-derived grant.
    #[must_use]
    pub fn is_quarantined(&self, plugin_id: &str) -> bool {
        self.quarantined
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(plugin_id)
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
    // C1b: `scan` is intentionally long — its job is the
    // exhaustive reconciliation between FS state and SQL state
    // (live rows, tombstoned-only rows, staging leftovers, orphan
    // live rows). Splitting it into helpers would fragment the
    // one place readers look to understand boot-time reconciliation.
    #[allow(clippy::too_many_lines)]
    pub fn scan(plugins_root: PathBuf, db: Arc<Db>) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&plugins_root)?;
        // Pull live installation rows keyed by plugin_id so the scan
        // loop can look up (and mint-if-missing) in one pass. Each
        // entry carries both the persisted installation UUID (C1b)
        // and the persisted granted-capabilities blob (C5).
        let LiveInstallationLoad {
            live: live_rows,
            quarantined_uuids,
        } = load_live_installations(&db)?;
        // C5 round-6 F1: pre-populate the quarantined registry
        // map from every SQL-side quarantined row (path = None
        // for now). The FS walk below fills in `path` when a
        // matching dir is found. Doing this up-front means a
        // quarantined row whose FS dir is missing / unreadable
        // still shows up in `is_quarantined()` — closes the
        // raw-path bypass where a CLI load with the same
        // plugin_id would fall through to dev-load semantics.
        let mut quarantined_registry: std::collections::HashMap<Arc<str>, QuarantineEntry> =
            quarantined_uuids
                .iter()
                .map(|(plugin_id, uuid)| {
                    (
                        Arc::<str>::from(plugin_id.as_str()),
                        QuarantineEntry {
                            installation_uuid: Arc::clone(uuid),
                            paths: Vec::new(),
                        },
                    )
                })
                .collect();

        let mut entries: HashMap<Arc<str>, InstalledPlugin> = HashMap::new();
        let mut backfills: Vec<InstalledPlugin> = Vec::new();
        // `plugin_id`s of directories whose manifest we successfully
        // parsed. The **authoritative** identifier is the one in
        // the manifest, not the dir name — `scan` explicitly accepts
        // a dir whose basename differs from its manifest id. Using
        // dir names here would double-count (leaving orphan live
        // rows for renamed manifests) or misidentify (a broken
        // manifest gets misattributed to the dir name). See fixup2
        // review F1 / F2.
        // Follow-up review H8: track the first-seen FS path per
        // manifest id so a second dir declaring the same id can
        // evict + quarantine both. Without this the second
        // insertion into `entries` silently overwrites the first;
        // uninstall then removes only the winning path, and the
        // loser's leftover dir gets backfilled with a fresh UUID
        // on restart, silently reactivating an install the
        // operator thought was gone.
        let mut observed_manifest_ids: std::collections::HashMap<String, PathBuf> =
            std::collections::HashMap::new();
        // Manifest ids seen more than once during this scan.
        // Every current + future sighting joins the quarantine
        // instead of being indexed. Cleared by the operator via
        // an explicit uninstall (or by removing the duplicate
        // dirs on disk).
        let mut duplicate_manifest_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // If any non-staging directory has a manifest we can't
        // parse or that declares an unsafe id, we can't know its
        // `plugin_id`, so the orphan-live-row sweep can't safely
        // decide anything for that boot — a live row could belong
        // to this dir, or genuinely be orphaned. Defer the sweep
        // entirely: skip it and let the next boot (after the
        // operator repairs the manifest) reconcile cleanly. This
        // preserves identity across transient manifest blips at
        // the cost of leaving genuine orphans in place for one
        // extra boot.
        let mut defer_orphan_sweep = false;
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
            // C1b review F2 (other reviewer): a crash between the
            // FS copy and the atomic rename leaves `.staging-<id>/`
            // populated. Its `manifest.toml` is valid, so the
            // pre-fix scan would treat it as an installed package —
            // silently activating an install the operator saw as
            // failed. Staging directories are, by construction,
            // transient: delete them on scan. The paired SQL row
            // (if any) is cleaned up in the orphan-live-row sweep
            // below.
            let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if dir_name.starts_with(".staging-") {
                match std::fs::remove_dir_all(&path) {
                    Ok(()) => tracing::info!(
                        path = %path.display(),
                        "removed leftover install staging directory on scan",
                    ),
                    Err(err) => tracing::error!(
                        path = %path.display(),
                        %err,
                        "failed to remove leftover install staging directory",
                    ),
                }
                continue;
            }
            // C5 round-6 review F2: if the dir NAME matches a
            // quarantined `plugin_id`, record its path now — even
            // if the manifest read below fails or declares an
            // unsafe id. Otherwise the pre-populated empty
            // `paths` would let `uninstall` succeed without
            // removing the FS dir, and the leftover would block a
            // subsequent `install` with `AlreadyInstalled`. Uses
            // the raw dir name (not the manifest id) as the match
            // key because the manifest may be unreadable — the
            // only stable observation for a broken manifest is
            // the on-disk name matching the install convention
            // `<plugins_root>/<plugin_id>/`.
            if !dir_name.is_empty()
                && let Some(entry) = quarantined_registry.get_mut(dir_name)
                && !entry.paths.contains(&path)
            {
                entry.paths.push(path.clone());
            }
            let manifest_path = path.join("manifest.toml");
            let manifest = match read_manifest_sync(&manifest_path) {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(
                        path = %manifest_path.display(),
                        %err,
                        "skipping installed dir with bad manifest — deferring orphan-live-row sweep this boot",
                    );
                    // We can't know this dir's plugin_id, so we
                    // can't safely tombstone any live row this
                    // boot. Defer.
                    defer_orphan_sweep = true;
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
                    "skipping installed dir whose manifest plugin.id is unsafe for use as a filesystem segment — deferring orphan-live-row sweep this boot",
                );
                // Same reasoning as the bad-manifest branch: we
                // can't reliably identify this dir, so defer.
                defer_orphan_sweep = true;
                continue;
            }
            if dir_name != manifest_id {
                tracing::warn!(
                    dir = %dir_name,
                    manifest_id = %manifest_id,
                    "installed dir name disagrees with manifest plugin.id; indexing by manifest id",
                );
            }
            // Follow-up review H8: reject/quarantine duplicate
            // manifest ids. If we've already seen a dir declaring
            // this `plugin_id`, both dirs are ambiguous — the
            // pre-fix behavior silently overwrote the first with
            // the second in `entries`, so uninstall removed only
            // the winning path and the loser's leftover dir got
            // backfilled with a fresh UUID on the next scan.
            // Neither dir is safe to index; quarantine both
            // (evict any prior entry, add both to
            // `quarantined_registry`), remember the id so any
            // third+ sighting also quarantines.
            //
            // We reuse the existing quarantine slot even though
            // there's no live SQL row per se — `is_quarantined`
            // + the API's `uninstall` handle the path-only case
            // fine, and the API's `install` still refuses via
            // `dest.exists()`. Operator resolves by removing the
            // duplicate dir(s) via `uninstall` (each call yanks
            // one path).
            if duplicate_manifest_ids.contains(&manifest_id)
                || observed_manifest_ids.contains_key(&manifest_id)
            {
                // First time we see the second-sighting: evict
                // the winner from `entries` if we've already
                // indexed one, add the winner's path to
                // quarantined.
                if !duplicate_manifest_ids.contains(&manifest_id) {
                    duplicate_manifest_ids.insert(manifest_id.clone());
                    let id_arc: Arc<str> = Arc::from(manifest_id.as_str());
                    let prior_uuid = entries
                        .remove(&id_arc)
                        .map(|e| e.installation_uuid)
                        .or_else(|| {
                            live_rows
                                .get(&manifest_id)
                                .map(|l| Arc::clone(&l.installation_uuid))
                        })
                        .unwrap_or_else(|| Arc::from("dup-unknown"));
                    if let Some(prior_path) = observed_manifest_ids.get(&manifest_id) {
                        tracing::error!(
                            plugin_id = %manifest_id,
                            first_path = %prior_path.display(),
                            "duplicate manifest.plugin.id on scan — quarantining first-seen dir",
                        );
                        quarantined_registry.insert(
                            Arc::clone(&id_arc),
                            QuarantineEntry {
                                installation_uuid: Arc::clone(&prior_uuid),
                                paths: vec![prior_path.clone()],
                            },
                        );
                    }
                }
                tracing::error!(
                    plugin_id = %manifest_id,
                    path = %path.display(),
                    "duplicate manifest.plugin.id on scan — quarantining this dir too (operator must resolve)",
                );
                // H8 round-2 F1: APPEND (not overwrite) so
                // `uninstall` yanks every duplicate dir in one
                // call. The pre-fix shape overwrote `path`, which
                // left the first dir on disk after uninstall —
                // next scan then saw it as unique + backfilled a
                // fresh UUID, reactivating the exact H8 scenario.
                let id_arc: Arc<str> = Arc::from(manifest_id.as_str());
                match quarantined_registry.get_mut(&id_arc) {
                    Some(entry) => {
                        if !entry.paths.contains(&path) {
                            entry.paths.push(path.clone());
                        }
                    }
                    None => {
                        quarantined_registry.insert(
                            id_arc,
                            QuarantineEntry {
                                installation_uuid: Arc::from("dup-unknown"),
                                paths: vec![path.clone()],
                            },
                        );
                    }
                }
                continue;
            }
            // Record the authoritative manifest id AND its FS
            // path — the path enables the duplicate-detection
            // eviction above. The orphan-live-row sweep uses
            // just the id set (via `.keys()`) to decide which
            // live SQL rows still have a matching dir on disk.
            observed_manifest_ids.insert(manifest_id.clone(), path.clone());
            // C5 review F1: quarantine any installation whose
            // grant JSON is malformed. Skip indexing so
            // `start_instance` can't launch the plugin under an
            // unknown grant; don't tombstone (identity stays
            // intact, operator repairs, next scan indexes normally).
            // Adding to `observed_manifest_ids` above already
            // protects the row from the orphan-live-row sweep.
            // C5 review F1/F3 (fail-closed): a live row that
            // failed the SQL-read validation (NULL / malformed
            // grant, or NULL digest) is quarantined. Skip
            // indexing so `start_instance` can't launch the
            // plugin under a broken grant; don't tombstone —
            // the row stays live and the plugin_id is in
            // `observed_manifest_ids` above, so the orphan
            // sweep doesn't tombstone it either. Operator
            // repairs via `uninstall` + `install` cycle.
            if let Some(uuid) = quarantined_uuids.get(&manifest_id) {
                tracing::warn!(
                    plugin_id = %manifest_id,
                    path = %path.display(),
                    "skipping quarantined installation (malformed grant or missing digest) — uninstall + reinstall via the API to re-issue",
                );
                // Set/overwrite the pre-populated entry with the
                // actual manifest_id key (may differ from dir_name
                // if the manifest renamed the plugin) and a valid
                // FS path so `uninstall` can remove the dir.
                quarantined_registry.insert(
                    Arc::from(manifest_id.as_str()),
                    QuarantineEntry {
                        installation_uuid: Arc::clone(uuid),
                        paths: vec![path.clone()],
                    },
                );
                continue;
            }
            let id_arc: Arc<str> = Arc::from(manifest_id.as_str());
            let (installation_uuid, granted_capabilities, content_digest_arc) = if let Some(live) =
                live_rows.get(&*id_arc)
            {
                (
                    Arc::clone(&live.installation_uuid),
                    Arc::clone(&live.granted_capabilities),
                    Arc::clone(&live.content_digest),
                )
            } else {
                // FS entry with no live SQL row — mint one.
                // Under the FS-first uninstall order, an
                // interrupted uninstall whose `remove_dir_all`
                // failed leaves the **live** SQL row in place
                // (tombstone step never ran), so this branch
                // isn't reachable for that shape. FS entries
                // with no live row are legit pre-C1b installs
                // or hand-placed / restored packages —
                // backfill mints a fresh UUID + computes a
                // fresh content digest, matching what the
                // API's `install` would have done.
                let uuid = mint_installation_uuid();
                let digest = match read_installed_bytes(&path, &manifest.runtime.wasm) {
                    Ok((d, _, _)) => Arc::<str>::from(d),
                    Err(err) => {
                        tracing::error!(
                            plugin_id = %manifest_id,
                            path = %path.display(),
                            %err,
                            "content_digest computation failed during backfill; skipping this directory",
                        );
                        continue;
                    }
                };
                let grant_arc = Arc::new(manifest.capabilities.clone());
                backfills.push(InstalledPlugin {
                    plugin_id: Arc::clone(&id_arc),
                    installation_uuid: Arc::clone(&uuid),
                    version: manifest.plugin.version.to_string(),
                    path: path.clone(),
                    granted_capabilities: Arc::clone(&grant_arc),
                    content_digest: Arc::clone(&digest),
                });
                (uuid, grant_arc, digest)
            };
            entries.insert(
                Arc::clone(&id_arc),
                InstalledPlugin {
                    plugin_id: id_arc,
                    installation_uuid,
                    version: manifest.plugin.version.to_string(),
                    path,
                    granted_capabilities,
                    content_digest: content_digest_arc,
                },
            );
        }

        // Live SQL rows whose plugin_id has NO successfully-parsed
        // manifest on disk (via `observed_manifest_ids`) —
        // auto-tombstone.
        //
        // The auto-tombstone shape covers:
        // - Install crashed after INSERT but before rename → row
        //   never had a working install.
        // - Uninstall's `remove_dir_all` succeeded but the SQL
        //   tombstone failed → row is effectively dead.
        // - Operator manually deleted the plugin dir → a reinstall
        //   should mint a new UUID.
        //
        // Without this sweep, a subsequent `install` for the same
        // `plugin_id` would hit `plugin_installation_live`'s unique
        // index and return `AlreadyInstalled` despite nothing on
        // disk. Identity does not rotate for anything that survived
        // (there is no FS entry, so nothing was actively minting
        // device ids against this row).
        //
        // Fixup2 review F2: if any directory had an unreadable /
        // unsafe manifest, we don't know its `plugin_id`, so the
        // sweep can't safely decide. Defer for one boot — the
        // operator repairs the manifest, next boot reconciles
        // cleanly. This preserves identity across transient
        // manifest blips at the cost of leaving genuine orphans in
        // place for one extra boot.
        if defer_orphan_sweep {
            tracing::warn!(
                "orphan-live-row sweep deferred this boot due to unresolvable directories (see prior warnings)",
            );
        } else {
            for (plugin_id, live) in &live_rows {
                // A quarantined-as-duplicate id is still
                // "observed on disk" for the orphan sweep —
                // we don't want to also tombstone its live row.
                if !observed_manifest_ids.contains_key(plugin_id.as_str())
                    && !duplicate_manifest_ids.contains(plugin_id.as_str())
                {
                    let uuid = &live.installation_uuid;
                    match tombstone_installation_row(&db, uuid) {
                        Ok(()) => tracing::warn!(
                            plugin_id = %plugin_id,
                            installation_uuid = %uuid,
                            "auto-tombstoned live plugin_installation row whose plugin dir is missing (crashed install or interrupted uninstall)",
                        ),
                        Err(err) => tracing::error!(
                            plugin_id = %plugin_id,
                            installation_uuid = %uuid,
                            %err,
                            "failed to auto-tombstone orphan live plugin_installation row",
                        ),
                    }
                }
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
            quarantined: RwLock::new(quarantined_registry),
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

    /// H12 review F1: return the `installation_uuid` for either a
    /// live *or* a quarantined install. `get()` returns None for
    /// quarantined rows on purpose (the runtime must refuse to
    /// launch them), but the API's uninstall path still needs to
    /// know the uuid so it can purge per-install KV / blob state
    /// under the tombstone. Without this, `Engine::uninstall_plugin`
    /// on a quarantined install silently skipped both purges and
    /// stranded the state.
    #[must_use]
    pub fn installation_uuid_for(&self, plugin_id: &str) -> Option<Arc<str>> {
        if let Some(entry) = self.read_entries().get(plugin_id) {
            return Some(Arc::clone(&entry.installation_uuid));
        }
        self.quarantined
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(plugin_id)
            .map(|q| Arc::clone(&q.installation_uuid))
    }

    /// The root under which installed plugin dirs live
    /// (`<state_dir>/plugins/`). `None` for in-memory registries
    /// (`Self::empty()`). Callers use this to decide whether a
    /// caller-supplied `wasm_path` was pointing at an installed
    /// plugin — the H2 round-2 F1 loader belt refuses to fall
    /// back to dev semantics for paths that live here.
    #[must_use]
    pub fn plugins_root(&self) -> Option<&Path> {
        self.plugins_root.as_deref()
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
    // C1b + C5: `install` is intentionally long — one path handles
    // manifest read/validate, unique-id check, FS staging + rename,
    // SQL INSERT (with rollback on any subsequent FS failure), and
    // in-memory registration. Splitting the SQL rollback closure
    // away from the FS steps would obscure the ordering guarantee
    // the C1b review F3 fixup depends on.
    #[allow(clippy::too_many_lines)]
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

        // C1b review F3: SQL INSERT first, FS copy second.
        //
        // A failed install must never silently activate: if we
        // did FS first and the SQL INSERT (or its rollback) failed,
        // the leftover dir would get backfilled with a fresh UUID
        // on the next scan and the "failed" install would become
        // live with a rotated identity. INSERT-first inverts the
        // failure mode — if any FS step fails afterwards, we
        // DELETE the row (not tombstone: this UUID was never
        // accepted), keeping SQL + FS + in-memory consistent.
        // If the DELETE also fails, the row is orphaned (live
        // SQL row without a dir) and scan warns — never rotates
        // identity for the FS side.
        let id_arc: Arc<str> = Arc::from(plugin_id.as_str());
        // Mint the installation UUID up-front so we can key the
        // staging directory on it. C5-fixup codex review F1:
        // deterministic `.staging-<plugin_id>` let two concurrent
        // installs for the same plugin_id race on the same tree;
        // per-request `.staging-<uuid>` makes each install's
        // staging area private, so only the SQL unique-live-index
        // decides which one wins.
        let installation_uuid = mint_installation_uuid();
        let staging = plugins_root.join(format!(".staging-{installation_uuid}"));

        // C5 review F3: copy + validate the staged manifest
        // **before** the SQL INSERT so the row's grant reflects
        // the manifest that actually lands on disk, not a
        // potentially-changed source-side manifest. If the
        // source dir races with a concurrent editor, the two
        // reads can disagree; deriving grant from source and
        // package contents from staging would let a broad
        // request be persisted while the on-disk manifest
        // advertises a narrow one. Staging is transient — a
        // crash between the copy and the INSERT leaves a
        // `.staging-<uuid>` dir that scan's staging-cleanup path
        // removes, so no ghost identity or FS residue survives.
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
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
        let staged_manifest_path = staging.join("manifest.toml");
        let staged_manifest = match read_manifest_sync(&staged_manifest_path) {
            Ok(m) => m,
            Err(err) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(InstallError::BadManifest {
                    path: staged_manifest_path,
                    reason: err.to_string(),
                });
            }
        };
        // Belt and suspenders: refuse if the staged manifest
        // declares a different `plugin_id` than the source.
        // Without this a source rewritten mid-install could
        // land under one id in SQL while the on-disk dir sits
        // under another.
        if staged_manifest.plugin.id != plugin_id {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(InstallError::BadManifest {
                path: staged_manifest_path,
                reason: format!(
                    "staged manifest plugin.id {:?} disagrees with source plugin.id {:?}",
                    staged_manifest.plugin.id, plugin_id
                ),
            });
        }

        // Phase 13 round-2 finding 5: verify every UI
        // asset path declared in `[ui]` resolves to a
        // regular file in the staged tree. `validate.rs`
        // in `oxidhome-manifest` catches shape / escape
        // problems on the paths themselves, but only a
        // package-aware check catches "this manifest
        // declares `ui/config.js` and the file simply
        // isn't there" — an installation that promises a
        // declarative renderer surface and can't deliver.
        if let Some(ui) = staged_manifest.ui.as_ref()
            && let Err(reason) = check_ui_assets_present(ui, &staging)
        {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(InstallError::BadManifest {
                path: staged_manifest_path,
                reason,
            });
        }

        // C5 review F3 + round-4 F2: compute the content digest
        // over the staged package's `manifest.toml` + wasm bytes
        // (post-copy, before rename). The loader recomputes from
        // the SAME in-memory bytes it uses to instantiate
        // wasmtime, so a mid-load rewrite of the on-disk files
        // can't slip past the digest check.
        let staged_digest = match read_installed_bytes(&staging, &staged_manifest.runtime.wasm) {
            Ok((d, _, _)) => d,
            Err(err) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(InstallError::Io(err));
            }
        };

        let row = InstalledPlugin {
            plugin_id: Arc::clone(&id_arc),
            installation_uuid,
            version: staged_manifest.plugin.version.to_string(),
            path: dest.clone(),
            // C5 review F3: grant + digest derived from the
            // **staged** manifest / staged bytes, not the source.
            granted_capabilities: Arc::new(staged_manifest.capabilities.clone()),
            content_digest: Arc::from(staged_digest),
        };
        if let Some(db) = &self.db
            && let Err(err) = insert_installation_row(db, &row)
        {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(if is_unique_constraint(&err) {
                InstallError::AlreadyInstalled {
                    plugin_id: (*id_arc).to_string(),
                }
            } else {
                InstallError::Persistence(err)
            });
        }

        // Any FS failure past the SQL INSERT must roll back the
        // SQL row so the operator sees a truthful "install
        // failed" and a retry can converge.
        let rollback_sql = |err: InstallError| -> InstallError {
            if let Some(db) = &self.db
                && let Err(delete_err) = delete_installation_row(db, &row.installation_uuid)
            {
                tracing::error!(
                    plugin_id = %row.plugin_id,
                    installation_uuid = %row.installation_uuid,
                    error = %delete_err,
                    "failed to roll back plugin_installation row after install error; \
                     row is orphaned (live SQL row without a dir) — \
                     operator must maintenance-tombstone before a retry"
                );
            }
            err
        };

        if let Err(err) = std::fs::rename(&staging, &dest) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(rollback_sql(InstallError::Io(err)));
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
    /// Returns the `installation_uuid` of the tombstoned row so the
    /// caller can drive H2's per-install state purge
    /// (`KvStore::purge_installation` / `BlobStore::purge_installation`).
    /// Wired in [`crate::runtime::Engine`]'s uninstall path, not
    /// here, so this module stays focused on the ledger + FS side of
    /// uninstall and doesn't need to import the state stores.
    ///
    /// # Errors
    ///
    /// See [`UninstallError`].
    pub fn uninstall(&self, plugin_id: &str) -> Result<Arc<str>, UninstallError> {
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
        // C5 review F1/F3 codex round-4: quarantined installations
        // are absent from `entries` on purpose (the runtime must
        // refuse them), but must still be uninstallable via the
        // API — otherwise an operator upgrading a database into
        // C5-with-digest can't recover an existing installation
        // without hand-editing `SQLite`. Resolve via the
        // quarantined map when entries misses.
        let (installation_uuid, dests, was_quarantined) =
            if let Some(entry) = entries.get(plugin_id) {
                (
                    Arc::clone(&entry.installation_uuid),
                    vec![entry.path.clone()],
                    false,
                )
            } else if let Some(q) = self
                .quarantined
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .get(plugin_id)
            {
                (Arc::clone(&q.installation_uuid), q.paths.clone(), true)
            } else {
                return Err(UninstallError::NotInstalled(plugin_id.to_string()));
            };
        // **Path safety: use the stored paths, not a recomputed
        // `plugins_root.join(plugin_id)`.** `install` validates ids
        // before they enter the registry, and `scan` skips
        // unsafe ones — but defense in depth, deleting only paths
        // we observed and recorded keeps the destructive operation
        // safe-by-construction. Belt + suspenders: re-verify
        // containment against `plugins_root` for every entry
        // before yanking any. A safe id's stored path is always
        // under `plugins_root`; any divergence is a sign of
        // registry corruption and we'd rather refuse than
        // `remove_dir_all` outside it.
        //
        // C5 round-5 F1: empty `dests` when the caller is
        // uninstalling a quarantined row whose FS dir went
        // missing between install and this call. Tombstone the
        // SQL row anyway so the identity boundary is cleared;
        // no FS operation runs.
        //
        // H8 round-2 F1: `dests` carries every duplicate dir for
        // a quarantined id — the loop below yanks all of them in
        // one call, so the reviewer's "second uninstall returns
        // NotInstalled" reactivation is closed.
        for dest in &dests {
            if !dest.starts_with(plugins_root) {
                tracing::error!(
                    plugin_id = %plugin_id,
                    path = %dest.display(),
                    root = %plugins_root.display(),
                    "uninstall refused: registry path escapes plugins root",
                );
                // Treat as "not installed" from the caller's POV
                // — the on-disk state is inconsistent and we
                // won't act on it. Operator must clean up
                // manually.
                return Err(UninstallError::NotInstalled(plugin_id.to_string()));
            }
        }
        // C1b review F2: FS remove first, SQL tombstone second.
        //
        // Identity rotation is more dangerous than a leaked FS dir.
        // Tombstoning first and then failing the `remove_dir_all`
        // (crash / permission bump / file lock) would leave the FS
        // dir behind with **no live SQL row**; the next scan would
        // treat it as an untracked install and backfill a fresh
        // UUID — silently rotating device ids after an uninstall
        // the operator saw as failed.
        //
        // FS-first: if `remove_dir_all` fails, the row is still
        // live, so the in-memory entry stays intact, identity does
        // not rotate, and a retry converges. If the tombstone
        // fails after the FS is gone, the row is orphaned (live
        // SQL row without a dir) — scan warns; a maintenance tool
        // can hard-tombstone. Identity still does not rotate on
        // the historical audit trail.
        for dest in &dests {
            if dest.exists() {
                std::fs::remove_dir_all(dest)?;
            }
        }
        if let Some(db) = &self.db {
            tombstone_installation_row(db, &installation_uuid)?;
        }
        if was_quarantined {
            self.quarantined
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(plugin_id);
        } else {
            entries.remove(plugin_id);
        }
        tracing::info!(
            plugin_id = %plugin_id,
            paths = ?dests,
            was_quarantined,
            "plugin uninstalled",
        );
        Ok(installation_uuid)
    }
}

// ── SQL helpers (C1b + C5) ──────────────────────────────────────────

/// One live-row projection scan needs: identity (`installation_uuid`)
/// plus the persisted grant (`granted_capabilities`). Separate from
/// `InstalledPlugin` because scan builds those *after* reading the
/// on-disk manifest.
#[derive(Debug, Clone)]
struct LiveInstallation {
    installation_uuid: Arc<str>,
    /// C5: successfully-parsed grant. NULL / malformed grants
    /// are quarantined at the SQL-read layer under the C5
    /// review F1 fail-closed policy — they never surface as a
    /// [`LiveInstallation`].
    granted_capabilities: Arc<CapabilitiesSection>,
    /// C5 review F3: content digest captured at install time.
    /// The loader recomputes and refuses to apply the grant to
    /// a load whose bytes disagree with this value.
    content_digest: Arc<str>,
}

/// Result of scanning `plugin_installation`. `live` holds rows
/// with a well-formed grant AND a non-NULL content digest;
/// `quarantined_plugin_ids` holds `plugin_id`s whose row is
/// unusable (NULL / malformed grant JSON, or NULL digest — the
/// C5 fail-closed policy). Quarantined installations aren't
/// indexed (so `start_instance` can't launch them) but their
/// rows stay live so an operator's `uninstall` + `install` cycle
/// re-issues both fields together. C5 review F1 (NULL grant
/// fail-closed) + F3 (missing digest fail-closed).
struct LiveInstallationLoad {
    live: HashMap<String, LiveInstallation>,
    /// `plugin_id → installation_uuid` for rows the SQL-read
    /// layer refused to accept. Scan pairs each with the matching
    /// on-disk path (if any) to populate
    /// [`InstalledPluginRegistry::quarantined`], so the API's
    /// `uninstall` can address quarantined installations without
    /// hand-editing `SQLite`. C5 review F1/F3 codex-fixup.
    quarantined_uuids: HashMap<String, Arc<str>>,
}

/// Load every live `plugin_installation` row (i.e. `uninstalled_ms IS
/// NULL`). Used by [`InstalledPluginRegistry::scan`] to reconcile
/// FS entries against stored identity + grant + digest.
///
/// C5 review F1 + F3 (fail-closed): a live row is quarantined if
/// its `granted_capabilities_json` is NULL / refuses to
/// deserialize, or if its `content_digest` is NULL. Falling back
/// to the manifest for either field would let a previously-
/// narrowed grant regain permissions after any parse failure /
/// migration boot; a NULL digest would let arbitrary on-disk
/// bytes run under a stored grant. Quarantined installations are
/// not indexed (so `start_instance` fails cleanly) but their
/// rows stay live (identity isn't rotated) — the scan protects
/// them from the orphan sweep too. An operator's `uninstall` +
/// `install` re-issues both fields together.
fn load_live_installations(db: &Db) -> Result<LiveInstallationLoad, rusqlite::Error> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT plugin_id, installation_uuid, granted_capabilities_json, content_digest
             FROM plugin_installation
             WHERE uninstalled_ms IS NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            let plugin_id: String = row.get(0)?;
            let uuid: String = row.get(1)?;
            let grant_json: Option<String> = row.get(2)?;
            let digest: Option<String> = row.get(3)?;
            Ok((plugin_id, uuid, grant_json, digest))
        })?;
        let mut live = HashMap::new();
        let mut quarantined_uuids: HashMap<String, Arc<str>> = HashMap::new();
        for row in rows {
            let (plugin_id, uuid, grant_json, digest) = row?;
            let uuid_arc = Arc::<str>::from(uuid.clone());
            let Some(digest) = digest else {
                tracing::error!(
                    plugin_id = %plugin_id,
                    installation_uuid = %uuid,
                    "content_digest is NULL (pre-C5 install or corrupt row); \
                     quarantining — reinstall to re-issue the grant + digest \
                     (C5 review F3 fail-closed)",
                );
                quarantined_uuids.insert(plugin_id, uuid_arc);
                continue;
            };
            let Some(json) = grant_json else {
                tracing::error!(
                    plugin_id = %plugin_id,
                    installation_uuid = %uuid,
                    "granted_capabilities_json is NULL (pre-C5 install or corrupt row); \
                     quarantining — reinstall to re-issue the grant \
                     (C5 review F1 fail-closed)",
                );
                quarantined_uuids.insert(plugin_id, uuid_arc);
                continue;
            };
            match serde_json::from_str::<CapabilitiesSection>(&json) {
                Ok(cap) => {
                    // H10 round-5: apply the same
                    // capability-list size caps we enforce at
                    // manifest-validation time to the *persisted*
                    // grant. Without this, a hand-repaired or
                    // future operator-modified row could push
                    // `consumes_services` past
                    // `MAX_CONSUMES_SERVICES_GRANTS` and re-open
                    // the per-dispatch DoS surface — manifest
                    // validation never sees the persisted grant
                    // on the load path.
                    if let Err(errs) = oxidhome_manifest::check_capability_limits_owned(&cap) {
                        tracing::error!(
                            plugin_id = %plugin_id,
                            installation_uuid = %uuid,
                            errors = ?errs,
                            "granted_capabilities_json exceeds capability-list caps; \
                             quarantining — reinstall or hand-repair the JSON \
                             (H10 round-5)",
                        );
                        quarantined_uuids.insert(plugin_id, uuid_arc);
                        continue;
                    }
                    live.insert(
                        plugin_id,
                        LiveInstallation {
                            installation_uuid: uuid_arc,
                            granted_capabilities: Arc::new(cap),
                            content_digest: Arc::<str>::from(digest),
                        },
                    );
                }
                Err(err) => {
                    tracing::error!(
                        plugin_id = %plugin_id,
                        installation_uuid = %uuid,
                        %err,
                        "granted_capabilities_json failed to deserialize; \
                         quarantining — reinstall or hand-repair the JSON \
                         (C5 review F1 fail-closed)",
                    );
                    quarantined_uuids.insert(plugin_id, uuid_arc);
                }
            }
        }
        Ok(LiveInstallationLoad {
            live,
            quarantined_uuids,
        })
    })
}

/// INSERT a fresh installation row. Fails with a unique-constraint
/// error if a live row already exists for `row.plugin_id` — callers
/// (both `install` and the scan backfill) must have ruled out that
/// case beforehand. C5: also persists the granted capabilities
/// JSON + content digest.
fn insert_installation_row(db: &Db, row: &InstalledPlugin) -> Result<(), rusqlite::Error> {
    // H10 round-5: defense-in-depth. Today `install` derives the
    // granted capabilities from the (already-validated) manifest,
    // so the check is redundant on the current path. But every
    // write into `plugin_installation.granted_capabilities_json`
    // funnels through here — a future operator-modify API can
    // reuse this function and picks up the caps automatically,
    // without a callsite forgetting to validate.
    if let Err(errs) =
        oxidhome_manifest::check_capability_limits_owned(row.granted_capabilities.as_ref())
    {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("granted_capabilities exceed size caps: {errs:?}"),
            ),
        )));
    }
    let grant_json = serde_json::to_string(row.granted_capabilities.as_ref()).map_err(|err| {
        // Should never happen — CapabilitiesSection is a plain
        // Serialize struct. Surface as a SqliteFailure with a
        // custom message so callers see the persistence-shaped
        // error class.
        rusqlite::Error::ToSqlConversionFailure(Box::new(err))
    })?;
    db.write(|conn| {
        conn.execute(
            "INSERT INTO plugin_installation
                 (installation_uuid, plugin_id, version, installed_ms, uninstalled_ms,
                  granted_capabilities_json, content_digest)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
            rusqlite::params![
                &*row.installation_uuid,
                &*row.plugin_id,
                &row.version,
                now_ms(),
                &grant_json,
                &*row.content_digest,
            ],
        )?;
        Ok(())
    })
}

/// Hard-delete an installation row. Only called from the install
/// rollback path — a row inserted mid-install that never made it
/// to a completed on-disk state was never really "accepted," so
/// tombstoning it would pollute the historical trace with an
/// entry that never had a working install.
fn delete_installation_row(db: &Db, installation_uuid: &str) -> Result<(), rusqlite::Error> {
    db.write(|conn| {
        conn.execute(
            "DELETE FROM plugin_installation WHERE installation_uuid = ?1",
            [installation_uuid],
        )?;
        Ok(())
    })
}

/// True if `err` is `SQLITE_CONSTRAINT_UNIQUE` (a violation of
/// the `plugin_installation_live` partial unique index). Used to
/// map an INSERT collision to `InstallError::AlreadyInstalled`.
fn is_unique_constraint(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _,
        )
    )
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
/// Phase 13 round-2 finding 5: verify every UI asset
/// path declared in `[ui]` exists as a regular file
/// under `base_dir`. Called from `install` on the staged
/// package (i.e. the exact tree that becomes live), so
/// an installation missing a declared config-schema or
/// widget bundle is refused with a specific reason.
///
/// The manifest validator already enforces that each
/// path is relative and doesn't escape via `.` / `..` /
/// leading `/`, so `base_dir.join(path)` is safe to use.
/// Returns an error message suitable for
/// `InstallError::BadManifest.reason`.
fn check_ui_assets_present(
    ui: &oxidhome_manifest::UiSection,
    base_dir: &Path,
) -> Result<(), String> {
    for (field, path) in [
        ("config", ui.config.as_ref()),
        ("device-config", ui.device_config.as_ref()),
        ("commands", ui.commands.as_ref()),
        ("config-schema", ui.config_schema.as_ref()),
        ("commands-schema", ui.commands_schema.as_ref()),
    ] {
        if let Some(p) = path {
            check_ui_asset_file(field, base_dir, p)?;
        }
    }
    for (index, p) in ui.widgets.iter().enumerate() {
        check_ui_asset_file(&format!("widgets[{index}]"), base_dir, p)?;
    }
    Ok(())
}

fn check_ui_asset_file(field_label: &str, base_dir: &Path, rel: &Path) -> Result<(), String> {
    let full = base_dir.join(rel);
    let metadata = std::fs::metadata(&full).map_err(|err| {
        format!(
            "ui.{field_label} `{}` doesn't exist in the plugin package: {err}",
            rel.display(),
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "ui.{field_label} `{}` must be a regular file",
            rel.display(),
        ));
    }
    Ok(())
}

pub(crate) fn read_manifest_sync(path: &Path) -> anyhow::Result<PluginManifest> {
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

    /// C5: install persists the granted capabilities alongside the
    /// installation row, defaulting to a verbatim copy of the
    /// manifest's requested capabilities. A scan re-reads them.
    #[test]
    fn install_persists_granted_capabilities_matching_manifest() {
        let root = tempdir("granted-persist");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();

        let source = write_plugin_dir(&root, "example.granted");
        let installed = reg.install(&source).expect("install");
        // Grant defaults to the manifest's request — for our test
        // fixture, the CapabilitiesSection is `Default`.
        assert_eq!(
            *installed.granted_capabilities,
            CapabilitiesSection::default()
        );

        // Fresh scan of the same DB re-reads the same grant.
        drop(reg);
        let reg2 = InstalledPluginRegistry::scan(plugins_root, db).unwrap();
        let listed = reg2.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            *listed[0].granted_capabilities,
            CapabilitiesSection::default()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C5 review F1 (fail-closed): a pre-C5 row (NULL grant JSON,
    /// NULL digest) must be quarantined by scan — not silently
    /// resolved from the manifest. The registry doesn't index it
    /// and `is_quarantined(plugin_id)` returns `true` so the
    /// direct-start / argv loader path refuses to shadow the
    /// quarantine with dev-load semantics.
    #[test]
    fn scan_quarantines_pre_c5_row_with_null_grant() {
        let root = tempdir("pre-c5-null-grant");
        let plugins_root = root.join("plugins");
        let db = fresh_db();

        let plugin_id = "example.legacy";
        let uuid = mint_installation_uuid();
        db.write(|conn| {
            conn.execute(
                "INSERT INTO plugin_installation
                     (installation_uuid, plugin_id, version, installed_ms, uninstalled_ms,
                      granted_capabilities_json, content_digest)
                 VALUES (?1, ?2, '0.1.0', 1, NULL, NULL, NULL)",
                rusqlite::params![&*uuid, plugin_id],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
        let plugin_dir = plugins_root.join(plugin_id);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!(
                r#"manifest_version = 1
[plugin]
id = "{plugin_id}"
name = "Legacy"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
            ),
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root, db).unwrap();
        assert!(
            reg.list().is_empty(),
            "pre-C5 NULL grant must be quarantined, not resolved from manifest",
        );
        assert!(
            reg.is_quarantined(plugin_id),
            "quarantined installations must be flagged so direct-start refuses to load them",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C5 round-6 review F1: a quarantined SQL row whose FS dir
    /// went missing (or has no FS entry at all) must still show
    /// up in `is_quarantined()` — otherwise a raw-path CLI load
    /// Follow-up review H8: two dirs whose manifests declare the
    /// same `plugin_id` must both be quarantined. Pre-fix the
    /// second insertion into `entries` silently overwrote the
    /// first, uninstall removed only the winning path, and the
    /// loser's leftover dir got backfilled with a fresh UUID on
    /// the next scan — silently reactivating an install the
    /// operator saw removed.
    #[test]
    fn scan_quarantines_duplicate_manifest_ids() {
        let root = tempdir("duplicate-manifest-ids");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();

        // Two dirs, each with manifest.plugin.id = "example.dup".
        // The second dir's name differs from its manifest id —
        // scan tolerates that (see `dir_name != manifest_id`
        // warn), and pre-H8 the two would silently collide in
        // `entries`.
        for dir_name in ["example.dup", "aliased-dir"] {
            let d = plugins_root.join(dir_name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("manifest.toml"),
                r#"manifest_version = 1
[plugin]
id = "example.dup"
name = "Dup"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
            )
            .unwrap();
            std::fs::write(d.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();
        }

        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        assert!(
            reg.list().is_empty(),
            "duplicate manifest ids must NOT be indexed as installs",
        );
        assert!(
            reg.is_quarantined("example.dup"),
            "duplicate manifest ids must be quarantined so raw-path loads refuse",
        );

        // H8 round-2 F1: a single `uninstall` must yank **every**
        // duplicate dir, tombstone the SQL row, and clear the
        // quarantine entry — so a subsequent scan finds no
        // matching dir at all and can't backfill a fresh UUID
        // (which was the pre-fix reactivation).
        reg.uninstall("example.dup").expect("uninstall");
        for dir_name in ["example.dup", "aliased-dir"] {
            assert!(
                !plugins_root.join(dir_name).exists(),
                "H8 F1 regression: {dir_name} must be removed by a single uninstall",
            );
        }
        assert!(
            !reg.is_quarantined("example.dup"),
            "quarantine entry must clear after uninstall of all duplicate paths",
        );

        // Simulate a restart: fresh scan on the empty plugins
        // root must NOT resurrect the plugin. Pre-fix, one dir
        // would have survived the uninstall, appeared as unique,
        // and gotten backfilled with a fresh UUID.
        let reg2 = InstalledPluginRegistry::scan(plugins_root.clone(), db).unwrap();
        assert!(
            reg2.list().is_empty(),
            "no dir survived uninstall, so scan must produce no entries",
        );
        assert!(
            !reg2.is_quarantined("example.dup"),
            "no dir survived uninstall, so quarantine must be clear",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Follow-up review H1: a quarantined SQL row whose FS dir
    /// went missing (or has no FS entry at all) must still show
    /// up in `is_quarantined()` — otherwise a raw-path CLI load
    /// declaring that `plugin_id` would fall through to dev-load
    /// semantics + synthetic identity. `uninstall` also has to
    /// still work; only the FS-remove step is a no-op.
    #[test]
    fn quarantined_row_without_fs_still_appears_in_is_quarantined() {
        let root = tempdir("quarantined-no-fs");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();
        let db = fresh_db();

        let plugin_id = "example.no-fs";
        let uuid = mint_installation_uuid();
        db.write(|conn| {
            conn.execute(
                "INSERT INTO plugin_installation
                     (installation_uuid, plugin_id, version, installed_ms, uninstalled_ms,
                      granted_capabilities_json, content_digest)
                 VALUES (?1, ?2, '0.1.0', 1, NULL, NULL, NULL)",
                rusqlite::params![&*uuid, plugin_id],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        assert!(
            reg.is_quarantined(plugin_id),
            "quarantined row must appear in is_quarantined even when FS dir is missing",
        );
        reg.uninstall(plugin_id)
            .expect("quarantined uninstall without FS must succeed");
        assert!(!reg.is_quarantined(plugin_id));
        let uninstalled_ms: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation
                     WHERE installation_uuid = ?1",
                    [&*uuid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(uninstalled_ms.is_some());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C5 round-6 review F2: scan-time backfill must refuse to
    /// follow a symlink for the wasm file — a hand-placed plugin
    /// dir whose `plugin.wasm` symlinks to `/dev/zero` would hang
    /// or exhaust memory. `read_no_follow_within` (via `O_NOFOLLOW`
    /// on Unix) returns `InvalidInput`, `read_installed_bytes`
    /// propagates.
    #[cfg(unix)]
    #[test]
    fn read_installed_bytes_refuses_symlinked_wasm() {
        use std::os::unix::fs::symlink;
        let root = tempdir("symlinked-wasm");
        let plugin_dir = root.join("example.symlinked");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.symlinked"
name = "Sym"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        let outside = root.join("outside.wasm");
        std::fs::write(&outside, b"\0asm\x01\x00\x00\x00").unwrap();
        symlink(&outside, plugin_dir.join("plugin.wasm")).unwrap();

        let err =
            read_installed_bytes(&plugin_dir, std::path::Path::new("plugin.wasm")).unwrap_err();
        // On Linux, O_NOFOLLOW yields ELOOP (which surfaces as
        // FilesystemLoop); the wrapping err kind can differ per
        // OS. Assert the error is present rather than pinning
        // the exact kind.
        assert!(!err.to_string().is_empty(), "symlinked wasm must fail");

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C5 review F1: a live installation row whose
    /// `granted_capabilities_json` refuses to deserialize must be
    /// **quarantined** (skipped by scan, not indexed) rather than
    /// silently falling back to the manifest's request. Also
    /// mustn't be tombstoned — the operator repairs the row and
    /// the next scan indexes normally.
    #[test]
    fn scan_quarantines_installation_with_malformed_grant_json() {
        let root = tempdir("malformed-grant");
        let plugins_root = root.join("plugins");
        let db = fresh_db();

        // Install cleanly, then corrupt the grant JSON manually.
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let source = write_plugin_dir(&root, "example.corrupt");
        let installed = reg.install(&source).expect("install");
        let uuid = Arc::clone(&installed.installation_uuid);
        drop(reg);

        // Overwrite the grant with garbage JSON.
        db.write(|conn| {
            conn.execute(
                "UPDATE plugin_installation
                    SET granted_capabilities_json = ?2
                  WHERE installation_uuid = ?1",
                rusqlite::params![&*uuid, "this is not { valid } json"],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();

        let reg2 = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        // Quarantined — not indexed.
        assert!(
            reg2.list().is_empty(),
            "malformed grant must quarantine the installation",
        );

        // But the row must still be live (identity intact —
        // operator can repair the grant and reindex).
        let uninstalled_ms: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation
                     WHERE installation_uuid = ?1",
                    [&*uuid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(
            uninstalled_ms.is_none(),
            "quarantine must not tombstone; row stays live for operator repair",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C5 review F2: `effective_capabilities` = requested ∩
    /// granted. A stale grant broader than the current
    /// manifest's request must not authorize the extra
    /// permissions.
    #[test]
    fn effective_capabilities_intersects_requested_and_granted() {
        use oxidhome_manifest::CapabilitiesSection;
        let requested = CapabilitiesSection {
            declares_devices: vec!["dimmer".into()],
            declares_services: vec![],
            storage_quota_kb: 100,
            blob_quota_mb: 50,
            subscribes_events: true,
            ..CapabilitiesSection::default()
        };
        let granted = CapabilitiesSection {
            declares_devices: vec!["switch".into(), "dimmer".into()],
            declares_services: vec!["automation".into()],
            storage_quota_kb: 1_000,
            blob_quota_mb: 10,
            subscribes_events: true,
            ..CapabilitiesSection::default()
        };
        let effective = effective_capabilities(&requested, &granted);
        // Set-shaped fields intersect on equality.
        assert_eq!(effective.declares_devices, vec!["dimmer".to_string()]);
        assert!(effective.declares_services.is_empty());
        // Quotas take the minimum.
        assert_eq!(effective.storage_quota_kb, 100);
        assert_eq!(effective.blob_quota_mb, 10);
        // Boolean fields AND.
        assert!(effective.subscribes_events);

        // A granted-false wins over requested-true.
        let narrow = CapabilitiesSection {
            subscribes_events: false,
            ..granted.clone()
        };
        let effective = effective_capabilities(&requested, &narrow);
        assert!(!effective.subscribes_events);
    }

    /// H10 round-4: `effective_capabilities` carries the granted
    /// `consumes_services` list through unchanged. Intersection is
    /// applied at dispatch time (via `any_grant_matches` on both
    /// the requested and granted lists), not at install time —
    /// see the round-4 rationale on the doc for
    /// `effective_capabilities`.
    #[test]
    fn effective_capabilities_carries_granted_consumes_services_through() {
        use oxidhome_manifest::CapabilitiesSection;
        let requested = CapabilitiesSection {
            consumes_services: vec![ServiceGrant {
                plugin: "example.counter".into(),
                instance: "*".into(),
                service: "counter".into(),
                commands: vec!["*".into()],
                caller_instance: "*".into(),
            }],
            ..CapabilitiesSection::default()
        };
        let granted = CapabilitiesSection {
            consumes_services: vec![ServiceGrant {
                plugin: "example.counter".into(),
                instance: "foo".into(),
                service: "counter".into(),
                commands: vec!["get".into()],
                caller_instance: "caller-a".into(),
            }],
            ..CapabilitiesSection::default()
        };
        let effective = effective_capabilities(&requested, &granted);
        assert_eq!(effective.consumes_services, granted.consumes_services);
    }

    /// H10 round-4: `any_grant_matches` is the dispatcher-side
    /// authorization predicate. Runs once against the caller's
    /// requested list and once against the operator's granted
    /// list; both must return true. No cross-product, no
    /// materialization.
    #[test]
    fn any_grant_matches_matches_against_the_call_tuple() {
        let grants = vec![
            ServiceGrant {
                plugin: "example.counter".into(),
                instance: "foo".into(),
                service: "counter".into(),
                commands: vec!["get".into()],
                caller_instance: "caller-a".into(),
            },
            ServiceGrant {
                plugin: "example.other".into(),
                instance: "*".into(),
                service: "svc".into(),
                commands: vec!["*".into()],
                caller_instance: "*".into(),
            },
        ];
        // First entry matches.
        assert!(any_grant_matches(
            &grants,
            "caller-a",
            "example.counter",
            "foo",
            "counter",
            "get",
        ));
        // Second entry (wildcard) matches for any target instance +
        // command on `example.other`.
        assert!(any_grant_matches(
            &grants,
            "any-caller",
            "example.other",
            "any-instance",
            "svc",
            "ping",
        ));
        // Wrong instance for `example.counter` → miss.
        assert!(!any_grant_matches(
            &grants,
            "caller-a",
            "example.counter",
            "bar",
            "counter",
            "get",
        ));
        // Empty grants → always deny.
        assert!(!any_grant_matches(
            &[],
            "caller-a",
            "example.counter",
            "foo",
            "counter",
            "get",
        ));
    }

    /// H10 round-5: a persisted `granted_capabilities_json` that
    /// exceeds `MAX_CONSUMES_SERVICES_GRANTS` is quarantined at
    /// scan time — a hand-repaired row (or a future operator
    /// tool that skips manifest validation) can't push per-call
    /// authorization work back into the O(N) blowup region.
    #[test]
    fn scan_quarantines_persisted_grant_exceeding_capability_caps() {
        use oxidhome_manifest::validate::MAX_CONSUMES_SERVICES_GRANTS;
        let root = tempdir("h10r5-oversize-grant");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();
        let db = fresh_db();

        // Build an oversize grant JSON directly (bypassing
        // insert_installation_row, which enforces the caps
        // defense-in-depth) so we exercise the load-path check.
        let mut oversized = Vec::new();
        for i in 0..=MAX_CONSUMES_SERVICES_GRANTS {
            oversized.push(oxidhome_manifest::ServiceGrant {
                plugin: format!("example.p{i}"),
                instance: "*".into(),
                service: "svc".into(),
                commands: vec!["*".into()],
                caller_instance: "*".into(),
            });
        }
        let caps = oxidhome_manifest::CapabilitiesSection {
            consumes_services: oversized,
            ..oxidhome_manifest::CapabilitiesSection::default()
        };
        let grant_json = serde_json::to_string(&caps).unwrap();

        let plugin_id = "example.oversized";
        let uuid = mint_installation_uuid();
        db.write(|conn| {
            conn.execute(
                "INSERT INTO plugin_installation
                     (installation_uuid, plugin_id, version, installed_ms, uninstalled_ms,
                      granted_capabilities_json, content_digest)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
                rusqlite::params![
                    &*uuid,
                    plugin_id,
                    "0.1.0",
                    now_ms(),
                    &grant_json,
                    "digest-fake",
                ],
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .unwrap();

        // Populate a matching install dir so the scan doesn't
        // reject on missing FS.
        let install_dir = plugins_root.join(&*uuid);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(
            install_dir.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.oversized"
name = "Oversized"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "x.wasm"
"#,
        )
        .unwrap();
        std::fs::write(install_dir.join("x.wasm"), b"stub").unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        assert!(
            reg.is_quarantined(plugin_id),
            "oversized persisted grant must land in quarantine",
        );
        assert!(
            reg.list().iter().all(|p| p.plugin_id.as_ref() != plugin_id),
            "quarantined install must not appear in the live registry",
        );
    }

    /// C5 review F3: install must derive the grant from the
    /// **staged** manifest, not the source, so a broad request in
    /// the source that changes to a narrow one between reads
    /// can't land a broad grant with a narrow package. (We
    /// simulate this by asserting the staged read is the one
    /// used: the grant on the returned row equals the source
    /// manifest's declared capabilities, which are copied
    /// verbatim into staging.)
    #[test]
    fn install_derives_grant_from_staged_not_source_manifest() {
        use oxidhome_manifest::CapabilitiesSection;
        let root = tempdir("grant-staged");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();

        // Source manifest declares a non-default grant (storage
        // quota) so we can tell if it's the one that landed.
        let source = root.join("source-staged");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.staged"
name = "Staged"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[capabilities]
storage_quota_kb = 42
subscribes_events = true
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(source.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let installed = reg.install(&source).expect("install");
        // Grant matches the (staged copy of the) source manifest.
        assert_eq!(
            *installed.granted_capabilities,
            CapabilitiesSection {
                storage_quota_kb: 42,
                subscribes_events: true,
                ..CapabilitiesSection::default()
            }
        );

        // Persisted grant JSON round-trips through scan.
        drop(reg);
        let reg2 = InstalledPluginRegistry::scan(plugins_root, db).unwrap();
        let listed = reg2.list();
        assert_eq!(
            *listed[0].granted_capabilities,
            *installed.granted_capabilities
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b fixup review F3 (P2): a hand-placed / restored plugin
    /// dir whose `plugin_id` has an existing tombstone must NOT
    /// be silently deleted by scan (the earlier cut of this
    /// recovery path did that). The operator restored the package
    /// intentionally; scan should mint a fresh UUID and keep the
    /// dir. The historical tombstone survives so the identity
    /// rotation is auditable.
    #[test]
    fn scan_backfills_hand_placed_dir_with_tombstoned_history() {
        let root = tempdir("restored-after-tombstone");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();

        let source = write_plugin_dir(&root, "example.rotate");
        let first = reg.install(&source).expect("install");
        let first_uuid = Arc::clone(&first.installation_uuid);
        reg.uninstall("example.rotate").expect("uninstall");
        drop(reg);

        // Operator hand-restores the plugin dir (or a valid
        // replacement package) under the same `plugin_id` after
        // the tombstone landed.
        let restored = plugins_root.join("example.rotate");
        std::fs::create_dir_all(&restored).unwrap();
        std::fs::copy(source.join("manifest.toml"), restored.join("manifest.toml")).unwrap();
        std::fs::copy(source.join("plugin.wasm"), restored.join("plugin.wasm")).unwrap();

        let reg2 = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let listed = reg2.list();
        assert_eq!(listed.len(), 1, "restored package must be indexed");
        assert!(
            restored.exists(),
            "restored dir must not be destroyed by scan",
        );
        assert_ne!(
            &*listed[0].installation_uuid, &*first_uuid,
            "restoration must mint a fresh UUID (not resurrect the tombstoned identity)",
        );

        // The historical tombstone survives; a live row was
        // inserted for the fresh identity.
        let rows: Vec<(String, Option<i64>)> = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT installation_uuid, uninstalled_ms
                     FROM plugin_installation
                     WHERE plugin_id = ?1
                     ORDER BY installed_ms",
                )?;
                let rows = stmt.query_map(["example.rotate"], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].1.is_some(), "historical tombstone preserved");
        assert!(rows[1].1.is_none(), "restoration inserts a fresh live row");

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b fixup review F2 (P1): a temporarily-unreadable manifest
    /// on an installed plugin dir must NOT cause its live SQL row
    /// to be tombstoned by the orphan-live-row sweep. That would
    /// turn a fixable file blip into permanent identity rotation.
    #[test]
    fn scan_does_not_tombstone_live_row_for_dir_with_bad_manifest() {
        let root = tempdir("bad-manifest-live");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let source = write_plugin_dir(&root, "example.brokenmani");
        let installed = reg.install(&source).expect("install");
        let uuid = Arc::clone(&installed.installation_uuid);
        drop(reg);

        // Corrupt the manifest of the installed dir so scan can't
        // parse it (the dir is still there).
        std::fs::write(
            plugins_root.join("example.brokenmani/manifest.toml"),
            "not valid toml [[[",
        )
        .unwrap();

        let _reg2 = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        // Live row must survive — the dir is on disk, just
        // unreadable.
        let uninstalled_ms: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation
                     WHERE installation_uuid = ?1",
                    [&*uuid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(
            uninstalled_ms.is_none(),
            "unreadable manifest must not tombstone the live SQL row",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b fixup2 review F1 (P2): a dir named `example.foo` whose
    /// manifest declares a different `example.bar` must tombstone
    /// the live SQL row for `example.foo` (nothing on disk actually
    /// represents that `plugin_id` anymore) and index / backfill
    /// `example.bar`. The pre-fix code protected both ids because
    /// it observed the dir name too.
    #[test]
    fn scan_tombstones_live_row_when_manifest_renames_plugin_id() {
        let root = tempdir("aliased-rename");
        let plugins_root = root.join("plugins");
        let db = fresh_db();
        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), Arc::clone(&db)).unwrap();
        let source = write_plugin_dir(&root, "example.foo");
        let old = reg.install(&source).expect("install foo");
        let foo_uuid = Arc::clone(&old.installation_uuid);
        drop(reg);

        // Operator (or corrupt update) rewrites the manifest to
        // declare `example.bar` while the dir is still named
        // `example.foo`. `scan` explicitly accepts this and
        // indexes by the manifest id, so nothing on disk still
        // represents `example.foo`.
        std::fs::write(
            plugins_root.join("example.foo/manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.bar"
name = "Renamed"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();

        let reg2 = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        let listed = reg2.list();
        assert_eq!(listed.len(), 1, "one indexed entry (example.bar)");
        assert_eq!(&*listed[0].plugin_id, "example.bar");

        // Old `example.foo` row must be tombstoned.
        let foo_uninstalled: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation
                     WHERE installation_uuid = ?1",
                    [&*foo_uuid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(
            foo_uninstalled.is_some(),
            "orphaned live row for example.foo must be tombstoned after manifest rename",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b fixup2 review F2 (P2): if any dir on disk has an
    /// unresolvable manifest (unreadable / unsafe id), the orphan
    /// sweep must be deferred entirely so a live row for a
    /// DIFFERENT `plugin_id` — which happens to have no matching
    /// dir on disk — is NOT tombstoned this boot. The unresolvable
    /// dir might BE that `plugin_id`; we can't tell.
    #[test]
    fn scan_defers_orphan_sweep_when_any_dir_is_unresolvable() {
        let root = tempdir("defer-sweep");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();
        let db = fresh_db();

        // Hand-INSERT a live SQL row for an "orphan" plugin_id
        // whose dir is absent. Under normal semantics scan would
        // tombstone this. But we also plant an unresolvable dir
        // to trigger the defer.
        let ghost = InstalledPlugin {
            plugin_id: Arc::from("example.ghost"),
            installation_uuid: mint_installation_uuid(),
            version: "0.1.0".to_string(),
            path: plugins_root.join("example.ghost"),
            granted_capabilities: Arc::new(CapabilitiesSection::default()),
            content_digest: Arc::from("0".repeat(64)),
        };
        insert_installation_row(&db, &ghost).unwrap();
        let ghost_uuid = Arc::clone(&ghost.installation_uuid);

        // Unresolvable dir: valid dir but broken manifest.
        let broken = plugins_root.join("some-dir");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("manifest.toml"), "not toml [[[").unwrap();

        let _reg = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();

        // The orphan row must NOT be tombstoned — deferred.
        let uninstalled_ms: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation
                     WHERE installation_uuid = ?1",
                    [&*ghost_uuid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(
            uninstalled_ms.is_none(),
            "orphan sweep must be deferred when any dir is unresolvable",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b review F2 (other reviewer, P1): a `.staging-<id>/` dir
    /// left over from a crashed install must not become an active
    /// install on the next scan.
    #[test]
    fn scan_removes_leftover_staging_dir_and_does_not_index_it() {
        let root = tempdir("staging-crash");
        let plugins_root = root.join("plugins");
        std::fs::create_dir_all(&plugins_root).unwrap();

        // Hand-craft a `.staging-<id>/` dir with a valid manifest
        // (the pre-fix scan would have indexed it as an install).
        let staging = plugins_root.join(".staging-example.crashed");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(
            staging.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.crashed"
name = "Crashed"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(staging.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root.clone(), fresh_db()).unwrap();
        assert!(
            reg.list().is_empty(),
            "staging dir must not be indexed as an install",
        );
        assert!(
            !staging.exists(),
            "scan must remove leftover staging directories",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// C1b review F3 (P1): after a crashed install (SQL INSERT
    /// landed but FS didn't) the next scan sees a live SQL row
    /// with no matching FS dir and must auto-tombstone it so a
    /// retry install can succeed.
    #[test]
    fn scan_auto_tombstones_orphan_live_row_with_no_fs_entry() {
        let root = tempdir("orphan-live");
        let plugins_root = root.join("plugins");
        let db = fresh_db();

        // Hand-INSERT a live row for a plugin_id whose FS dir is
        // absent — the shape a crashed install leaves behind.
        let ghost = InstalledPlugin {
            plugin_id: Arc::from("example.ghost"),
            installation_uuid: mint_installation_uuid(),
            version: "0.1.0".to_string(),
            path: plugins_root.join("example.ghost"),
            granted_capabilities: Arc::new(CapabilitiesSection::default()),
            content_digest: Arc::from("0".repeat(64)),
        };
        insert_installation_row(&db, &ghost).unwrap();

        let reg = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db)).unwrap();
        assert!(reg.list().is_empty());

        // The row was auto-tombstoned by the scan.
        let uninstalled_ms: Option<i64> = db
            .read(|conn| {
                conn.query_row(
                    "SELECT uninstalled_ms FROM plugin_installation WHERE plugin_id = ?1",
                    ["example.ghost"],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(
            uninstalled_ms.is_some(),
            "scan must auto-tombstone the orphan live row",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
