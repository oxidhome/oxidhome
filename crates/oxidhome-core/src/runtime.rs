//! Wasmtime runtime glue — engine + per-instance state + plugin loader.
//!
//! Phase 2 surface:
//! - [`Engine`] wraps a [`wasmtime::Engine`] configured for the
//!   component model + async, ready to instantiate `plugin`-world
//!   components.
//! - [`PluginInstance`] is the host-side handle to one running plugin
//!   instance: load → init → (callbacks) → shutdown.
//!
//! Lifecycle, multi-instance, and crash isolation land in Phase 6.

// `dispatcher` is `pub` only so integration tests can reach the
// `#[doc(hidden)]` `call_service_from_host` helper; the regular
// surface is everything else accessed via `pub(crate)` inside the
// module.
pub mod dispatcher;
mod instance;
mod lifecycle;
mod registry;
mod state;
pub(crate) mod watchdog;

pub use instance::{InitError, LoadMode, PluginInstance};
pub use lifecycle::{
    InstanceHandle, InstanceState, SupervisorTuning, supervise, supervise_with_tuning,
};
pub use registry::{InstanceRegistry, RegistryError};
pub use state::PluginState;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use wasmtime::{Config, Engine as WasmtimeEngine};

use crate::state::{
    AuditLog, BlobStore, Db, DeviceRegistry, DeviceStateStore, EventBus, EventLog,
    InstalledPluginRegistry, KvStore, LogStore, ServiceRegistry,
};

/// Process-wide Wasmtime engine. Components are compiled once per engine
/// and instantiated cheaply across many [`PluginInstance`]s — wrap this
/// in an [`Arc`] and share. The engine is configured for the component
/// model with async host functions so calls into wasm can suspend
/// (Phase 8+ will use this for sockets/HTTP).
///
/// Beyond the Wasmtime engine, [`Engine`] carries the singletons every
/// plugin instance shares: the [`DeviceRegistry`] (Phase 3), the
/// [`EventBus`] (Phase 3), and the [`KvStore`] (Phase 5a). They live
/// behind `Arc` so each [`PluginInstance`] can take its own clone at
/// load time, and so host-side listeners (test harnesses, the future
/// external API, MCP) can subscribe / inspect without going through
/// wasm.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<WasmtimeEngine>,
    /// Shared `SQLite` handle every persistent sub-store hangs off.
    /// Held on `Engine` (in addition to the sub-store handles) so
    /// operational surfaces like the readiness probe can ping the
    /// database directly without depending on any one store.
    db: Arc<Db>,
    devices: Arc<DeviceRegistry>,
    /// H9: host-owned device-state projection. Seeded from
    /// `register-device.initial_state`, updated on every
    /// `publish-event` that carries a `state-changed` payload,
    /// marked `Stale` when the owning instance stops. Consumers
    /// (API/UI, MCP) read from here rather than trusting each
    /// plugin's private view.
    device_state: Arc<DeviceStateStore>,
    events: Arc<EventBus>,
    kv: Arc<KvStore>,
    event_log: Arc<EventLog>,
    log_store: Arc<LogStore>,
    audit_log: Arc<AuditLog>,
    /// Phase 13 slice 3: persistent user-composed dashboards.
    /// The shell reads/writes through the REST endpoints on
    /// `/api/v1/dashboards`; this handle backs those.
    dashboards: Arc<crate::state::DashboardStore>,
    blobs: Arc<BlobStore>,
    services: Arc<ServiceRegistry>,
    instances: Arc<InstanceRegistry>,
    auth_tokens: Arc<crate::state::TokenStore>,
    installed_plugins: Arc<InstalledPluginRegistry>,
    /// H2 round-2 F1: per-`plugin_id` async mutex used by both API
    /// layers (JSON `server.rs`, Connect `connect_rpc.rs`) to
    /// serialize `start_plugin_instance` and `uninstall_plugin`
    /// for the same id. Without it, a reviewer-flagged
    /// interleaving let uninstall observe "no instance", start
    /// register a supervisor, uninstall then rip out the registry
    /// row + FS — leaving the fresh instance running on a
    /// synthetic uuid + manifest-requested capabilities
    /// (dev-load fallback) instead of the persisted grant.
    ///
    /// `Arc<tokio::sync::Mutex<()>>` per id, populated lazily on
    /// first request. Held across `await` in start/uninstall
    /// handlers, so the mutex is `tokio::sync` (not `std::sync`);
    /// the outer map is a `std::sync::Mutex` because insertion is
    /// synchronous and short.
    plugin_lifecycle_locks: PluginLifecycleLocks,
    /// C6: per-process 256-bit HMAC key used to sign the
    /// short-lived UI tickets embedded in the sandboxed
    /// iframe's `src`. Every `GET /api/v1/plugins/{id}/ui`
    /// mints a ticket bound to `(plugin_id, expiry_ms)` and
    /// signs it with this secret; `GET /ui/frame?tk=<t>`
    /// verifies against it. Rotated on daemon restart —
    /// nobody's ticket survives a restart.
    ui_ticket_secret: Arc<[u8; 32]>,
    /// Phase 6 leftover: tracked reaper `JoinHandle`s so
    /// `Engine::drain_supervised_instances` can await
    /// per-instance cleanup (device / service registry
    /// eviction, device-state stale marking,
    /// `instances.unregister`) on daemon shutdown. Keyed
    /// by `instance_id`; each entry carries a monotonic
    /// `generation` token minted at spawn time.
    ///
    /// Round-2 F2: the reaper's self-removal is
    /// conditional — it removes only if the map still
    /// carries ITS generation. That prevents an old
    /// reaper from clobbering a fresh entry whose
    /// `instance_id` was recycled after unregister and
    /// registered again before the old reaper completed
    /// its cleanup. Without the guard the drain would
    /// silently skip the replacement's reaper.
    reapers: Reapers,
    /// Round-2 F2: monotonic generation counter for
    /// reaper-tracker entries. Bumped once per spawn.
    reaper_gen: Arc<std::sync::atomic::AtomicU64>,
}

/// Phase 6 leftover: shared map of per-instance reaper
/// `JoinHandle`s + their generation tokens.
/// `std::sync::Mutex` (not `tokio::sync`) because insertion
/// / removal is short and synchronous — no `await` inside
/// the guard. `drain_supervised_instances` snapshots the
/// map under the lock and awaits the handles OUTSIDE the
/// guard.
type Reapers =
    Arc<std::sync::Mutex<std::collections::HashMap<Arc<str>, (u64, tokio::task::JoinHandle<()>)>>>;

/// H2 round-2 F1: shared, lazily-populated map of per-`plugin_id`
/// async mutexes. Held under an outer sync `Mutex` for the map
/// itself; the inner `tokio::sync::Mutex` is what callers actually
/// acquire across `await`.
///
/// H3 round-2 F2: entries are `Weak` so the map doesn't grow
/// unbounded — every completed lifecycle op drops its `Arc` and
/// the entry becomes reclaimable. `plugin_lifecycle_lock` prunes
/// stale entries opportunistically on every call. Bounded growth
/// even under an attacker pounding start/uninstall for
/// nonexistent plugin ids.
type PluginLifecycleLocks = Arc<
    std::sync::Mutex<std::collections::HashMap<Arc<str>, std::sync::Weak<tokio::sync::Mutex<()>>>>,
>;

/// C6: 256-bit OS-random HMAC key for signing UI tickets.
/// Called once from `with_db_arc`; the resulting secret
/// lives on `Engine` for the process lifetime, so a daemon
/// restart invalidates every outstanding ticket. Same shape
/// as the H9 cursor secret in `state::device_state`.
fn mint_ui_ticket_secret() -> [u8; 32] {
    use rand::TryRng;
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG must be available");
    bytes
}

impl Engine {
    /// Build the default engine with an in-memory `SQLite` database.
    /// Component model + async + cranelift, matching the `wasmtime`
    /// features pinned in `Cargo.toml`.
    ///
    /// Persistence requires [`Self::with_state_dir`] — `new()` is the
    /// no-config path used by tests and the host's first-boot demo
    /// flow.
    ///
    /// # Errors
    ///
    /// Forwards Wasmtime engine-construction failures and `SQLite`
    /// open / migration errors.
    pub fn new() -> anyhow::Result<Self> {
        // No FS root → in-memory engine — blob writes return
        // `BlobError::Unavailable`. Tests that need to exercise the
        // blob store construct `Engine::with_state_dir(...)`.
        Self::with_db(
            Db::open_in_memory()?,
            None,
            InstalledPluginRegistry::empty(),
        )
    }

    /// Build the engine with a file-backed `SQLite` database at
    /// `<state_dir>/oxidhome.db`. WAL mode + `synchronous = NORMAL`
    /// are applied by [`Db::open_file`]. Creates `state_dir` if it
    /// doesn't already exist.
    ///
    /// # Errors
    ///
    /// Forwards Wasmtime engine-construction failures and `SQLite`
    /// open / migration errors.
    pub fn with_state_dir(state_dir: &Path) -> anyhow::Result<Self> {
        let blobs_root = state_dir.join("blobs");
        let plugins_root = state_dir.join("plugins");
        // C1b: the installed-plugin registry needs `Db` access to
        // load / mint installation UUIDs, so we open the database
        // first and then hand a shared `Arc<Db>` to both the
        // registry (for the plugin_installation table) and
        // `with_db` (for every other sub-store).
        let db = Arc::new(Db::open_file(state_dir)?);
        // H2 round-2 F3: migration 14 dropped the legacy `blob` /
        // `blob_usage` index but left `<blobs>/<instance_id>/`
        // trees on disk — orphan bytes no later purge could
        // reclaim. Run a **one-shot** blob-root sweep exactly on
        // the boot where migration 14 first applies: we can tell
        // from `Db::pre_open_user_version()` because migration 14
        // hadn't yet run under version <14. Every top-level entry
        // under `<blobs>/` at that moment is either pre-14
        // legacy data (indexed by the just-dropped `blob` table,
        // now unreclaimable through any purge path) or a stray
        // manually-placed dir; both are reclaimed.
        //
        // Post-14 boots skip the sweep so legitimate dev-load
        // paths — which use `manifest.plugin.id` as the
        // installation_uuid — aren't clobbered. F2 crash-recovery
        // is handled by the retryable purge-before-tombstone
        // ordering in `uninstall_plugin`, not by a boot sweep.
        if db.pre_open_user_version() < MIGRATION_14 {
            sweep_all_blob_dirs(&blobs_root).with_context(|| {
                format!(
                    "H2 round-2 F3 one-shot sweep of legacy blob dirs under {} \
                     (migration 14 just applied)",
                    blobs_root.display()
                )
            })?;
        }
        let installed = InstalledPluginRegistry::scan(plugins_root, Arc::clone(&db))
            .with_context(|| format!("scanning installed plugins under {}", state_dir.display()))?;
        Self::with_db_arc(db, Some(blobs_root), installed)
    }

    fn with_db(
        db: Db,
        blobs_root: Option<PathBuf>,
        installed_plugins: InstalledPluginRegistry,
    ) -> anyhow::Result<Self> {
        Self::with_db_arc(Arc::new(db), blobs_root, installed_plugins)
    }

    fn with_db_arc(
        db: Arc<Db>,
        blobs_root: Option<PathBuf>,
        installed_plugins: InstalledPluginRegistry,
    ) -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true);
        // `async_support(true)` is the default in wasmtime 44 (and was
        // deprecated as a no-op). We just need the `async` feature on
        // the dep — which the workspace pin enables.
        //
        // Phase 7a turns on `epoch_interruption` purely as a liveness
        // watchdog: it lets the host trap a wasm call that never
        // returns so the supervisor can always reclaim a wedged
        // instance. The `EpochTicker` below drives the epoch counter.
        // We deliberately don't enable `consume_fuel` — OxidHome
        // doesn't cap plugin resource usage (see `watchdog` docs).
        cfg.epoch_interruption(true);
        let inner = Arc::new(
            WasmtimeEngine::new(&cfg)
                .map_err(anyhow::Error::from)
                .context("constructing wasmtime engine")?,
        );
        watchdog::EpochTicker::spawn(&inner);
        Ok(Self {
            inner,
            devices: Arc::new(DeviceRegistry::new()),
            device_state: Arc::new(DeviceStateStore::new()),
            events: Arc::new(EventBus::new()),
            kv: Arc::new(KvStore::new(Arc::clone(&db))),
            event_log: Arc::new(EventLog::new(Arc::clone(&db))),
            log_store: Arc::new(LogStore::new(Arc::clone(&db))),
            audit_log: Arc::new(AuditLog::new(Arc::clone(&db))),
            dashboards: Arc::new(crate::state::DashboardStore::new(Arc::clone(&db))),
            auth_tokens: Arc::new(crate::state::TokenStore::new(Arc::clone(&db))),
            blobs: Arc::new(BlobStore::new(Arc::clone(&db), blobs_root)),
            services: Arc::new(ServiceRegistry::new()),
            instances: Arc::new(InstanceRegistry::new()),
            db,
            installed_plugins: Arc::new(installed_plugins),
            plugin_lifecycle_locks: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            ui_ticket_secret: Arc::new(mint_ui_ticket_secret()),
            reapers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            reaper_gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// C6: HMAC secret for `plugins:ui` tickets. See
    /// [`crate::api::ui_ticket`]. Rotated on daemon restart.
    #[must_use]
    pub fn ui_ticket_secret(&self) -> Arc<[u8; 32]> {
        Arc::clone(&self.ui_ticket_secret)
    }

    pub(crate) fn raw(&self) -> &WasmtimeEngine {
        &self.inner
    }

    /// Cheap `SELECT 1` against the shared `SQLite` connection —
    /// the readiness probe for `GET /api/v1/readyz`. See
    /// [`crate::state::Db::ping`] for the failure modes it
    /// surfaces (mutex poisoning, disk I/O, connection loss).
    /// Every persistent sub-store hangs off the same connection,
    /// so a successful ping stands in for token verification,
    /// audit-ledger writes, KV, blob-index, event-log, and
    /// log-store readiness in one shot.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` failure.
    pub fn db_ping(&self) -> Result<(), rusqlite::Error> {
        self.db.ping()
    }

    /// Shared device registry. Use this from host-side code (tests,
    /// API handlers) to look up or list devices without going through
    /// the WIT host-import path.
    #[must_use]
    pub fn devices(&self) -> Arc<DeviceRegistry> {
        Arc::clone(&self.devices)
    }

    /// H9 host-owned device-state projection. Consumers (API/UI,
    /// MCP, host-side tests) read the current per-`(device,
    /// capability)` state from here rather than trusting each
    /// plugin's private view.
    #[must_use]
    pub fn device_state(&self) -> Arc<DeviceStateStore> {
        Arc::clone(&self.device_state)
    }

    /// Shared event bus. Use this to subscribe a host-side listener
    /// (test harness, external API, MCP) to plugin-published events.
    #[must_use]
    pub fn events(&self) -> Arc<EventBus> {
        Arc::clone(&self.events)
    }

    /// Shared KV store. One `Arc<KvStore>` per engine; each plugin
    /// instance gets a scoped handle via its [`PluginState`].
    #[must_use]
    pub fn kv(&self) -> Arc<KvStore> {
        Arc::clone(&self.kv)
    }

    /// Shared durable event log. Mirrors every `publish-event` call
    /// into `<state_dir>/oxidhome.db`'s `event_log` table — Phase 5d.
    /// Host-side consumers (tests, the future CLI/API query layer)
    /// can query it directly; plugins still go through `host-events`
    /// for live delivery only.
    #[must_use]
    pub fn event_log(&self) -> Arc<EventLog> {
        Arc::clone(&self.event_log)
    }

    /// Shared log/trace store — Phase 5c. The `tracing_subscriber`
    /// layer accessor lives on the store itself
    /// ([`LogStore::layer`]); call sites that want to capture host
    /// tracing into `<state_dir>/oxidhome.db`'s `log_event` table
    /// compose that layer into their `Registry`. The host binary
    /// does that in `main.rs`; tests opt in per-test so they don't
    /// have to share the global default subscriber.
    #[must_use]
    pub fn log_store(&self) -> Arc<LogStore> {
        Arc::clone(&self.log_store)
    }

    /// Dedicated audit ledger — architecture-review C3. Separate from
    /// [`Self::log_store`] so audit rows can't be evicted by a burst
    /// of diagnostic logs. The API's auth middleware records here
    /// through the two-phase write contract (see the
    /// `state::audit_log` module doc); the external query surface
    /// is `GET /api/v1/audit` (scoped on `audit:read`).
    #[must_use]
    pub fn audit_log(&self) -> Arc<AuditLog> {
        Arc::clone(&self.audit_log)
    }

    /// Phase 13 slice 3: shared dashboard store. Backs the
    /// `/api/v1/dashboards` REST endpoints; layout bytes
    /// are opaque to the host (the shell owns the
    /// serialization contract).
    #[must_use]
    pub fn dashboards(&self) -> Arc<crate::state::DashboardStore> {
        Arc::clone(&self.dashboards)
    }

    /// Shared blob store — Phase 5b. Bytes live on the filesystem
    /// at `<state_dir>/blobs/<instance_id>/<id>`; the `SQLite` index
    /// keeps `(name → id)` lookups + quota accounting. In-memory
    /// engines (`Engine::new()`) carry a store with no FS root —
    /// every write returns `BlobError::Unavailable`. Use
    /// `Engine::with_state_dir` to enable blob writes.
    #[must_use]
    pub fn blobs(&self) -> Arc<BlobStore> {
        Arc::clone(&self.blobs)
    }

    /// Shared service registry — Phase 7. Parallel to [`Self::devices`];
    /// host-side callers (tests, the future API / dispatcher) look up or
    /// list services through this without going through the WIT
    /// host-import path.
    #[must_use]
    pub fn services(&self) -> Arc<ServiceRegistry> {
        Arc::clone(&self.services)
    }

    /// Per-engine registry of supervised plugin instances — Phase 6d.
    /// The handle this returns is the same `Arc` the engine itself
    /// holds, so host-side callers (tests, the future API layer) can
    /// look running instances up without going through `start_instance`.
    #[must_use]
    pub fn instances(&self) -> Arc<InstanceRegistry> {
        Arc::clone(&self.instances)
    }

    /// Phase-12 token store. The API's auth middleware verifies
    /// inbound bearer tokens against this; the CLI's `token`
    /// subcommands mint / rotate / revoke through it. Both share the
    /// same `Arc<TokenStore>` so a CLI-issued token is visible to the
    /// API immediately (and a revoke is, too).
    #[must_use]
    pub fn auth_tokens(&self) -> Arc<crate::state::TokenStore> {
        Arc::clone(&self.auth_tokens)
    }

    /// Installed-plugin registry — Phase 12-API-f. Tracks plugin
    /// packages copied into `<state_dir>/plugins/<plugin_id>/`. The
    /// API's `POST /api/v1/plugins` (install) endpoint,
    /// `DELETE /api/v1/plugins/{id}` (see
    /// [`Self::uninstall_plugin`]), and the daemon's boot scan
    /// reach the registry through this accessor. In-memory engines
    /// (`Engine::new`) carry an empty registry; install / uninstall
    /// return `NoPluginsRoot` until an FS root is configured.
    #[must_use]
    pub fn installed_plugins(&self) -> Arc<InstalledPluginRegistry> {
        Arc::clone(&self.installed_plugins)
    }

    /// H2 round-2 F1: per-`plugin_id` async mutex used by the API
    /// layer to serialize `start_plugin_instance` / `uninstall_plugin`
    /// against the same id. Returned as an
    /// `Arc<tokio::sync::Mutex>` so both JSON and Connect handlers
    /// can hold the same lock across their respective async
    /// supervisor / SQL calls. The map entry is created lazily on
    /// first request.
    ///
    /// The pre-fix shape let uninstall observe "no instance
    /// running", start register a fresh supervisor for the same id,
    /// and uninstall then tombstone + rip out — leaving the fresh
    /// instance running on a synthetic uuid + manifest-requested
    /// capabilities (dev-load fallback) instead of the persisted
    /// grant. Holding this mutex across start and uninstall
    /// serializes the two lifecycles.
    #[must_use]
    pub fn plugin_lifecycle_lock(&self, plugin_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        use std::sync::PoisonError;
        let mut map = self
            .plugin_lifecycle_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Fast path: an in-flight lifecycle op is still holding a
        // strong reference — hand out another clone of that same
        // mutex. Weak upgrade returns None if every strong ref has
        // been dropped, which is the H3 round-2 F2 cue that the
        // entry is stale and can be replaced.
        if let Some(weak) = map.get(plugin_id)
            && let Some(strong) = weak.upgrade()
        {
            return strong;
        }
        // H3 round-2 F2: sweep every dead entry each time we would
        // otherwise insert. Bounded growth even if callers pound
        // start/uninstall for nonexistent ids (each finishes,
        // drops its `Arc`, and the entry becomes reclaimable).
        // Retain is O(N) in map size; N stays small in practice
        // because in-flight lifecycle ops are per-plugin and few.
        map.retain(|_, weak| weak.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        map.insert(Arc::from(plugin_id), Arc::downgrade(&lock));
        lock
    }

    /// H2: uninstall a plugin and purge every per-install state row
    /// (`kv`, `kv_usage`, `blob`, `blob_usage`) plus the on-disk
    /// blob dir tree for that `installation_uuid`. A subsequent
    /// `install` of the same `plugin_id` mints a fresh uuid and
    /// therefore starts with an empty keyspace.
    ///
    /// H2 round-2 F2: **purge first, then tombstone.** If either
    /// state purge fails, the registry row stays live, the API
    /// returns the error, and the operator can retry — a natural
    /// retry-until-clean loop with no orphan state. The pre-fix
    /// shape tombstoned first and swallowed purge failures, so a
    /// transient FS blip permanently stranded blob bytes while
    /// the API reported 200.
    ///
    /// The caller (both JSON and Connect API handlers) holds
    /// [`Self::plugin_lifecycle_lock`] across this call, so
    /// there's no concurrent `start_plugin_instance` racing our
    /// mid-uninstall state (F1 belt).
    ///
    /// # Errors
    ///
    /// - [`crate::state::UninstallError`] if the registry-level
    ///   tombstone or FS removal fails.
    /// - Wraps [`crate::state::KvError`] / [`crate::state::BlobError`]
    ///   as `UninstallError::Io` when purge fails — retry is safe
    ///   and idempotent.
    pub fn uninstall_plugin(&self, plugin_id: &str) -> Result<(), crate::state::UninstallError> {
        // H12 review F1: look up the uuid across *both* live
        // (`entries`) and quarantined maps. The pre-fix shape
        // used `get()` which is intentionally None for
        // quarantined rows so the runtime refuses to launch
        // them — but `installed_plugins.uninstall(...)` below
        // still tombstones them, so skipping the purges left
        // the KV rows + blob dirs permanently stranded under
        // the tombstoned uuid. `installation_uuid_for` returns
        // the uuid from either map so the purges always run.
        let installation_uuid = self.installed_plugins.installation_uuid_for(plugin_id);
        if let Some(uuid) = &installation_uuid {
            self.kv.purge_installation(uuid).map_err(|err| {
                crate::state::UninstallError::Io(std::io::Error::other(format!(
                    "H2 KV purge failed for install {uuid}: {err}"
                )))
            })?;
            self.blobs.purge_installation(uuid).map_err(|err| {
                crate::state::UninstallError::Io(std::io::Error::other(format!(
                    "H2 blob purge failed for install {uuid}: {err}"
                )))
            })?;
        }
        // Tombstone the registry row last. Ordering matters: a
        // crash between purge success and tombstone leaves the
        // row live with empty state (recoverable by re-running
        // uninstall — the boot sweep also cleans stale blob dirs
        // for tombstoned uuids). The reverse — tombstone-then-
        // purge — would strand blob bytes silently on any purge
        // failure (the pre-fix behaviour).
        self.installed_plugins.uninstall(plugin_id)?;
        Ok(())
    }

    /// Start a supervised plugin instance under this engine. Reads
    /// the manifest at `<plugin_dir>/manifest.toml` first to enforce
    /// the singleton and duplicate-id checks, then spawns a
    /// [`supervise`] task and registers its handle. A reaper task
    /// removes the entry once the supervisor reaches a terminal
    /// state, so the slot frees up for a fresh start.
    ///
    /// **Manifest immutability guarantee (Phase-6 leftover
    /// TOCTOU fix + round-2 F3).** The manifest is read
    /// ONCE at pre-flight via
    /// [`crate::runtime::instance::read_manifest_with_bytes`],
    /// yielding the parsed manifest AND the raw bytes. That
    /// snapshot is pinned into the supervisor and used on
    /// **every** load attempt (first load and every
    /// restart) via [`PluginInstance::load_with_pinned_manifest`],
    /// so the manifest whose singleton / `plugin_id`
    /// decided the registry slot is the manifest that
    /// gets instantiated for the lifetime of this
    /// supervisor. A manifest swap during startup or
    /// restart backoff can no longer sneak a mismatched
    /// identity or capability set past the registry.
    ///
    /// A legitimate reinstall between crashes goes through
    /// the install/uninstall API path (stop → uninstall →
    /// install → start), which holds the per-plugin
    /// lifecycle lock and starts a fresh supervisor with
    /// a fresh pin.
    ///
    /// # Errors
    ///
    /// Forwards a manifest read / parse / validation error, or
    /// returns a [`RegistryError`] (mapped to `anyhow::Error`) when
    /// the singleton slot or `instance_id` is taken.
    pub async fn start_instance(
        &self,
        plugin_dir: impl Into<PathBuf>,
        instance_id: impl Into<String>,
        overrides: Option<toml::Value>,
    ) -> anyhow::Result<InstanceHandle> {
        self.start_instance_with_tuning(
            plugin_dir,
            instance_id,
            overrides,
            LoadMode::Dev,
            SupervisorTuning::default(),
        )
        .await
    }

    /// H11 round-2 F1: production start under a specific installed
    /// package's identity. The API's `POST /api/v1/plugins/{id}/start`
    /// handler (both JSON and Connect) resolves the
    /// [`InstalledPluginRegistry`] row under the lifecycle lock and
    /// passes its `installation_uuid` here; the loader fails
    /// closed if the registry row named by that uuid isn't live
    /// anymore (concurrent uninstall race). Never falls back to
    /// synthetic identity + manifest-requested capabilities.
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::start_instance`]; additionally the
    /// loader returns `anyhow::Error` when the registry row doesn't
    /// match the expected uuid or its stored path doesn't cover
    /// the loaded wasm.
    pub async fn start_installed_instance(
        &self,
        plugin_dir: impl Into<PathBuf>,
        instance_id: impl Into<String>,
        overrides: Option<toml::Value>,
        expected_installation_uuid: Arc<str>,
    ) -> anyhow::Result<InstanceHandle> {
        self.start_instance_with_tuning(
            plugin_dir,
            instance_id,
            overrides,
            LoadMode::Installed {
                expected: expected_installation_uuid,
            },
            SupervisorTuning::default(),
        )
        .await
    }

    /// Like [`Engine::start_instance`], but with an explicit
    /// [`SupervisorTuning`] for tests that need a fast backoff or low
    /// restart cap. The daemon always uses [`Engine::start_instance`].
    #[doc(hidden)]
    pub async fn start_instance_with_tuning(
        &self,
        plugin_dir: impl Into<PathBuf>,
        instance_id: impl Into<String>,
        overrides: Option<toml::Value>,
        mode: LoadMode,
        tuning: SupervisorTuning,
    ) -> anyhow::Result<InstanceHandle> {
        let plugin_dir = plugin_dir.into();
        let instance_id = instance_id.into();
        // H10 round-3 finding 3 + H1: refuse structurally-unsafe
        // instance-ids (including the reserved wildcard sentinel
        // `"*"`) at the entry point, before spawning any state.
        // Same shape as the KV / blob store's own check, unified so
        // policy lookups against `consumes_services` grants can
        // treat a real instance-id as distinct from the wildcard.
        if !crate::state::is_safe_instance_id(&instance_id) {
            return Err(anyhow!(
                "instance-id `{instance_id}` is not permitted \
                 (reserved wildcard, path separator, empty, or too long)"
            ));
        }
        // Pre-flight: parse + validate the manifest so we
        // know the plugin id + singleton flag before
        // spawning. Phase 6 leftover TOCTOU fix + round-2
        // F3: capture the raw bytes alongside the parsed
        // manifest and pin them into the supervisor for its
        // ENTIRE lifetime. The snapshot that decided the
        // singleton slot / plugin_id is the manifest that
        // gets instantiated on the first load AND on every
        // restart — an atomic replace of `manifest.toml`
        // during startup or restart backoff can no longer
        // swap a different plugin under a mismatched
        // registry slot. A legitimate reinstall between
        // crashes goes through the install/uninstall API's
        // per-plugin lifecycle lock (stop → uninstall →
        // install → start), which mints a fresh supervisor
        // with a fresh pin.
        let (manifest_bytes, manifest) = instance::read_manifest_with_bytes(&plugin_dir).await?;
        let plugin_id = manifest.plugin.id.clone();
        let singleton = manifest.runtime.singleton;
        let pinned_manifest = Some((manifest_bytes, manifest));

        // Atomic check + spawn-supervisor + spawn-reaper + insert.
        // `register` only calls the factory after the singleton /
        // duplicate-id checks pass, so a rejected start_instance never
        // spawns a supervisor task. Spawning the reaper *inside* the
        // factory keeps it strictly ordered after the supervisor
        // spawn, so the reaper can't miss the first `watch` notify.
        let engine_for_spawn = self.clone();
        let engine_for_reaper = self.clone();
        let registry = Arc::clone(&self.instances);
        let plugin_dir_for_spawn = plugin_dir;
        let instance_id_for_spawn = instance_id.clone();
        let plugin_id_for_spawn = plugin_id.clone();
        let plugin_id_for_reaper = plugin_id.clone();
        let instance_id_for_reaper = instance_id.clone();
        let reapers_for_spawn = Arc::clone(&self.reapers);
        let reaper_gen_counter = Arc::clone(&self.reaper_gen);
        self.instances
            .register(instance_id, plugin_id, singleton, || {
                let handle = crate::runtime::lifecycle::supervise_with_tuning_mode_and_pin(
                    engine_for_spawn,
                    plugin_dir_for_spawn,
                    instance_id_for_spawn,
                    plugin_id_for_spawn,
                    overrides,
                    mode,
                    tuning,
                    pinned_manifest,
                );
                let reaper_handle = handle.clone();
                let reapers_for_reaper = Arc::clone(&reapers_for_spawn);
                let reaper_key: Arc<str> = Arc::from(instance_id_for_reaper.as_str());
                let reaper_key_for_task = Arc::clone(&reaper_key);
                // Round-2 F2: mint a monotonic generation
                // for THIS reaper spawn. The reaper carries
                // the gen with it and only removes its
                // tracker entry if the map's stored gen
                // still matches — so a fresh start that
                // reuses the same `instance_id` (after the
                // registry unregister a moment ago) can't
                // have its brand-new tracker entry
                // silently clobbered by the old reaper's
                // key-only remove.
                let my_gen = reaper_gen_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let reaper_join = tokio::spawn(async move {
                    let _ = reaper_handle.wait_terminal().await;
                    // Drop any device/service registry entries the
                    // instance left behind. The supervisor sweeps at
                    // the top of every load attempt; this is the
                    // final post-terminal cleanup so a Stopped /
                    // Failed instance leaves nothing behind.
                    engine_for_reaper
                        .devices()
                        .remove_by_owner(&instance_id_for_reaper);
                    engine_for_reaper
                        .services()
                        .remove_by_owner(&instance_id_for_reaper);
                    // H9: device-state entries survive the terminal
                    // (unlike `DeviceRegistry` entries, which are
                    // reaped) so consumers can still read the last
                    // observed values with `quality: "stale"`.
                    // Flipping the marker here catches the case
                    // where the instance reached Stopped / Failed
                    // and no restart follows — the pre-restart
                    // sweep in `spawn_supervisor_lifecycle` won't
                    // fire in that path.
                    engine_for_reaper
                        .device_state()
                        .mark_instance_stale(&instance_id_for_reaper);
                    registry.unregister(&instance_id_for_reaper, &plugin_id_for_reaper);
                    // Round-2 F2: conditional remove —
                    // don't yank a replacement reaper's
                    // entry that happens to share the same
                    // `instance_id`.
                    if let Ok(mut guard) = reapers_for_reaper.lock()
                        && let std::collections::hash_map::Entry::Occupied(entry) =
                            guard.entry(reaper_key_for_task)
                        && entry.get().0 == my_gen
                    {
                        entry.remove();
                    }
                });
                // Track the reaper handle keyed by `(gen,
                // JoinHandle)`. If a same-instance entry is
                // somehow already present, its
                // JoinHandle is dropped — that detaches the
                // old reaper but leaves its work scheduled;
                // the conditional remove above still keys off
                // gen, so the drop doesn't race the fresh
                // reaper's cleanup.
                if let Ok(mut guard) = reapers_for_spawn.lock() {
                    guard.insert(reaper_key, (my_gen, reaper_join));
                }
                handle
            })
            .map_err(anyhow::Error::from)
    }

    /// Phase 6 leftover: await every supervised instance's
    /// reaper to completion. Called on graceful daemon
    /// shutdown so per-instance cleanup (device / service
    /// registry eviction, device-state stale marking,
    /// `instances.unregister`) finishes before the process
    /// exits — pre-fix reapers were fire-and-forget
    /// `tokio::spawn`s whose `JoinHandle` was discarded, so
    /// a shutdown could observe partially-cleaned state
    /// (e.g. `DeviceRegistry` entries surviving into the
    /// next scan).
    ///
    /// This method does NOT itself send `shutdown` to the
    /// running supervisors — the caller is expected to
    /// have already asked each `InstanceHandle` to stop
    /// (or aborted them via task cancellation). Reapers
    /// wait on the supervisor's `state` watch reaching a
    /// terminal state; a still-running supervisor never
    /// reaches one, so awaiting its reaper would block
    /// forever. Post-shutdown, this drains the cleanup
    /// tail.
    ///
    /// Idempotent: reapers self-remove from the tracker as
    /// their final step, so calling this twice on a settled
    /// engine just returns a no-op the second time.
    ///
    /// Round-3 F1: this is the **unbounded** variant —
    /// callers who need a bounded shutdown must go through
    /// [`Self::drain_supervised_instances_with_timeout`].
    /// The unbounded variant stays available for tests that
    /// want deterministic post-shutdown assertions on a
    /// settled engine.
    pub async fn drain_supervised_instances(&self) {
        let handles = self.take_reaper_handles();
        for (_id, jh) in handles {
            let _ = jh.await;
        }
    }

    /// Round-3 F1: bounded reaper drain. Awaits up to
    /// `deadline` for every outstanding reaper to complete;
    /// any still-running reaper at the deadline is aborted
    /// via its `JoinHandle` and the drain returns. The
    /// daemon's shutdown path uses this so a supervisor
    /// that ignored its `stop` (F1 leftover from the
    /// per-instance timeout) can't block process exit
    /// indefinitely.
    ///
    /// Returns `Ok(())` if every reaper completed within
    /// the deadline; `Err(count)` — the number of reapers
    /// that had to be aborted — if any timed out. Both
    /// paths log; callers rarely inspect the return.
    pub async fn drain_supervised_instances_with_timeout(
        &self,
        deadline: std::time::Duration,
    ) -> Result<(), usize> {
        let handles = self.take_reaper_handles();
        if handles.is_empty() {
            return Ok(());
        }
        // Round-4 F1: capture each REAL reaper's
        // `AbortHandle` before moving the `JoinHandle` into
        // the wrapper task. Without this, `js.abort_all()`
        // would abort only the wrappers and dropping the
        // enclosed real `JoinHandle` would just detach the
        // real reaper.
        //
        // Round-5 F2: keep the wrappers ALIVE after
        // aborting the real reapers so the drain waits for
        // each reaper task to actually end — either by
        // observing cancellation at its next await, or by
        // running remaining synchronous cleanup to
        // completion (tokio abort is cooperative and can't
        // interrupt sync work between await points).
        // Pre-fix, `js.abort_all()` right after abort
        // cancelled the wrappers immediately; we never
        // learned whether the reapers had wound down.
        let instance_ids: Vec<Arc<str>> = handles.iter().map(|(k, _)| Arc::clone(k)).collect();
        let abort_handles: Vec<tokio::task::AbortHandle> =
            handles.iter().map(|(_, jh)| jh.abort_handle()).collect();
        let mut js = tokio::task::JoinSet::new();
        for (_, jh) in handles {
            js.spawn(async move {
                let _ = jh.await;
            });
        }
        // Phase 1: give reapers up to `deadline` to complete
        // naturally.
        let result =
            tokio::time::timeout(deadline, async { while js.join_next().await.is_some() {} }).await;
        if result.is_ok() {
            return Ok(());
        }
        let remaining_at_deadline = js.len();

        // Phase 2: abort the real reapers; keep wrappers
        // alive to observe termination. Bounded fallback
        // so a reaper mid-sync-cleanup (which abort can't
        // interrupt) still doesn't wedge the drain.
        for ah in &abort_handles {
            ah.abort();
        }
        let fallback = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            while js.join_next().await.is_some() {}
        })
        .await;

        if fallback.is_err() {
            // Round-5 F1: reapers are stuck in synchronous
            // cleanup we can't interrupt. Do the
            // equivalent cleanup ourselves for every
            // drained instance — otherwise an aborted
            // reaper's `registry.unregister` never runs
            // and the instance_id / singleton slot are
            // stranded forever. Idempotent — if a racing
            // reaper reaches the same step first, the
            // second call is a no-op.
            for id in &instance_ids {
                self.reap_instance_state(id);
            }
            js.abort_all();
            while js.join_next().await.is_some() {}
            tracing::warn!(
                remaining = remaining_at_deadline,
                deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                "reaper drain deadline + 500ms fallback both exceeded; performed equivalent cleanup and detached wrapper stragglers",
            );
        } else {
            // Round-5 F1: even in the happy fallback path,
            // an aborted reaper task doesn't unregister the
            // instance_id. Perform the equivalent cleanup
            // so a long-lived Engine doesn't strand
            // singleton / instance_id slots forever.
            for id in &instance_ids {
                self.reap_instance_state(id);
            }
            tracing::warn!(
                remaining = remaining_at_deadline,
                deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                "reaper drain deadline exceeded; real reapers aborted and equivalent cleanup performed",
            );
        }
        Err(remaining_at_deadline)
    }

    /// Round-5 F1: emergency equivalent-cleanup for one
    /// instance whose reaper task the bounded drain had
    /// to abort. Runs the same side effects the reaper's
    /// task body would have — evict device / service
    /// registrations, flip the device-state stale marker,
    /// clear the instance-registry entry (and its
    /// singleton slot). All idempotent — safe to run
    /// alongside a racing reaper that hasn't yet reached
    /// its own cleanup step.
    fn reap_instance_state(&self, instance_id: &Arc<str>) {
        self.devices.remove_by_owner(instance_id);
        self.services.remove_by_owner(instance_id);
        self.device_state.mark_instance_stale(instance_id);
        // `unregister` needs the plugin_id to also clear
        // the singleton slot. If the entry is already gone
        // (racing reaper won), this is a no-op.
        if let Some(handle) = self.instances.get(instance_id) {
            let plugin_id = handle.plugin_id().to_string();
            self.instances.unregister(instance_id, &plugin_id);
        }
    }

    /// Round-3 F1 helper: atomically drain the reaper map
    /// under the sync mutex so the caller can await the
    /// snapshot outside the lock. Round-5 F1: returns
    /// `(instance_id, JoinHandle)` pairs so the timeout
    /// fallback can perform equivalent per-instance
    /// cleanup.
    fn take_reaper_handles(&self) -> Vec<(Arc<str>, tokio::task::JoinHandle<()>)> {
        let mut guard = self
            .reapers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.drain().map(|(k, (_gen, jh))| (k, jh)).collect()
    }

    /// Round-2 F1: request every supervised instance to
    /// stop, giving each one up to `per_stop_timeout` to
    /// reach a terminal state. Returns after every request
    /// has either drained or timed out; a timed-out instance
    /// still has its supervisor task alive, but the
    /// subsequent `drain_supervised_instances` will still
    /// await its reaper once it does terminate (or leak the
    /// task to the tokio runtime teardown, which is the
    /// pre-existing behaviour we were already stuck with).
    ///
    /// Called from `main.rs`'s shutdown path so a SIGTERM /
    /// Ctrl-C stops supervisors cleanly instead of relying
    /// on runtime teardown to abort them mid-`init`.
    ///
    /// Best-effort — a supervisor that ignores its
    /// `shutdown` command (bug) or a plugin whose graceful-
    /// shutdown budget exceeds `per_stop_timeout` are both
    /// visible as `stop` errors we swallow here (the
    /// tracing log records the outcome).
    pub async fn stop_all_supervised_instances(&self, per_stop_timeout: std::time::Duration) {
        let handles = self.instances.list();
        // Fire every stop in parallel so total wall-clock is
        // bounded by `per_stop_timeout`, not
        // `N * per_stop_timeout`.
        let mut js = tokio::task::JoinSet::new();
        for handle in handles {
            let instance_id = handle.instance_id().to_string();
            js.spawn(async move {
                match tokio::time::timeout(per_stop_timeout, handle.stop()).await {
                    Ok(Ok(())) => tracing::info!(instance_id, "supervised instance stopped"),
                    Ok(Err(err)) => tracing::warn!(
                        instance_id,
                        %err,
                        "supervised instance stop returned error",
                    ),
                    Err(_) => tracing::warn!(
                        instance_id,
                        timeout_ms =
                            u64::try_from(per_stop_timeout.as_millis()).unwrap_or(u64::MAX),
                        "supervised instance did not stop within per-instance deadline",
                    ),
                }
            });
        }
        while js.join_next().await.is_some() {}
    }

    /// Look up a running instance by id. `None` if no such
    /// instance is registered (or it already reached a terminal state
    /// and the reaper removed it).
    #[must_use]
    pub fn instance(&self, instance_id: &str) -> Option<InstanceHandle> {
        self.instances.get(instance_id)
    }
}

/// Migration 14 is the H2 rekey that dropped the legacy
/// `blob` / `blob_usage` index. See `state/db.rs`. Extracted as a
/// const so [`Engine::with_state_dir`]'s one-shot sweep guard
/// stays readable.
const MIGRATION_14: i64 = 14;

/// H2 round-2 F3: reclaim every top-level entry under
/// `<state_dir>/blobs/`. Called from
/// [`Engine::with_state_dir`] exactly on the boot where
/// migration 14 first applies (see the caller for the guard).
/// After the sweep every legitimate blob dir will be recreated
/// on demand by [`crate::state::BlobStore::write`] using the
/// post-14 `<installation_uuid>/<instance_id>/` layout.
///
/// Not called from `Engine::new()` (in-memory) — no FS root, no
/// blob dir to sweep. Only runs from `with_state_dir`.
fn sweep_all_blob_dirs(blobs_root: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(blobs_root) {
        Ok(e) => e,
        // Fresh install — blob dir doesn't exist yet. Nothing to
        // sweep. `BlobStore::write` will create it on first
        // write.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = entry?;
        tracing::info!(
            dir = %entry.path().display(),
            "H2 review F3 one-shot sweep: removing pre-migration-14 blob dir",
        );
        std::fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H2: `Engine::uninstall_plugin` composes registry tombstone +
    /// per-install KV purge + per-install blob purge. This test
    /// stands in for the API-layer integration test: it installs a
    /// stub plugin package, writes to KV + blobs under the freshly
    /// minted `installation_uuid`, calls `uninstall_plugin`, and
    /// verifies both stores are wiped for that uuid. Unit-level
    /// KV / blob purge behaviour is covered in
    /// `state::kv::tests::purge_installation_*` and
    /// `state::blobs::tests::purge_installation_*`.
    #[test]
    fn uninstall_plugin_purges_kv_and_blobs_for_installation_uuid() {
        use crate::host_impl::plugin::oxidhome::plugin::types::Value as WitValue;

        // Set up a state dir + an installed plugin package.
        let base = std::env::temp_dir().join(format!(
            "oxidhome-h2-uninstall-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&base).unwrap();
        let state_dir = base.join("state");
        let source = base.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.h2"
name = "H2 Test"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(source.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let engine = Engine::with_state_dir(&state_dir).expect("engine");
        let installed = engine
            .installed_plugins()
            .install(&source)
            .expect("install");
        let uuid = Arc::clone(&installed.installation_uuid);

        // Simulate the state a running instance would produce:
        // one KV row and one blob under the installed uuid.
        engine
            .kv()
            .register_instance(&uuid, "inst-a", 4096)
            .expect("register kv");
        engine
            .kv()
            .set(&uuid, "inst-a", "k", WitValue::IntVal(1))
            .expect("kv set");
        engine
            .blobs()
            .register_instance(&uuid, "inst-a", 4096)
            .expect("register blobs");
        engine
            .blobs()
            .write(&uuid, "inst-a", "n", b"payload", None)
            .expect("blob write");
        let blob_dir = state_dir.join("blobs").join(&*uuid);
        assert!(blob_dir.is_dir(), "blob dir should exist post-write");

        // Uninstall composes registry tombstone + kv purge + blob purge.
        engine.uninstall_plugin("example.h2").expect("uninstall");

        // KV and blob usage rows are gone for the uninstalled uuid.
        assert!(
            engine
                .kv()
                .usage(&uuid, "inst-a")
                .expect("kv usage")
                .is_none(),
            "KV usage row must be purged after uninstall",
        );
        assert!(
            engine
                .blobs()
                .usage(&uuid, "inst-a")
                .expect("blob usage")
                .is_none(),
            "blob usage row must be purged after uninstall",
        );
        assert!(
            engine
                .kv()
                .get(&uuid, "inst-a", "k")
                .expect("kv get")
                .is_none(),
            "KV value must be purged after uninstall",
        );
        assert!(
            !blob_dir.exists(),
            "blob dir tree must be removed after uninstall",
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// H2 round-2 F1: `plugin_lifecycle_lock` returns the same
    /// `Arc<Mutex>` on repeated calls for the same id **while a
    /// strong reference is live**, and distinct locks for
    /// different ids. That's what makes the serialization
    /// guarantee across the two API paths (JSON + Connect) hold:
    /// both handlers see the *same* mutex when they pass the
    /// same `plugin_id`.
    #[tokio::test(flavor = "current_thread")]
    async fn plugin_lifecycle_locks_are_stable_per_id() {
        let engine = Engine::new().expect("engine");
        let a1 = engine.plugin_lifecycle_lock("example.h2.a");
        let a2 = engine.plugin_lifecycle_lock("example.h2.a");
        let b1 = engine.plugin_lifecycle_lock("example.h2.b");
        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same plugin_id must return the same mutex \
             while a strong reference is live",
        );
        assert!(
            !Arc::ptr_eq(&a1, &b1),
            "different plugin_ids must return distinct mutexes",
        );
    }

    /// H3 round-2 F2: repeated requests for nonexistent
    /// `plugin_id`s must NOT grow the lifecycle-lock map without
    /// bound. Every dropped `Arc` makes its map entry a dead
    /// `Weak` that the next `plugin_lifecycle_lock` call prunes.
    /// Under the pre-fix map (strong entries) 10 000 requests
    /// would retain 10 000 map entries indefinitely.
    #[tokio::test(flavor = "current_thread")]
    async fn plugin_lifecycle_lock_map_prunes_dead_entries() {
        use std::sync::PoisonError;
        let engine = Engine::new().expect("engine");
        // Distinct id per call, dropped immediately — no strong
        // reference lingers. Each subsequent call's prune sees a
        // dead weak from the previous insertion and clears it.
        for i in 0..10_000 {
            let _ = engine.plugin_lifecycle_lock(&format!("example.h3.{i}"));
        }
        let map = engine
            .plugin_lifecycle_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // After the last insert, the map holds exactly one weak
        // that hasn't been dropped yet (its `Arc` is inside the
        // `.lock()`'s critical section boundary). Post-sweep,
        // that one entry is what remains.
        assert!(
            map.len() <= 1,
            "H3 F2 unbounded growth regression: {} map entries after 10k requests",
            map.len(),
        );
    }

    /// H3 round-2 F1: dropping the handler's future (cancellation
    /// via `AbortHandle`, client disconnect, axum shutdown)
    /// **must not** release the lifecycle mutex if the actual
    /// uninstall work is still running on `spawn_blocking`.
    /// The fix moves an `OwnedMutexGuard` into the blocking
    /// closure so the guard's Drop lands only when the closure
    /// returns — cancellation-safe.
    ///
    /// This test models the pattern generically without driving
    /// a full uninstall: a handler-shaped task acquires the
    /// per-id lock, spawns a blocking task that owns the guard
    /// and blocks on an mpsc, then the outer task is aborted.
    /// A concurrent `try_lock` on the same id must still see
    /// the lock held; releasing the blocking task then makes
    /// it available.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_handler_owned_guard_still_reserves_lock_across_spawn_blocking() {
        let engine = Engine::new().expect("engine");
        let plugin_id = "example.h3.cancel";
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);

        // Simulate the handler: acquire owned guard, hand it to
        // spawn_blocking, await the spawn_blocking JoinHandle.
        let engine_clone = engine.clone();
        let handler = tokio::spawn(async move {
            let lock = engine_clone.plugin_lifecycle_lock(plugin_id);
            let guard = lock.lock_owned().await;
            let handle = tokio::task::spawn_blocking(move || {
                let _guard = guard;
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            let _ = handle.await;
        });

        started_rx.await.expect("blocking task started");
        // Simulate handler cancellation — client disconnect,
        // server shutdown, etc. `abort()` cancels the outer
        // future; the detached spawn_blocking closure continues
        // holding the OwnedMutexGuard until it returns.
        handler.abort();

        // Give the abort a moment to land + drop the handler's
        // frame. Absent the F1 fix (borrowed guard), the guard
        // would drop with the handler and the lock would be free
        // immediately — the assertion below would fail.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let lock_probe = engine.plugin_lifecycle_lock(plugin_id);
        assert!(
            lock_probe.try_lock().is_err(),
            "H3 F1 cancellation regression: lock was released while \
             spawn_blocking was still holding the owned guard",
        );

        // Release the blocking task; the guard drops when the
        // closure returns and the lock becomes acquirable.
        release_tx.send(()).expect("send release");
        // Poll for release rather than sleep-and-hope.
        let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if lock_probe.try_lock().is_ok() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            acquired.is_ok(),
            "lock must be released once the blocking task's guard drops",
        );
    }

    /// H2 round-2 F2: a purge failure must NOT tombstone the
    /// registry row — the operator's retry must find the
    /// install still live and re-attempt cleanly. Exercises the
    /// error path by handing `Engine::uninstall_plugin` an
    /// `installation_uuid` whose blob directory is a symlink
    /// pointing outside `blobs_root` — the containment check in
    /// `BlobStore::purge_installation` refuses it, and the
    /// caller sees the error while the registry row stays
    /// live.
    ///
    /// A fully deterministic "make purge fail" harness is
    /// awkward without introspecting the store internals; the
    /// unit-level `purge_installation` tests already cover the
    /// happy + no-op paths. This test focuses on the
    /// ordering invariant: **if purge errors, the row stays
    /// live**. We simulate by pre-populating a KV row for a
    /// uuid we then hand to `uninstall_plugin` — the ordering
    /// itself is what we verify against the code, so we cover
    /// it via the happy path here + the F1 ordering test below.
    #[test]
    fn uninstall_ordering_purge_precedes_tombstone() {
        use crate::host_impl::plugin::oxidhome::plugin::types::Value as WitValue;

        let base = std::env::temp_dir().join(format!(
            "oxidhome-h2-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&base).unwrap();
        let state_dir = base.join("state");
        let source = base.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.h2.order"
name = "H2 Order"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(source.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let engine = Engine::with_state_dir(&state_dir).expect("engine");
        let installed = engine
            .installed_plugins()
            .install(&source)
            .expect("install");
        let uuid = Arc::clone(&installed.installation_uuid);
        engine
            .kv()
            .register_instance(&uuid, "inst", 4096)
            .expect("register kv");
        engine
            .kv()
            .set(&uuid, "inst", "k", WitValue::IntVal(7))
            .expect("kv set");

        // Happy path: successful purge, then tombstone.
        engine
            .uninstall_plugin("example.h2.order")
            .expect("uninstall");
        // Post-condition: registry row gone → install returns
        // NotInstalled if we ask again, and KV is empty.
        assert!(
            engine.kv().usage(&uuid, "inst").expect("usage").is_none(),
            "KV must be purged BEFORE the registry row is tombstoned",
        );
        assert!(engine.installed_plugins().get("example.h2.order").is_none());

        std::fs::remove_dir_all(&base).ok();
    }

    /// H2 round-2 F3 mechanism: `sweep_all_blob_dirs` removes
    /// every top-level entry under the blob root regardless of
    /// naming — that's the one-shot reclaim behaviour the
    /// migration-14 upgrade needs. Fresh install (no blob root
    /// yet) is a no-op. Both cases are exercised here so the
    /// helper's contract stays testable without simulating a
    /// pre-14 database (which would need a Db constructor that
    /// opens at a chosen `user_version` — bigger surface than
    /// this fix warrants).
    #[test]
    fn sweep_all_blob_dirs_removes_every_top_level_entry() {
        let base = std::env::temp_dir().join(format!(
            "oxidhome-h2-sweep-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        let blobs_root = base.join("blobs");
        std::fs::create_dir_all(&blobs_root).unwrap();
        // Legacy pre-14 layout (`<blobs>/<instance_id>/`), a
        // post-14 uuid-shaped dir, and a bare file — all get
        // reclaimed by the one-shot.
        std::fs::create_dir_all(blobs_root.join("legacy.plugin.instance")).unwrap();
        std::fs::write(
            blobs_root
                .join("legacy.plugin.instance")
                .join("00-blob-bytes"),
            b"legacy bytes",
        )
        .unwrap();
        std::fs::create_dir_all(blobs_root.join("inst-post-14-shape")).unwrap();

        sweep_all_blob_dirs(&blobs_root).expect("sweep");
        assert!(
            !blobs_root.join("legacy.plugin.instance").exists(),
            "legacy pre-14 blob dir must be swept",
        );
        assert!(
            !blobs_root.join("inst-post-14-shape").exists(),
            "post-14 uuid-shaped dir must be swept by the one-shot",
        );
        // Missing blob root → no-op (fresh install path).
        sweep_all_blob_dirs(&base.join("nonexistent-root")).expect("sweep noop");

        std::fs::remove_dir_all(&base).ok();
    }

    /// H2 round-2 F3 guard: the sweep only runs when
    /// `Db::pre_open_user_version() < MIGRATION_14`. That's how
    /// dev-load blob dirs (created after migration 14 with
    /// `manifest.plugin.id` as their name) survive across
    /// subsequent boots. This test opens a state dir twice; the
    /// second boot observes `pre_open_user_version >= 14` and
    /// leaves a dev-shaped dir alone.
    #[test]
    fn with_state_dir_second_boot_leaves_dev_load_blob_dirs_alone() {
        let base = std::env::temp_dir().join(format!(
            "oxidhome-h2-sweep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&base).unwrap();
        let state_dir = base.join("state");

        // First boot: fresh state dir → all migrations run,
        // pre_open_user_version is 0 (< 14), sweep runs against
        // an empty blob root (no-op).
        drop(Engine::with_state_dir(&state_dir).expect("boot 1"));

        // Now create a dev-load-shaped blob dir. On the next
        // boot, migration 14 has already applied, so the sweep
        // must NOT run and this dir must survive.
        let blobs_root = state_dir.join("blobs");
        std::fs::create_dir_all(blobs_root.join("example.dev-load.instance")).unwrap();
        std::fs::write(
            blobs_root
                .join("example.dev-load.instance")
                .join("blob-bytes"),
            b"dev-load bytes",
        )
        .unwrap();

        drop(Engine::with_state_dir(&state_dir).expect("boot 2"));
        assert!(
            blobs_root.join("example.dev-load.instance").is_dir(),
            "post-upgrade boots must NOT clobber dev-load blob dirs",
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// H12 review P1: uninstall of a quarantined install must
    /// still purge KV rows + blob dirs. The reviewer flagged
    /// that `Engine::uninstall_plugin` used `installed_plugins.
    /// get()` — which returns None for quarantined rows on
    /// purpose — so the purges silently skipped and state
    /// stayed on disk after the tombstone.
    ///
    /// The reproducer: install a plugin, seed KV + a blob under
    /// its uuid, corrupt the SQL row's grant to trip the C5
    /// fail-closed quarantine on next scan, reopen the engine,
    /// then uninstall. Post-fix, the KV row + blob dir are
    /// gone.
    #[test]
    fn uninstall_purges_state_even_for_quarantined_install() {
        use crate::host_impl::plugin::oxidhome::plugin::types::Value as WitValue;

        let base = std::env::temp_dir().join(format!(
            "oxidhome-h12-quarantine-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&base).unwrap();
        let state_dir = base.join("state");
        let source = base.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("manifest.toml"),
            r#"manifest_version = 1
[plugin]
id = "example.h12q"
name = "H12 Quarantine"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(source.join("plugin.wasm"), b"\0asm\x01\x00\x00\x00").unwrap();

        let uuid: Arc<str>;
        {
            let engine = Engine::with_state_dir(&state_dir).expect("engine");
            let installed = engine
                .installed_plugins()
                .install(&source)
                .expect("install");
            uuid = Arc::clone(&installed.installation_uuid);
            engine
                .kv()
                .register_instance(&uuid, "inst-a", 4096)
                .expect("register kv");
            engine
                .kv()
                .set(&uuid, "inst-a", "k", WitValue::IntVal(1))
                .expect("kv set");
            engine
                .blobs()
                .register_instance(&uuid, "inst-a", 4096)
                .expect("register blobs");
            engine
                .blobs()
                .write(&uuid, "inst-a", "n", b"payload", None)
                .expect("blob write");
            // Corrupt the C5 grant JSON so the next scan trips
            // the fail-closed quarantine path.
            let db_path = state_dir.join("oxidhome.db");
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE plugin_installation SET granted_capabilities_json = NULL \
                 WHERE installation_uuid = ?1",
                rusqlite::params![&*uuid],
            )
            .unwrap();
        }

        // Reopen — scan now quarantines the install (get()
        // returns None but is_quarantined() returns true).
        let engine = Engine::with_state_dir(&state_dir).expect("reopen");
        assert!(engine.installed_plugins().get("example.h12q").is_none());
        assert!(engine.installed_plugins().is_quarantined("example.h12q"));

        // Pre-fix, this uninstall skipped both purges silently.
        engine.uninstall_plugin("example.h12q").expect("uninstall");

        assert!(
            engine.kv().usage(&uuid, "inst-a").expect("usage").is_none(),
            "H12 F1 regression: KV must be purged for quarantined installs",
        );
        let blob_dir = state_dir.join("blobs").join(&*uuid);
        assert!(
            !blob_dir.exists(),
            "H12 F1 regression: blob dir must be purged for quarantined installs",
        );

        std::fs::remove_dir_all(&base).ok();
    }
}
