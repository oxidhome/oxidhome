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

pub use instance::{InitError, PluginInstance};
pub use lifecycle::{
    InstanceHandle, InstanceState, SupervisorTuning, supervise, supervise_with_tuning,
};
pub use registry::{InstanceRegistry, RegistryError};
pub use state::PluginState;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use wasmtime::{Config, Engine as WasmtimeEngine};

use crate::state::{
    AuditLog, BlobStore, Db, DeviceRegistry, EventBus, EventLog, InstalledPluginRegistry, KvStore,
    LogStore, ServiceRegistry,
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
    events: Arc<EventBus>,
    kv: Arc<KvStore>,
    event_log: Arc<EventLog>,
    log_store: Arc<LogStore>,
    audit_log: Arc<AuditLog>,
    blobs: Arc<BlobStore>,
    services: Arc<ServiceRegistry>,
    instances: Arc<InstanceRegistry>,
    auth_tokens: Arc<crate::state::TokenStore>,
    installed_plugins: Arc<InstalledPluginRegistry>,
    /// Follow-up review H3: per-`plugin_id` async mutex used to
    /// serialize `install` / `start_instance` / `uninstall` from
    /// the API layer. Without it, `uninstall_plugin` and
    /// `start_plugin_instance` for the same `plugin_id` could
    /// race: uninstall passes its running-instances check, then
    /// start registers a fresh instance + supervisor, then
    /// uninstall yanks the FS dir — leaving a running instance
    /// whose backing has been deleted. `Arc<TokioMutex<()>>` per
    /// id, entries created lazily on first lock acquisition.
    plugin_lifecycle_locks: PluginLifecycleLocks,
}

/// Follow-up review H3: shared, lazily-populated map of per-
/// `plugin_id` async mutexes. Held under an outer sync `Mutex`
/// for the map itself; the inner `tokio::sync::Mutex` is what
/// callers actually acquire across `await`. Extracted to a
/// type alias so the clippy `very_complex_type` lint stops
/// firing on every field-access site.
type PluginLifecycleLocks =
    Arc<std::sync::Mutex<std::collections::HashMap<Arc<str>, Arc<tokio::sync::Mutex<()>>>>>;

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
            events: Arc::new(EventBus::new()),
            kv: Arc::new(KvStore::new(Arc::clone(&db))),
            event_log: Arc::new(EventLog::new(Arc::clone(&db))),
            log_store: Arc::new(LogStore::new(Arc::clone(&db))),
            audit_log: Arc::new(AuditLog::new(Arc::clone(&db))),
            auth_tokens: Arc::new(crate::state::TokenStore::new(Arc::clone(&db))),
            blobs: Arc::new(BlobStore::new(Arc::clone(&db), blobs_root)),
            services: Arc::new(ServiceRegistry::new()),
            instances: Arc::new(InstanceRegistry::new()),
            db,
            installed_plugins: Arc::new(installed_plugins),
            plugin_lifecycle_locks: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        })
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
    /// API's `POST /api/v1/plugins` (install),
    /// `DELETE /api/v1/plugins/{id}` (uninstall) endpoints, and the
    /// daemon's boot scan reach the registry through this accessor.
    /// In-memory engines (`Engine::new`) carry an empty registry;
    /// install / uninstall return `NoPluginsRoot` until an FS root
    /// is configured.
    #[must_use]
    pub fn installed_plugins(&self) -> Arc<InstalledPluginRegistry> {
        Arc::clone(&self.installed_plugins)
    }

    /// Follow-up review H3: per-`plugin_id` async mutex used by
    /// the API layer to serialize `install` / `start` / `uninstall`
    /// against the same id. Returned as an `Arc<tokio::sync::Mutex>`
    /// so both the JSON and Connect handlers can hold the same
    /// lock across their respective async supervisor / SQL calls.
    /// The map entry is created lazily on first request.
    #[must_use]
    pub fn plugin_lifecycle_lock(&self, plugin_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        use std::sync::PoisonError;
        let mut map = self
            .plugin_lifecycle_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(lock) = map.get(plugin_id) {
            return Arc::clone(lock);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        map.insert(Arc::from(plugin_id), Arc::clone(&lock));
        lock
    }

    /// Start a supervised plugin instance under this engine. Reads
    /// the manifest at `<plugin_dir>/manifest.toml` first to enforce
    /// the singleton and duplicate-id checks, then spawns a
    /// [`supervise`] task and registers its handle. A reaper task
    /// removes the entry once the supervisor reaches a terminal
    /// state, so the slot frees up for a fresh start.
    ///
    /// **Manifest immutability assumption.** This call reads the
    /// manifest once for the singleton / `plugin_id` check, then the
    /// supervisor's load path reads it again to instantiate. The two
    /// reads are *not* atomic against an on-disk edit between them; a
    /// manifest swap mid-call could let a singleton coexist with a
    /// non-singleton or unregister the wrong slot on terminal. Live-
    /// reload (Phase 7+) needs a re-register through this method.
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
        tuning: SupervisorTuning,
    ) -> anyhow::Result<InstanceHandle> {
        let plugin_dir = plugin_dir.into();
        let instance_id = instance_id.into();
        // Pre-flight: parse + validate the manifest so we know the
        // plugin id + singleton flag before spawning. The supervisor's
        // load path re-reads + re-validates — small redundancy, but it
        // keeps the supervisor self-contained for the test_host crate.
        // See the immutability note on `start_instance`.
        let manifest = instance::read_manifest(&plugin_dir).await?;
        let plugin_id = manifest.plugin.id.clone();
        let singleton = manifest.runtime.singleton;

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
        self.instances
            .register(instance_id, plugin_id, singleton, || {
                let handle = supervise_with_tuning(
                    engine_for_spawn,
                    plugin_dir_for_spawn,
                    instance_id_for_spawn,
                    plugin_id_for_spawn,
                    overrides,
                    tuning,
                );
                let reaper_handle = handle.clone();
                tokio::spawn(async move {
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
                    registry.unregister(&instance_id_for_reaper, &plugin_id_for_reaper);
                });
                handle
            })
            .map_err(anyhow::Error::from)
    }

    /// Look up a running instance by id. `None` if no such
    /// instance is registered (or it already reached a terminal state
    /// and the reaper removed it).
    #[must_use]
    pub fn instance(&self, instance_id: &str) -> Option<InstanceHandle> {
        self.instances.get(instance_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Follow-up review H3: repeated calls to
    /// `plugin_lifecycle_lock(id)` return the same `Arc<Mutex>`
    /// so `start` and `uninstall` for the same `plugin_id`
    /// serialize via a shared lock. Different ids get different
    /// locks (no false-sharing).
    #[tokio::test]
    async fn plugin_lifecycle_locks_are_stable_per_id() {
        let engine = Engine::new().expect("engine");
        let a1 = engine.plugin_lifecycle_lock("example.plugin.a");
        let a2 = engine.plugin_lifecycle_lock("example.plugin.a");
        let b1 = engine.plugin_lifecycle_lock("example.plugin.b");
        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same plugin_id must yield same lock Arc",
        );
        assert!(
            !Arc::ptr_eq(&a1, &b1),
            "different plugin_ids must yield different locks",
        );
        // Concurrent locks against the same id serialize.
        let held = a1.lock().await;
        let a3 = engine.plugin_lifecycle_lock("example.plugin.a");
        let contender = tokio::spawn(async move {
            let _g = a3.lock().await;
            "contender acquired"
        });
        // The contender is now waiting; give it a tick to prove
        // it hasn't acquired yet.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            !contender.is_finished(),
            "contender must block until we release the lock",
        );
        drop(held);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), contender)
            .await
            .expect("contender must acquire once we release")
            .expect("contender task panicked");
        assert_eq!(result, "contender acquired");
    }
}
