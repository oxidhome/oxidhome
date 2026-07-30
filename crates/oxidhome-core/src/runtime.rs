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

    /// H2: uninstall a plugin and purge every per-install state row
    /// (`kv`, `kv_usage`, `blob`, `blob_usage`) plus the on-disk
    /// blob dir tree for that `installation_uuid`. The registry
    /// tombstones the ledger row and yanks the plugin dir, then we
    /// wipe the per-install stores so a subsequent `install` of the
    /// same `plugin_id` (which mints a fresh uuid) starts with an
    /// empty keyspace.
    ///
    /// Purge is best-effort *for the state stores*: the registry
    /// tombstone is the source of truth for "is this plugin
    /// installed?", so a downstream purge failure is logged (visible
    /// to operators) but not returned — the alternative would be
    /// leaving the ledger row live after the FS is gone, which is
    /// the worse state. A retry of `uninstall_plugin` re-tombstones
    /// no-op and re-attempts the purge (both purges are idempotent).
    ///
    /// # Errors
    ///
    /// Only registry-level failures ([`crate::state::UninstallError`]) —
    /// the FS tree removal + SQL row tombstone. State-store purge
    /// failures surface as `tracing::error` and are not returned so
    /// the ledger-level uninstall completes atomically for the
    /// caller.
    pub fn uninstall_plugin(&self, plugin_id: &str) -> Result<(), crate::state::UninstallError> {
        let installation_uuid = self.installed_plugins.uninstall(plugin_id)?;
        if let Err(err) = self.kv.purge_installation(&installation_uuid) {
            tracing::error!(
                plugin_id = %plugin_id,
                installation_uuid = %installation_uuid,
                error = %err,
                "H2: KV purge failed after uninstall; retry uninstall to re-attempt",
            );
        }
        if let Err(err) = self.blobs.purge_installation(&installation_uuid) {
            tracing::error!(
                plugin_id = %plugin_id,
                installation_uuid = %installation_uuid,
                error = %err,
                "H2: blob purge failed after uninstall; retry uninstall to re-attempt",
            );
        }
        Ok(())
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
}
