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

mod instance;
mod state;

pub use instance::PluginInstance;
pub use state::PluginState;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use wasmtime::{Config, Engine as WasmtimeEngine};

use crate::state::{Db, DeviceRegistry, EventBus, KvStore};

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
    devices: Arc<DeviceRegistry>,
    events: Arc<EventBus>,
    kv: Arc<KvStore>,
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
        Self::with_db(Db::open_in_memory()?)
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
        Self::with_db(Db::open_file(state_dir)?)
    }

    fn with_db(db: Db) -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true);
        // `async_support(true)` is the default in wasmtime 44 (and was
        // deprecated as a no-op). We just need the `async` feature on
        // the dep — which the workspace pin enables.
        cfg.epoch_interruption(false);
        let inner = Arc::new(
            WasmtimeEngine::new(&cfg)
                .map_err(anyhow::Error::from)
                .context("constructing wasmtime engine")?,
        );
        let db = Arc::new(db);
        Ok(Self {
            inner,
            devices: Arc::new(DeviceRegistry::new()),
            events: Arc::new(EventBus::new()),
            kv: Arc::new(KvStore::new(db)),
        })
    }

    pub(crate) fn raw(&self) -> &WasmtimeEngine {
        &self.inner
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
}
