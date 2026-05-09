//! Wasmtime runtime glue — engine + per-instance state + plugin loader.
//!
//! Phase 2 surface:
//! - [`Engine`] wraps a [`wasmtime::Engine`] configured for the
//!   component model + async, ready to instantiate `plugin`-world
//!   components.
//! - [`PluginInstance`] is the host-side handle to one running plugin
//!   instance: load → init → (callbacks) → shutdown.
//!
//! Lifecycle, multi-instance, and crash isolation land in Phase 6
//! (`.claude/docs/03_core.md`).

mod instance;
mod state;

pub use instance::PluginInstance;
pub use state::PluginState;

use std::sync::Arc;

use anyhow::Context;
use wasmtime::{Config, Engine as WasmtimeEngine};

/// Process-wide Wasmtime engine. Components are compiled once per engine
/// and instantiated cheaply across many [`PluginInstance`]s — wrap this
/// in an [`Arc`] and share. The engine is configured for the component
/// model with async host functions so calls into wasm can suspend
/// (Phase 7+ will use this for sockets/HTTP).
#[derive(Clone)]
pub struct Engine {
    inner: Arc<WasmtimeEngine>,
}

impl Engine {
    /// Build the default engine. Component model + async + cranelift,
    /// matching the `wasmtime` features pinned in `Cargo.toml`.
    pub fn new() -> anyhow::Result<Self> {
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
        Ok(Self { inner })
    }

    pub(crate) fn raw(&self) -> &WasmtimeEngine {
        &self.inner
    }
}
