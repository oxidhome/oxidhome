//! Per-plugin-instance host state — the user-data that rides inside a
//! Wasmtime [`Store`](wasmtime::Store).
//!
//! Every host import the plugin world declares (`host-devices`,
//! `host-events`, `host-config`, `storage`, `logging`) is implemented
//! against this struct. Phase 2 only makes `logging` functional; the
//! rest return `error::unavailable(...)` until their owning phases land
//! per `.claude/docs/03_core.md`.

use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::host_impl::plugin::oxidhome::plugin::{
    capabilities, devices,
    devices::DeviceInfo,
    events,
    events::{Event, EventFilter},
    host_config, host_devices, host_events,
    logging::{self, Level as WitLevel},
    storage, types,
    types::{DeviceId, Error as WitError, KeyValue, SubscriptionId, Value as WitValue},
};

/// Identifier the host assigns to a plugin instance — Phase 6 fleshes
/// this out (manifest-driven IDs, multi-instance dedup). Phase 2 uses
/// the .wasm filename as a placeholder.
pub type InstanceId = String;

/// Host data carried inside the wasmtime [`Store`](wasmtime::Store).
///
/// Held mutably by every host-import callback. Phase 2 only uses
/// `instance_id` (for log span context) and the WASI ctx (so plugin
/// libstd doesn't error on init).
pub struct PluginState {
    /// Stable id for the plugin instance — currently the plugin's
    /// filename stem; Phase 6 swaps for the manifest-declared id.
    pub instance_id: InstanceId,
    /// Resource handles owned by this store. Required by Wasmtime's
    /// component model; populated when Phase 5 introduces blob/model
    /// resource handing.
    pub table: ResourceTable,
    /// WASI p2 context. Plugin's libstd pulls in `wasi:io`, `wasi:cli`,
    /// `wasi:clocks` etc. by virtue of being compiled with std; the
    /// host has to satisfy them in the Linker.
    pub wasi: WasiCtx,
}

impl PluginState {
    /// Default builder — inheritable stdio so plugin panic prints
    /// reach the host operator's terminal during Phase 2 development.
    pub fn new(instance_id: impl Into<InstanceId>) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        Self {
            instance_id: instance_id.into(),
            table: ResourceTable::new(),
            wasi: wasi.build(),
        }
    }
}

impl WasiView for PluginState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Host trait impls for the `plugin` world. Phase 2 only makes `logging`
// functional. The rest stub with `Error::Unavailable` so plugins that
// reach for them get a clear permission-denied-style error instead of
// an obscure trap.
//
// `types`, `capabilities`, `devices`, `events` are *data* interfaces
// (no functions), but wasmtime's bindgen still generates an empty
// `Host` trait per imported interface that the linker requires
// `PluginState` to implement. Empty impls are enough.
// ─────────────────────────────────────────────────────────────────────

impl types::Host for PluginState {}
impl capabilities::Host for PluginState {}
impl devices::Host for PluginState {}
impl events::Host for PluginState {}

const NOT_IMPL: &str = "not implemented in Phase 2";

fn unavailable() -> WitError {
    WitError::Unavailable(NOT_IMPL.into())
}

impl host_devices::Host for PluginState {
    async fn register_device(&mut self, _info: DeviceInfo) -> Result<DeviceId, WitError> {
        Err(unavailable())
    }
    async fn update_device(&mut self, _id: DeviceId, _info: DeviceInfo) -> Result<(), WitError> {
        Err(unavailable())
    }
    async fn remove_device(&mut self, _id: DeviceId) -> Result<(), WitError> {
        Err(unavailable())
    }
    async fn get_device(&mut self, _id: DeviceId) -> Result<DeviceInfo, WitError> {
        Err(unavailable())
    }
}

impl host_events::Host for PluginState {
    async fn publish_event(&mut self, _ev: Event) -> Result<(), WitError> {
        Err(unavailable())
    }
    async fn subscribe(&mut self, _filter: EventFilter) -> Result<SubscriptionId, WitError> {
        Err(unavailable())
    }
    async fn unsubscribe(&mut self, _id: SubscriptionId) -> Result<(), WitError> {
        Err(unavailable())
    }
}

impl host_config::Host for PluginState {
    async fn get_config(&mut self, _key: String) -> Result<Option<WitValue>, WitError> {
        Ok(None)
    }
    async fn list_config(&mut self) -> Result<Vec<KeyValue>, WitError> {
        Ok(Vec::new())
    }
}

impl storage::Host for PluginState {
    async fn get(&mut self, _key: String) -> Result<Option<WitValue>, WitError> {
        Err(unavailable())
    }
    async fn set(&mut self, _key: String, _val: WitValue) -> Result<(), WitError> {
        Err(unavailable())
    }
    async fn delete(&mut self, _key: String) -> Result<(), WitError> {
        Err(unavailable())
    }
    async fn list_keys(&mut self, _prefix: String) -> Result<Vec<String>, WitError> {
        Err(unavailable())
    }
}

impl logging::Host for PluginState {
    async fn log(&mut self, level: WitLevel, message: String) {
        // Phase 2: forward as a tracing event tagged with the instance
        // id so host operators can correlate plugin output. Phase 5c
        // plugs the SQLite log store onto the same tracing layer.
        let instance_id = self.instance_id.as_str();
        match level {
            WitLevel::Trace => tracing::trace!(instance_id, "{message}"),
            WitLevel::Debug => tracing::debug!(instance_id, "{message}"),
            WitLevel::Info => tracing::info!(instance_id, "{message}"),
            WitLevel::Warn => tracing::warn!(instance_id, "{message}"),
            WitLevel::Error => tracing::error!(instance_id, "{message}"),
        }
    }
}
