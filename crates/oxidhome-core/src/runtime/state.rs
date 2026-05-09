//! Per-plugin-instance host state — the user-data that rides inside a
//! Wasmtime [`Store`](wasmtime::Store).
//!
//! Every host import the plugin world declares (`host-devices`,
//! `host-events`, `host-config`, `storage`, `logging`) is implemented
//! against this struct. Phase 3 makes `host-devices`, `host-events`,
//! and `logging` fully functional; `host-config` returns empty until
//! Phase 4 wires the manifest, and `storage` returns
//! [`Error::Unavailable`] until Phase 5a's SQLite-backed KV.

use std::sync::Arc;

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
use crate::state::{DeviceRegistry, EventBus, EventSubscription};

/// Identifier the host assigns to a plugin instance — Phase 6 fleshes
/// this out (manifest-driven IDs, multi-instance dedup). Phase 2 uses
/// the .wasm filename as a placeholder.
pub type InstanceId = String;

/// Host data carried inside the wasmtime [`Store`](wasmtime::Store).
///
/// Held mutably by every host-import callback. The registry + event
/// bus are shared with the [`Engine`](crate::Engine) via `Arc`; the
/// per-instance subscription bookkeeping (`subscriptions`) lives here
/// alongside the WASI context.
pub struct PluginState {
    /// Stable id for the plugin instance — currently the plugin's
    /// filename stem; Phase 6 swaps for the manifest-declared id.
    pub instance_id: InstanceId,
    /// Resource handles owned by this store. Required by Wasmtime's
    /// component model; populated when Phase 5 introduces blob/model
    /// resource handling.
    pub table: ResourceTable,
    /// WASI p2 context. Plugin's libstd pulls in `wasi:io`, `wasi:cli`,
    /// `wasi:clocks` etc. by virtue of being compiled with std; the
    /// host has to satisfy them in the Linker.
    pub wasi: WasiCtx,
    /// Shared device registry — Phase 3.
    pub devices: Arc<DeviceRegistry>,
    /// Shared event bus — Phase 3.
    pub events: Arc<EventBus>,
    /// Per-instance subscription bookkeeping. Phase 3 stores the
    /// subscription metadata so [`unsubscribe`](host_events::Host::unsubscribe)
    /// can find and drop it; the receiver itself isn't drained yet
    /// (per-instance dispatch loop is Phase 6 — see
    /// `crate::state::events`).
    pub subscriptions: Vec<EventSubscription>,
}

impl PluginState {
    /// Build a fresh state for one plugin instance. `devices` /
    /// `events` come from the parent [`Engine`](crate::Engine).
    pub fn new(
        instance_id: impl Into<InstanceId>,
        devices: Arc<DeviceRegistry>,
        events: Arc<EventBus>,
    ) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        Self {
            instance_id: instance_id.into(),
            table: ResourceTable::new(),
            wasi: wasi.build(),
            devices,
            events,
            subscriptions: Vec::new(),
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
// Host trait impls for the `plugin` world.
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

const NOT_IMPL: &str = "not implemented in Phase 3";

fn unavailable() -> WitError {
    WitError::Unavailable(NOT_IMPL.into())
}

// ── Devices ──────────────────────────────────────────────────────────
//
// Phase 3 makes the device registry calls fully functional. Ownership
// is tracked so commands can be routed back to the registering
// instance. Phase 4 layers in the manifest's `declares_devices`
// capability gate (so a plugin that didn't declare a capability gets
// `permission-denied` on register-device); Phase 6 adds multi-
// instance lifecycle and crash-isolated re-registration.

impl host_devices::Host for PluginState {
    async fn register_device(&mut self, info: DeviceInfo) -> Result<DeviceId, WitError> {
        let id = self.devices.register(self.instance_id.clone(), info).await;
        tracing::debug!(
            instance_id = %self.instance_id,
            device_id = %id,
            "registered device"
        );
        Ok(id)
    }

    async fn update_device(&mut self, id: DeviceId, info: DeviceInfo) -> Result<(), WitError> {
        self.devices.update(&self.instance_id, &id, info).await
    }

    async fn remove_device(&mut self, id: DeviceId) -> Result<(), WitError> {
        let outcome = self.devices.remove(&self.instance_id, &id).await;
        if outcome.is_ok() {
            tracing::debug!(
                instance_id = %self.instance_id,
                device_id = %id,
                "removed device"
            );
        }
        outcome
    }

    async fn get_device(&mut self, id: DeviceId) -> Result<DeviceInfo, WitError> {
        self.devices
            .get(&self.instance_id, &id)
            .await
            .map(|meta| meta.info)
    }
}

// ── Events ───────────────────────────────────────────────────────────
//
// `publish-event` fans out via the bus's broadcast channel. `subscribe`
// records the filter in `PluginState::subscriptions` and returns a
// real id; the per-instance task that drains the receiver and calls
// `on-event` lands in Phase 6, so subscriptions are bookkeeping until
// then. `unsubscribe` removes the entry.

impl host_events::Host for PluginState {
    async fn publish_event(&mut self, ev: Event) -> Result<(), WitError> {
        let _delivered = self.events.publish(ev);
        Ok(())
    }

    async fn subscribe(&mut self, filter: EventFilter) -> Result<SubscriptionId, WitError> {
        let subscription = self.events.subscribe(filter);
        let id = subscription.id;
        self.subscriptions.push(subscription);
        Ok(id)
    }

    async fn unsubscribe(&mut self, id: SubscriptionId) -> Result<(), WitError> {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|s| s.id != id);
        if self.subscriptions.len() == before {
            return Err(WitError::NotFound(format!("subscription {id} not found")));
        }
        Ok(())
    }
}

// ── Config / storage / logging — see header. ─────────────────────────

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
