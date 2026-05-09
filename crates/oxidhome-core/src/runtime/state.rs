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
    /// Per-instance subscriptions: filter + receiver per active
    /// `host-events::subscribe` call. Drained by
    /// [`PluginInstance::drain_events`](crate::PluginInstance::drain_events),
    /// which calls the plugin's `on-event` export for each match.
    /// Phase 3 ships the polling-drain shape; Phase 6 wraps the same
    /// data in a per-instance tokio task so delivery is automatic
    /// without an explicit driver.
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
// records the filter + receiver in `PluginState::subscriptions` and
// returns a real id; `PluginInstance::drain_events` picks them up and
// calls `on-event` on the plugin. Phase 6 wraps the same shape in a
// per-instance tokio task so delivery happens automatically.
// `unsubscribe` removes the entry.

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

#[cfg(test)]
mod tests {
    //! Direct unit tests on the host trait impls. These bypass the
    //! WIT round-trip — `host_devices::Host`, `host_events::Host`,
    //! `host_config::Host`, `storage::Host`, and `logging::Host` are
    //! plain async methods we can call from a `#[tokio::test]`. The
    //! integration tests under `tests/` cover the full
    //! Wasmtime-driven path; these fill in the corner cases (the
    //! Phase 2 stubs, error variants, multi-instance ownership) that
    //! the integration scenarios don't reach.
    //!
    //! `flavor = "current_thread"` matches the integration tests
    //! and keeps the WASI ctx happy without needing a multi-thread
    //! runtime.
    #![allow(clippy::semicolon_if_nothing_returned)]

    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, EventPayload, StateChange,
    };

    fn empty_device(local: &str) -> DeviceInfo {
        DeviceInfo {
            local_id: local.into(),
            name: local.into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: Vec::new(),
            initial_state: Vec::new(),
            metadata: Vec::new(),
        }
    }

    fn fresh_state(instance_id: &str) -> PluginState {
        PluginState::new(
            instance_id,
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
        )
    }

    fn shared_state(
        instance_id: &str,
        registry: Arc<DeviceRegistry>,
        bus: Arc<EventBus>,
    ) -> PluginState {
        PluginState::new(instance_id, registry, bus)
    }

    // ── host-devices ──────────────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_then_get_returns_owned_info() {
        let mut state = fresh_state("alpha");
        let id = host_devices::Host::register_device(&mut state, empty_device("d-1"))
            .await
            .expect("register");
        let info = host_devices::Host::get_device(&mut state, id.clone())
            .await
            .expect("get");
        assert_eq!(info.local_id, "d-1");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_get_unknown_returns_not_found() {
        let mut state = fresh_state("alpha");
        let err = host_devices::Host::get_device(&mut state, "ghost".into())
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_update_on_other_instance_returns_not_found() {
        let registry = Arc::new(DeviceRegistry::new());
        let bus = Arc::new(EventBus::new());
        let mut alpha = shared_state("alpha", registry.clone(), bus.clone());
        let mut beta = shared_state("beta", registry.clone(), bus.clone());

        let id = host_devices::Host::register_device(&mut alpha, empty_device("d-1"))
            .await
            .expect("alpha register");

        // Beta sees it as not-found whether it tries to update,
        // remove, or get — owner check collapses every mismatch.
        let err = host_devices::Host::update_device(&mut beta, id.clone(), empty_device("d-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)));
        let err = host_devices::Host::remove_device(&mut beta, id.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)));
        let err = host_devices::Host::get_device(&mut beta, id.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)));

        // Alpha still owns it.
        host_devices::Host::get_device(&mut alpha, id)
            .await
            .expect("alpha still owns");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_remove_then_update_fails() {
        let mut state = fresh_state("alpha");
        let id = host_devices::Host::register_device(&mut state, empty_device("d-1"))
            .await
            .unwrap();
        host_devices::Host::remove_device(&mut state, id.clone())
            .await
            .expect("remove");
        let err = host_devices::Host::update_device(&mut state, id.clone(), empty_device("d-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)));
    }

    // ── host-events ───────────────────────────────────────────────

    fn state_change_event(device: &str) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: 0,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: Vec::new(),
            }),
        }
    }

    fn custom_event(topic: &str) -> Event {
        Event {
            device: None,
            timestamp: 0,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: String::new(),
            }),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_reaches_external_subscriber() {
        let registry = Arc::new(DeviceRegistry::new());
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe_all();
        let mut state = shared_state("alpha", registry, bus);

        host_events::Host::publish_event(&mut state, state_change_event("d-1"))
            .await
            .expect("publish");

        let ev = sub.receiver.try_recv().expect("event delivered");
        assert_eq!(ev.device.as_deref(), Some("d-1"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_subscribe_and_unsubscribe_round_trip() {
        let mut state = fresh_state("alpha");
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let id = host_events::Host::subscribe(&mut state, filter)
            .await
            .expect("subscribe");
        assert_eq!(state.subscriptions.len(), 1);

        host_events::Host::unsubscribe(&mut state, id)
            .await
            .expect("unsubscribe");
        assert!(state.subscriptions.is_empty());

        let err = host_events::Host::unsubscribe(&mut state, id)
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_subscription_filter_drops_non_matches() {
        let mut state = fresh_state("alpha");
        let id = host_events::Host::subscribe(
            &mut state,
            EventFilter {
                device: None,
                topic: Some("automation.".into()),
            },
        )
        .await
        .unwrap();

        // Publish two custom events; only the prefixed one matches.
        host_events::Host::publish_event(&mut state, custom_event("automation.morning"))
            .await
            .unwrap();
        host_events::Host::publish_event(&mut state, custom_event("switch"))
            .await
            .unwrap();

        let sub = state.subscriptions.iter_mut().find(|s| s.id == id).unwrap();
        let ev1 = sub.receiver.try_recv().unwrap();
        assert!(sub.matches(&ev1));
        let ev2 = sub.receiver.try_recv().unwrap();
        assert!(!sub.matches(&ev2));
        // Both arrive on the wire (broadcast is unfiltered); the
        // per-subscription filter is what `matches` checks.
    }

    // ── host-config / storage / logging ───────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn host_config_returns_empty() {
        let mut state = fresh_state("alpha");
        // `Value` doesn't impl `PartialEq` (the WIT-generated variant
        // carries a `list<u8>` arm and bindgen leaves Eq off), so use
        // `is_none()` rather than `assert_eq!(.., None)`.
        assert!(
            host_config::Host::get_config(&mut state, "anything".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            host_config::Host::list_config(&mut state)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn storage_methods_all_unavailable() {
        let mut state = fresh_state("alpha");
        for outcome in [
            storage::Host::get(&mut state, "k".into()).await,
            storage::Host::set(&mut state, "k".into(), WitValue::BoolVal(true))
                .await
                .map(|()| None),
            storage::Host::delete(&mut state, "k".into())
                .await
                .map(|()| None),
            storage::Host::list_keys(&mut state, "p".into())
                .await
                .map(|_| None),
        ] {
            let err = outcome.unwrap_err();
            assert!(matches!(err, WitError::Unavailable(_)), "got {err:?}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logging_dispatches_each_level() {
        // Just exercise every match arm so coverage reports it; no
        // assertion is needed on the tracing output, the test fails
        // only if a level path panics.
        let mut state = fresh_state("alpha");
        for level in [
            WitLevel::Trace,
            WitLevel::Debug,
            WitLevel::Info,
            WitLevel::Warn,
            WitLevel::Error,
        ] {
            logging::Host::log(&mut state, level, format!("msg-{level:?}")).await;
        }
    }
}
