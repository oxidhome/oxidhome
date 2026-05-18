//! Idiomatic wrappers around the WIT host imports the `plugin` world
//! exposes.
//!
//! Plugin authors call these from inside [`Plugin::init`](crate::Plugin::init),
//! `on_event`, `execute_command`, or `tick`. Each function is a thin
//! wrapper over the corresponding wit-bindgen-generated import; the
//! point is type ergonomics (e.g. accepting [`Device`] instead of
//! [`DeviceInfo`]) and a single import path
//! (`oxidhome_sdk::host::register_device`) instead of the deep
//! `bindings::oxidhome::plugin::host_devices::register_device`.
//!
//! ## Coverage
//!
//! These functions are deliberately not unit-tested on the native
//! target. They forward into wit-bindgen-generated import stubs
//! (`bindings::oxidhome::plugin::{host_devices, host_events}::*`)
//! that resolve only inside a wasm component instantiated by a
//! Wasmtime host — calling them from a native test binary would be
//! a link-time unresolved symbol. End-to-end coverage for the
//! Phase 3 device + event surface lives in
//! `oxidhome-core/tests/{simulated_switch,event_dispatch}.rs`,
//! which builds the `simulated-switch` / `event-recorder` examples
//! against this exact module and drives the round-trip through
//! Wasmtime. This is the "boilerplate / hard-to-mock IO" exemption
//! category from the project-wide coverage policy.

use crate::bindings::oxidhome::plugin::devices::DeviceInfo;
use crate::bindings::oxidhome::plugin::events::{
    CustomEvent, Event, EventFilter, EventPayload, StateChange,
};
use crate::bindings::oxidhome::plugin::types::{DeviceId, Error, KeyValue, SubscriptionId};
use crate::bindings::oxidhome::plugin::{host_devices, host_events};

/// Per-instance config reads (Phase 4C). Plugin authors call
/// `oxidhome_sdk::host::config::get_typed::<T>("...")` etc. — see
/// the [`config`] module for the surface.
pub mod config;

/// Per-instance KV storage (Phase 5a). Plugin authors call
/// `oxidhome_sdk::host::storage::get` / `set` / `delete` /
/// `list_keys`, plus the typed `get_typed::<T>` / `set_typed::<T>`
/// helpers. Quota lives in `manifest.toml` under
/// `[capabilities] storage_quota_kb`; a quota of `0` (default) keeps
/// every call gated off behind `permission-denied`.
pub mod storage;

/// Per-instance blob store (Phase 5b). Plugin authors call
/// `oxidhome_sdk::host::blobs::write(name, &bytes, Some("image/jpeg"))`
/// to store a blob (camera snapshot, recording, oversized config),
/// then `read_by_name` / `read` / `list_blobs` / `delete` for the
/// usual lifecycle. Quota lives under
/// `[capabilities] blob_quota_mb`; `0` (default) gates every call
/// off behind `permission-denied`. Phase 5b v1 buffers through
/// `list<u8>` at the WIT boundary; a streaming resource-handle
/// follow-up is planned for plugins that need to write recordings
/// without buffering end-to-end.
pub mod blobs;

// ── Devices ──────────────────────────────────────────────────────────

/// Register a device with the host. Accepts either a
/// [`Device`] builder (recommended) or a raw [`DeviceInfo`].
/// Returns the host-assigned `device-id`, which is what later
/// `update_device` / `remove_device` / `publish_state_change` calls
/// reference.
///
/// # Errors
///
/// Forwards any [`Error`] the host returns — typically
/// [`Error::PermissionDenied`] when the manifest didn't authorize the
/// capability the device declares (Phase 4 onward).
pub fn register_device(device: impl Into<DeviceInfo>) -> Result<DeviceId, Error> {
    host_devices::register_device(&device.into())
}

/// Update an already-registered device's metadata.
///
/// # Errors
///
/// [`Error::NotFound`] if the host doesn't have a device with that id
/// registered to this plugin instance.
pub fn update_device(id: &DeviceId, info: &DeviceInfo) -> Result<(), Error> {
    host_devices::update_device(id, info)
}

/// Remove a device from the registry.
///
/// # Errors
///
/// [`Error::NotFound`] if the id isn't registered.
pub fn remove_device(id: &DeviceId) -> Result<(), Error> {
    host_devices::remove_device(id)
}

/// Look up a device the plugin previously registered.
///
/// # Errors
///
/// [`Error::NotFound`] if the id isn't registered.
pub fn get_device(id: &DeviceId) -> Result<DeviceInfo, Error> {
    host_devices::get_device(id)
}

// ── Events ───────────────────────────────────────────────────────────

/// Push a fully-constructed [`Event`] onto the host's event bus.
///
/// # Errors
///
/// Forwards host errors (e.g. [`Error::PermissionDenied`] if a future
/// phase gates publishes by capability).
pub fn publish_event(event: &Event) -> Result<(), Error> {
    host_events::publish_event(event)
}

/// Convenience wrapper for the most common publish: a state change
/// on a device the plugin owns. Builds the
/// [`Event`]/[`EventPayload::StateChanged`]/[`StateChange`] tuple
/// from `(device_id, capability, fields)` and forwards to
/// [`publish_event`].
///
/// `timestamp` defaults to `0` (the host treats this as
/// "unknown / use receive-time" per the WIT comment on
/// `event::timestamp`); use [`publish_event`] directly if you have a
/// real plugin-side wall-clock value.
///
/// # Errors
///
/// Same as [`publish_event`].
pub fn publish_state_change(
    device_id: DeviceId,
    capability: impl Into<String>,
    fields: Vec<KeyValue>,
) -> Result<(), Error> {
    publish_event(&Event {
        device: Some(device_id),
        timestamp: 0,
        payload: EventPayload::StateChanged(StateChange {
            capability: capability.into(),
            fields,
        }),
    })
}

/// Publish a plugin-defined custom event on a topic.
///
/// # Errors
///
/// Same as [`publish_event`].
pub fn publish_custom_event(
    device_id: Option<DeviceId>,
    topic: impl Into<String>,
    payload: impl Into<String>,
) -> Result<(), Error> {
    publish_event(&Event {
        device: device_id,
        timestamp: 0,
        payload: EventPayload::Custom(CustomEvent {
            topic: topic.into(),
            payload: payload.into(),
        }),
    })
}

/// Subscribe to events. The returned [`SubscriptionId`] is what
/// [`unsubscribe`] later references. Matching events are delivered
/// to the plugin's `on-event` export by the host's
/// `PluginInstance::drain_events` driver; Phase 3 polls the drain
/// explicitly, Phase 6 wraps it in a per-instance tokio task so
/// delivery is automatic.
///
/// # Errors
///
/// Forwards host errors.
pub fn subscribe(filter: &EventFilter) -> Result<SubscriptionId, Error> {
    host_events::subscribe(filter)
}

/// Subscribe to every event without filtering. Sugar for
/// [`subscribe`] with both filter fields `None`.
///
/// # Errors
///
/// Same as [`subscribe`].
pub fn subscribe_all() -> Result<SubscriptionId, Error> {
    subscribe(&EventFilter {
        device: None,
        topic: None,
    })
}

/// Subscribe to events touching a specific device.
///
/// # Errors
///
/// Same as [`subscribe`].
pub fn subscribe_device(device_id: DeviceId) -> Result<SubscriptionId, Error> {
    subscribe(&EventFilter {
        device: Some(device_id),
        topic: None,
    })
}

/// Subscribe to events by topic. Capability events
/// (`state-changed`, `button`, `inference`) match exactly on the
/// capability/topic name; custom events match by **prefix** — a
/// subscription to `"camera."` receives every `camera.motion`,
/// `camera.snapshot`, etc. Sugar for [`subscribe`] with `device =
/// None` and `topic = Some(topic.into())`.
///
/// # Errors
///
/// Same as [`subscribe`].
pub fn subscribe_topic(topic: impl Into<String>) -> Result<SubscriptionId, Error> {
    subscribe(&EventFilter {
        device: None,
        topic: Some(topic.into()),
    })
}

/// Drop a subscription previously returned by [`subscribe`].
///
/// # Errors
///
/// [`Error::NotFound`] if `id` doesn't match an active subscription.
pub fn unsubscribe(id: SubscriptionId) -> Result<(), Error> {
    host_events::unsubscribe(id)
}
