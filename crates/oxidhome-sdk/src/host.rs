//! Idiomatic wrappers around the WIT host imports the `plugin` world
//! exposes.
//!
//! Plugin authors call these from inside [`Plugin::init`](crate::Plugin::init),
//! `on_event`, `execute_command`, or `tick`. Each function is a thin
//! wrapper over the corresponding wit-bindgen-generated import; the
//! point is type ergonomics (e.g. accepting [`Device`](crate::Device)
//! instead of [`DeviceInfo`]) and a single import path
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

use crate::bindings::oxidhome::plugin::devices::CommandResult;
use crate::bindings::oxidhome::plugin::devices::DeviceInfo;
use crate::bindings::oxidhome::plugin::events::{
    CustomEvent, Event, EventFilter, EventPayload, StateChange,
};
use crate::bindings::oxidhome::plugin::services::ServiceInfo;
use crate::bindings::oxidhome::plugin::types::{
    DeviceId, Error, KeyValue, ServiceId, SubscriptionId,
};
use crate::bindings::oxidhome::plugin::{host_devices, host_events, host_services};

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
/// [`Device`](crate::Device) builder (recommended) or a raw
/// [`DeviceInfo`].
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

// ── Services (Phase 7) ───────────────────────────────────────────────

/// Register a service with the host. Accepts either a
/// [`Service`](crate::Service) builder (recommended) or a raw
/// [`ServiceInfo`]. Returns the host-assigned `service-id`.
///
/// H10: `service.local_id` is the immutable logical key. Two
/// registrations from the same instance under the same `local_id`
/// return [`Error::InvalidArgument`].
///
/// # Errors
///
/// - [`Error::PermissionDenied`] when the manifest's
///   `[capabilities] declares_services` didn't authorize the
///   service's `name`.
/// - [`Error::InvalidArgument`] when `local_id` collides with
///   another live service registered by this instance.
pub fn register_service(service: impl Into<ServiceInfo>) -> Result<ServiceId, Error> {
    host_services::register_service(&service.into())
}

/// Update an already-registered service's metadata / commands.
///
/// H10: `info.local_id` is immutable — an update whose `local_id`
/// differs from the registration returns [`Error::InvalidArgument`]
/// and does not mutate the registry. `name`, `metadata`, and
/// `commands` remain freely mutable.
///
/// # Errors
///
/// - [`Error::NotFound`] if the id isn't registered to this instance.
/// - [`Error::InvalidArgument`] if `info.local_id` differs from the
///   registered value.
pub fn update_service(id: &ServiceId, info: &ServiceInfo) -> Result<(), Error> {
    host_services::update_service(id, info)
}

/// Remove a service from the registry.
///
/// # Errors
///
/// [`Error::NotFound`] if the id isn't registered; [`Error::Unavailable`]
/// if a `call-service` to it is still in flight.
pub fn remove_service(id: &ServiceId) -> Result<(), Error> {
    host_services::remove_service(id)
}

/// Look up a service the plugin previously registered.
///
/// # Errors
///
/// [`Error::NotFound`] if the id isn't registered.
pub fn get_service(id: &ServiceId) -> Result<ServiceInfo, Error> {
    host_services::get_service(id)
}

/// H10: resolve the stable `(plugin_id, instance_id, local_id)`
/// address to the currently-registered `service-id`. `service-id`
/// values are per-run — callers persist the three-tuple (all
/// components stable across restarts) and re-resolve on demand.
///
/// Uses the immutable `local-id`, not the human-readable `name`
/// (which `update_service` can change). Resolution does not imply
/// the caller may then invoke the service; [`call_service`]
/// authorizes against the caller's structured
/// `[capabilities] consumes_services` grants per-command.
///
/// # Errors
///
/// [`Error::NotFound`] if no live service matches the three-tuple.
pub fn resolve_service(
    plugin_id: &str,
    instance_id: &str,
    service_local_id: &str,
) -> Result<ServiceId, Error> {
    host_services::resolve_service(plugin_id, instance_id, service_local_id)
}

/// Synchronously call another plugin's service command. The host
/// routes `target` to its owning instance and returns the result.
///
/// **Caller-side capability gate.** The dispatcher matches the
/// target service's `(plugin, instance, local_id, command)` and
/// the actual caller's instance-id against the caller's
/// `[capabilities] consumes_services` grants; each entry is a
/// resource selector `{plugin, instance, service, commands,
/// caller_instance}` with `"*"` wildcards on `instance`,
/// `commands`, and `caller_instance`. Authorization requires
/// **both** an entry in the plugin-declared requested list AND an
/// entry in the operator's granted copy to match — the granted
/// copy does not simply override the requested list, so the
/// manifest still acts as a ceiling. A call without matches in
/// both lists returns [`Error::PermissionDenied`] before the
/// callee's `execute-service-command` runs.
///
/// **Same-instance dispatch is not supported.** Going through
/// `call_service` to a service the calling instance also owns
/// returns [`Error::InvalidArgument`] with the message
/// `same-instance dispatch is not supported`. Plugins colocating
/// multiple services in one instance dispatch between them in
/// plugin-local code.
///
/// # Errors
///
/// [`Error::NotFound`] (no such service),
/// [`Error::PermissionDenied`] (no matching `consumes_services`
/// grant), [`Error::InvalidArgument`] (same-instance target,
/// A→…→A cycle, or bad command/args), [`Error::Unavailable`]
/// (owner not running or dispatch timed out).
pub fn call_service(
    target: &ServiceId,
    command: &str,
    args: &[KeyValue],
) -> Result<CommandResult, Error> {
    host_services::call_service(target, command, args)
}

// ── Events ───────────────────────────────────────────────────────────

/// Push a fully-constructed [`Event`] onto the host's event bus.
///
/// The host stamps `origin-plugin-id` and `origin-instance-id` on
/// publish from this instance's manifest + instance id — any values
/// on `event` for those fields are overwritten. Subscribers see the
/// immutable origin regardless.
///
/// # Errors
///
/// Forwards host errors. The host enforces device-ownership on
/// publish: an event whose `device` field references a device this
/// plugin instance did not register is refused with
/// [`Error::PermissionDenied`]. Bus-only events (`device: None`,
/// used for lifecycle and custom topics) bypass that check.
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
        // `origin-plugin-id` / `origin-instance-id` are host-
        // populated at publish time (see the WIT `event` docstring).
        // Any value passed here is overwritten by the host, so send
        // empty strings from the plugin-side helpers.
        origin_plugin_id: String::new(),
        origin_instance_id: String::new(),
        // H5: `row-id` is host-populated on publish — the host
        // overwrites `None` with the durable `event_log` id
        // before broadcasting.
        row_id: None,
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
        // Host-populated on publish — see `publish_state_change`.
        origin_plugin_id: String::new(),
        origin_instance_id: String::new(),
        row_id: None,
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
