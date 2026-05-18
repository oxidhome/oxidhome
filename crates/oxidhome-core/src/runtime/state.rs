//! Per-plugin-instance host state — the user-data that rides inside a
//! Wasmtime [`Store`](wasmtime::Store).
//!
//! Every host import the plugin world declares (`host-devices`,
//! `host-events`, `host-config`, `storage`, `logging`) is implemented
//! against this struct. As of Phase 5a:
//!
//! - `host-devices::register-device` and `update-device` are gated by
//!   the manifest's `capabilities.declares_devices` (plus an
//!   `initial-state`-must-have-matching-spec cross-check).
//!   `remove-device` and `get-device` are always-allow — they can't
//!   smuggle new capabilities in.
//! - `host-events`, `host-config`, and `logging` are functional but
//!   not manifest-gated. There's no per-call authorization for
//!   publishing or subscribing yet; capability gating beyond device
//!   registration (network rules for streaming plugins, services,
//!   blob quotas) lives in later phases.
//! - `storage` is backed by the shared `SQLite` [`KvStore`] with
//!   per-instance quotas from `capabilities.storage_quota_kb`. A
//!   manifest quota of `0` keeps storage gated off
//!   (`permission-denied`); a positive quota lets calls through, with
//!   the KV's own transactional quota check refusing writes that
//!   would push past the cap.

use std::sync::Arc;

use oxidhome_manifest::{ConfigValue, InstanceConfig, PluginManifest};
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::{
    blob_store::{self, BlobInfo as WitBlobInfo},
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
/// alongside the WASI context, the parsed manifest, the [`Actor`]
/// identity for this instance, and the resolved per-instance config.
pub struct PluginState {
    /// Stable id for the plugin instance. Phase 4 derives it from
    /// the manifest's `plugin.id` plus a per-instance suffix chosen
    /// by the loader caller; Phase 6 wraps the lifecycle that mints
    /// them.
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
    /// The plugin's manifest. Capability decisions (`declares_devices`
    /// gating, future Phase 7's `declares_services`, Phase 5's
    /// storage quotas) consult this directly. `Arc` so cloning a
    /// `PluginState` for tests is cheap.
    pub manifest: Arc<PluginManifest>,
    /// Who's making host calls *from this instance*. For Phase 4 always
    /// the in-process plugin actor; Phase 12 routes external HTTP/WS
    /// callers through the same struct so the audit-log shape is
    /// consistent.
    pub actor: Actor,
    /// Per-instance config — manifest `[config]` schema folded with
    /// any user override blob. Returned to the plugin via
    /// `host-config::get-config` / `list-config`. Empty when the
    /// manifest has no `[config]` block.
    pub config: InstanceConfig,
    /// Shared SQLite-backed KV store — Phase 5a. Per-instance quota +
    /// bookkeeping live in the store itself; this is just the handle.
    /// `host-storage::*` calls go through here.
    pub kv: Arc<crate::state::KvStore>,
    /// Shared durable event log — Phase 5d. Every `host-events::publish-event`
    /// is mirrored here before the live broadcast. The handle is
    /// per-`Engine`, cloned into each `PluginState` so the trait impl
    /// can reach the store without going through the engine.
    pub event_log: Arc<crate::state::EventLog>,
    /// Shared blob store — Phase 5b. Bytes live on the filesystem
    /// at `<state_dir>/blobs/<instance_id>/<id>`; the `SQLite` index
    /// keeps `(name → id)` lookup + quota accounting. `blob-store`
    /// host calls go through here.
    pub blobs: Arc<crate::state::BlobStore>,
}

impl PluginState {
    /// Build a fresh state for one plugin instance. `devices` /
    /// `events` / `kv` / `event_log` / `blobs` come from the parent
    /// [`Engine`](crate::Engine); the manifest, actor, and resolved
    /// config come from the loader (real or test).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: impl Into<InstanceId>,
        manifest: Arc<PluginManifest>,
        actor: Actor,
        config: InstanceConfig,
        devices: Arc<DeviceRegistry>,
        events: Arc<EventBus>,
        kv: Arc<crate::state::KvStore>,
        event_log: Arc<crate::state::EventLog>,
        blobs: Arc<crate::state::BlobStore>,
    ) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        Self {
            instance_id: instance_id.into(),
            table: ResourceTable::new(),
            wasi: wasi.build(),
            devices,
            events,
            kv,
            event_log,
            blobs,
            subscriptions: Vec::new(),
            manifest,
            actor,
            config,
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

// ── Devices ──────────────────────────────────────────────────────────
//
// Phase 3 makes the device registry calls functional. Ownership is
// tracked so commands can be routed back to the registering instance.
// Phase 4 layers in the manifest's `declares_devices` capability
// gate: each capability the device declares must be in the manifest's
// declared list (or the `extension(<name>)` escape hatch), otherwise
// `register-device` returns `permission-denied`. Phase 6 adds multi-
// instance lifecycle and crash-isolated re-registration.

/// Stable string name for a `capability-spec` variant — what
/// `manifest.capabilities.declares_devices` lists. Mirrors
/// `capability-spec` in `wit/oxidhome.wit`.
fn capability_name(spec: &capabilities::CapabilitySpec) -> String {
    match spec {
        capabilities::CapabilitySpec::Switch => "switch".into(),
        capabilities::CapabilitySpec::Dimmer => "dimmer".into(),
        capabilities::CapabilitySpec::ColorLight(_) => "color-light".into(),
        capabilities::CapabilitySpec::Sensor(_) => "sensor".into(),
        capabilities::CapabilitySpec::Button => "button".into(),
        capabilities::CapabilitySpec::VideoStream => "video-stream".into(),
        capabilities::CapabilitySpec::AudioStream => "audio-stream".into(),
        capabilities::CapabilitySpec::Extension(name) => format!("extension({name})"),
    }
}

/// Capability name for an `initial_state` variant. The
/// `capability-state` WIT variant only covers the stateful
/// capabilities (button / video-stream / audio-stream / extension
/// have no entry), so this returns the matching capability-spec name
/// for each. Used by the device-registration gate to confirm a
/// plugin isn't smuggling state for a capability it didn't declare.
fn capability_state_name(state: &capabilities::CapabilityState) -> &'static str {
    match state {
        capabilities::CapabilityState::Switch(_) => "switch",
        capabilities::CapabilityState::Dimmer(_) => "dimmer",
        capabilities::CapabilityState::ColorLight(_) => "color-light",
        capabilities::CapabilityState::Sensor(_) => "sensor",
    }
}

/// Run both gates for a `register-device` / `update-device` call:
///
/// 1. Every `initial_state` entry must have a matching
///    `capability-spec` in `info.capabilities`. A state-without-spec
///    `DeviceInfo` is malformed — the WIT contract is "one entry per
///    stateful capability the plugin can already report."
/// 2. Every `capability-spec` in `info.capabilities` (which, after
///    step 1, transitively covers every state variant) must appear
///    in the manifest's `declares_devices` list.
///
/// Both surface as `PermissionDenied` with a specific message. The
/// state-without-spec case is technically "invalid argument" more
/// than "permission denied," but the WIT only carries
/// `permission-denied` / `not-found` / `unavailable` etc.; we use
/// the most useful existing variant rather than reaching for a new
/// WIT error today.
fn authorize_device_info(declared: &[String], info: &DeviceInfo) -> Result<(), WitError> {
    for state in &info.initial_state {
        let name = capability_state_name(state);
        if !info
            .capabilities
            .iter()
            .any(|spec| capability_name(spec) == name)
        {
            return Err(WitError::PermissionDenied(format!(
                "initial_state contains `{name}` but the device doesn't declare \
                 a matching `{name}` capability"
            )));
        }
    }
    for spec in &info.capabilities {
        let name = capability_name(spec);
        if !declared.contains(&name) {
            return Err(WitError::PermissionDenied(format!(
                "capability `{name}` is not declared in this plugin's manifest \
                 (capabilities.declares_devices)"
            )));
        }
    }
    Ok(())
}

impl host_devices::Host for PluginState {
    async fn register_device(&mut self, info: DeviceInfo) -> Result<DeviceId, WitError> {
        // Authorize the full DeviceInfo: gate `capabilities` against
        // the manifest's `declares_devices`, *and* refuse any
        // `initial_state` entry that doesn't have a matching spec on
        // the same device (otherwise a plugin could smuggle in state
        // for an undeclared sensor / switch / etc. via the state list).
        if let Err(err) = authorize_device_info(&self.manifest.capabilities.declares_devices, &info)
        {
            tracing::warn!(
                instance_id = %self.instance_id,
                error = %err,
                "register-device denied",
            );
            return Err(err);
        }

        let id = self.devices.register(self.instance_id.clone(), info).await;
        tracing::debug!(
            instance_id = %self.instance_id,
            device_id = %id,
            "registered device"
        );
        Ok(id)
    }

    async fn update_device(&mut self, id: DeviceId, info: DeviceInfo) -> Result<(), WitError> {
        // Same gate as register-device — a plugin that wasn't allowed
        // to register a switch shouldn't be able to update one into a
        // switch either, and the initial_state cross-check still
        // applies. Log denials symmetrically with register-device so
        // the Phase-5c log/trace store captures both paths through the
        // same `warn`.
        if let Err(err) = authorize_device_info(&self.manifest.capabilities.declares_devices, &info)
        {
            tracing::warn!(
                instance_id = %self.instance_id,
                device_id = %id,
                error = %err,
                "update-device denied",
            );
            return Err(err);
        }
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
        // Durable mirror first (Phase 5d): if the write fails — disk
        // full, sqlite corruption, etc. — we'd rather refuse the
        // publish than silently lose history. Live broadcast comes
        // second.
        let event_log = Arc::clone(&self.event_log);
        let instance_id = self.instance_id.clone();
        let plugin_id = self.manifest.plugin.id.clone();
        let to_record = ev.clone();
        // rusqlite is sync — hop to a blocking thread for the write
        // so we don't park the tokio worker on disk I/O. Panics in
        // the spawn_blocking body surface as `Error::Internal`,
        // matching the storage-side error mapping.
        let recorded = tokio::task::spawn_blocking(move || {
            event_log.record(
                crate::state::event_log::now_unix_ms(),
                &to_record,
                &instance_id,
                &plugin_id,
            )
        })
        .await;
        match recorded {
            Ok(Ok(_id)) => {}
            Ok(Err(e)) => {
                return Err(WitError::Internal(format!("event_log: write failed: {e}")));
            }
            Err(join) => {
                return Err(WitError::Internal(format!(
                    "event_log: blocking task panicked: {join}",
                )));
            }
        }

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
    /// Look up a config field by its dot-joined path (`broker.host`
    /// for a nested field, `default_state` for a flat one). Returns
    /// `Ok(None)` when the key is absent from the resolved
    /// [`InstanceConfig`]; bare-string nested lookups (`broker`,
    /// which would map to a nested table) also return `Ok(None)` —
    /// plugins access *leaves*, the host doesn't JSON-encode nested
    /// subtrees today.
    async fn get_config(&mut self, key: String) -> Result<Option<WitValue>, WitError> {
        Ok(lookup_leaf(&self.config, key.split('.')).and_then(config_value_to_wit))
    }

    /// Flatten the resolved config into dot-joined `KeyValue` pairs,
    /// one per leaf. Nested fields appear as `parent.child` keys.
    /// Order is the iteration order of the underlying `BTreeMap`
    /// (lexicographic).
    async fn list_config(&mut self) -> Result<Vec<KeyValue>, WitError> {
        let mut out = Vec::new();
        flatten_config(&self.config, "", &mut out);
        Ok(out)
    }
}

/// Walk the resolved config along the `.`-separated path, returning
/// the leaf (or `None` if the path doesn't lead to one).
fn lookup_leaf<'a>(
    cfg: &'a InstanceConfig,
    mut parts: std::str::Split<'_, char>,
) -> Option<&'a ConfigValue> {
    let first = parts.next()?;
    let mut current = cfg.get(first)?;
    for next in parts {
        match current {
            ConfigValue::Nested(inner) => current = inner.get(next)?,
            _ => return None, // path keeps going but we hit a leaf — no such field
        }
    }
    Some(current)
}

/// Recursively flatten the resolved config into `(dot-joined-key,
/// WitValue)` pairs, skipping anything that doesn't have a WIT
/// representation (today: nested-themselves; `ConfigValue` itself
/// only has leaf variants the WIT understands, so this is just the
/// recursion).
fn flatten_config(cfg: &InstanceConfig, prefix: &str, out: &mut Vec<KeyValue>) {
    for (k, v) in cfg {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            ConfigValue::Nested(inner) => flatten_config(inner, &key, out),
            leaf => {
                if let Some(value) = config_value_to_wit(leaf) {
                    out.push(KeyValue { key, value });
                }
            }
        }
    }
}

/// Map a leaf [`ConfigValue`] to its [`WitValue`] representation.
/// Nested values (which the path-lookup code already filters out)
/// return `None`.
fn config_value_to_wit(v: &ConfigValue) -> Option<WitValue> {
    match v {
        ConfigValue::Bool(b) => Some(WitValue::BoolVal(*b)),
        ConfigValue::Int(n) => Some(WitValue::IntVal(*n)),
        ConfigValue::Float(n) => Some(WitValue::FloatVal(*n)),
        ConfigValue::String(s) => Some(WitValue::StringVal(s.clone())),
        ConfigValue::Nested(_) => None,
    }
}

// ── Storage ─────────────────────────────────────────────────────────
//
// Phase 5a backs the WIT `storage` interface with the SQLite-based
// `KvStore`. Gating semantics are inherited from the manifest:
// `capabilities.storage_quota_kb = 0` (or absent) is the "storage off"
// signal — every call returns `permission-denied` before it ever hits
// the KV. A positive quota lets calls through; the KV's transactional
// quota check then refuses writes that would exceed it (also
// `permission-denied`, mirroring the `register_device` shape).
//
// All four methods hop to `tokio::task::spawn_blocking` because
// rusqlite is synchronous. Anything that goes wrong on the blocking
// thread surfaces as `Error::Internal` — the task should not panic in
// practice, but the WIT contract requires *something* if it does.

/// Refuse the call with a clear message when the manifest didn't
/// grant any KV quota. Returns `Ok(())` when storage is enabled.
fn require_storage_enabled(state: &PluginState) -> Result<(), WitError> {
    if state.manifest.capabilities.storage_quota_kb == 0 {
        return Err(WitError::PermissionDenied(
            "storage disabled: capabilities.storage_quota_kb is 0 (set a positive value in manifest.toml)".into(),
        ));
    }
    Ok(())
}

/// Map [`crate::state::KvError`] to the WIT [`WitError`]. `QuotaExceeded`
/// surfaces as `permission-denied` (consistent with the
/// `declares_devices` gate's shape); the unregistered-instance case
/// can only happen on a host bug (loader didn't register), so that
/// lands as `internal`.
fn kv_error_to_wit(err: crate::state::KvError) -> WitError {
    use crate::state::KvError;
    match err {
        KvError::QuotaExceeded {
            instance_id: _,
            would_use,
            allowed,
        } => WitError::PermissionDenied(format!(
            "quota exceeded: {would_use} bytes used / {allowed} allowed",
        )),
        KvError::UnregisteredInstance { ref instance_id } => WitError::Internal(format!(
            "kv: instance `{instance_id}` not registered (host bug)",
        )),
        KvError::Encode { key, source } => {
            WitError::Internal(format!("kv: encoding `{key}`: {source}"))
        }
        KvError::Sql(e) => WitError::Internal(format!("kv: sqlite error: {e}")),
    }
}

/// Lift a `KvStore` operation into the WIT result shape via
/// `spawn_blocking`. The op runs on a dedicated blocking thread (the
/// store itself is sync), and panics inside it bubble out as
/// `Error::Internal`.
async fn kv_op<R, F>(f: F) -> Result<R, WitError>
where
    R: Send + 'static,
    F: FnOnce() -> Result<R, crate::state::KvError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(kv_error_to_wit(e)),
        Err(join) => Err(WitError::Internal(format!(
            "kv: blocking task panicked: {join}",
        ))),
    }
}

impl storage::Host for PluginState {
    async fn get(&mut self, key: String) -> Result<Option<WitValue>, WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.get(&instance_id, &key)).await
    }

    async fn set(&mut self, key: String, val: WitValue) -> Result<(), WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.set(&instance_id, &key, val)).await
    }

    async fn delete(&mut self, key: String) -> Result<(), WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.delete(&instance_id, &key)).await
    }

    async fn list_keys(&mut self, prefix: String) -> Result<Vec<String>, WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.list_keys(&instance_id, &prefix)).await
    }
}

// ── Blob store ──────────────────────────────────────────────────────
//
// Phase 5b. Same shape as `storage`: a manifest-side gate
// (`blob_quota_mb = 0` ⇒ `permission-denied` before the store is
// touched), then `spawn_blocking` to keep the sync FS + SQLite work
// off the tokio worker.

fn require_blobs_enabled(state: &PluginState) -> Result<(), WitError> {
    if state.manifest.capabilities.blob_quota_mb == 0 {
        return Err(WitError::PermissionDenied(
            "blob store disabled: capabilities.blob_quota_mb is 0 (set a positive value in manifest.toml)".into(),
        ));
    }
    Ok(())
}

/// Map [`crate::state::BlobError`] to a WIT [`WitError`]. Quota and
/// "store unavailable" surface as `permission-denied`; missing
/// blobs as `not-found`; everything else as `internal`.
fn blob_error_to_wit(err: crate::state::BlobError) -> WitError {
    use crate::state::BlobError;
    match err {
        BlobError::Unavailable => WitError::PermissionDenied(
            "blob store unavailable: engine has no state directory configured".into(),
        ),
        BlobError::UnregisteredInstance { ref instance_id } => WitError::Internal(format!(
            "blob_store: instance `{instance_id}` not registered (host bug)"
        )),
        BlobError::QuotaExceeded {
            would_use, allowed, ..
        } => WitError::PermissionDenied(format!(
            "blob quota exceeded: {would_use} bytes used / {allowed} allowed"
        )),
        BlobError::NotFound { what } => WitError::NotFound(format!("blob {what}")),
        BlobError::Io { path, source } => WitError::Internal(format!(
            "blob_store: filesystem error at {}: {source}",
            path.display()
        )),
        BlobError::Sql(e) => WitError::Internal(format!("blob_store: sqlite error: {e}")),
    }
}

async fn blob_op<R, F>(f: F) -> Result<R, WitError>
where
    R: Send + 'static,
    F: FnOnce() -> Result<R, crate::state::BlobError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(blob_error_to_wit(e)),
        Err(join) => Err(WitError::Internal(format!(
            "blob_store: blocking task panicked: {join}"
        ))),
    }
}

/// Convert host-side [`crate::state::BlobInfo`] into the wit-bindgen
/// `BlobInfo` record. The two have the same shape — this is a
/// trivial field-by-field move kept inline so the host's blob impl
/// doesn't have to depend on the wit-bindgen types.
fn blob_info_to_wit(info: crate::state::BlobInfo) -> WitBlobInfo {
    WitBlobInfo {
        name: info.name,
        id: info.id,
        size_bytes: info.size_bytes,
        created_ms: info.created_ms,
        mime: info.mime,
    }
}

impl blob_store::Host for PluginState {
    async fn write(
        &mut self,
        name: String,
        data: Vec<u8>,
        mime: Option<String>,
    ) -> Result<String, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.write(&instance_id, &name, &data, mime.as_deref())).await
    }

    async fn read(&mut self, id: String) -> Result<Vec<u8>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.read(&instance_id, &id)).await
    }

    async fn read_by_name(&mut self, name: String) -> Result<Vec<u8>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.read_by_name(&instance_id, &name)).await
    }

    async fn get_info(&mut self, name: String) -> Result<WitBlobInfo, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.get_info(&instance_id, &name))
            .await
            .map(blob_info_to_wit)
    }

    async fn delete(&mut self, name: String) -> Result<(), WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.delete(&instance_id, &name)).await
    }

    async fn list_blobs(&mut self, prefix: String) -> Result<Vec<WitBlobInfo>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let instance_id = self.instance_id.clone();
        let rows = blob_op(move || blobs.list_blobs(&instance_id, &prefix)).await?;
        Ok(rows.into_iter().map(blob_info_to_wit).collect())
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

    /// A bare-minimum manifest just complete enough for `PluginState`
    /// to be constructed. The trait-impl unit tests below don't
    /// exercise any of these fields beyond their existence; they
    /// poke individual host calls directly, not through the loader.
    fn fixture_manifest(plugin_id: &str) -> Arc<PluginManifest> {
        use oxidhome_manifest::{CapabilitiesSection, PluginSection, RuntimeSection, World};
        use semver::Version;
        Arc::new(PluginManifest {
            manifest_version: 1,
            plugin: PluginSection {
                id: plugin_id.to_owned(),
                name: plugin_id.to_owned(),
                version: Version::new(0, 1, 0),
                authors: Vec::new(),
                description: None,
                source: None,
                license: None,
                keywords: Vec::new(),
                world: World::Plugin,
                sdk_version: Version::new(0, 1, 0),
            },
            runtime: RuntimeSection {
                wasm: std::path::PathBuf::from("plugin.wasm"),
                singleton: false,
                tick_interval_ms: None,
                fuel_per_call: None,
                memory_max_mb: None,
                call_timeout_ms: None,
            },
            // Devices declared so the in-module gating tests for
            // *non-device* paths (events, logging) don't trip the
            // gate. Per-test overrides can replace this manifest
            // via `with_caps` below.
            capabilities: CapabilitiesSection {
                declares_devices: vec![
                    "switch".into(),
                    "dimmer".into(),
                    "color-light".into(),
                    "sensor".into(),
                    "button".into(),
                    "video-stream".into(),
                    "audio-stream".into(),
                ],
                ..CapabilitiesSection::default()
            },
            config: std::collections::BTreeMap::new(),
            ui: None,
        })
    }

    /// Build a fresh KV store backed by an in-memory database and
    /// register the instance with `quota_kb` KiB of quota. Returns
    /// the `Arc<KvStore>` so individual tests can vary the quota
    /// without re-typing the wiring.
    fn fresh_kv(instance_id: &str, quota_kb: u64) -> Arc<crate::state::KvStore> {
        let db = Arc::new(crate::state::Db::open_in_memory().expect("db"));
        let kv = Arc::new(crate::state::KvStore::new(db));
        kv.register_instance(instance_id, quota_kb * 1024)
            .expect("register kv");
        kv
    }

    /// Build a throw-away [`EventLog`] backed by its own in-memory
    /// [`Db`]. Lib unit tests don't share a DB between the KV and the
    /// event log (each test makes its own); the persistence
    /// integration test in `tests/event_history.rs` exercises the
    /// shared-file shape that matters for production.
    fn fresh_event_log() -> Arc<crate::state::EventLog> {
        let db = Arc::new(crate::state::Db::open_in_memory().expect("db"));
        Arc::new(crate::state::EventLog::new(db))
    }

    /// Build a throw-away [`BlobStore`] backed by its own in-memory
    /// `Db` and no FS root — every mutating call will return
    /// `BlobError::Unavailable`. Tests that exercise actual blob
    /// writes go through `tests/blob_persistence.rs` against
    /// `Engine::with_state_dir`.
    fn fresh_blobs() -> Arc<crate::state::BlobStore> {
        let db = Arc::new(crate::state::Db::open_in_memory().expect("db"));
        Arc::new(crate::state::BlobStore::new(db, None))
    }

    fn fresh_state(instance_id: &str) -> PluginState {
        let manifest = fixture_manifest("test.fixture");
        PluginState::new(
            instance_id,
            manifest,
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
            fresh_kv(instance_id, 0),
            fresh_event_log(),
            fresh_blobs(),
        )
    }

    /// Same as [`fresh_state`] but the fixture manifest grants `kb`
    /// KiB of storage quota — the host's `require_storage_enabled`
    /// gate then lets storage calls through.
    fn fresh_state_with_storage(instance_id: &str, quota_kb: u64) -> PluginState {
        use oxidhome_manifest::CapabilitiesSection;
        let mut manifest = (*fixture_manifest("test.fixture")).clone();
        manifest.capabilities = CapabilitiesSection {
            storage_quota_kb: quota_kb,
            ..manifest.capabilities
        };
        PluginState::new(
            instance_id,
            Arc::new(manifest),
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
            fresh_kv(instance_id, quota_kb),
            fresh_event_log(),
            fresh_blobs(),
        )
    }

    fn shared_state(
        instance_id: &str,
        registry: Arc<DeviceRegistry>,
        bus: Arc<EventBus>,
    ) -> PluginState {
        PluginState::new(
            instance_id,
            fixture_manifest("test.fixture"),
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            registry,
            bus,
            fresh_kv(instance_id, 0),
            fresh_event_log(),
            fresh_blobs(),
        )
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

    /// Inject a hand-built `InstanceConfig` so the host-config trait
    /// impl can be exercised without spinning up the full loader.
    /// The flatten + leaf-lookup behavior is what we want pinned.
    #[tokio::test(flavor = "current_thread")]
    async fn host_config_returns_resolved_leaves() {
        let mut state = fresh_state("alpha");
        let mut nested = std::collections::BTreeMap::new();
        nested.insert("host".into(), ConfigValue::String("mqtt.local".into()));
        nested.insert("port".into(), ConfigValue::Int(1883));
        state
            .config
            .insert("default_state".into(), ConfigValue::Bool(true));
        state
            .config
            .insert("broker".into(), ConfigValue::Nested(nested));

        // Flat leaf.
        let v = host_config::Host::get_config(&mut state, "default_state".into())
            .await
            .unwrap()
            .expect("default_state must resolve");
        assert!(matches!(v, WitValue::BoolVal(true)));

        // Nested leaf.
        let v = host_config::Host::get_config(&mut state, "broker.host".into())
            .await
            .unwrap()
            .expect("broker.host must resolve");
        match v {
            WitValue::StringVal(s) => assert_eq!(s, "mqtt.local"),
            other => panic!("expected StringVal, got {other:?}"),
        }

        // Asking for the nested *node* (not a leaf) returns None.
        assert!(
            host_config::Host::get_config(&mut state, "broker".into())
                .await
                .unwrap()
                .is_none(),
            "bare-string nested lookups return None — leaves only"
        );

        // list_config flattens to dot-joined keys.
        let listed = host_config::Host::list_config(&mut state).await.unwrap();
        let keys: Vec<_> = listed.iter().map(|kv| kv.key.as_str()).collect();
        assert!(keys.contains(&"default_state"));
        assert!(keys.contains(&"broker.host"));
        assert!(keys.contains(&"broker.port"));
        // No bare "broker" entry — nested intermediate nodes don't
        // appear in the flattened list.
        assert!(!keys.contains(&"broker"));
    }

    /// register-device for an undeclared capability returns
    /// `PermissionDenied` — Phase 4's call-site gating in action.
    /// `fresh_state("alpha")` uses a fixture manifest that declares
    /// every standard capability; build one that declares *only*
    /// `switch` and watch a `dimmer` registration get refused.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_denied_when_capability_not_declared() {
        use oxidhome_manifest::CapabilitiesSection;

        // Construct a manifest where the plugin only declared `switch`.
        let mut manifest = (*fixture_manifest("test.switch-only")).clone();
        manifest.capabilities = CapabilitiesSection {
            declares_devices: vec!["switch".into()],
            ..CapabilitiesSection::default()
        };
        let mut state = PluginState::new(
            "alpha",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
        );

        // A device that claims `dimmer` should be refused.
        let mut info = empty_device("d-1");
        info.capabilities = vec![capabilities::CapabilitySpec::Dimmer];
        let err = host_devices::Host::register_device(&mut state, info)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("dimmer")),
            "got {err:?}",
        );

        // A device that claims only `switch` goes through.
        let mut info = empty_device("d-2");
        info.capabilities = vec![capabilities::CapabilitySpec::Switch];
        host_devices::Host::register_device(&mut state, info)
            .await
            .expect("switch is declared, register should succeed");
    }

    /// The `extension(<name>)` escape hatch must round-trip through
    /// the gate: a manifest declaring `extension(window-shade)`
    /// accepts a device with that capability.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_allows_declared_extension() {
        use oxidhome_manifest::CapabilitiesSection;

        let mut manifest = (*fixture_manifest("test.window-shade")).clone();
        manifest.capabilities = CapabilitiesSection {
            declares_devices: vec!["extension(window-shade)".into()],
            ..CapabilitiesSection::default()
        };
        let mut state = PluginState::new(
            "alpha",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
        );

        let mut info = empty_device("d-shade");
        info.capabilities = vec![capabilities::CapabilitySpec::Extension(
            "window-shade".into(),
        )];
        host_devices::Host::register_device(&mut state, info)
            .await
            .expect("declared extension should pass");
    }

    /// `initial_state` for a capability the device's `capabilities`
    /// list doesn't declare is malformed: the WIT contract says
    /// "one entry per stateful capability the plugin can already
    /// report." Reject before it lands in the registry, otherwise an
    /// undeclared sensor / switch state could slip in via the state
    /// list even when `capabilities` looks clean.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_denied_when_state_lacks_matching_capability() {
        let mut state = fresh_state("alpha");
        let mut info = empty_device("d-stateful");
        // Device claims it's a switch, but the plugin tries to ship
        // sensor state alongside — sensor isn't in `capabilities`.
        info.capabilities = vec![capabilities::CapabilitySpec::Switch];
        info.initial_state = vec![
            capabilities::CapabilityState::Switch(capabilities::Switchable { state: true }),
            capabilities::CapabilityState::Sensor(capabilities::Measurement {
                value: 21.5,
                unit: "celsius".into(),
            }),
        ];
        let err = host_devices::Host::register_device(&mut state, info)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("sensor")),
            "expected PermissionDenied naming `sensor`, got {err:?}",
        );
    }

    /// Even when `capabilities` is the empty list (no declared spec),
    /// the plugin can't smuggle state in. The state-without-spec
    /// check fires first, before the manifest gate.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_denied_when_state_present_without_any_spec() {
        let mut state = fresh_state("alpha");
        let mut info = empty_device("d-bare");
        info.initial_state = vec![capabilities::CapabilityState::Switch(
            capabilities::Switchable { state: false },
        )];
        let err = host_devices::Host::register_device(&mut state, info)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("switch")),
            "got {err:?}",
        );
    }

    /// Update path runs the same gate. A previously-clean device's
    /// `update_device` call that adds state for an undeclared
    /// capability must be refused.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_update_denied_when_state_lacks_matching_capability() {
        use oxidhome_manifest::CapabilitiesSection;

        let mut manifest = (*fixture_manifest("test.switch-only")).clone();
        manifest.capabilities = CapabilitiesSection {
            declares_devices: vec!["switch".into()],
            ..CapabilitiesSection::default()
        };
        let mut state = PluginState::new(
            "alpha",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
        );

        let mut info = empty_device("d-up");
        info.capabilities = vec![capabilities::CapabilitySpec::Switch];
        let id = host_devices::Host::register_device(&mut state, info)
            .await
            .expect("initial register");

        // Now try to update with sensor state attached.
        let mut bad = empty_device("d-up");
        bad.capabilities = vec![capabilities::CapabilitySpec::Switch];
        bad.initial_state = vec![capabilities::CapabilityState::Sensor(
            capabilities::Measurement {
                value: 21.5,
                unit: "celsius".into(),
            },
        )];
        let err = host_devices::Host::update_device(&mut state, id, bad)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("sensor")),
            "got {err:?}",
        );
    }

    /// `capabilities.storage_quota_kb = 0` (the manifest default)
    /// keeps storage gated off — every call returns `permission-denied`
    /// before it reaches the KV. The 0-vs-positive split is the
    /// host's gate; the KV's own quota check is the second line of
    /// defense once storage is enabled.
    #[tokio::test(flavor = "current_thread")]
    async fn storage_methods_denied_when_quota_zero() {
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
            assert!(
                matches!(err, WitError::PermissionDenied(_)),
                "expected PermissionDenied, got {err:?}",
            );
        }
    }

    /// With a positive quota the KV-backed methods round-trip.
    #[tokio::test(flavor = "current_thread")]
    async fn storage_round_trip_when_quota_enabled() {
        let mut state = fresh_state_with_storage("alpha", 4);
        storage::Host::set(&mut state, "k".into(), WitValue::IntVal(42))
            .await
            .expect("set");
        let got = storage::Host::get(&mut state, "k".into())
            .await
            .expect("get")
            .expect("present");
        assert!(matches!(got, WitValue::IntVal(42)), "got {got:?}");
        let keys = storage::Host::list_keys(&mut state, String::new())
            .await
            .expect("list");
        assert_eq!(keys, vec!["k".to_string()]);
        storage::Host::delete(&mut state, "k".into())
            .await
            .expect("delete");
        let after = storage::Host::get(&mut state, "k".into())
            .await
            .expect("get");
        assert!(after.is_none(), "key should be gone after delete");
    }

    /// A KV write that would push past the manifest-declared quota
    /// surfaces as `permission-denied` from the WIT side — same
    /// shape as the "storage off" gate so plugins handle both
    /// arms in one branch.
    #[tokio::test(flavor = "current_thread")]
    async fn storage_quota_exceeded_returns_permission_denied() {
        // 1 KiB quota — small enough that one big string blows past
        // it after JSON overhead.
        let mut state = fresh_state_with_storage("alpha", 1);
        let err = storage::Host::set(
            &mut state,
            "big".into(),
            WitValue::StringVal("x".repeat(4096)),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("quota exceeded")),
            "got {err:?}",
        );
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
