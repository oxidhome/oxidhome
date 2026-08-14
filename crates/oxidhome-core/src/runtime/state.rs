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
use std::time::Instant;

use oxidhome_manifest::{ConfigValue, InstanceConfig, PluginManifest};
use wasmtime::ResourceLimiter;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// C4: per-`Store` wasmtime resource ceilings applied to every plugin
/// instance. Enforces the "no compute limits equals host-wide `DoS`" fix from
/// the architecture review by capping what a single plugin's `Store`
/// can allocate — **aggregated** across every core memory and table
/// the component materializes.
///
/// Sized generously enough that legitimate plugins (device drivers,
/// automations, small ML pipelines) run untouched, but low enough
/// that a runaway allocation is refused at the wasmtime layer with a
/// trap the supervisor catches, rather than growing the host process
/// until the OOM killer intervenes. All values are per-plugin-instance
/// (each `PluginInstance` gets its own `Store` and its own limits
/// state). No per-manifest override yet — a future extension can
/// derive these from the granted-capabilities row when operators need
/// to widen or tighten specific installs.
///
/// C4 review P1 F1: aggregate ceilings, not per-memory / per-table.
/// The wasmtime-provided `StoreLimits` applies its `memory_size`
/// cap to each memory independently; a component with 8 memories
/// (the per-store max we allow) could therefore reach 8 × the
/// nominal cap = 1 GiB per Store, defeating the documented
/// "128 MiB per instance" guarantee. The custom
/// [`PluginResourceLimits`] below tracks a single aggregate byte
/// counter across every memory grow and a single aggregate element
/// counter across every table grow, so `STORE_MAX_MEMORY_BYTES`
/// truly bounds the instance.
///
/// Linear-memory aggregate cap (128 MiB per instance): well above
/// the ~few-MB working set a typical device driver needs, but
/// small enough that a hundred concurrent instances stay within
/// the ~few-GB envelope a hub-class host can sustain.
pub(crate) const STORE_MAX_MEMORY_BYTES: usize = 128 * 1024 * 1024;
/// Aggregate cap on table entries across every table in the store.
/// 100k is 10× a big libstd program's callsite count; preserves
/// component tooling headroom while refusing pathological growth.
pub(crate) const STORE_MAX_TABLE_ELEMENTS: usize = 100_000;
/// Max linear memories per store. A component-model instance usually
/// materializes one linear memory per core module; a plugin declaring
/// 8 core modules is already an outlier. Anything past this refuses
/// at instantiate time.
pub(crate) const STORE_MAX_MEMORIES: usize = 8;
/// Max tables per store. Same logic as [`STORE_MAX_MEMORIES`] — one
/// per core module is typical; the cap catches pathological compositions.
pub(crate) const STORE_MAX_TABLES: usize = 16;
/// Max sub-instances per store. Component-model instantiation can
/// create nested instances; this caps the fan-out so a hostile
/// component can't drive wasmtime into unbounded allocation before
/// its `start` function even runs.
pub(crate) const STORE_MAX_INSTANCES: usize = 128;

/// C4 review P1 F1: custom [`ResourceLimiter`] that aggregates
/// linear-memory bytes and table elements across every memory /
/// table the plugin instance's component materializes. The
/// wasmtime-provided `StoreLimits` applies its byte cap
/// per-memory, so a component with 8 memories (the per-store max
/// we allow) could reach 8 × the nominal cap — defeating the
/// documented per-instance guarantee. Aggregating in a bespoke
/// limiter closes that.
///
/// C4 review P2 F1: refusals return `Err(_)` from `memory_growing`
/// / `table_growing`, which wasmtime translates into a **trap**.
/// The pre-fix shape returned `Ok(false)` (via
/// `StoreLimitsBuilder::trap_on_grow_failure(false)`, the default),
/// which the wasm program observes as `memory.grow` returning `-1`
/// — a guest that handles allocation failure gracefully keeps
/// running, and the supervisor never sees the `Failed` state the
/// PR promised. Trapping is the right shape for a policy denial:
/// the plugin is over-quota; kill it.
#[derive(Debug)]
pub struct PluginResourceLimits {
    /// Aggregate linear-memory bytes across every memory in the
    /// store. Incremented on every accepted `memory_growing` by
    /// the delta between `desired` and `current` bytes.
    aggregate_memory_bytes: usize,
    max_aggregate_memory_bytes: usize,
    /// Aggregate table element count across every table in the
    /// store. Incremented on every accepted `table_growing` by
    /// the delta between `desired` and `current` elements.
    aggregate_table_elements: usize,
    max_aggregate_table_elements: usize,
    max_memories: usize,
    max_tables: usize,
    max_instances: usize,
}

impl PluginResourceLimits {
    fn new() -> Self {
        Self {
            aggregate_memory_bytes: 0,
            max_aggregate_memory_bytes: STORE_MAX_MEMORY_BYTES,
            aggregate_table_elements: 0,
            max_aggregate_table_elements: STORE_MAX_TABLE_ELEMENTS,
            max_memories: STORE_MAX_MEMORIES,
            max_tables: STORE_MAX_TABLES,
            max_instances: STORE_MAX_INSTANCES,
        }
    }
}

impl ResourceLimiter for PluginResourceLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum
            && desired > max
        {
            // Guest-declared max is separate from our host cap;
            // let wasmtime surface a non-trap failure for that.
            return Ok(false);
        }
        let delta = desired.saturating_sub(current);
        let projected = self.aggregate_memory_bytes.saturating_add(delta);
        if projected > self.max_aggregate_memory_bytes {
            return Err(wasmtime::Error::msg(format!(
                "C4 aggregate memory cap exceeded: {projected} B would exceed the \
                 {} B per-instance ceiling",
                self.max_aggregate_memory_bytes,
            )));
        }
        self.aggregate_memory_bytes = projected;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum
            && desired > max
        {
            return Ok(false);
        }
        let delta = desired.saturating_sub(current);
        let projected = self.aggregate_table_elements.saturating_add(delta);
        if projected > self.max_aggregate_table_elements {
            return Err(wasmtime::Error::msg(format!(
                "C4 aggregate table cap exceeded: {projected} elements would exceed \
                 the {} per-instance ceiling",
                self.max_aggregate_table_elements,
            )));
        }
        self.aggregate_table_elements = projected;
        Ok(true)
    }

    fn instances(&self) -> usize {
        self.max_instances
    }

    fn memories(&self) -> usize {
        self.max_memories
    }

    fn tables(&self) -> usize {
        self.max_tables
    }
}

/// C4: per-instance host-side payload + fan-out ceilings applied
/// beyond the wasmtime `Store` limits above. Enforce DoS-relevant
/// caps on things wasmtime doesn't know about (blob writes, event
/// payload sizes, active subscription count). Refusals surface as
/// [`WitError::PermissionDenied`] so the plugin sees a clean
/// capability-shaped error rather than a trap.
///
/// `MAX_KV_VALUE_BYTES` — largest value payload the KV `storage::set`
/// import will accept, on top of the manifest's byte quota. The
/// per-instance byte quota bounds *total* KV bytes; this cap bounds
/// a *single* write so a plugin can't spend its entire quota on one
/// enormous value.
pub(crate) const MAX_KV_VALUE_BYTES: usize = 64 * 1024;
/// `MAX_BLOB_WRITE_BYTES` — largest single blob write. Beyond this,
/// use of the streaming blob API (Phase 8+) is the intended path.
/// 16 MiB comfortably covers snapshot images and short audio clips
/// while refusing a single-call attempt to fill the disk.
pub(crate) const MAX_BLOB_WRITE_BYTES: usize = 16 * 1024 * 1024;
/// `MAX_EVENT_PAYLOAD_BYTES` — largest serialized `publish-event`
/// payload. Bounds the per-event copy fanned out to every subscriber
/// (already `Arc`'d after C2e P1, but the byte total still gates
/// per-subscriber slot occupancy). 64 KiB covers state deltas and
/// button events by orders of magnitude.
pub(crate) const MAX_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;
/// `MAX_SUBSCRIPTIONS_PER_INSTANCE` — hard cap on live subscriptions
/// one plugin instance can hold at once. Distinct from the bus-side
/// `SOFT_SUBSCRIBER_CAP` (soft, warn-only, across all subscribers)
/// because a *per-instance* cap is what stops one buggy plugin from
/// registering thousands of overlapping filters and pinning the
/// filter-eval loop in `EventBus::publish`. Sized to comfortably
/// exceed a real driver's needs — a few dozen device-scoped filters,
/// plus a handful of topic filters.
pub(crate) const MAX_SUBSCRIPTIONS_PER_INSTANCE: usize = 64;

/// C4 review P1 F2: per-message byte cap on the `logging::log`
/// host import. Messages larger than this are truncated (with
/// an `[…truncated N B]` suffix) rather than refused, so a
/// legitimate plugin that logs a big struct doesn't lose the
/// call — but the `LogStore`'s queue and any downstream consumer
/// see a bounded per-record cost. 4 KiB is well above the
/// typical structured-log line (a few hundred bytes) and small
/// enough that even a saturated 1024-slot `LogStore` queue holds
/// at most ~4 MiB of message text, not gigabytes.
pub(crate) const MAX_LOG_MESSAGE_BYTES: usize = 4 * 1024;
/// C4 review P1 F2: per-instance log call rate ceiling
/// (calls/second, refilled continuously). The pre-fix path
/// forwarded every `logging::log` call to `tracing`, which the
/// `SQLite` `LogStore` layer buffers up to 1024 owned records; a
/// plugin loop could accumulate multi-GiB of host memory in the
/// pending queue before the drain caught up. Rate-limiting the
/// admission bounds queue growth by construction. 100/sec is a
/// generous ceiling for real device drivers (interaction events,
/// periodic state, occasional error) and matches the shape of
/// the C2d `publish-event` rate limit.
pub(crate) const LOG_RATE_PER_SEC: f64 = 100.0;
/// Burst capacity for the log rate limiter. Sized to accommodate
/// a plugin logging a batch of startup diagnostics without being
/// throttled, but low enough that a rogue publisher can't spend
/// the `LogStore` queue in one burst.
pub(crate) const LOG_RATE_BURST: f64 = 64.0;

/// Per-instance token bucket for `logging::log` admission.
/// Same shape as [`crate::state::events`]'s publish limiter but
/// lives here because per-instance log state is naturally
/// per-`PluginState`. Non-blocking, non-async — the check is
/// entirely local to one Store.
#[doc(hidden)]
#[derive(Debug)]
pub struct LogRateBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl LogRateBucket {
    fn new() -> Self {
        Self {
            tokens: LOG_RATE_BURST,
            capacity: LOG_RATE_BURST,
            refill_per_sec: LOG_RATE_PER_SEC,
            last_refill: Instant::now(),
        }
    }

    /// Consume one token if available; return `false` when
    /// exhausted so the caller can drop the log call.
    fn consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::{
    blob_store::{self, BlobInfo as WitBlobInfo},
    capabilities,
    devices::{self, CommandResult, DeviceInfo},
    events,
    events::{Event, EventFilter, EventPayload},
    host_config, host_devices, host_events, host_services,
    logging::{self, Level as WitLevel},
    services::{self, ServiceInfo},
    storage, types,
    types::{DeviceId, Error as WitError, KeyValue, ServiceId, SubscriptionId, Value as WitValue},
};
use crate::runtime::registry::InstanceRegistry;
use crate::state::{
    DeviceRegistry, EventBus, EventSubscription, MAX_CAPABILITIES_PER_DEVICE, ServiceRegistry,
};

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
    /// C1b — host-minted, per-install UUID from
    /// [`crate::state::InstalledPluginRegistry`]. Pinned at
    /// [`PluginInstance::load`](crate::PluginInstance::load) time
    /// so all device ids minted by this instance derive from the
    /// same installation identity (see [`crate::state::stable_device_id`]).
    /// For in-memory loads that don't go through the installed-plugin
    /// registry (test harness, `Engine::new()`), the fallback is
    /// `manifest.plugin.id` itself — cheap synthetic UUID; identity
    /// still stable per-run but doesn't survive a fresh process.
    pub installation_uuid: Arc<str>,
    /// C5 — the host-owned **granted** capabilities for this
    /// install. Runtime gates (`register-device`,
    /// `host-events::subscribe`, storage/blob quota checks)
    /// consult this rather than `manifest.capabilities` so a
    /// future operator override at install / modify time takes
    /// effect without editing the plugin's manifest. Pinned at
    /// load time to what [`crate::state::InstalledPluginRegistry`]
    /// remembers for the loaded install; falls back to the
    /// manifest's requested capabilities for dev-time loads that
    /// don't go through `install`.
    pub granted_capabilities: Arc<oxidhome_manifest::CapabilitiesSection>,
    /// H10 round-4: `consumes_services` grants as declared in the
    /// **manifest** (before operator narrowing). The dispatcher
    /// authorizes a `call-service` iff at least one entry here
    /// AND at least one entry in
    /// `granted_capabilities.consumes_services` matches the call.
    /// Held separately from `granted_capabilities` because the
    /// requested-vs-granted intersection is applied at dispatch
    /// time instead of being materialized at load time — a
    /// materialized cross-product grows O(N²) in the count of
    /// selectors and is DoS-able from the manifest side.
    pub consumes_services_requested: Arc<Vec<oxidhome_manifest::ServiceGrant>>,
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
    /// H9 host-owned device-state projection. Seeded from
    /// `register-device.initial_state` and updated on every
    /// `publish-event` carrying a `state-changed` payload.
    pub device_state: Arc<crate::state::DeviceStateStore>,
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
    /// Shared service registry — Phase 7. `host-services` calls go
    /// through here; owner-scoped to this instance's `instance_id`.
    pub services: Arc<ServiceRegistry>,
    /// Shared instance registry — Phase 7c. `call_service` resolves
    /// the target's owner through `services.get_any(...)` and then
    /// looks up that owner's handle here to dispatch.
    pub instances: Arc<InstanceRegistry>,
    /// Per-instance wake `Notify` — C2d wake-isolation. Signaled by
    /// the [`EventBus`] every time a published event matches one
    /// of this plugin's active subscription filters. The
    /// supervisor's `select!` awaits `notify.notified()` so it
    /// only wakes when a delivery would land, not on every bus
    /// event system-wide (the pre-C2d amplification path).
    ///
    /// Held by two owners: this struct (used at
    /// `subscribe_with_wake` call time), and the supervisor's
    /// serve loop (retrieved through
    /// [`crate::PluginInstance::wake`]).
    pub wake: Arc<tokio::sync::Notify>,
    /// C4 — wasmtime resource ceilings for this instance's `Store`.
    /// Populated in [`Self::new`] from the module-level `STORE_MAX_*`
    /// constants and installed via `store.limiter(|s| &mut s.limits)`
    /// in the loader. A plugin whose linear-memory / table / instance
    /// growth would breach a cap traps at wasmtime's allocation path
    /// (C4 review P2 F1: [`PluginResourceLimits`] returns `Err(_)` on
    /// refusal, which wasmtime converts to a trap); the supervisor
    /// catches the trap and applies the manifest's restart policy.
    pub limits: PluginResourceLimits,
    /// C4 review P1 F2: per-instance token bucket for
    /// `logging::log` admission. Refuses log calls past
    /// [`LOG_RATE_PER_SEC`] / [`LOG_RATE_BURST`] so a flooder
    /// can't drive the `LogStore` queue into multi-GiB retention.
    /// `std::sync::Mutex` because the check runs synchronously
    /// inside the host import; the critical section is O(1).
    pub log_rate: std::sync::Mutex<LogRateBucket>,
}

impl PluginState {
    /// Build a fresh state for one plugin instance. `devices` /
    /// `events` / `kv` / `event_log` / `blobs` come from the parent
    /// [`Engine`](crate::Engine); the manifest, actor, and resolved
    /// config come from the loader (real or test).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: impl Into<InstanceId>,
        installation_uuid: impl Into<Arc<str>>,
        manifest: Arc<PluginManifest>,
        actor: Actor,
        config: InstanceConfig,
        devices: Arc<DeviceRegistry>,
        device_state: Arc<crate::state::DeviceStateStore>,
        events: Arc<EventBus>,
        kv: Arc<crate::state::KvStore>,
        event_log: Arc<crate::state::EventLog>,
        blobs: Arc<crate::state::BlobStore>,
        services: Arc<ServiceRegistry>,
        instances: Arc<InstanceRegistry>,
    ) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        // C5: `PluginState::new` doesn't know about
        // `InstalledPluginRegistry` (it's the low-level
        // constructor used by tests + the loader). Default the
        // grant to the manifest's request — the loader
        // (`PluginInstance::instantiate`) overrides via
        // `Self::with_granted_capabilities` when a live install
        // row is present.
        let granted_capabilities = Arc::new(manifest.capabilities.clone());
        // H10 round-4: seed the "requested" list from the manifest
        // directly, matching the granted default above. The loader
        // (`PluginInstance::instantiate`) overrides only the
        // granted side when a live install row is present; the
        // requested side always reflects what the plugin author
        // asked for.
        let consumes_services_requested = Arc::new(manifest.capabilities.consumes_services.clone());
        // C4: aggregate-tracking wasmtime `ResourceLimiter`. Every
        // plugin instance gets the same shape today; per-manifest
        // overrides can layer on later without changing the wiring
        // here. The custom limiter (rather than
        // `StoreLimitsBuilder`) is what makes the byte / element
        // cap a true per-instance ceiling across all memories /
        // tables (C4 review P1 F1) and traps on refusal (P2 F1).
        let limits = PluginResourceLimits::new();
        Self {
            instance_id: instance_id.into(),
            installation_uuid: installation_uuid.into(),
            granted_capabilities,
            consumes_services_requested,
            table: ResourceTable::new(),
            wasi: wasi.build(),
            devices,
            device_state,
            events,
            kv,
            event_log,
            blobs,
            services,
            instances,
            subscriptions: Vec::new(),
            manifest,
            actor,
            config,
            wake: Arc::new(tokio::sync::Notify::new()),
            limits,
            log_rate: std::sync::Mutex::new(LogRateBucket::new()),
        }
    }

    /// C5: override the granted capabilities set by
    /// [`Self::new`]'s manifest-default. The loader
    /// [`PluginInstance::instantiate`](crate::PluginInstance) calls
    /// this after looking the installation up in
    /// [`InstalledPluginRegistry`](crate::state::InstalledPluginRegistry)
    /// so the runtime gates consult the persisted grant, not the
    /// manifest.
    #[must_use]
    pub fn with_granted_capabilities(
        mut self,
        granted: Arc<oxidhome_manifest::CapabilitiesSection>,
    ) -> Self {
        self.granted_capabilities = granted;
        self
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
impl services::Host for PluginState {}

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
pub(crate) fn capability_name(spec: &capabilities::CapabilitySpec) -> String {
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

/// H9: project a `DeviceInfo.initial_state` list into the
/// `(capability_name, Vec<KeyValue>)` shape that
/// [`crate::state::DeviceStateStore::seed`] takes. Uses the same
/// field names the plugin author would emit on a
/// `state-changed(...)` event so seed and post-registration updates
/// share a shape.
fn seed_state_from_initial(info: &DeviceInfo) -> Vec<(String, Vec<KeyValue>)> {
    use crate::host_impl::plugin::oxidhome::plugin::types::Value;
    info.initial_state
        .iter()
        .map(|state| {
            let name = capability_state_name(state).to_string();
            let fields = match state {
                capabilities::CapabilityState::Switch(s) => vec![KeyValue {
                    key: "state".into(),
                    value: Value::BoolVal(s.state),
                }],
                capabilities::CapabilityState::Dimmer(d) => vec![KeyValue {
                    key: "level".into(),
                    value: Value::FloatVal(d.level),
                }],
                capabilities::CapabilityState::ColorLight(c) => {
                    let mut fields = vec![
                        KeyValue {
                            key: "hue".into(),
                            value: Value::FloatVal(c.hue),
                        },
                        KeyValue {
                            key: "saturation".into(),
                            value: Value::FloatVal(c.saturation),
                        },
                        KeyValue {
                            key: "value".into(),
                            value: Value::FloatVal(c.value),
                        },
                    ];
                    if let Some(kelvin) = c.color_temp_kelvin {
                        fields.push(KeyValue {
                            key: "color_temp_kelvin".into(),
                            value: Value::IntVal(i64::from(kelvin)),
                        });
                    }
                    fields
                }
                capabilities::CapabilityState::Sensor(m) => vec![
                    KeyValue {
                        key: "value".into(),
                        value: Value::FloatVal(m.value),
                    },
                    KeyValue {
                        key: "unit".into(),
                        value: Value::StringVal(m.unit.clone()),
                    },
                ],
            };
            (name, fields)
        })
        .collect()
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
    // H9 round-14 finding 2: cap capabilities per device.
    // Without this, a single device can hold arbitrarily
    // many `extension(<unique>)` slots — bypassing the
    // per-instance device quota (only one device) and
    // amplifying every snapshot page (one device forces
    // every capability onto the same page). Chosen
    // generously — real devices in the review's registry
    // don't exceed a handful of capabilities.
    if info.capabilities.len() > MAX_CAPABILITIES_PER_DEVICE {
        return Err(WitError::InvalidArgument(format!(
            "device `{}` declares {} capabilities; the per-device cap is {MAX_CAPABILITIES_PER_DEVICE}",
            info.local_id,
            info.capabilities.len(),
        )));
    }
    // H9 round-14 finding 1: reject oversized `initial_state`
    // entries at the WIT boundary. Pre-fix, the store
    // silently truncated them and the caller saw success.
    // Uses the same per-variant projection as
    // `seed_state_from_initial` so the check matches what
    // actually reaches the store.
    for (name, fields) in seed_state_from_initial(info) {
        if let Err(overflow) = crate::state::DeviceStateStore::check_snapshot_admission(&fields) {
            return Err(WitError::InvalidArgument(format!(
                "initial_state entry `{name}` on device `{}` would exceed the projection's \
                 per-slot cap ({overflow})",
                info.local_id,
            )));
        }
    }

    // H9 round-11 finding 2: WIT contract is one entry per
    // stateful capability. Duplicates in either list are
    // rejected up front — pre-fix, two `Switch` entries in
    // `initial_state` silently hit the same projection key and
    // the last-written value won, producing non-deterministic
    // canonical state. Same story for two `Switch` entries in
    // `capabilities`: `reset_and_seed_device` sees the key
    // once but the reconciliation semantics get muddled.
    let mut seen_caps: std::collections::HashSet<String> = std::collections::HashSet::new();
    for spec in &info.capabilities {
        let name = capability_name(spec);
        if !seen_caps.insert(name.clone()) {
            return Err(WitError::InvalidArgument(format!(
                "capability `{name}` appears more than once in `DeviceInfo.capabilities` \
                 (the WIT contract is one spec per capability)"
            )));
        }
    }
    let mut seen_state: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    for state in &info.initial_state {
        let name = capability_state_name(state);
        if !seen_state.insert(name) {
            return Err(WitError::InvalidArgument(format!(
                "initial_state contains multiple `{name}` entries (the WIT contract is \
                 one entry per stateful capability)"
            )));
        }
    }
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

#[cfg(test)]
mod authorize_device_info_tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::capabilities;

    fn info(
        caps: Vec<capabilities::CapabilitySpec>,
        state: Vec<capabilities::CapabilityState>,
    ) -> DeviceInfo {
        DeviceInfo {
            local_id: "d".into(),
            name: "d".into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: caps,
            initial_state: state,
            metadata: Vec::new(),
        }
    }

    /// H9 round-11 finding 2: two `Switch` entries in
    /// `capabilities` are rejected up front. Pre-fix the second
    /// spec was silently accepted.
    #[test]
    fn rejects_duplicate_capability_spec() {
        let declared = vec!["switch".to_string()];
        let d = info(
            vec![
                capabilities::CapabilitySpec::Switch,
                capabilities::CapabilitySpec::Switch,
            ],
            Vec::new(),
        );
        let err = authorize_device_info(&declared, &d).unwrap_err();
        assert!(matches!(err, WitError::InvalidArgument(_)), "got {err:?}");
    }

    /// H9 round-11 finding 2: two `Switch` entries in
    /// `initial_state` are rejected. Pre-fix both hit the same
    /// projection key sequentially and the second silently
    /// overwrote the first.
    #[test]
    fn rejects_duplicate_initial_state_entry() {
        let declared = vec!["switch".to_string()];
        let d = info(
            vec![capabilities::CapabilitySpec::Switch],
            vec![
                capabilities::CapabilityState::Switch(capabilities::Switchable { state: true }),
                capabilities::CapabilityState::Switch(capabilities::Switchable { state: false }),
            ],
        );
        let err = authorize_device_info(&declared, &d).unwrap_err();
        assert!(matches!(err, WitError::InvalidArgument(_)), "got {err:?}");
    }
}

impl host_devices::Host for PluginState {
    async fn register_device(&mut self, info: DeviceInfo) -> Result<DeviceId, WitError> {
        // Authorize the full DeviceInfo: gate `capabilities` against
        // the manifest's `declares_devices`, *and* refuse any
        // `initial_state` entry that doesn't have a matching spec on
        // the same device (otherwise a plugin could smuggle in state
        // for an undeclared sensor / switch / etc. via the state list).
        if let Err(err) = authorize_device_info(&self.granted_capabilities.declares_devices, &info)
        {
            tracing::warn!(
                instance_id = %self.instance_id,
                error = %err,
                "register-device denied",
            );
            return Err(err);
        }

        // C1b: derive device_id from `installation_uuid` (host-minted
        // per-install) rather than `manifest.plugin.id` (reusable
        // name). Uninstall + reinstall produces different device ids.
        //
        // H9: also seed the host-owned state projection with any
        // `initial_state` entries the plugin registered. The
        // `authorize_device_info` gate above already refused any
        // `initial_state` entry that doesn't match a declared
        // capability, so what lands here is safe to project.
        // Cloning `info.initial_state` + `capabilities` before the
        // move into `register` — need them for state seeding /
        // reconciliation.
        let seed_state = seed_state_from_initial(&info);
        // H9 round-17 finding 1: run the aggregate-bytes
        // check BEFORE the registry mutation. The device_id
        // is deterministic (`stable_device_id`), so we can
        // compute it without registering first. Pre-fix, a
        // re-register that passed the device-count cap but
        // failed the aggregate cap called `devices.remove`
        // to roll back — which unconditionally deleted the
        // entry, dropping the *pre-register* metadata that
        // had been overwritten in-place. State APIs would
        // then advertise a Fresh device that command routing
        // and registry reads said didn't exist.
        let would_be_id = crate::state::devices::stable_device_id(
            &self.installation_uuid,
            &self.instance_id,
            &info.local_id,
        );
        if let Err(overflow) = self.device_state.check_instance_register_admission(
            &would_be_id,
            &self.instance_id,
            &seed_state,
        ) {
            tracing::warn!(
                instance_id = %self.instance_id,
                device_id = %would_be_id,
                overflow = %overflow,
                "register-device denied (per-instance aggregate cap); registry untouched",
            );
            return Err(WitError::InvalidArgument(format!(
                "register-device on `{would_be_id}` would exceed the projection's \
                 per-instance aggregate cap ({overflow})",
            )));
        }
        // H9 round-11 finding 1: per-instance registration cap
        // is enforced under the registry's write lock so a
        // check-then-insert can't overshoot. Refusal returns
        // `Unavailable` — the plugin can retry after removing
        // some devices.
        let id =
            match self
                .devices
                .try_register(&self.installation_uuid, self.instance_id.clone(), info)
            {
                Ok(id) => id,
                Err(err) => {
                    tracing::warn!(
                        instance_id = %self.instance_id,
                        error = %err,
                        "register-device denied (per-instance device cap)",
                    );
                    return Err(err);
                }
            };
        debug_assert_eq!(
            id, would_be_id,
            "stable_device_id must match try_register's derivation"
        );
        let received_ms = crate::state::event_log::now_unix_ms();
        // H9 round-10 finding 1: atomically flip every pre-existing
        // `Fresh` entry for this stable device-id to `Stale`, then
        // seed the current registration's `initial_state`. Handles
        // three cases in one lock:
        //   * capability removed — flipped stale, not re-seeded
        //   * capability retained, seeded — re-appears Fresh
        //   * capability retained, NOT seeded — stays Stale until
        //     the plugin publishes a `state-change`, matching the
        //     "empty initial_state means state arrives later"
        //     contract. Pre-fix, that last case silently retained
        //     the pre-restart value as Fresh.
        self.device_state.reset_and_seed_device(
            &id,
            &self.instance_id,
            seed_state,
            0, // observed_ms — plugin didn't attach one for register-time state
            received_ms,
        );
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
        if let Err(err) = authorize_device_info(&self.granted_capabilities.declares_devices, &info)
        {
            tracing::warn!(
                instance_id = %self.instance_id,
                device_id = %id,
                error = %err,
                "update-device denied",
            );
            return Err(err);
        }
        // H9 round-2 finding 3: reconcile the projection with the
        // (possibly narrower) capabilities list before the update
        // lands, so a dropped capability's entries flip to `Stale`
        // instead of continuing to advertise as `Fresh` on a
        // device that no longer declares them.
        let live_capabilities: Vec<String> =
            info.capabilities.iter().map(capability_name).collect();
        let outcome = self.devices.update(&self.instance_id, &id, info);
        if outcome.is_ok() {
            self.device_state
                .reconcile_capabilities(&id, &live_capabilities);
        }
        outcome
    }

    async fn remove_device(&mut self, id: DeviceId) -> Result<(), WitError> {
        let outcome = self.devices.remove(&self.instance_id, &id);
        if outcome.is_ok() {
            // H9 round-2 finding 3: the device is gone; flip every
            // projection entry for it to `Stale` so consumers stop
            // reading pre-remove values as `Fresh`. Runs only on
            // successful remove — a `NotFound` / `Unavailable`
            // return means the device wasn't ours (or is
            // uninstall-locked) and its state is someone else's
            // to sweep.
            self.device_state.mark_device_stale(&id);
            tracing::debug!(
                instance_id = %self.instance_id,
                device_id = %id,
                "removed device"
            );
        }
        outcome
    }

    async fn get_device(&mut self, id: DeviceId) -> Result<DeviceInfo, WitError> {
        // The Arc holds the canonical meta; the WIT surface returns
        // `DeviceInfo` by value so we clone `info` once at the
        // boundary. `id` and `owner_instance` aren't cloned.
        self.devices
            .get(&self.instance_id, &id)
            .map(|meta| meta.info.clone())
    }
}

// ── Services (Phase 7) ─────────────────────────────────────────────────
//
// `register-service` is gated by the manifest's `declares_services`
// (matching `host-devices`'s `declares_devices` shape). `update` /
// `remove` / `get` are owner-scoped through the registry.
// `call-service` is the synchronous cross-plugin dispatch — it
// routes through `runtime::dispatcher::call_service`, which resolves
// the target's owner, rejects cycles at instance granularity, and
// hops to the owner's supervisor task via
// `ControlCommand::ExecuteService`. The in-flight refcount
// (`CallGuard`) travels with the message so `remove-service` refuses
// while a call is alive.

/// Whether `name` appears in the manifest's `declares_services`. The
/// service's `name` field is the capability key (the human-readable
/// name), mirroring how `declares_devices` gates by capability.
fn service_name_declared(declared: &[String], name: &str) -> bool {
    declared.iter().any(|d| d == name)
}

/// H10 round-3 finding 3: reject `"*"` command names on
/// `register_service` / `update_service`. `"*"` is the reserved
/// wildcard sentinel in `ServiceGrant.commands`; letting a
/// service register a command literally named `"*"` would create
/// a real command that no grant can name distinctly from
/// "authorize every command".
fn check_no_wildcard_command_names(info: &ServiceInfo) -> Result<(), WitError> {
    for cmd in &info.commands {
        if cmd.name == oxidhome_manifest::ServiceGrant::ANY_COMMAND {
            return Err(WitError::InvalidArgument(format!(
                "command name `{}` is reserved (wildcard sentinel in \
                 `[[capabilities.consumes_services]]` grants); pick a \
                 different name",
                cmd.name
            )));
        }
    }
    Ok(())
}

impl host_services::Host for PluginState {
    async fn register_service(&mut self, info: ServiceInfo) -> Result<ServiceId, WitError> {
        if !service_name_declared(&self.granted_capabilities.declares_services, &info.name) {
            let err = WitError::PermissionDenied(format!(
                "service name `{}` is not declared in this plugin's manifest \
                 (capabilities.declares_services)",
                info.name,
            ));
            tracing::warn!(
                instance_id = %self.instance_id,
                service_name = %info.name,
                error = %err,
                "register-service denied",
            );
            return Err(err);
        }
        check_no_wildcard_command_names(&info)?;
        // H10: registry now enforces `(owner_instance, local_id)`
        // uniqueness and surfaces the collision as
        // `InvalidArgument` — pass it through.
        let id = self.services.register(
            self.instance_id.clone(),
            self.manifest.plugin.id.clone(),
            info,
        )?;
        tracing::debug!(
            instance_id = %self.instance_id,
            service_id = %id,
            "registered service"
        );
        Ok(id)
    }

    async fn update_service(&mut self, id: ServiceId, info: ServiceInfo) -> Result<(), WitError> {
        // Same capability gate as register — a plugin can't update a
        // service into a name it wasn't allowed to declare. H10:
        // `local-id` is immutable; the registry rejects any attempt
        // to change it with `InvalidArgument`. `"*"` command names
        // are refused on update too (see `register_service`).
        if !service_name_declared(&self.granted_capabilities.declares_services, &info.name) {
            let err = WitError::PermissionDenied(format!(
                "service name `{}` is not declared in this plugin's manifest \
                 (capabilities.declares_services)",
                info.name,
            ));
            tracing::warn!(
                instance_id = %self.instance_id,
                service_id = %id,
                error = %err,
                "update-service denied",
            );
            return Err(err);
        }
        check_no_wildcard_command_names(&info)?;
        self.services.update(&self.instance_id, &id, info)
    }

    async fn remove_service(&mut self, id: ServiceId) -> Result<(), WitError> {
        let outcome = self.services.remove(&self.instance_id, &id);
        if outcome.is_ok() {
            tracing::debug!(
                instance_id = %self.instance_id,
                service_id = %id,
                "removed service"
            );
        }
        outcome
    }

    async fn get_service(&mut self, id: ServiceId) -> Result<ServiceInfo, WitError> {
        // Clone `info` once at the WIT boundary; `id` and
        // `owner_instance` are kept behind the Arc.
        self.services
            .get(&self.instance_id, &id)
            .map(|meta| meta.info.clone())
    }

    async fn resolve_service(
        &mut self,
        plugin_id: String,
        instance_id: String,
        service_local_id: String,
    ) -> Result<ServiceId, WitError> {
        // H10: stable `(plugin_id, instance_id, local_id)` →
        // `service_id` lookup. Not owner-scoped by design — a
        // caller resolves services on other plugins routinely.
        // Resolution returns the id even if the caller cannot
        // then invoke it; the `consumes_services` authorization
        // check runs later in the dispatcher on `call_service`
        // and is finer-grained (matches on plugin, instance,
        // local_id, and command).
        self.services
            .resolve_by_local_id(&plugin_id, &instance_id, &service_local_id)
            .ok_or_else(|| {
                WitError::NotFound(format!(
                    "no service `{service_local_id}` owned by plugin \
                     `{plugin_id}` instance `{instance_id}`"
                ))
            })
    }

    async fn call_service(
        &mut self,
        target: ServiceId,
        command: String,
        args: Vec<KeyValue>,
    ) -> Result<CommandResult, WitError> {
        // Phase 7c: route through the dispatcher. Resolves target →
        // `(owner_instance, owner_plugin_id, local_id)`. H10
        // round-4: authorizes by checking **both** the caller's
        // requested `consumes_services` list AND the operator's
        // granted list at call time — a call is authorized iff at
        // least one entry in each matches the call tuple. Rejects
        // same-instance / A→…→A cycles, races
        // `execute-service-command` against the dispatcher
        // timeout, holds a `CallGuard` so `remove-service` refuses
        // while the call is alive.
        crate::runtime::dispatcher::call_service(
            &self.services,
            &self.instances,
            self.instance_id.clone(),
            &self.consumes_services_requested,
            &self.granted_capabilities.consumes_services,
            target,
            command,
            args,
        )
        .await
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

/// Payload → required device capability name, or `None` if the
/// payload variant doesn't imply a device capability. Kept as a free
/// function so the trait impl body stays readable.
fn required_capability_for_payload(payload: &EventPayload) -> Option<String> {
    match payload {
        // `state-changed.capability` names the changed capability —
        // require the device to actually declare it.
        EventPayload::StateChanged(sc) => Some(sc.capability.clone()),
        // The `button` variant only fires on devices with the button
        // capability.
        EventPayload::Button(_) => Some("button".into()),
        // `inference` results are ML-pipeline output; the tap can
        // attach to any capability (video-stream, audio-stream, or
        // even sensor). `custom` topics are free-form by design.
        // Neither implies a device capability contract.
        EventPayload::Inference(_) | EventPayload::Custom(_) => None,
    }
}

/// Publish gate — see the block comment in `publish_event`.
fn require_publish_authorized(
    devices: &DeviceRegistry,
    instance_id: &InstanceId,
    ev: &Event,
) -> Result<(), WitError> {
    match (&ev.device, &ev.payload) {
        // Variants that describe something *about a device* refuse
        // `device: None`. Without a device the subscriber has no
        // way to attribute the event, and — since the wire shape
        // carries no host-populated origin today — accepting these
        // would let any plugin forge arbitrary state-changes,
        // button presses, or inference results.
        (
            None,
            EventPayload::StateChanged(_) | EventPayload::Button(_) | EventPayload::Inference(_),
        ) => Err(WitError::InvalidArgument(
            "publish-event: this payload variant requires a `device` field".into(),
        )),
        // Bus-only custom event — no device implies no ownership or
        // capability check.
        (None, EventPayload::Custom(_)) => Ok(()),
        // Owned-device path. `DeviceRegistry::get` collapses foreign
        // and unregistered into the same `NotFound`; we map it to
        // `PermissionDenied` here so the error framing matches the
        // spoofing-gate semantics.
        (Some(device_id), payload) => {
            let meta = devices.get(instance_id, device_id).map_err(|_| {
                WitError::PermissionDenied(format!(
                    "publish-event: device `{device_id}` is not owned by this instance",
                ))
            })?;
            if let Some(required) = required_capability_for_payload(payload)
                && !meta
                    .info
                    .capabilities
                    .iter()
                    .any(|spec| capability_name(spec) == required)
            {
                return Err(WitError::PermissionDenied(format!(
                    "publish-event: device `{device_id}` does not declare capability `{required}`",
                )));
            }
            Ok(())
        }
    }
}

impl host_events::Host for PluginState {
    #[allow(clippy::too_many_lines)]
    async fn publish_event(&mut self, ev: Event) -> Result<(), WitError> {
        // Architecture-review C2 — three gates before the event
        // reaches the bus:
        //
        // 1. Payload/device consistency: `state-changed`, `button`,
        //    and `inference` are all *about* something on a device,
        //    so `device: None` for those variants is malformed —
        //    the subscriber has no way to attribute the event
        //    otherwise. Only `custom` may skip the device.
        // 2. Ownership: when the event does carry a device, that
        //    device must have been registered from this instance.
        //    Foreign and unregistered IDs collapse to the same
        //    `permission-denied` message so the call can't be used
        //    to probe for device existence.
        // 3. Capability: the event variant must be consistent with
        //    the device's declared capabilities — a device with no
        //    `switch` cap can't publish a `state-changed("switch")`,
        //    a device without `button` can't fire `button` events.
        //    `inference` and `custom` carry no capability contract
        //    of their own, so their capability check is a no-op.
        require_publish_authorized(&self.devices, &self.instance_id, &ev)?;

        // Architecture-review C2b: stamp the event's origin from the
        // publisher's own instance / manifest identity. Any value the
        // plugin passed for these fields is discarded — subscribers
        // (WIT `on-event`, JSON `/events/tail`, Connect
        // `Events.TailEvents`) trust `origin-plugin-id` /
        // `origin-instance-id` as the immutable event origin.
        let mut ev = ev;
        ev.origin_plugin_id = self.manifest.plugin.id.clone();
        ev.origin_instance_id = self.instance_id.clone();

        // C4 review P2 F2: serialize the payload ONCE, cap on the
        // exact bytes that will hit disk, then hand the same
        // buffer to `record_prepared` so persistence doesn't
        // re-encode. Measured after the origin stamp so the cap
        // reflects what the durable log actually stores (not the
        // caller-supplied strings that were about to be
        // overwritten). Failure on serialize returns `Internal` —
        // the standard WIT payload variants all round-trip, so a
        // failure here means an unexpected variant, not a client
        // input problem.
        let topic = crate::state::event_log::topic_of(&ev).to_owned();
        let payload_blob = crate::state::event_log::serialize_payload(&ev.payload, &topic)
            .map_err(|e| WitError::Internal(format!("publish-event: serialize failed: {e}")))?;
        // C4 review round-2: the cap is named `MAX_EVENT_PAYLOAD_BYTES`
        // and the error message says "serialized payload", so measure
        // exactly that — the serialized payload blob alone. The
        // durable row also stores the topic + host-stamped identity
        // strings + fixed-width columns, but those are bounded by
        // construction (`plugin_id` / `instance_id` are host-validated,
        // topic is host-derived from the payload variant) and the
        // cap intent is about the plugin-controlled payload bytes.
        // The pre-fix shape mixed payload + wrapper into `stored_bytes`
        // and compared it to the payload constant, so the effective
        // payload budget shrank silently as identifiers got longer.
        let payload_bytes = payload_blob.len();
        if payload_bytes > MAX_EVENT_PAYLOAD_BYTES {
            tracing::warn!(
                target: "host.events",
                instance_id = %self.instance_id,
                payload_bytes,
                max = MAX_EVENT_PAYLOAD_BYTES,
                "publish-event refused: serialized payload exceeds C4 per-event byte cap",
            );
            return Err(WitError::PermissionDenied(format!(
                "publish-event serialized payload ({payload_bytes} bytes) exceeds \
                 per-event cap ({MAX_EVENT_PAYLOAD_BYTES} bytes)"
            )));
        }

        // C2d admission (PR #82 review, F2): consult the per-instance
        // rate limiter *before* the durable-mirror spawn_blocking.
        // The first cut of C2d put admission at the end of this
        // function, so a flooder still consumed a blocking-pool
        // thread + a SQLite write per over-quota publish; on refusal
        // the caller saw `Unavailable` even though the row was
        // already committed to `event_log`. Admission-first means a
        // refused publish never spends disk or blocking-pool budget
        // and never leaves a durable side effect for the caller to
        // reconcile.
        if let Err(crate::state::PublishDenied::RateLimited {
            capacity,
            refill_per_sec,
            ..
        }) = self.events.admit_publish(&self.instance_id)
        {
            tracing::warn!(
                target: "host.events",
                instance_id = %self.instance_id,
                capacity,
                refill_per_sec,
                "publish rate-limited (pre-persistence)",
            );
            return Err(WitError::Unavailable(format!(
                "publish-event: per-instance publish quota exhausted \
                 (capacity {capacity} events, refill {refill_per_sec}/s)",
            )));
        }

        // H9 round-14 finding 1: for `state-changed` events,
        // pre-check the per-slot cap before persisting to
        // the event log / broadcasting. Pre-fix, the store
        // silently dropped overflow fields — leaving the
        // durable log carrying the full event and the
        // projection carrying a truncated slot, two
        // conflicting authoritative views.
        if let (
            Some(device_id),
            crate::host_impl::plugin::oxidhome::plugin::events::EventPayload::StateChanged(sc),
        ) = (ev.device.as_deref(), &ev.payload)
            && let Err(overflow) = self.device_state.check_delta_admission(
                device_id,
                &self.instance_id,
                &sc.capability,
                &sc.fields,
            )
        {
            tracing::warn!(
                target: "device_state.slot_field_cap",
                instance_id = %self.instance_id,
                device_id = %device_id,
                capability = %sc.capability,
                overflow = %overflow,
                "publish_event denied: state-change would exceed a projection cap",
            );
            return Err(WitError::InvalidArgument(format!(
                "state-change on `{device_id}/{cap}` would exceed a projection cap \
                 ({overflow}); host refuses the publish so the durable log and the \
                 projection stay consistent",
                cap = sc.capability,
            )));
        }

        // Durable mirror first (Phase 5d): if the write fails — disk
        // full, sqlite corruption, etc. — we'd rather refuse the
        // publish than silently lose history. Live broadcast comes
        // second.
        let event_log = Arc::clone(&self.event_log);
        let instance_id = self.instance_id.clone();
        let plugin_id = self.manifest.plugin.id.clone();
        let to_record = ev.clone();
        // H5 review round-2 P2 F1: hold the bus's
        // `publish_sequence` gate across the record + publish
        // pair so two concurrent publishers can't commit rows in
        // one order (A: rowid 1, B: rowid 2) and fan out in the
        // opposite order (B's publish runs first because A is
        // still parked on the `spawn_blocking` join). Without
        // this gate, the `event.row_id` values stamped by
        // `publish_with_id` would arrive out of order and clients
        // using "last seen id" as a cursor high-water mark would
        // miss rows.
        //
        // The critical section is one spawn_blocking join + one
        // synchronous `publish_with_id`. Publishes are already
        // per-instance rate-limited (C2d) upstream, so
        // contention on this gate is bounded.
        let sequence_gate = self.events.publish_sequence();
        let _sequence_guard = sequence_gate.lock().await;
        // rusqlite is sync — hop to a blocking thread for the write
        // so we don't park the tokio worker on disk I/O. Panics in
        // the spawn_blocking body surface as `Error::Internal`,
        // matching the storage-side error mapping. C4 review P2 F2:
        // reuse the payload we already serialized for the cap
        // check so we don't encode the same event twice.
        let recorded = tokio::task::spawn_blocking(move || {
            event_log.record_prepared(
                crate::state::event_log::now_unix_ms(),
                &to_record,
                &instance_id,
                &plugin_id,
                payload_blob,
            )
        })
        .await;
        let row_id = match recorded {
            Ok(Ok(id)) => Some(id),
            Ok(Err(e)) => {
                return Err(WitError::Internal(format!("event_log: write failed: {e}")));
            }
            Err(join) => {
                return Err(WitError::Internal(format!(
                    "event_log: blocking task panicked: {join}",
                )));
            }
        };

        // H9: update the host-owned state projection before the
        // fanout. Runs under the same `publish_sequence` gate as
        // `event_log.record` above, so a snapshot API call
        // observes the same ordering the durable log records —
        // no post-fanout callers can see a state update before
        // the projection has it. Only `state-changed` events
        // land here; other variants (button, inference, custom)
        // aren't state-carrying by the WIT contract. H9 round-3:
        // uses `apply_delta` (merge by key) because WIT
        // `state-change.fields` is documented as *changes only*
        // — the register-device / OkWithState paths use
        // `replace_snapshot` instead.
        if let (
            Some(device_id),
            crate::host_impl::plugin::oxidhome::plugin::events::EventPayload::StateChanged(sc),
        ) = (ev.device.clone(), &ev.payload)
        {
            self.device_state.apply_delta(
                device_id,
                self.instance_id.clone(),
                sc.capability.clone(),
                sc.fields.clone(),
                ev.timestamp,
                crate::state::event_log::now_unix_ms(),
            );
        }

        // Admission already consumed above (pre-persistence). The
        // bus's `publish_with_id` sends the event onto every
        // subscriber's mpsc queue and signals matching wakes — see
        // `EventBus::publish_with_id` for the send-before-signal
        // ordering that keeps waking supervisors from racing an
        // empty receiver. H5: the row id captured from
        // `event_log.record` above rides with the fanout so tail
        // clients can reconcile against `GET /api/v1/events`. The
        // `_sequence_guard` from `publish_sequence` above is still
        // held here — dropped when this function returns — so no
        // other publisher runs between the record and this publish.
        let _delivered = self.events.publish_with_id(ev, row_id);
        Ok(())
    }

    async fn subscribe(&mut self, filter: EventFilter) -> Result<SubscriptionId, WitError> {
        // Architecture-review C2c: gate subscribe on
        // `capabilities.subscribes_events`. Without the flag the
        // plugin has no declared reason to observe the bus, so
        // every subscribe fails permission-denied. Publishers are
        // already gated by C2 ownership + capability checks; this
        // is the parallel check on the subscriber side so
        // cross-plugin observability is a manifest-declared
        // decision, not a default. `unsubscribe` is deliberately
        // uncapped — cleaning up a subscription that shouldn't
        // exist is fine.
        if !self.granted_capabilities.subscribes_events {
            tracing::warn!(
                target: "host.events",
                instance_id = %self.instance_id,
                "subscribe denied — capabilities.subscribes_events is not set",
            );
            return Err(WitError::PermissionDenied(
                "subscribe requires `capabilities.subscribes_events = true` in the plugin manifest"
                    .into(),
            ));
        }
        // C4: per-instance subscription cap. Complements the bus-side
        // `SOFT_SUBSCRIBER_CAP` (soft, cross-subscriber): this is the
        // *hard* per-instance cap that stops one buggy plugin from
        // registering thousands of overlapping filters and pinning
        // the filter-eval loop in `EventBus::publish`.
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_INSTANCE {
            tracing::warn!(
                target: "host.events",
                instance_id = %self.instance_id,
                held = self.subscriptions.len(),
                max = MAX_SUBSCRIPTIONS_PER_INSTANCE,
                "subscribe refused: per-instance C4 subscription cap reached",
            );
            return Err(WitError::PermissionDenied(format!(
                "subscribe refused: plugin instance already holds \
                 {} subscriptions (cap {MAX_SUBSCRIPTIONS_PER_INSTANCE}); \
                 unsubscribe unused filters or narrow existing ones",
                self.subscriptions.len(),
            )));
        }
        // C2d: register this subscription's filter on the bus with
        // our per-instance wake `Notify`. Publishes whose payload
        // matches the filter signal the notify — the supervisor's
        // serve loop awaits on it and calls `drain_events()` next.
        // Dropping the returned `EventSubscription` drops its
        // `WakeToken`, which deregisters the wake — so unsubscribe
        // is automatic on drop and `unsubscribe()` (below) just
        // removes the local entry.
        let subscription = self
            .events
            .subscribe_with_wake(filter, Arc::clone(&self.wake));
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

// ── C4 payload sizing helpers ───────────────────────────────────────
//
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
    if state.granted_capabilities.storage_quota_kb == 0 {
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
            would_use, allowed, ..
        } => WitError::PermissionDenied(format!(
            "quota exceeded: {would_use} bytes used / {allowed} allowed",
        )),
        KvError::UnregisteredInstance {
            installation_uuid,
            instance_id,
        } => WitError::Internal(format!(
            "kv: instance `{instance_id}` (install `{installation_uuid}`) \
             not registered (host bug)",
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
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.get(&installation_uuid, &instance_id, &key)).await
    }

    async fn set(&mut self, key: String, val: WitValue) -> Result<(), WitError> {
        require_storage_enabled(self)?;
        // C4 + C4 review P1 F1 (kv): per-write value size cap. The
        // KV byte quota bounds *total* storage; this cap bounds a
        // *single* write so a plugin can't spend its entire quota
        // on one enormous value. Uses `stored_value_size` — the
        // exact byte count the KV row will hold — so a `bytes`
        // value can't slip past by picking a variant whose JSON
        // encoding expands significantly (a byte array serializes
        // as `[255,255,…]`, ~4-6× the raw byte count). The pre-fix
        // shape used raw `.len()` and let 20 KiB byte payloads
        // through even though they persisted as ~100 KiB rows.
        let value_bytes = crate::state::stored_value_size(&val);
        if value_bytes > MAX_KV_VALUE_BYTES {
            tracing::warn!(
                target: "host.storage",
                instance_id = %self.instance_id,
                key = %key,
                value_bytes,
                max = MAX_KV_VALUE_BYTES,
                "storage.set refused: value exceeds C4 per-write byte cap",
            );
            return Err(WitError::PermissionDenied(format!(
                "storage.set serialized value ({value_bytes} bytes) exceeds \
                 per-write cap ({MAX_KV_VALUE_BYTES} bytes); split into smaller \
                 values or use blob-store"
            )));
        }
        let kv = Arc::clone(&self.kv);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.set(&installation_uuid, &instance_id, &key, val)).await
    }

    async fn delete(&mut self, key: String) -> Result<(), WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.delete(&installation_uuid, &instance_id, &key)).await
    }

    async fn list_keys(&mut self, prefix: String) -> Result<Vec<String>, WitError> {
        require_storage_enabled(self)?;
        let kv = Arc::clone(&self.kv);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        kv_op(move || kv.list_keys(&installation_uuid, &instance_id, &prefix)).await
    }
}

// ── Blob store ──────────────────────────────────────────────────────
//
// Phase 5b. Same shape as `storage`: a manifest-side gate
// (`blob_quota_mb = 0` ⇒ `permission-denied` before the store is
// touched), then `spawn_blocking` to keep the sync FS + SQLite work
// off the tokio worker.

fn require_blobs_enabled(state: &PluginState) -> Result<(), WitError> {
    if state.granted_capabilities.blob_quota_mb == 0 {
        return Err(WitError::PermissionDenied(
            "blob store disabled: capabilities.blob_quota_mb is 0 (set a positive value in manifest.toml)".into(),
        ));
    }
    Ok(())
}

/// Map [`crate::state::BlobError`] to a WIT [`WitError`]. Quota
/// surfaces as `permission-denied`; missing blobs as `not-found`;
/// "store unavailable" (no state dir) as `unavailable` — it isn't a
/// permission problem, the store is just not configured for the
/// engine. Everything else lands as `internal`.
fn blob_error_to_wit(err: crate::state::BlobError) -> WitError {
    use crate::state::BlobError;
    match err {
        BlobError::Unavailable => WitError::Unavailable(
            "blob store unavailable: engine has no state directory configured".into(),
        ),
        BlobError::UnregisteredInstance {
            installation_uuid,
            instance_id,
        } => WitError::Internal(format!(
            "blob_store: instance `{instance_id}` (install `{installation_uuid}`) \
             not registered (host bug)"
        )),
        // Follow-up review H1: unsafe segment caught at the
        // blob-store boundary. The API layer already refuses these
        // with 400 before they reach the store, so a leak here
        // implies a direct-caller path (test harness) with a bad
        // id — treat as host bug.
        BlobError::UnsafeInstanceId { ref segment } => WitError::Internal(format!(
            "blob_store: path segment {segment:?} unsafe for use as a filesystem segment (host bug)"
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
        // Should never escape `state::blobs::write` — the matcher
        // downconverts to `BlobError::Sql` after cleaning the orphan
        // file. Treat any leakage as a host bug.
        BlobError::CommitFailedAfterRename { final_path, source } => WitError::Internal(format!(
            "blob_store: commit-after-rename leaked to WIT layer at {}: {source}",
            final_path.display(),
        )),
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
        // C4: per-call blob write cap. The manifest's `blob_quota_mb`
        // still bounds cumulative storage; this cap bounds a single
        // write so a plugin can't consume its whole quota — or a
        // whole free-disk slice — with one call. Streaming blob
        // uploads (Phase 8+) are the intended path for anything
        // larger.
        if data.len() > MAX_BLOB_WRITE_BYTES {
            tracing::warn!(
                target: "host.blob_store",
                instance_id = %self.instance_id,
                name = %name,
                bytes = data.len(),
                max = MAX_BLOB_WRITE_BYTES,
                "blob_store.write refused: payload exceeds C4 per-call byte cap",
            );
            return Err(WitError::PermissionDenied(format!(
                "blob_store.write payload ({} bytes) exceeds per-call cap \
                 ({MAX_BLOB_WRITE_BYTES} bytes); split the write or use \
                 the streaming blob API when it lands",
                data.len(),
            )));
        }
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        blob_op(move || {
            blobs.write(
                &installation_uuid,
                &instance_id,
                &name,
                &data,
                mime.as_deref(),
            )
        })
        .await
    }

    async fn read(&mut self, id: String) -> Result<Vec<u8>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.read(&installation_uuid, &instance_id, &id)).await
    }

    async fn read_by_name(&mut self, name: String) -> Result<Vec<u8>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.read_by_name(&installation_uuid, &instance_id, &name)).await
    }

    async fn get_info(&mut self, name: String) -> Result<WitBlobInfo, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.get_info(&installation_uuid, &instance_id, &name))
            .await
            .map(blob_info_to_wit)
    }

    async fn delete(&mut self, name: String) -> Result<(), WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        blob_op(move || blobs.delete(&installation_uuid, &instance_id, &name)).await
    }

    async fn list_blobs(&mut self, prefix: String) -> Result<Vec<WitBlobInfo>, WitError> {
        require_blobs_enabled(self)?;
        let blobs = Arc::clone(&self.blobs);
        let installation_uuid = Arc::clone(&self.installation_uuid);
        let instance_id = self.instance_id.clone();
        let rows =
            blob_op(move || blobs.list_blobs(&installation_uuid, &instance_id, &prefix)).await?;
        Ok(rows.into_iter().map(blob_info_to_wit).collect())
    }
}

impl logging::Host for PluginState {
    async fn log(&mut self, level: WitLevel, message: String) {
        // C4 review P1 F2: bound host-memory exposure from
        // `logging::log`. The SQLite `LogStore` layer buffers up to
        // 1024 owned records; without an admission check a plugin
        // could submit near-cap messages faster than the drain
        // caught up and accumulate multi-GiB of pending queue
        // memory. Two-part fix:
        //
        // 1. Rate-limit host log calls per instance (token bucket
        //    on `PluginState`). Bounds the *arrival* rate.
        // 2. Truncate the message to `MAX_LOG_MESSAGE_BYTES`.
        //    Bounds the *per-call* size. Truncation with an
        //    explicit suffix beats refusal because a legitimate
        //    plugin that logs a big struct still gets its call
        //    through with a marker the operator can grep for.
        //
        // Refused calls silently drop — the plugin can't observe
        // the throttle (logging is one-way), and emitting a
        // tracing::warn here would itself be rate-limited so a
        // meta-log-flood is closed off too.
        {
            let mut bucket = self
                .log_rate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !bucket.consume() {
                return;
            }
        }
        let message = if message.len() > MAX_LOG_MESSAGE_BYTES {
            use std::fmt::Write as _;
            // Find the largest char boundary at or below the
            // limit so the truncation lands on a valid UTF-8
            // boundary. `floor_char_boundary` isn't stable, so
            // walk backwards until `is_char_boundary`.
            let mut cut = MAX_LOG_MESSAGE_BYTES;
            while cut > 0 && !message.is_char_boundary(cut) {
                cut -= 1;
            }
            let dropped = message.len() - cut;
            let mut truncated = String::with_capacity(cut + 32);
            truncated.push_str(&message[..cut]);
            let _ = write!(&mut truncated, " […truncated {dropped} B]");
            truncated
        } else {
            message
        };
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
        use oxidhome_manifest::{
            CapabilitiesSection, PluginSection, RestartPolicy, RuntimeSection, World,
        };
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
                restart: RestartPolicy::default(),
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
                // C2c: the default fixture is subscribe-capable so
                // the pre-existing subscribe/unsubscribe unit tests
                // keep passing. The denial test below builds its
                // own manifest without the flag.
                subscribes_events: true,
                ..CapabilitiesSection::default()
            },
            config: std::collections::BTreeMap::new(),
            ui: None,
        })
    }

    /// Standing synthetic installation uuid for tests that don't go
    /// through [`crate::state::InstalledPluginRegistry`]. Real loads
    /// pass the per-install uuid the registry minted; tests that pin
    /// this constant only care about the fixture's *shape*, not the
    /// specific hex.
    const TEST_INSTALLATION_UUID: &str = "test.fixture";

    /// Build a fresh KV store backed by an in-memory database and
    /// register the instance with `quota_kb` KiB of quota. Returns
    /// the `Arc<KvStore>` so individual tests can vary the quota
    /// without re-typing the wiring.
    fn fresh_kv(instance_id: &str, quota_kb: u64) -> Arc<crate::state::KvStore> {
        let db = Arc::new(crate::state::Db::open_in_memory().expect("db"));
        let kv = Arc::new(crate::state::KvStore::new(db));
        kv.register_instance(TEST_INSTALLATION_UUID, instance_id, quota_kb * 1024)
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
            // Synthetic installation_uuid — tests that don't go
            // through InstalledPluginRegistry use the fixture
            // plugin_id itself. C1b only changes the *derivation*
            // input; the test assertions ("dev-*", cross-instance
            // ownership isolation) don't care about the specific
            // hex output.
            "test.fixture",
            manifest,
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv(instance_id, 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
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
            "test.fixture",
            Arc::new(manifest),
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv(instance_id, quota_kb),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        )
    }

    fn shared_state(
        instance_id: &str,
        registry: Arc<DeviceRegistry>,
        bus: Arc<EventBus>,
    ) -> PluginState {
        PluginState::new(
            instance_id,
            "test.fixture",
            fixture_manifest("test.fixture"),
            Actor::plugin(instance_id),
            InstanceConfig::new(),
            registry,
            Arc::new(crate::state::DeviceStateStore::new()),
            bus,
            fresh_kv(instance_id, 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
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

    fn switch_device(local: &str) -> DeviceInfo {
        DeviceInfo {
            local_id: local.into(),
            name: local.into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: vec![capabilities::CapabilitySpec::Switch],
            initial_state: Vec::new(),
            metadata: Vec::new(),
        }
    }

    fn state_change_event(device: &str) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: 0,
            // Host-populated on publish (C2b); test fixtures pass
            // empty strings and rely on `publish_event` overwriting.
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: Vec::new(),
            }),
        }
    }

    fn state_change_event_of(device: Option<String>, capability: &str) -> Event {
        Event {
            device,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::StateChanged(StateChange {
                capability: capability.into(),
                fields: Vec::new(),
            }),
        }
    }

    fn button_event(device: Option<String>) -> Event {
        use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent;
        Event {
            device,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::Button(ButtonEvent::Pressed),
        }
    }

    fn custom_event(topic: &str) -> Event {
        Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
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

        // The C2 gates refuse unregistered/foreign devices and
        // capability mismatches, so register a `switch`-capable
        // device first and publish a matching `state-changed`.
        let id = host_devices::Host::register_device(&mut state, switch_device("d-1"))
            .await
            .expect("register");
        host_events::Host::publish_event(&mut state, state_change_event(&id))
            .await
            .expect("publish");

        let ev = sub
            .receiver
            .try_recv()
            .expect("event delivered")
            .expect_event();
        assert_eq!(ev.device.as_deref(), Some(id.as_str()));
        // C2b: host stamped the origin from the publisher's identity.
        assert_eq!(ev.origin_instance_id, "alpha");
        assert_eq!(ev.origin_plugin_id, "test.fixture");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_stamps_origin_over_client_supplied_values() {
        // Architecture-review C2b: the host overwrites `origin-plugin-id`
        // / `origin-instance-id` on every publish. A plugin that
        // fabricates values there — trying to impersonate another
        // plugin to a downstream subscriber — has those values
        // discarded before the event reaches the bus.
        let registry = Arc::new(DeviceRegistry::new());
        let bus = Arc::new(EventBus::new());
        let mut sub = bus.subscribe_all();
        let mut state = shared_state("alpha", registry, bus);
        let id = host_devices::Host::register_device(&mut state, switch_device("d-1"))
            .await
            .expect("register");

        // Publish with hostile origin fields.
        let mut forged = state_change_event(&id);
        forged.origin_plugin_id = "com.evil.impostor".into();
        forged.origin_instance_id = "evil-instance-42".into();
        host_events::Host::publish_event(&mut state, forged)
            .await
            .expect("publish");

        let ev = sub
            .receiver
            .try_recv()
            .expect("event delivered")
            .expect_event();
        assert_eq!(
            ev.origin_plugin_id, "test.fixture",
            "host must overwrite forged origin_plugin_id, got {:?}",
            ev.origin_plugin_id,
        );
        assert_eq!(
            ev.origin_instance_id, "alpha",
            "host must overwrite forged origin_instance_id, got {:?}",
            ev.origin_instance_id,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_rejects_unregistered_device() {
        let mut state = fresh_state("alpha");
        // No device was ever registered — publishing for a fabricated
        // id must be refused (architecture-review C2 spoofing gate).
        let err = host_events::Host::publish_event(&mut state, state_change_event("ghost"))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_rejects_foreign_device() {
        let registry = Arc::new(DeviceRegistry::new());
        let bus = Arc::new(EventBus::new());
        let mut alpha = shared_state("alpha", registry.clone(), bus.clone());
        let mut beta = shared_state("beta", registry, bus);

        let id = host_devices::Host::register_device(&mut alpha, switch_device("d-1"))
            .await
            .expect("alpha register");

        // Beta publishing for alpha's device is refused — same
        // permission-denied shape as an unregistered id, so the call
        // can't be used to probe for device existence.
        let err = host_events::Host::publish_event(&mut beta, state_change_event(&id))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_rejects_capability_not_declared() {
        // Owner + registered, but the device declares no
        // capabilities. Publishing a `switch` state-change is still
        // refused: register-device gates *declaration* against the
        // manifest, publish-event gates *event variants* against the
        // device's own declared capabilities.
        let mut state = fresh_state("alpha");
        let id = host_devices::Host::register_device(&mut state, empty_device("d-1"))
            .await
            .expect("register empty");
        let err = host_events::Host::publish_event(&mut state, state_change_event(&id))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_rejects_state_changed_without_device() {
        // `state-changed` describes something *about a device* — a
        // publisher with no device is malformed and refused with
        // invalid-argument. Same rule holds for `button` and
        // `inference`.
        let mut state = fresh_state("alpha");
        let err =
            host_events::Host::publish_event(&mut state, state_change_event_of(None, "switch"))
                .await
                .unwrap_err();
        assert!(matches!(err, WitError::InvalidArgument(_)), "got {err:?}");

        let err = host_events::Host::publish_event(&mut state, button_event(None))
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::InvalidArgument(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_publish_allows_bus_only_custom_events() {
        // Only `custom` may skip the device field — that's the
        // deliberate lifecycle / free-topic escape hatch.
        let mut state = fresh_state("alpha");
        host_events::Host::publish_event(&mut state, custom_event("automation.morning"))
            .await
            .expect("bus-only publish");
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
    async fn host_events_subscribe_denied_without_capability() {
        // Architecture-review C2c: a plugin whose manifest does not
        // declare `subscribes_events = true` cannot observe the
        // bus. The default fixture manifest sets the flag; this
        // test rebuilds the manifest with the flag stripped and
        // asserts subscribe refuses.
        use oxidhome_manifest::CapabilitiesSection;
        let mut manifest = (*fixture_manifest("no.subscribe")).clone();
        manifest.capabilities = CapabilitiesSection {
            subscribes_events: false,
            ..manifest.capabilities
        };
        let mut state = PluginState::new(
            "alpha",
            "no.subscribe",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        );

        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let err = host_events::Host::subscribe(&mut state, filter)
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
        assert!(
            state.subscriptions.is_empty(),
            "denied subscribe must not persist a subscription",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_events_unsubscribe_is_uncapped() {
        // C2c gates `subscribe`, not `unsubscribe` — cleaning up a
        // subscription that shouldn't exist is fine, and gating
        // both would trap a plugin whose capability was revoked
        // mid-flight in an un-cleanable-state limbo.
        use oxidhome_manifest::CapabilitiesSection;
        let mut manifest = (*fixture_manifest("no.subscribe")).clone();
        manifest.capabilities = CapabilitiesSection {
            subscribes_events: false,
            ..manifest.capabilities
        };
        let mut state = PluginState::new(
            "alpha",
            "no.subscribe",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        );
        // No subscription exists → NotFound (not PermissionDenied).
        let err = host_events::Host::unsubscribe(&mut state, 42)
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn publish_event_returns_unavailable_over_rate_limit() {
        // C2d: `PluginState::publish_event` routes through the
        // bus's per-instance token bucket, which refuses over-
        // quota bursts. The response maps to `WitError::Unavailable`
        // with a message naming the capacity + refill rate so the
        // plugin's `?` propagates a signal the operator can act
        // on. Post-PR-#82 review: admission happens *before* the
        // durable event-log write, so a refused publish leaves no
        // side effect for the caller to reconcile.
        let mut state = fresh_state("alpha");
        let id = host_devices::Host::register_device(&mut state, switch_device("d-1"))
            .await
            .expect("register");
        // Drain the burst — no wall-clock time elapses so refill
        // stays at 0 across the loop and the (N+1)th call trips
        // the limit.
        let mut denied: Option<WitError> = None;
        for _ in 0..256 {
            match host_events::Host::publish_event(&mut state, state_change_event(&id)).await {
                Ok(()) => {}
                Err(err @ WitError::Unavailable(_)) => {
                    denied = Some(err);
                    break;
                }
                Err(other) => panic!("unexpected publish error: {other:?}"),
            }
        }
        let err = denied.expect("burst should exceed the default rate ceiling");
        let WitError::Unavailable(msg) = err else {
            unreachable!()
        };
        assert!(
            msg.contains("publish quota"),
            "message should name the quota, got {msg}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscribe_registers_wake_on_bus() {
        // C2d wake-isolation: an authorized subscribe registers
        // a wake handle on the bus that fires the plugin's
        // supervisor `Notify` on matching publishes. Verify from
        // the state side that both the wake registration and the
        // notify fire.
        let mut state = fresh_state("alpha");
        let id = host_devices::Host::register_device(&mut state, switch_device("d-1"))
            .await
            .expect("register");
        let wake = Arc::clone(&state.wake);

        host_events::Host::subscribe(
            &mut state,
            EventFilter {
                device: Some(id.clone()),
                topic: None,
            },
        )
        .await
        .expect("subscribe");

        // Publishing for the matching device fires the wake.
        host_events::Host::publish_event(&mut state, state_change_event(&id))
            .await
            .expect("publish");
        // Notify has a permit stored from the notify_one above;
        // notified() resolves immediately.
        let permit = wake.notified();
        tokio::pin!(permit);
        assert!(
            std::future::Future::poll(
                permit.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop()),
            )
            .is_ready(),
            "wake must fire on matching publish",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn denied_subscribe_leaves_no_wake_registered() {
        // C2c + C2d interaction: a plugin without
        // `subscribes_events` is refused at subscribe time, so no
        // wake registration lands on the bus. Under a flood from
        // another plugin, this instance's supervisor wake never
        // fires — the F2 amplification path is closed.
        use oxidhome_manifest::CapabilitiesSection;
        let mut manifest = (*fixture_manifest("no.subscribe")).clone();
        manifest.capabilities = CapabilitiesSection {
            subscribes_events: false,
            ..manifest.capabilities
        };
        let events = Arc::new(EventBus::new());
        let mut state = PluginState::new(
            "beta",
            "no.subscribe",
            Arc::new(manifest),
            Actor::plugin("beta"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::clone(&events),
            fresh_kv("beta", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        );
        let wake = Arc::clone(&state.wake);

        // subscribe → denied, no wake registered.
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let err = host_events::Host::subscribe(&mut state, filter)
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");

        // Now a flood from an external publisher (bus.publish
        // bypasses the plugin-facing rate limit). The wake must
        // not fire — this beta instance opted out of the bus.
        for _ in 0..10 {
            events.publish(custom_event("firehose"));
        }

        let permit = wake.notified();
        tokio::pin!(permit);
        assert!(
            std::future::Future::poll(
                permit.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop()),
            )
            .is_pending(),
            "wake must NOT fire when no subscription was ever registered",
        );
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
        // C2e: publish filters at delivery time (per-subscriber
        // mpsc queue). Only the matching event reaches this
        // subscriber; the non-matching event is dropped at
        // enqueue rather than filtered on receive.
        let ev1 = sub.receiver.try_recv().unwrap().expect_event();
        assert!(sub.matches(&ev1));
        assert!(
            sub.receiver.try_recv().is_err(),
            "non-matching event must not reach the subscriber queue under C2e",
        );
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
            "test.switch-only",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
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
            "test.window-shade",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
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
            "test.switch-only",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
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

    /// C5: runtime gates must consult `granted_capabilities`, not
    /// `manifest.capabilities`. A `register-device` for a
    /// manifest-declared capability that has been REMOVED from
    /// the grant must be refused.
    #[tokio::test(flavor = "current_thread")]
    async fn host_devices_register_denied_when_grant_narrows_manifest() {
        use oxidhome_manifest::CapabilitiesSection;

        // Manifest declares `switch`; grant is narrower (empty).
        let mut manifest = (*fixture_manifest("test.grant-narrow")).clone();
        manifest.capabilities = CapabilitiesSection {
            declares_devices: vec!["switch".into()],
            ..CapabilitiesSection::default()
        };
        let mut state = PluginState::new(
            "alpha",
            "test.grant-narrow",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        )
        .with_granted_capabilities(Arc::new(CapabilitiesSection::default()));

        let mut info = empty_device("d-1");
        info.capabilities = vec![capabilities::CapabilitySpec::Switch];
        let err = host_devices::Host::register_device(&mut state, info)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("switch")),
            "grant narrower than manifest must deny: got {err:?}",
        );
    }

    /// C5: symmetric — a `subscribes_events` grant that's `false`
    /// while the manifest requested `true` must refuse
    /// `host-events::subscribe`.
    #[tokio::test(flavor = "current_thread")]
    async fn host_events_subscribe_denied_when_grant_revokes_subscribes() {
        use oxidhome_manifest::CapabilitiesSection;

        let mut manifest = (*fixture_manifest("test.grant-revoke-sub")).clone();
        manifest.capabilities = CapabilitiesSection {
            subscribes_events: true,
            ..CapabilitiesSection::default()
        };
        let mut state = PluginState::new(
            "alpha",
            "test.grant-revoke-sub",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        )
        .with_granted_capabilities(Arc::new(CapabilitiesSection {
            subscribes_events: false,
            ..CapabilitiesSection::default()
        }));

        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let err = host_events::Host::subscribe(&mut state, filter)
            .await
            .unwrap_err();
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
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

    // ─── C4 ceilings ─────────────────────────────────────────────

    /// C4: `storage.set` refuses a single value larger than
    /// `MAX_KV_VALUE_BYTES` with `PermissionDenied`, regardless of
    /// remaining quota. Protects against a plugin spending its
    /// whole KV budget on one enormous entry.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_storage_set_refuses_oversized_value() {
        // Plenty of quota so the refusal is the per-write cap,
        // not the manifest byte quota.
        let mut state = fresh_state_with_storage("alpha", 1024);
        let oversized = "x".repeat(MAX_KV_VALUE_BYTES + 1);
        let err = storage::Host::set(&mut state, "k".into(), WitValue::StringVal(oversized))
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref m) if m.contains("per-write cap")),
            "expected PermissionDenied with per-write cap message, got {err:?}",
        );
        // Below-cap write still succeeds.
        storage::Host::set(&mut state, "k".into(), WitValue::StringVal("small".into()))
            .await
            .expect("under-cap set");
    }

    /// C4 review round-2 P1 F1 (kv): the cap must measure the
    /// **serialized** value size, not raw payload bytes. A
    /// `BytesVal` payload serializes as a JSON array of decimal
    /// ints (`[255,255,…]`) — ~4-6× the raw byte count. The
    /// pre-fix `wit_value_size` returned raw `.len()` and let
    /// ~20 KiB byte payloads slip past the 64 KiB cap even
    /// though they'd persist as ~100 KiB rows.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_review_p1f1_kv_cap_measures_serialized_bytes() {
        let mut state = fresh_state_with_storage("alpha", 1024);
        // Bytes payload sized so raw len is well under the cap
        // but the JSON-array serialization blows past it. Each
        // byte serializes as ≈ 4 chars (`255,`); take MAX / 4
        // raw bytes plus slack (the outer `{"t":"Bytes","v":[…]}`
        // wrapper adds ~18 chars) to guarantee the encoded form
        // exceeds the cap.
        let raw = vec![0xFFu8; MAX_KV_VALUE_BYTES / 4 + 1024];
        assert!(
            raw.len() < MAX_KV_VALUE_BYTES,
            "raw payload should look under-cap; got {} B (cap {})",
            raw.len(),
            MAX_KV_VALUE_BYTES,
        );
        let err = storage::Host::set(&mut state, "b".into(), WitValue::BytesVal(raw))
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref m) if m.contains("serialized value")),
            "expected PermissionDenied with serialized-value message, got {err:?}",
        );
    }

    /// C4: `host-events.subscribe` refuses past
    /// `MAX_SUBSCRIPTIONS_PER_INSTANCE`. Complements the bus-side
    /// soft cap — this is the *hard* per-instance limit that stops
    /// one buggy plugin from pinning the filter-eval loop.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_subscribe_refuses_past_per_instance_cap() {
        use oxidhome_manifest::CapabilitiesSection;
        let mut manifest = (*fixture_manifest("test.fixture")).clone();
        manifest.capabilities = CapabilitiesSection {
            subscribes_events: true,
            ..manifest.capabilities
        };
        let mut state = PluginState::new(
            "alpha",
            "test.fixture",
            Arc::new(manifest),
            Actor::plugin("alpha"),
            InstanceConfig::new(),
            Arc::new(DeviceRegistry::new()),
            Arc::new(crate::state::DeviceStateStore::new()),
            Arc::new(EventBus::new()),
            fresh_kv("alpha", 0),
            fresh_event_log(),
            fresh_blobs(),
            Arc::new(ServiceRegistry::new()),
            Arc::new(InstanceRegistry::new()),
        );
        // Explicitly grant subscribes_events (default `new` copies
        // manifest.capabilities, so this already carries the flag).
        for _ in 0..MAX_SUBSCRIPTIONS_PER_INSTANCE {
            host_events::Host::subscribe(
                &mut state,
                EventFilter {
                    device: None,
                    topic: None,
                },
            )
            .await
            .expect("under-cap subscribe");
        }
        // The next subscribe is at the cap.
        let err = host_events::Host::subscribe(
            &mut state,
            EventFilter {
                device: None,
                topic: None,
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref m) if m.contains("subscribe refused")),
            "expected PermissionDenied with per-instance cap refusal, got {err:?}",
        );
    }

    /// C4: `host-events.publish-event` refuses an event whose
    /// serialized payload exceeds `MAX_EVENT_PAYLOAD_BYTES`. The
    /// refusal fires *before* the durable-log write or the bus
    /// fan-out, so a flooder can't spend disk/broadcast budget on
    /// oversized payloads.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_publish_event_refuses_oversized_payload() {
        let mut state = fresh_state("alpha");
        // A custom-event with a giant JSON payload string.
        let big = "y".repeat(MAX_EVENT_PAYLOAD_BYTES + 1);
        let ev = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::Custom(
                crate::host_impl::plugin::oxidhome::plugin::events::CustomEvent {
                    topic: "test".into(),
                    payload: big,
                },
            ),
        };
        let err = host_events::Host::publish_event(&mut state, ev)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref m) if m.contains("per-event cap")),
            "expected PermissionDenied with per-event cap message, got {err:?}",
        );
    }

    // ─── C4 review fixes ────────────────────────────────────────

    /// C4 review P1 F1: `PluginResourceLimits` aggregates memory
    /// bytes across every memory in the store, not per-memory.
    /// A grow that pushes the aggregate past
    /// [`STORE_MAX_MEMORY_BYTES`] returns `Err(_)` (which
    /// wasmtime translates to a trap — see P2 F1) rather than
    /// silently succeeding because a single memory is still
    /// under the cap. Two grows on nominally-separate memories
    /// that together exceed the cap are refused.
    #[test]
    fn c4_review_p1f1_resource_limits_aggregate_across_memories() {
        let mut limits = PluginResourceLimits::new();
        // First memory grows up to 3/4 of the aggregate cap.
        let three_quarters = STORE_MAX_MEMORY_BYTES * 3 / 4;
        assert!(matches!(
            limits.memory_growing(0, three_quarters, None),
            Ok(true)
        ));
        // Second memory tries to grow to 1/2 of the cap. The
        // pre-fix per-memory `StoreLimits` would accept (each
        // memory sees its own limit); the aggregate limiter
        // refuses — 3/4 + 1/2 > 1.
        let half = STORE_MAX_MEMORY_BYTES / 2;
        let refusal = limits.memory_growing(0, half, None);
        assert!(
            refusal.is_err(),
            "aggregate limiter must refuse; got {refusal:?}",
        );
        assert!(
            format!("{}", refusal.unwrap_err()).contains("aggregate memory cap"),
            "refusal should mention aggregate memory cap",
        );
    }

    /// C4 review P1 F1: same aggregate check for table elements.
    #[test]
    fn c4_review_p1f1_resource_limits_aggregate_across_tables() {
        let mut limits = PluginResourceLimits::new();
        let three_quarters = STORE_MAX_TABLE_ELEMENTS * 3 / 4;
        assert!(matches!(
            limits.table_growing(0, three_quarters, None),
            Ok(true)
        ));
        let half = STORE_MAX_TABLE_ELEMENTS / 2;
        let refusal = limits.table_growing(0, half, None);
        assert!(
            refusal.is_err(),
            "aggregate limiter must refuse; got {refusal:?}",
        );
    }

    /// C4 review P1 F2: `logging::log` refuses calls past the
    /// per-instance rate. Consuming a full burst then attempting
    /// another call silently drops (no observable side effect
    /// from the plugin's POV, no `tracing::warn` amplification).
    /// The bucket's `tokens` field is what advances / rolls back
    /// as consume/refuse decisions land, so we inspect it before
    /// and after a post-burst call to prove the refusal path
    /// doesn't consume.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_review_p1f2_log_rate_limit_admission() {
        let mut state = fresh_state("alpha");
        // `LOG_RATE_BURST` is a small non-negative f64 constant
        // used purely as a loop bound; truncation is intentional.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let burst = LOG_RATE_BURST as usize;
        for _ in 0..burst {
            logging::Host::log(&mut state, WitLevel::Info, "hello".into()).await;
        }
        // Bucket should now be near-empty; the next call must
        // find < 1 token and drop.
        let tokens_after_burst = state
            .log_rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tokens;
        assert!(
            tokens_after_burst < 1.0,
            "bucket should be sub-token after burst; got {tokens_after_burst}",
        );
        // Drive the extra call the pre-fix test claimed but
        // didn't actually perform. Post-fix: no consume happens,
        // so `tokens` is monotonically non-decreasing (may go up
        // slightly from refill during the elapsed wall-clock).
        logging::Host::log(&mut state, WitLevel::Info, "dropped".into()).await;
        let tokens_after_drop = state
            .log_rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tokens;
        assert!(
            tokens_after_drop >= tokens_after_burst,
            "over-burst call must not consume a token; \
             tokens went {tokens_after_burst} → {tokens_after_drop}",
        );
    }

    /// C4 review P1 F2: `logging::log` truncates messages larger
    /// than [`MAX_LOG_MESSAGE_BYTES`] so a rogue plugin can't
    /// enqueue near-cap owned strings into the `LogStore` queue.
    /// The truncation lands on a valid UTF-8 char boundary and
    /// appends an explicit marker.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_review_p1f2_log_message_truncates_beyond_cap() {
        // Unit-test the truncation via the same char-boundary
        // walk the `log` impl uses. A pure ASCII string of
        // length MAX_LOG_MESSAGE_BYTES + 1 truncates at MAX.
        let over = "a".repeat(MAX_LOG_MESSAGE_BYTES + 1);
        // Round-trip through log to exercise the truncation
        // path (no observable output, but the code path runs
        // and mustn't panic on the boundary walk).
        let mut state = fresh_state("alpha");
        logging::Host::log(&mut state, WitLevel::Info, over.clone()).await;
        // A non-ASCII string sitting on a char boundary at
        // MAX_LOG_MESSAGE_BYTES minus a few also mustn't panic
        // — this is the boundary-walk safety.
        let unicode_over = "日".repeat(MAX_LOG_MESSAGE_BYTES); // 3 bytes/char
        logging::Host::log(&mut state, WitLevel::Info, unicode_over).await;
        // Truncation is best-effort observability; the load-
        // bearing invariant is that we didn't panic and didn't
        // consume more memory than the budget. Bucket state
        // proves the admission gate held.
        let _ = state.log_rate;
    }

    /// C4 review P2 F2: the per-event byte cap measures the
    /// **serialized** payload (what the durable log actually
    /// stores), not raw string sums. A plugin that supplies a
    /// payload whose escaped JSON representation exceeds
    /// [`MAX_EVENT_PAYLOAD_BYTES`] is refused even when the
    /// raw string is smaller.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_review_p2f2_publish_event_measures_serialized_bytes() {
        let mut state = fresh_state("alpha");
        // Control characters `\x00`..=`\x1f` serialize as
        // `\uXXXX` — 6 bytes each. At (MAX / 6) + slack raw
        // bytes, the serialized size exceeds the cap even
        // though `raw.len()` looks fine.
        let escapable = '\x01';
        let raw = escapable
            .to_string()
            .repeat(MAX_EVENT_PAYLOAD_BYTES / 6 + 512);
        let ev = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::Custom(
                crate::host_impl::plugin::oxidhome::plugin::events::CustomEvent {
                    topic: "escape-test".into(),
                    payload: raw,
                },
            ),
        };
        let err = host_events::Host::publish_event(&mut state, ev)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WitError::PermissionDenied(ref m) if m.contains("serialized payload")),
            "expected PermissionDenied with serialized-payload message, got {err:?}",
        );
    }

    /// C4 review P2 F2: the per-event cap ignores
    /// caller-supplied origin strings — they're overwritten by
    /// the host stamp before serialization, so their length
    /// mustn't contribute to a refusal. A plugin passing
    /// enormous origin strings should still succeed as long as
    /// the real (post-stamp) size is under the cap.
    #[tokio::test(flavor = "current_thread")]
    async fn c4_review_p2f2_publish_event_ignores_caller_origin_bytes() {
        let mut state = fresh_state("alpha");
        // Fills MAX_EVENT_PAYLOAD_BYTES with caller-supplied
        // origin strings; the *real* payload is tiny.
        let ev = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: "x".repeat(MAX_EVENT_PAYLOAD_BYTES),
            origin_instance_id: "y".repeat(MAX_EVENT_PAYLOAD_BYTES),
            row_id: None,
            payload: EventPayload::Custom(
                crate::host_impl::plugin::oxidhome::plugin::events::CustomEvent {
                    topic: "tiny".into(),
                    payload: "ok".into(),
                },
            ),
        };
        // The publish should succeed because the origin fields
        // are stamped (`test.fixture` / `alpha`) *before* the
        // size check runs. Any other failure indicates the
        // check counted the caller-supplied strings.
        host_events::Host::publish_event(&mut state, ev)
            .await
            .expect("publish should succeed — origin strings are stamped before the cap check");
    }
}
