//! Axum server + router.
//!
//! [`serve`] takes an [`Engine`] and an [`ApiConfig`], builds the
//! router, binds the listener, and runs forever. Integration tests
//! call [`build_router`] directly to drive routes via `tower::Service`
//! without binding a TCP port.

use std::net::SocketAddr;

use std::collections::HashMap;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State, WebSocketUpgrade, ws::WebSocket},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::Engine;
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};
use crate::state::{
    HistoricalLogEvent, InstallError, LogLevel, LogQuery, LogStore, LogValue, UninstallError,
};

use super::auth::{AuthState, require_token};
use super::scopes::{
    DEVICES_COMMAND, DEVICES_LIST, EVENTS_TAIL, INSTANCES_LIST, LOGS_READ, PLUGINS_INSTALL,
    PLUGINS_LIST, PLUGINS_START, PLUGINS_STOP, PLUGINS_UNINSTALL, ScopeDenied, require_scope,
};

/// Listener configuration. Defaults to `127.0.0.1:0` (random
/// loopback port — what tests use). Daemon callers set `bind` to
/// a concrete address from the host config.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind: SocketAddr,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }
}

/// Build the API router. Public for integration tests; the
/// `serve(...)` entry point that production callers use lives below.
///
/// The router serves **two protocols on one listener**:
///
/// - JSON `/api/v1/*` (Phase 12) — every existing handler.
/// - Connect-RPC `/oxidhome.v1.{Service}/{Method}` (Phase 15-a+) —
///   mounted as a `fallback_service` so any path not matched by the
///   JSON routes above falls through to the Connect dispatcher.
///   See [`super::connect_rpc`] for the registered services.
pub fn build_router(engine: Engine) -> Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
    };
    let connect_service = super::connect_rpc::router().into_axum_service();
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/instances", get(list_instances))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{device_id}/command", post(send_command))
        .route("/api/v1/plugins", get(list_plugins).post(install_plugin))
        .route(
            "/api/v1/plugins/{plugin_id}",
            axum::routing::delete(uninstall_plugin),
        )
        .route(
            "/api/v1/plugins/{plugin_id}/start",
            post(start_plugin_instance),
        )
        .route(
            "/api/v1/plugins/{plugin_id}/stop",
            post(stop_plugin_instances),
        )
        .route("/api/v1/events/tail", get(tail_events))
        .route("/api/v1/logs", get(query_logs))
        .layer(from_fn_with_state(auth_state.clone(), require_token))
        .fallback_service(connect_service)
        .with_state(ApiState { engine })
}

/// Bind a TCP listener at the configured address.
///
/// Split out from [`serve`] so the daemon can log the resolved
/// address (`listener.local_addr()`) *before* moving into the
/// accept loop, and so integration tests can drive a real
/// `127.0.0.1:0` listener through a `tokio::spawn`ed [`serve`]
/// without losing the ephemeral port.
///
/// # Errors
///
/// - `TcpListener::bind` failure (port in use, permission denied).
pub async fn bind(config: ApiConfig) -> anyhow::Result<TcpListener> {
    TcpListener::bind(config.bind)
        .await
        .map_err(anyhow::Error::from)
}

/// Run the API accept loop on `listener` until the future is dropped.
///
/// The daemon's `main.rs` holds this future inside a `tokio::select!`
/// against `tokio::signal::ctrl_c` (and SIGTERM on Unix). The test
/// harness drives it via `tokio::spawn` + `abort()` on drop.
///
/// # Errors
///
/// - `axum::serve` errors (rare; mostly accept-loop failures).
pub async fn serve(engine: Engine, listener: TcpListener) -> anyhow::Result<()> {
    axum::serve(listener, build_router(engine))
        .await
        .map_err(anyhow::Error::from)
}

/// Router state — the live [`Engine`] every authenticated handler
/// reaches its `engine.devices()` / `instances()` / etc. through.
/// Clone is cheap (Engine is `Arc`-backed internally).
#[derive(Clone)]
struct ApiState {
    engine: Engine,
}

// ── Handlers ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    version: &'static str,
}

/// Anonymous liveness probe. Lives outside [`PUBLIC_PATHS`] only
/// nominally — the route is wired before the middleware via the
/// path-match in `require_token`.
async fn health() -> (StatusCode, Json<HealthBody>) {
    (
        StatusCode::OK,
        Json(HealthBody {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

#[derive(Serialize)]
struct InstancesBody {
    instances: Vec<InstanceSummary>,
}

#[derive(Serialize)]
struct InstanceSummary {
    instance_id: String,
    /// Manifest-resolved plugin id (e.g. `example.simulated-switch`).
    /// 12-API-d wired this onto `InstanceHandle`; before that the
    /// API only carried `instance_id` here.
    plugin_id: String,
    /// `Debug` repr of the current [`InstanceState`](crate::InstanceState).
    /// A structured projection (with `state_changed_at` etc.) is a
    /// follow-up once a UI/CLI consumer asks for it.
    state: String,
}

/// Authenticated `GET /api/v1/instances`. Returns every supervised
/// instance under the engine with its current lifecycle state. Gated
/// on the `instances:list` scope; the admin / wildcard token
/// satisfies it via [`crate::api::scopes::WILDCARD`].
async fn list_instances(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
) -> Result<Json<InstancesBody>, ScopeDenied> {
    require_scope(&actor, INSTANCES_LIST)?;
    let mut instances = Vec::new();
    for handle in state.engine.instances().list() {
        instances.push(InstanceSummary {
            instance_id: handle.instance_id().to_string(),
            plugin_id: handle.plugin_id().to_string(),
            state: format!("{:?}", handle.state()),
        });
    }
    Ok(Json(InstancesBody { instances }))
}

#[derive(Serialize)]
struct DevicesBody {
    devices: Vec<DeviceSummary>,
}

#[derive(Serialize)]
struct DeviceSummary {
    device_id: String,
    /// Owning plugin instance id (the host's routing key for
    /// `execute-command`).
    owner_instance: String,
    /// Human-readable name from the registration `DeviceInfo`.
    name: String,
}

/// Authenticated `GET /api/v1/devices`. Lists every device any
/// supervised instance has registered with the host. Gated on the
/// `devices:list` scope.
///
/// Returns a flat snapshot suitable for the CLI's `device list`
/// table — `device_id`, `owner_instance`, `name`. Capability /
/// state-vector projection lands in a later slice once we have a
/// concrete UI/CLI consumer.
async fn list_devices(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
) -> Result<Json<DevicesBody>, ScopeDenied> {
    require_scope(&actor, DEVICES_LIST)?;
    let devices = state
        .engine
        .devices()
        .list()
        .into_iter()
        .map(|meta| DeviceSummary {
            device_id: meta.id.clone(),
            owner_instance: meta.owner_instance.clone(),
            name: meta.info.name.clone(),
        })
        .collect();
    Ok(Json(DevicesBody { devices }))
}

// ── Device command (write path) ──────────────────────────────────

/// `POST /api/v1/devices/{device_id}/command` body.
#[derive(Deserialize)]
struct CommandBody {
    /// Capability key — `"switch"`, `"dimmer"`, etc. — that the
    /// plugin's `execute-command` matches on alongside `action`.
    capability: String,
    /// Action verb — `"set"`, `"toggle"`, `"increment"`, … — the
    /// plugin's command dispatch interprets.
    action: String,
    /// `key=value` arguments. Each `value` is the JSON-tagged
    /// [`WireValue`] enum (mirrors the WIT `value` variant so the
    /// CLI / UI can pass typed payloads without losing precision).
    #[serde(default)]
    args: Vec<WireKeyValue>,
}

/// JSON wire mirror of the WIT `key-value` record. The on-wire
/// `value` is the tagged-JSON [`WireValue`] below.
#[derive(Deserialize)]
struct WireKeyValue {
    key: String,
    value: WireValue,
}

/// JSON wire mirror of the WIT `value` variant — same tag/content
/// shape as the storage encoding so a future API <-> persisted
/// record migration is a pure-Rust transform. Round-trippable in
/// **both directions**: clients deserialize into [`Value`] via
/// `From<WireValue>`, and the API serializes responses into
/// [`WireValue`] via `From<Value>` so the input `{t,v}` shape on
/// command args matches the `{t,v}` shape on the
/// `OkWithState` state map. Drop the round-trip and a client
/// can't tell `Int(5)` from `Float(5.0)`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "t", content = "v")]
enum WireValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(String),
}

impl From<WireValue> for Value {
    fn from(v: WireValue) -> Self {
        match v {
            WireValue::Bool(b) => Value::BoolVal(b),
            WireValue::Int(i) => Value::IntVal(i),
            WireValue::Float(f) => Value::FloatVal(f),
            WireValue::String(s) => Value::StringVal(s),
            WireValue::Bytes(b) => Value::BytesVal(b),
            WireValue::Json(j) => Value::JsonVal(j),
        }
    }
}

impl From<Value> for WireValue {
    fn from(v: Value) -> Self {
        match v {
            Value::BoolVal(b) => WireValue::Bool(b),
            Value::IntVal(i) => WireValue::Int(i),
            Value::FloatVal(f) => WireValue::Float(f),
            Value::StringVal(s) => WireValue::String(s),
            Value::BytesVal(b) => WireValue::Bytes(b),
            Value::JsonVal(j) => WireValue::Json(j),
        }
    }
}

/// Wire mirror of the WIT `command-result` variant. `ok` carries
/// no body; `ok_with_state` carries a `{key: WireValue}` map — a
/// keyed dict reads better in JSON than the WIT `Vec<KeyValue>`,
/// and using [`WireValue`] (tagged) instead of a flat
/// `serde_json::Value` keeps the round-trip lossless: a client
/// that sent `{"t":"int","v":5}` and reads `{"t":"int","v":5}`
/// back can distinguish int from float, json-payload from string,
/// etc. `err` carries the host's [`WitError`] mapped to a tagged
/// `{kind, message}` shape.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireCommandResult {
    Ok,
    OkWithState { state: HashMap<String, WireValue> },
    Err { error: WireWitError },
}

/// Wire mirror of the WIT `error` variant. Same shape clients can
/// already see on other endpoints' error responses.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireWitError {
    NotFound { message: String },
    InvalidArgument { message: String },
    PermissionDenied { message: String },
    Unavailable { message: String },
    Internal { message: String },
}

impl From<WitError> for WireWitError {
    fn from(e: WitError) -> Self {
        match e {
            WitError::NotFound(m) => WireWitError::NotFound { message: m },
            WitError::InvalidArgument(m) => WireWitError::InvalidArgument { message: m },
            WitError::PermissionDenied(m) => WireWitError::PermissionDenied { message: m },
            WitError::Unavailable(m) => WireWitError::Unavailable { message: m },
            WitError::Internal(m) => WireWitError::Internal { message: m },
        }
    }
}

fn command_result_to_wire(r: CommandResult) -> WireCommandResult {
    match r {
        CommandResult::Ok => WireCommandResult::Ok,
        CommandResult::OkWithState(kvs) => WireCommandResult::OkWithState {
            state: kvs
                .into_iter()
                .map(|kv| (kv.key, kv.value.into()))
                .collect(),
        },
        CommandResult::Err(e) => WireCommandResult::Err { error: e.into() },
    }
}

/// `POST /api/v1/devices/{device_id}/command` — route a command
/// through the owning plugin instance's `execute-command` export
/// and return the result.
///
/// **Sensitive.** Gated on the `devices:command` scope: this is
/// the write-side device endpoint that can physically actuate
/// locks, garage doors, alarms, etc. The audit log already records
/// every authenticated request (`api.audit` target); 12-CLI's
/// `logs query --target api.audit --field path=/api/v1/devices/...`
/// surfaces the trail.
///
/// **Error shape** (5xx are reserved for *host* failures; 4xx mean
/// the request was structurally rejected; 2xx with a `kind: "err"`
/// in the body means the plugin returned a structured error):
/// - `404 not_found` — no device with that id, or its owning
///   instance isn't currently running. Indistinguishable from
///   "wrong id" so a probing caller can't enumerate device ids.
/// - `403` — scope check failed.
/// - `500` — supervisor channel error / plugin trap (the dispatch
///   path crashed the owning instance).
/// - `200` — plugin processed the command; the body's
///   `WireCommandResult` says whether the plugin returned `Ok`,
///   `OkWithState`, or `Err`.
async fn send_command(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Path(device_id): Path<String>,
    Json(body): Json<CommandBody>,
) -> Result<Json<WireCommandResult>, CommandError> {
    require_scope(&actor, DEVICES_COMMAND).map_err(CommandError::Scope)?;

    // Resolve device → owning instance via the registry's
    // cross-instance owner-only lookup (mirrors the dispatcher's
    // `ServiceRegistry::get_owner` shape). The previous
    // `list().into_iter().find(...)` was O(n) + Vec-alloc per
    // command; this is one read-lock + map lookup.
    let owner = state
        .engine
        .devices()
        .get_owner(&device_id)
        .ok_or(CommandError::NotFound)?;
    let handle = state
        .engine
        .instances()
        .get(&owner)
        .ok_or(CommandError::NotFound)?;

    // Build the WIT command. JSON `value` shapes map to typed
    // `Value` variants via the `From<WireValue>` impl.
    let cmd = Command {
        capability: body.capability,
        action: body.action,
        args: body
            .args
            .into_iter()
            .map(|kv| KeyValue {
                key: kv.key,
                value: kv.value.into(),
            })
            .collect(),
    };

    let result = handle
        .execute_command(device_id, cmd)
        .await
        .map_err(CommandError::Dispatch)?;
    Ok(Json(command_result_to_wire(result)))
}

enum CommandError {
    Scope(ScopeDenied),
    NotFound,
    Dispatch(anyhow::Error),
}

impl IntoResponse for CommandError {
    fn into_response(self) -> axum::response::Response {
        match self {
            CommandError::Scope(s) => s.into_response(),
            CommandError::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            CommandError::Dispatch(err) => {
                tracing::error!(target: "api.devices", error = %err, "device command dispatch failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

// ── Plugins (aggregate by plugin_id) ─────────────────────────────

#[derive(Serialize)]
struct PluginsBody {
    plugins: Vec<PluginSummary>,
}

#[derive(Serialize)]
struct PluginSummary {
    plugin_id: String,
    /// `true` if `<state_dir>/plugins/<plugin_id>/` is present on
    /// disk. A row with `installed = false` means there's a
    /// running instance whose plugin id isn't in the installed
    /// registry — typically the dev-time argv-driven start path
    /// in the daemon, not an actual install.
    installed: bool,
    /// Semver from the installed manifest, or `null` for the
    /// running-but-not-installed case above.
    version: Option<String>,
    /// How many supervised instances are currently registered for
    /// this plugin. Zero is valid for installed-but-stopped plugins;
    /// it's how the CLI distinguishes "ready to start" from
    /// "actively running".
    instance_count: u32,
}

/// `GET /api/v1/plugins` — list of every plugin known to the host:
/// every entry in the installed-plugin registry plus any
/// running-but-uninstalled instances (the dev-time argv path).
/// `instance_count` is aggregated from
/// [`InstanceRegistry::list`] by `plugin_id`. Gated on
/// `plugins:list`. Sorted by plugin id for stable CLI output.
async fn list_plugins(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
) -> Result<Json<PluginsBody>, ScopeDenied> {
    require_scope(&actor, PLUGINS_LIST)?;
    // First, count running instances by plugin id.
    let mut by_plugin: HashMap<String, u32> = HashMap::new();
    for handle in state.engine.instances().list() {
        *by_plugin.entry(handle.plugin_id().to_string()).or_default() += 1;
    }
    // Then merge in installed plugins; an installed-but-stopped
    // plugin lands as `instance_count = 0` (the typical CLI
    // listing on a fresh boot — install endpoints don't auto-start).
    let mut plugins: Vec<PluginSummary> = Vec::new();
    for installed in state.engine.installed_plugins().list() {
        let id = installed.plugin_id.to_string();
        // `remove` doubles as "found?" — every installed id
        // disappears from `by_plugin` here, so the leftover-loop
        // below sees only running-but-not-installed entries
        // without needing a separate seen-set.
        let count = by_plugin.remove(&id).unwrap_or(0);
        plugins.push(PluginSummary {
            plugin_id: id,
            installed: true,
            version: Some(installed.version),
            instance_count: count,
        });
    }
    // Whatever's left in `by_plugin` is running-but-not-installed
    // (the dev-time argv flow).
    for (plugin_id, instance_count) in by_plugin {
        plugins.push(PluginSummary {
            plugin_id,
            installed: false,
            version: None,
            instance_count,
        });
    }
    plugins.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
    Ok(Json(PluginsBody { plugins }))
}

// ── Plugin lifecycle (install / start / stop / uninstall) ────────

/// `POST /api/v1/plugins` body. `source_dir` is a path on the
/// daemon-local filesystem the operator already staged; the daemon
/// copies it into `<state_dir>/plugins/<plugin_id>/`. A remote-fetch
/// / multipart-upload variant is a follow-up that layers on top.
#[derive(Deserialize)]
struct InstallBody {
    source_dir: std::path::PathBuf,
}

#[derive(Serialize)]
struct InstalledRow {
    plugin_id: String,
    version: String,
    installed_path: String,
}

/// `POST /api/v1/plugins` — install. Reads
/// `<source_dir>/manifest.toml` to extract the canonical plugin id,
/// then recursively copies `source_dir` into
/// `<state_dir>/plugins/<plugin_id>/`. Gated on `plugins:install`
/// (sensitive — installs new code on the host).
///
/// Does **not** start the plugin: the operator follows up with
/// `POST /api/v1/plugins/{plugin_id}/start`. Auto-start on install
/// would surprise an operator who wanted to inspect the staged
/// install before letting it run.
async fn install_plugin(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Json(body): Json<InstallBody>,
) -> Result<Json<InstalledRow>, PluginLifecycleError> {
    require_scope(&actor, PLUGINS_INSTALL)?;
    // The registry's install is sync (filesystem + manifest read
    // is fast enough not to need tokio::fs). Wrap in `spawn_blocking`
    // so a slow disk doesn't stall the axum runtime; a `cp -r` of a
    // 10 MB wasm + manifest is sub-100 ms on the slowest hardware
    // but the API thread shouldn't own it either way.
    let installed_registry = state.engine.installed_plugins();
    let source = body.source_dir;
    let installed = tokio::task::spawn_blocking(move || installed_registry.install(&source))
        .await
        .map_err(|err| PluginLifecycleError::Internal(err.into()))??;
    Ok(Json(InstalledRow {
        plugin_id: installed.plugin_id.to_string(),
        version: installed.version,
        installed_path: installed.path.display().to_string(),
    }))
}

#[derive(Deserialize, Default)]
struct StartBody {
    /// Defaults to `plugin_id` if omitted — matches the dev
    /// argv-driven path where the instance id is implicit.
    #[serde(default)]
    instance_id: Option<String>,
    /// Per-instance config overrides (the same TOML-shaped JSON
    /// blob the supervisor accepts via `start_instance`'s
    /// `overrides` parameter).
    #[serde(default)]
    config_overrides: Option<toml::Value>,
}

#[derive(Serialize)]
struct StartedRow {
    plugin_id: String,
    instance_id: String,
    state: String,
}

/// `POST /api/v1/plugins/{plugin_id}/start` — start a supervised
/// instance of an installed plugin. Returns once the instance
/// reaches `Running` (or fails to). Gated on `plugins:start`.
async fn start_plugin_instance(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    body: Option<Json<StartBody>>,
) -> Result<Json<StartedRow>, PluginLifecycleError> {
    require_scope(&actor, PLUGINS_START)?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let instance_id = body
        .instance_id
        .clone()
        .unwrap_or_else(|| plugin_id.clone());
    let installed = state
        .engine
        .installed_plugins()
        .get(&plugin_id)
        .ok_or(PluginLifecycleError::NotFound)?;
    // `start_instance` is itself async and supervises in the
    // background; we await its initial Running transition so the
    // API response reflects the reach-Running outcome.
    let handle = state
        .engine
        .start_instance(installed.path.clone(), &instance_id, body.config_overrides)
        .await
        .map_err(PluginLifecycleError::Start)?;
    handle
        .wait_for_running()
        .await
        .map_err(PluginLifecycleError::Start)?;
    Ok(Json(StartedRow {
        plugin_id,
        instance_id,
        state: format!("{:?}", handle.state()),
    }))
}

#[derive(Deserialize, Default)]
struct StopBody {
    /// If provided, only this instance is stopped. If omitted,
    /// every supervised instance of `plugin_id` is stopped.
    #[serde(default)]
    instance_id: Option<String>,
}

#[derive(Serialize)]
struct StoppedRow {
    stopped: Vec<String>,
}

/// `POST /api/v1/plugins/{plugin_id}/stop` — stop one or all
/// running instances of `plugin_id`. Gated on `plugins:stop`.
/// Returns the list of `instance_id`s actually stopped (empty
/// if none were running, which is success — idempotent).
async fn stop_plugin_instances(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    body: Option<Json<StopBody>>,
) -> Result<Json<StoppedRow>, PluginLifecycleError> {
    require_scope(&actor, PLUGINS_STOP)?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let mut stopped = Vec::new();
    let registry = state.engine.instances();
    for handle in registry.list() {
        if handle.plugin_id() != plugin_id {
            continue;
        }
        if let Some(want) = &body.instance_id
            && handle.instance_id() != want
        {
            continue;
        }
        let id = handle.instance_id().to_string();
        if let Err(err) = handle.stop().await {
            tracing::warn!(
                instance_id = %id,
                error = %err,
                "stop instance failed; continuing with siblings",
            );
            continue;
        }
        // `stop()` returns when the supervisor acks the shutdown
        // command. `wait_terminal()` returns when the supervisor
        // task ends. The InstanceRegistry's reaper task — which
        // does the actual `unregister` — runs in a *separately*
        // spawned tokio task that awaits the same `wait_terminal`
        // we just awaited. So there's a brief window where we've
        // observed the terminal state but the reaper hasn't run
        // yet, and a follow-up `DELETE /api/v1/plugins/{id}`
        // would see the entry and return 409. Poll the registry
        // for clear — under realistic scheduling the reaper runs
        // within a few ticks of the wait_terminal completion.
        let _ = handle.wait_terminal().await;
        wait_for_registry_clear(&registry, &id).await;
        stopped.push(id);
    }
    Ok(Json(StoppedRow { stopped }))
}

/// Bounded poll for the instance to leave the registry after its
/// supervisor reached a terminal state. Under realistic scheduling
/// the reaper runs within a few ticks; this just guarantees the
/// API caller sees a consistent post-stop state. 5 s is comfortably
/// above any plausible reaper-scheduling latency.
async fn wait_for_registry_clear(registry: &crate::InstanceRegistry, instance_id: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while registry.get(instance_id).is_some() {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                instance_id = %instance_id,
                "instance registry didn't clear after 5s — reaper task lagging?",
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[derive(Serialize)]
struct UninstalledRow {
    plugin_id: String,
}

/// `DELETE /api/v1/plugins/{plugin_id}` — remove the installed
/// plugin's directory recursively. Refuses if any supervised
/// instance of the plugin is still running (`409 Conflict`); the
/// operator must `POST .../stop` first. Gated on
/// `plugins:uninstall` (sensitive).
async fn uninstall_plugin(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
) -> Result<Json<UninstalledRow>, PluginLifecycleError> {
    require_scope(&actor, PLUGINS_UNINSTALL)?;
    let running: Vec<String> = state
        .engine
        .instances()
        .list()
        .into_iter()
        .filter(|h| h.plugin_id() == plugin_id)
        .map(|h| h.instance_id().to_string())
        .collect();
    if !running.is_empty() {
        return Err(PluginLifecycleError::InstancesRunning(running));
    }
    let registry = state.engine.installed_plugins();
    let id_for_blocking = plugin_id.clone();
    let result = tokio::task::spawn_blocking(move || registry.uninstall(&id_for_blocking))
        .await
        .map_err(|err| PluginLifecycleError::Internal(err.into()))?;
    result?;
    Ok(Json(UninstalledRow { plugin_id }))
}

/// Mapped error taxonomy for the install / start / stop /
/// uninstall handlers. Each variant lands on a distinct HTTP
/// status so a caller can tell "plugin not installed" from
/// "instances still running" from "transient IO error".
enum PluginLifecycleError {
    Scope(ScopeDenied),
    /// Plugin not installed (start, uninstall) or — for install —
    /// the source dir doesn't exist.
    NotFound,
    /// `<plugins_root>/<plugin_id>/` already exists (install).
    AlreadyInstalled(String),
    /// One or more instances of the plugin are still running
    /// (uninstall). Carries the offending instance ids so the
    /// caller can `POST .../stop` and retry.
    InstancesRunning(Vec<String>),
    /// 400-class manifest / source-dir validation error from the
    /// install path.
    BadInstall(String),
    /// Internal failure that doesn't fit the buckets above. 500.
    Internal(anyhow::Error),
    /// `start_instance` or `wait_for_running` returned Err — the
    /// supervisor either failed to load the plugin or it crashed
    /// before reaching Running. 500.
    Start(anyhow::Error),
    /// In-memory engines have no plugins root. 503.
    NoPluginsRoot,
}

impl From<ScopeDenied> for PluginLifecycleError {
    fn from(s: ScopeDenied) -> Self {
        Self::Scope(s)
    }
}

impl From<InstallError> for PluginLifecycleError {
    fn from(err: InstallError) -> Self {
        match err {
            InstallError::NoPluginsRoot => Self::NoPluginsRoot,
            InstallError::SourceMissing(_) => Self::NotFound,
            InstallError::AlreadyInstalled { plugin_id } => Self::AlreadyInstalled(plugin_id),
            InstallError::BadManifest { reason, .. } => Self::BadInstall(reason),
            InstallError::Io(err) => Self::Internal(err.into()),
        }
    }
}

impl From<UninstallError> for PluginLifecycleError {
    fn from(err: UninstallError) -> Self {
        match err {
            UninstallError::NoPluginsRoot => Self::NoPluginsRoot,
            UninstallError::NotInstalled(_) => Self::NotFound,
            UninstallError::Io(err) => Self::Internal(err.into()),
        }
    }
}

impl IntoResponse for PluginLifecycleError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Scope(s) => s.into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            Self::AlreadyInstalled(id) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "already_installed", "plugin_id": id})),
            )
                .into_response(),
            Self::InstancesRunning(ids) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "instances_running", "instance_ids": ids})),
            )
                .into_response(),
            Self::BadInstall(reason) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "bad_install", "reason": reason})),
            )
                .into_response(),
            Self::Internal(err) => {
                tracing::error!(target: "api.plugins", error = %err, "plugin lifecycle internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            Self::Start(err) => {
                tracing::error!(target: "api.plugins", error = %err, "plugin start failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "start_failed", "reason": err.to_string()})),
                )
                    .into_response()
            }
            Self::NoPluginsRoot => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "no_plugins_root"})),
            )
                .into_response(),
        }
    }
}

// ── Events tail (WebSocket) ──────────────────────────────────────

/// `GET /api/v1/events/tail` — WebSocket upgrade that streams every
/// bus event to the client as a JSON text frame. Gated on
/// `events:tail`. Filter parameters (`--filter device=…`, topic
/// prefix) are a follow-up; v1 streams everything and lets the
/// client filter, matching the existing `EventBus::subscribe_all`
/// shape. Backpressure is the broadcast channel's lag policy: if
/// a client falls behind, the channel drops the oldest events and
/// the client sees a `Lagged` notice (encoded as a `{"lagged":N}`
/// frame so a consumer can log the gap rather than silently miss
/// rows).
///
/// **Ordering note.** Axum runs extractors in declaration order; a
/// non-WS request rejects at `WebSocketUpgrade` with **426
/// Upgrade Required** (no `OnUpgrade` in request extensions)
/// *before* the scope check runs. That's a deliberate
/// information-leak property: a probing caller without
/// `events:tail` and without a proper WS handshake gets the same
/// 426 a wrong-method probe would, so they can't distinguish
/// "scope missing" from "wrong shape". Real WS handshakes (the
/// only ones operators actually send) reach the handler body and
/// get the 403 they should.
///
/// **Audit consequence.** A non-WS probe (426) never reaches the
/// handler body, so `emit_audit` doesn't run — non-WS requests to
/// this path leave no audit row. Real WS handshakes (success or
/// scope-deny) are audited normally. This is the same shape as
/// the `WWW-Authenticate: Bearer` 401 from `require_token`: failed
/// extractor → no audit because there's no authenticated request
/// to record. Documenting so a future audit-completeness audit
/// doesn't read it as a gap.
async fn tail_events(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    upgrade: WebSocketUpgrade,
) -> Result<axum::response::Response, ScopeDenied> {
    require_scope(&actor, EVENTS_TAIL)?;
    let engine = state.engine.clone();
    Ok(upgrade.on_upgrade(move |socket| tail_events_loop(socket, engine)))
}

async fn tail_events_loop(mut socket: WebSocket, engine: Engine) {
    use axum::extract::ws::Message;
    use tokio::sync::broadcast::error::RecvError;
    let mut sub = engine.events().subscribe_all();
    loop {
        // Select between the bus (events to push) and the socket
        // (client frames + disconnects). Polling `socket.recv()`
        // is what makes axum drive the WS control frames —
        // auto-Pong on client Ping, Close handling — and what
        // notices a client disconnect *promptly* on quiet event
        // buses rather than waiting for the next publish to find
        // a dead send target.
        tokio::select! {
            ev = sub.receiver.recv() => match ev {
                Ok(event) => {
                    let wire = WireEvent::from_host(&event);
                    let Ok(text) = serde_json::to_string(&wire) else {
                        continue;
                    };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    let _ = socket
                        .send(Message::Text(format!("{{\"lagged\":{n}}}").into()))
                        .await;
                }
                Err(RecvError::Closed) => break,
            },
            client = socket.recv() => match client {
                // Client gone (None) or socket error → exit. Close
                // frame is the polite version of the same thing.
                None
                | Some(Err(_) | Ok(Message::Close(_))) => break,
                // Other client frames (Text, Binary, Pong) are
                // ignored; the WS protocol forbids text from the
                // client on this endpoint anyway. `Ping` is
                // handled automatically by axum's WebSocket
                // implementation as part of `recv()` polling.
                Some(Ok(_)) => {}
            },
        }
    }
}

/// JSON wire shape for an event over the WS / future history reads.
/// Deliberately decoupled from the WIT bindgen type (so the WIT
/// regenerates without breaking external clients) and from the
/// `event_log` storage shape (which is private to that module).
#[derive(Serialize)]
struct WireEvent {
    device_id: Option<String>,
    /// Plugin-claimed `unix-ms`. The host's receive-time isn't
    /// available on the live bus (only the durable `event_log`
    /// tracks it); a tailing client treats this as best-effort.
    timestamp_ms: u64,
    /// Capability name for `StateChanged` / `"button"` /
    /// `"inference"` for those variants, or the custom-event topic
    /// for `Custom`. Mirrors `EventBus::subscribe`'s topic match.
    topic: String,
    payload: WireEventPayload,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireEventPayload {
    StateChanged {
        capability: String,
    },
    Button {
        /// One of `"pressed"` / `"released"` / `"single_press"`
        /// / `"double_press"` / `"long_press"` / `"rotated"`.
        /// Matches the WIT `button-event` variant 1:1.
        variant: &'static str,
        /// Rotational delta (positive = clockwise), only set on
        /// the `"rotated"` variant per the WIT comment on
        /// `button-event::rotated`. `None` for the discrete
        /// press/release variants.
        #[serde(skip_serializing_if = "Option::is_none")]
        delta: Option<f64>,
    },
    Inference {
        model: String,
        payload: String,
    },
    Custom {
        topic: String,
        payload: String,
    },
}

impl WireEvent {
    fn from_host(event: &Event) -> Self {
        let (topic, payload) = match &event.payload {
            EventPayload::StateChanged(sc) => (
                sc.capability.clone(),
                WireEventPayload::StateChanged {
                    capability: sc.capability.clone(),
                },
            ),
            EventPayload::Button(b) => {
                let (variant, delta) = match *b {
                    ButtonEvent::Pressed => ("pressed", None),
                    ButtonEvent::Released => ("released", None),
                    ButtonEvent::SinglePress => ("single_press", None),
                    ButtonEvent::DoublePress => ("double_press", None),
                    ButtonEvent::LongPress => ("long_press", None),
                    ButtonEvent::Rotated(d) => ("rotated", Some(d)),
                };
                (
                    "button".to_string(),
                    WireEventPayload::Button { variant, delta },
                )
            }
            EventPayload::Inference(i) => (
                "inference".to_string(),
                WireEventPayload::Inference {
                    model: i.model.clone(),
                    payload: i.payload.clone(),
                },
            ),
            EventPayload::Custom(c) => (
                c.topic.clone(),
                WireEventPayload::Custom {
                    topic: c.topic.clone(),
                    payload: c.payload.clone(),
                },
            ),
        };
        Self {
            device_id: event.device.clone(),
            timestamp_ms: event.timestamp,
            topic,
            payload,
        }
    }
}

// ── Logs query ───────────────────────────────────────────────────

/// Query-string parameters for `GET /api/v1/logs`. All fields are
/// optional and AND-combined (same semantics as
/// [`LogQuery`](crate::state::LogQuery)). `limit` defaults to 100;
/// the handler clamps it to a sane maximum.
#[derive(Deserialize, Default)]
struct LogsParams {
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    min_level: Option<LogLevel>,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    target: Option<String>,
    target_prefix: Option<String>,
    span_path_prefix: Option<String>,
    /// Maximum rows to return. Clamped to `LOGS_QUERY_MAX_LIMIT`;
    /// 0 / missing defaults to `LOGS_QUERY_DEFAULT_LIMIT`.
    limit: Option<u32>,
}

/// Default `limit` when the caller omits one. Matches what
/// `oxidhome logs query` (Phase 12-CLI) will default to.
const LOGS_QUERY_DEFAULT_LIMIT: u32 = 100;

/// Upper bound on a single query's `limit` — guards a misbehaving
/// client from pulling the whole log table in one shot, which
/// would pin the `SQLite` read mutex (and the request thread)
/// for a long time on a busy host. The CLI streams in chunks
/// rather than asking for more than this in a single call.
const LOGS_QUERY_MAX_LIMIT: u32 = 1_000;

/// `GET /api/v1/logs?…` — historical log query against the
/// `LogStore` `SQLite` table. Gated on `logs:read`. Returns rows
/// newest-first (the store's native order).
async fn query_logs(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
    Query(params): Query<LogsParams>,
) -> Result<Json<LogsBody>, LogsError> {
    require_scope(&actor, LOGS_READ).map_err(LogsError::Scope)?;
    let limit = params
        .limit
        .unwrap_or(LOGS_QUERY_DEFAULT_LIMIT)
        .clamp(1, LOGS_QUERY_MAX_LIMIT);
    let query = LogQuery {
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        min_level: params.min_level,
        instance_id: params.instance_id,
        plugin_id: params.plugin_id,
        device_id: params.device_id,
        target: params.target,
        target_prefix: params.target_prefix,
        span_path_prefix: params.span_path_prefix,
    };
    let rows =
        run_logs_query(&state.engine.log_store(), &query, limit).map_err(LogsError::Storage)?;
    let logs = rows.into_iter().map(WireLogEvent::from_row).collect();
    Ok(Json(LogsBody { logs }))
}

fn run_logs_query(
    store: &LogStore,
    query: &LogQuery,
    limit: u32,
) -> Result<Vec<HistoricalLogEvent>, crate::state::LogStoreError> {
    // `LogStore::query` takes `usize`; `usize::from(u32)` is only
    // defined on 64+-bit targets. The handler clamps `limit` to
    // `LOGS_QUERY_MAX_LIMIT` (1_000) so any reasonable `usize`
    // width (≥16 bits) holds it; `try_from` keeps it explicit.
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    store.query(query, limit)
}

/// Composite error for `query_logs` so a 403 (scope) and a 500
/// (storage) flow through the same `?` chain without a custom
/// trait juggling.
enum LogsError {
    Scope(ScopeDenied),
    Storage(crate::state::LogStoreError),
}

impl IntoResponse for LogsError {
    fn into_response(self) -> axum::response::Response {
        match self {
            LogsError::Scope(s) => s.into_response(),
            LogsError::Storage(err) => {
                tracing::error!(target: "api.logs", error = %err, "logs query failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

#[derive(Serialize)]
struct LogsBody {
    logs: Vec<WireLogEvent>,
}

#[derive(Serialize)]
struct WireLogEvent {
    id: u64,
    ts_unix_ms: i64,
    level: LogLevel,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    target: String,
    span_path: Option<String>,
    message: String,
    /// Structured fields as `[ [key, JSON-tagged-value], ... ]`.
    /// Tag shape matches the host-side [`LogValue`] enum's serde
    /// repr — clients can deserialize back into the same enum.
    fields: Vec<(String, LogValue)>,
}

impl WireLogEvent {
    fn from_row(row: HistoricalLogEvent) -> Self {
        Self {
            id: row.id,
            ts_unix_ms: row.ts_unix_ms,
            level: row.level,
            instance_id: row.instance_id,
            plugin_id: row.plugin_id,
            device_id: row.device_id,
            target: row.target,
            span_path: row.span_path,
            message: row.message,
            fields: row.fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{
        ButtonEvent as WitButtonEvent, Event,
    };

    /// `WireEvent::from_host` projects each `ButtonEvent` variant to
    /// the matching `snake_case` string, with `delta` set only on
    /// `Rotated`. Pre-fix the wire shape collapsed every button
    /// event to `variant: "event"` — a UI tailing button events had
    /// no way to distinguish a press from a release.
    /// `WireValue` round-trips losslessly through both directions
    /// of the API: a client posts `{"t":"int","v":5}` and reads
    /// `{"t":"int","v":5}` back from `OkWithState`. Pins the
    /// tagged-shape symmetry so a future code change can't
    /// silently flatten the response side.
    #[test]
    fn wire_value_roundtrips_in_both_directions() {
        let cases = [
            Value::BoolVal(true),
            Value::IntVal(-42),
            Value::FloatVal(3.5),
            Value::StringVal("hi".into()),
            Value::BytesVal(vec![0x00, 0xff, 0x42]),
            Value::JsonVal(r#"{"nested":1}"#.into()),
        ];
        for input in cases {
            // Host -> wire (response side, e.g. OkWithState).
            let wire = WireValue::from(input.clone());
            let json = serde_json::to_string(&wire).expect("serialize");
            // Round trip through JSON like a client would.
            let parsed: WireValue = serde_json::from_str(&json).expect("deserialize");
            let back = Value::from(parsed);
            assert!(
                values_equal(&input, &back),
                "round trip failed for {input:?} (json={json})",
            );
        }
    }

    /// Variant-aware equality for the round-trip test. Compares
    /// floats by `to_bits` so the assertion can't be fooled by a
    /// `Float(0.0) == Float(-0.0)` quirk, and so clippy doesn't
    /// flag a strict `==` on `f64` (the test's whole point is that
    /// the wire encoding is bit-exact for the same input).
    fn values_equal(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::BoolVal(x), Value::BoolVal(y)) => x == y,
            (Value::IntVal(x), Value::IntVal(y)) => x == y,
            (Value::FloatVal(x), Value::FloatVal(y)) => x.to_bits() == y.to_bits(),
            (Value::StringVal(x), Value::StringVal(y)) | (Value::JsonVal(x), Value::JsonVal(y)) => {
                x == y
            }
            (Value::BytesVal(x), Value::BytesVal(y)) => x == y,
            _ => false,
        }
    }

    #[test]
    fn button_variant_projects_one_to_one() {
        let cases = [
            (WitButtonEvent::Pressed, "pressed", None),
            (WitButtonEvent::Released, "released", None),
            (WitButtonEvent::SinglePress, "single_press", None),
            (WitButtonEvent::DoublePress, "double_press", None),
            (WitButtonEvent::LongPress, "long_press", None),
            (WitButtonEvent::Rotated(1.5), "rotated", Some(1.5)),
        ];
        for (input, expected_variant, expected_delta) in cases {
            let event = Event {
                device: Some("dev-1".into()),
                timestamp: 0,
                payload: EventPayload::Button(input),
            };
            let wire = WireEvent::from_host(&event);
            match wire.payload {
                WireEventPayload::Button { variant, delta } => {
                    assert_eq!(variant, expected_variant, "variant mismatch for {input:?}");
                    assert_eq!(delta, expected_delta, "delta mismatch for {input:?}");
                }
                other => panic!("expected Button payload, got {other:?}"),
            }
            assert_eq!(wire.topic, "button");
        }
    }
}
