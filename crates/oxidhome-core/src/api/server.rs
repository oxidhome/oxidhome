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
use crate::state::{HistoricalLogEvent, LogLevel, LogQuery, LogStore, LogValue};

use super::auth::{AuthState, require_token};
use super::scopes::{
    DEVICES_COMMAND, DEVICES_LIST, EVENTS_TAIL, INSTANCES_LIST, LOGS_READ, PLUGINS_LIST,
    ScopeDenied, require_scope,
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
pub fn build_router(engine: Engine) -> Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
    };
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/instances", get(list_instances))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{device_id}/command", post(send_command))
        .route("/api/v1/plugins", get(list_plugins))
        .route("/api/v1/events/tail", get(tail_events))
        .route("/api/v1/logs", get(query_logs))
        .layer(from_fn_with_state(auth_state.clone(), require_token))
        .with_state(ApiState { engine })
}

/// Run the API server until the future is dropped.
///
/// Returns the bound [`SocketAddr`] once the listener is up; the
/// future keeps running until the caller drops it. The daemon's
/// `main.rs` will hold this future inside a `tokio::select!` against
/// a shutdown signal in a follow-up PR; for this slice the test
/// harness drives it via `tokio::spawn` + a oneshot abort.
///
/// # Errors
///
/// - `TcpListener::bind` failure (port in use, permission denied).
/// - `axum::serve` errors (rare; mostly accept-loop failures).
pub async fn serve(engine: Engine, config: ApiConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    let actual = listener.local_addr()?;
    tracing::info!(addr = %actual, "oxidhome API listening");
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
    /// How many supervised instances are currently registered for
    /// this plugin. `0` is never returned (a plugin with no live
    /// instances isn't in the registry at all in 12-API-d; a real
    /// "installed plugins" registry that tracks packages
    /// independent of running copies lands with `plugin install`
    /// in a follow-up slice).
    instance_count: u32,
}

/// `GET /api/v1/plugins` — list of plugins with currently-running
/// instances on this host. Aggregated from
/// [`InstanceRegistry::list`] by `plugin_id`; counts unique
/// instance ids per plugin. Gated on `plugins:list`.
async fn list_plugins(
    Extension(actor): Extension<Actor>,
    State(state): State<ApiState>,
) -> Result<Json<PluginsBody>, ScopeDenied> {
    require_scope(&actor, PLUGINS_LIST)?;
    let mut by_plugin: HashMap<String, u32> = HashMap::new();
    for handle in state.engine.instances().list() {
        *by_plugin.entry(handle.plugin_id().to_string()).or_default() += 1;
    }
    let mut plugins: Vec<PluginSummary> = by_plugin
        .into_iter()
        .map(|(plugin_id, instance_count)| PluginSummary {
            plugin_id,
            instance_count,
        })
        .collect();
    // Stable order so the CLI's `plugin list` output isn't a
    // HashMap-iteration coin flip across requests.
    plugins.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
    Ok(Json(PluginsBody { plugins }))
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
