//! Axum server + router.
//!
//! [`serve`] takes an [`Engine`] and an [`ApiConfig`], builds the
//! router, binds the listener, and runs forever. Integration tests
//! call [`build_router`] directly to drive routes via `tower::Service`
//! without binding a TCP port.

use std::net::SocketAddr;

use axum::{
    Extension, Json, Router,
    extract::{Query, State, WebSocketUpgrade, ws::WebSocket},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::get,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::Engine;
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventPayload};
use crate::state::{HistoricalLogEvent, LogLevel, LogQuery, LogStore, LogValue};

use super::auth::{AuthState, require_token};
use super::scopes::{
    DEVICES_LIST, EVENTS_TAIL, INSTANCES_LIST, LOGS_READ, ScopeDenied, require_scope,
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
    /// `Debug` repr of the current [`InstanceState`](crate::InstanceState).
    /// The richer shape (plus `plugin_id`, `state_changed_at`, etc.)
    /// lands in 12-API-b once `InstanceHandle` grows the matching
    /// accessors — keeping this skeleton dependency-free.
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
/// malformed (non-WS) request rejects at `WebSocketUpgrade` with
/// 400 *before* the scope check runs. That's a deliberate
/// information-leak property, not a bug: a probing caller without
/// `events:tail` and without a proper WS handshake gets the same
/// 400 a wrong-method probe would, so they can't distinguish
/// "scope missing" from "wrong shape". Real WS handshakes (the
/// only ones operators actually send) reach the handler body and
/// get the 403 they should.
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
    let mut sub = engine.events().subscribe_all();
    loop {
        match sub.receiver.recv().await {
            Ok(event) => {
                let wire = WireEvent::from_host(&event);
                let Ok(text) = serde_json::to_string(&wire) else {
                    continue;
                };
                if socket
                    .send(axum::extract::ws::Message::Text(text.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let _ = socket
                    .send(axum::extract::ws::Message::Text(
                        format!("{{\"lagged\":{n}}}").into(),
                    ))
                    .await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireEventPayload {
    StateChanged { capability: String },
    Button { variant: &'static str },
    Inference { model: String, payload: String },
    Custom { topic: String, payload: String },
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
            EventPayload::Button(_) => (
                "button".to_string(),
                // Button-variant detail isn't projected here; v1
                // wire surface is "something happened on the
                // button capability". The richer projection
                // matches the WIT variant 1:1 in a follow-up.
                WireEventPayload::Button { variant: "event" },
            ),
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
    // `LogStore::query` takes `usize`; we cap at
    // `LOGS_QUERY_MAX_LIMIT` (1_000) at the handler so the cast is
    // always safe even on 16-bit targets (which we don't target,
    // but the explicit upcast keeps clippy quiet anyway).
    store.query(query, limit as usize)
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
