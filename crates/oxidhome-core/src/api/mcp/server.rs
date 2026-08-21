//! MCP mount for the host axum router.
//!
//! Hand-rolls three axum routes (POST/GET/DELETE) at
//! [`MCP_ENDPOINT`] that forward to the SDK's
//! [`McpHttpHandler::handle_streamable_http`]. The mount is a
//! plain [`axum::Router`] merged into the main API server so MCP
//! shares the same listener, TLS, and (eventually) auth stack as
//! REST + Connect.
//!
//! # Why we don't use `rust-mcp-axum`
//!
//! PR #119 review, F2 + F3. `rust_mcp_axum::mcp_routes` is
//! convenient but drags:
//!
//! - The SDK's `auth` feature — pulling `jsonwebtoken` and a
//!   TLS/OAuth `reqwest` chain (`rustls`, `webpki-roots`, both
//!   ISC / `CDLA-Permissive-2.0`) into the graph. The workspace
//!   licence policy in `deny.toml` rejects both — CI's
//!   dependency check fails on those two families.
//! - An unconditional SSE + `/messages` mount, even in a
//!   streamable-only build. That surface has no auth guard
//!   today and advertises a broken message URL to the client
//!   because the router is nested under a prefix the SDK
//!   doesn't know about — a live foot-gun until 14.4 wraps
//!   auth around every MCP path.
//!
//! Owning the three route functions here is ~30 lines and lets
//! us keep the SDK dep at `["server", "macros", "streamable-http"]`
//! (no `sse`, no `auth`), matches the SDK's own
//! `hello-world-server-streamable-http-core.rs` walkthrough, and
//! keeps the SSE + `/messages` mounts on the shelf for 14.5.
//!
//! # MCP spec compliance layers
//!
//! Round-2 review of PR #119 surfaced three transport-spec gaps
//! that the SDK does not close for a BYO-server mount:
//!
//! - [F1](super::server::streamable_http_post) — notifications
//!   and responses (JSON-RPC messages with no request id) must
//!   return `202 Accepted` with no body. The SDK's JSON-response
//!   path returns `500` because it waits for a stream reply that
//!   never comes; we peek at the body and normalize.
//! - [F2](super::origin) — `Origin` allow-list against DNS
//!   rebinding.
//! - [F3](super::session_store) — atomic-admission session
//!   store to bound overshoot.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    middleware::from_fn,
    response::IntoResponse,
    routing::{delete, get, post},
};
use rust_mcp_sdk::{
    ToMcpServerHandler,
    id_generator::{FastIdGenerator, UuidGenerator},
    mcp_http::{McpAppState, McpHttpHandler},
    schema::{
        Implementation, InitializeResult, ProtocolVersion, ServerCapabilities,
        ServerCapabilitiesPrompts, ServerCapabilitiesResources, ServerCapabilitiesTools,
    },
};

use crate::Engine;

use super::handler::OxidHomeMcpHandler;
use super::origin::require_local_origin;
use super::session_store::BoundedSessionStore;

/// Public URL prefix the MCP surface is nested under. Callers
/// POST/GET/DELETE this exact path for the streamable-HTTP
/// transport. Kept public so the CLI walkthrough + integration
/// tests point clients at one string instead of a magic literal
/// that could drift.
pub const MCP_ENDPOINT: &str = "/api/v1/mcp";

/// Maximum concurrent MCP sessions retained in memory. Well
/// below the SDK's 10 000 default because on a small home hub
/// with one operator, more than a handful of live agent
/// sessions is a bug (or an abuser); the reduced cap plus
/// [`BoundedSessionStore`]'s single-lock admission bounds
/// overshoot to zero. Bumps land as a config knob when 14.4
/// wires per-token limits.
const MAX_SESSIONS: usize = 128;

/// Sessions the client has abandoned (browser tab closed, agent
/// process killed) are evicted after this idle window. Without
/// it the store fills forever because clients rarely send the
/// spec-optional DELETE. 30 min matches the typical agent-idle
/// window observed on Claude Desktop and Cursor.
const SESSION_IDLE_TTL: Duration = Duration::from_mins(30);

/// Server-side "who we are" + declared capabilities. Kept in a
/// helper so tests can assert on the exact [`InitializeResult`]
/// bytes we would ship over the wire without spinning a router.
///
/// The three capability blocks (`tools`, `resources`, `prompts`)
/// are declared with `list_changed = None` because 14.1 exposes no
/// dynamic surface yet — 14.2/14.3/14.6 flip that on once we start
/// emitting `notifications/tools/list_changed` and friends.
pub(super) fn initialize_result() -> InitializeResult {
    InitializeResult {
        server_info: Implementation {
            name: "oxidhome".into(),
            title: Some("OxidHome MCP".into()),
            version: env!("CARGO_PKG_VERSION").into(),
            description: Some(
                "OxidHome home-automation hub. Exposes device state, event history, logs, and \
                 plugin control to MCP-speaking agents."
                    .into(),
            ),
            website_url: Some("https://github.com/oxidhome/oxidhome".into()),
            icons: Vec::new(),
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            resources: Some(ServerCapabilitiesResources {
                list_changed: None,
                subscribe: None,
            }),
            prompts: Some(ServerCapabilitiesPrompts { list_changed: None }),
            ..Default::default()
        },
        instructions: Some(
            "Discover data with `resources/list`, actions with `tools/list`. Read tools are \
             safe; action tools carry an `oxidhome.audit` note when they mutate host state."
                .into(),
        ),
        meta: None,
        protocol_version: ProtocolVersion::V2025_11_25.to_string(),
    }
}

/// Build the MCP mount. The returned router carries its own
/// state (session store + handler) and is ready to `.merge` into
/// [`crate::api::build_router`].
///
/// # Scope for 14.1
///
/// - Only the streamable-HTTP transport is mounted, on a single
///   path. SSE + stdio adapters land in 14.5, deliberately
///   held back so an unauthenticated GET `/api/v1/mcp/sse`
///   can't open a persistent session.
/// - No bearer guard — 14.4 wraps the mount in our token layer
///   so the same token store gates MCP + REST. The
///   [`require_local_origin`] middleware is on today so DNS
///   rebinding can't ride the browser's ambient auth against a
///   loopback bind.
/// - Session store is [`BoundedSessionStore`] with a modest cap
///   ([`MAX_SESSIONS`]) and a 30-minute idle TTL
///   ([`SESSION_IDLE_TTL`]) so abandoned clients release
///   resources without an explicit DELETE. Redis / `SQLite`
///   backing is a 14.7 polish item.
pub fn mount_routes(engine: Engine) -> Router {
    let handler = OxidHomeMcpHandler::new(engine).to_mcp_server_handler();
    let state = Arc::new(McpAppState {
        session_store: Arc::new(BoundedSessionStore::new(MAX_SESSIONS, SESSION_IDLE_TTL)),
        id_generator: Arc::new(UuidGenerator),
        stream_id_gen: Arc::new(FastIdGenerator::new(Some("s_"))),
        server_details: Arc::new(initialize_result()),
        handler,
        // Matches the SDK default (`create_axum_server`); the
        // client-facing ping loop only fires once a streaming
        // response is active, so this doesn't cost cycles on
        // request/response calls.
        ping_interval: Duration::from_secs(12),
        transport_options: Arc::default(),
        // JSON responses on the streamable-HTTP path for real
        // requests. Notifications and responses are peeled off
        // in `streamable_http_post` before they reach the SDK
        // (the SDK's JSON path hangs / 500s on them — see the
        // module doc F1 note).
        enable_json_response: true,
        event_store: None,
        task_store: None,
        client_task_store: None,
        message_observer: None,
    });

    // With the SDK's `auth` feature off, `McpHttpHandler::new`
    // takes just middlewares + health_handler. 14.4 replaces
    // the empty middleware list with our bearer + scope guard.
    let http_handler = Arc::new(McpHttpHandler::new(Vec::new(), None));

    Router::new()
        .route(MCP_ENDPOINT, get(streamable_http_get))
        .route(MCP_ENDPOINT, post(streamable_http_post))
        .route(MCP_ENDPOINT, delete(streamable_http_delete))
        .with_state(state)
        .layer(Extension(http_handler))
        .layer(from_fn(require_local_origin))
}

/// GET forwards the resumable stream request. Axum doesn't
/// expose `http::Method` as a first-class extractor, so each
/// verb gets its own handler that hard-codes its `Method`
/// value; the SDK's `handle_streamable_http` still dispatches
/// on `Method` internally.
async fn streamable_http_get(
    State(state): State<Arc<McpAppState>>,
    Extension(http_handler): Extension<Arc<McpHttpHandler>>,
    uri: Uri,
    headers: HeaderMap,
) -> axum::response::Response {
    forward(&http_handler, state, Method::GET, uri, headers, None).await
}

/// POST carries a JSON-RPC payload. UTF-8 validation up front
/// so a bogus body fails cheap; we then classify the payload
/// per MCP HTTP spec (2025-11-25):
///
/// - **Request** (has `method` + `id`): forward to the SDK,
///   return its response as-is (200 JSON or 200 SSE).
/// - **Notification / response** (no request id): forward to
///   the SDK so the runtime dispatches `on_initialized` and
///   friends, but drop the SDK's response body and answer
///   `202 Accepted` — the SDK's JSON path returns `500 "End of
///   the transport stream reached"` on notifications because it
///   waits for a stream reply that never comes.
///
/// See the module doc F1 note.
async fn streamable_http_post(
    State(state): State<Arc<McpAppState>>,
    Extension(http_handler): Extension<Arc<McpHttpHandler>>,
    uri: Uri,
    headers: HeaderMap,
    payload: Bytes,
) -> axum::response::Response {
    let Ok(body) = std::str::from_utf8(&payload) else {
        return (StatusCode::BAD_REQUEST, "Request body must be valid UTF-8").into_response();
    };
    let is_request = payload_contains_request(body);
    let response = forward(&http_handler, state, Method::POST, uri, headers, Some(body)).await;
    if is_request {
        response
    } else {
        // MCP HTTP spec: notifications and responses always
        // 202, no body. We already awaited the SDK call so
        // the runtime has processed the message.
        (StatusCode::ACCEPTED, ()).into_response()
    }
}

/// DELETE tears down a session the client no longer needs. The
/// client-driven path — the SDK also evicts sessions after
/// [`SESSION_IDLE_TTL`] idle, so a well-behaved but
/// silently-disconnected client still frees its slot.
async fn streamable_http_delete(
    State(state): State<Arc<McpAppState>>,
    Extension(http_handler): Extension<Arc<McpHttpHandler>>,
    uri: Uri,
    headers: HeaderMap,
) -> axum::response::Response {
    forward(&http_handler, state, Method::DELETE, uri, headers, None).await
}

/// Shared marshalling: axum extractors → SDK
/// [`http::Request<&str>`] → SDK response → axum response.
/// The three verb handlers only differ in their extractor
/// signature; this fn keeps their bodies to one line each so
/// axum's handler-trait errors stay legible when the extractor
/// list changes.
async fn forward(
    http_handler: &McpHttpHandler,
    state: Arc<McpAppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<&str>,
) -> axum::response::Response {
    let request = McpHttpHandler::create_request(method, uri, headers, body);
    match http_handler.handle_streamable_http(request, state).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            axum::response::Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(err) => {
            tracing::warn!(error = %err, "MCP handler error");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

/// JSON-RPC classification: `true` when the payload is a
/// request (or a batch containing at least one request) — i.e.
/// something the server MUST answer with a real response. `false`
/// for notifications, responses, and unparseable JSON (the SDK
/// will reject those with its own 400 which we forward via the
/// 202 path — non-requests never get a real body).
///
/// A JSON-RPC 2.0 **request** carries both a `method` string and
/// a non-null `id`. A **notification** carries `method` with no
/// `id`. A **response** carries `result` or `error` and its
/// `id`, but no `method`. Batches (arrays) count as requests if
/// any entry is a request.
fn payload_contains_request(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Object(map) => object_is_request(&map),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| item.as_object().is_some_and(object_is_request)),
        _ => false,
    }
}

fn object_is_request(map: &serde_json::Map<String, serde_json::Value>) -> bool {
    let has_method = map.contains_key("method");
    let has_id = map.get("id").is_some_and(|v| !v.is_null());
    has_method && has_id
}

#[cfg(test)]
mod tests {
    use super::payload_contains_request;
    use serde_json::json;

    #[test]
    fn requests_are_classified() {
        assert!(payload_contains_request(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string()
        ));
        assert!(payload_contains_request(
            &json!({"jsonrpc":"2.0","id":"abc","method":"initialize","params":{}}).to_string()
        ));
    }

    #[test]
    fn notifications_are_not_requests() {
        // No id at all → notification.
        assert!(!payload_contains_request(
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string()
        ));
        // Explicit null id (some clients send this) →
        // still a notification per JSON-RPC 2.0.
        assert!(!payload_contains_request(
            &json!({"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}).to_string()
        ));
    }

    #[test]
    fn responses_are_not_requests() {
        // Client's answer to a server-initiated call — no
        // `method`, has `result` + `id`. MCP spec: server MUST
        // return 202 for these.
        assert!(!payload_contains_request(
            &json!({"jsonrpc":"2.0","id":42,"result":{}}).to_string()
        ));
    }

    #[test]
    fn garbage_is_not_a_request() {
        assert!(!payload_contains_request("not json"));
        assert!(!payload_contains_request("null"));
        assert!(!payload_contains_request("42"));
    }

    #[test]
    fn batch_with_any_request_counts_as_request() {
        // Mixed batch: one notification + one request → the
        // batch as a whole demands a response body.
        let batch = json!([
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","id":1,"method":"tools/list"}
        ]);
        assert!(payload_contains_request(&batch.to_string()));
        // All-notifications batch → no response demanded.
        let batch = json!([
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","method":"notifications/roots/list_changed"}
        ]);
        assert!(!payload_contains_request(&batch.to_string()));
    }
}
