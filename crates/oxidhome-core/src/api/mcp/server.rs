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

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
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
    session_store::InMemorySessionStore,
};

use crate::Engine;

use super::handler::OxidHomeMcpHandler;

/// Public URL prefix the MCP surface is nested under. Callers
/// POST/GET/DELETE this exact path for the streamable-HTTP
/// transport. Kept public so the CLI walkthrough + integration
/// tests point clients at one string instead of a magic literal
/// that could drift.
pub const MCP_ENDPOINT: &str = "/api/v1/mcp";

/// Maximum concurrent MCP sessions retained in memory. Well
/// below the SDK's 10 000 default because on a small home hub
/// with one operator, more than a handful of live agent
/// sessions is a bug (or an abuser); the reduced cap keeps the
/// tail of Finding 1's admission race short — an attacker who
/// wins the check-to-register window on the SDK's admission
/// path can only over-shoot by a few sessions before the next
/// insert trips the cap. Bumps land as a config knob when 14.4
/// wires per-token limits.
const MAX_SESSIONS: usize = 128;

/// Sessions the client has abandoned (browser tab closed, agent
/// process killed) are evicted after this idle window. Without
/// it the store fills forever because clients rarely send the
/// spec-optional DELETE (PR #119 review, F1). 30 min matches
/// the typical agent-idle window observed on Claude Desktop
/// and Cursor.
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
/// - No auth guard — 14.4 wraps the mount in our bearer layer
///   so the same token store gates MCP + REST.
/// - Session store is [`InMemorySessionStore`] with a modest
///   cap ([`MAX_SESSIONS`]) and a 30-minute idle TTL
///   ([`SESSION_IDLE_TTL`]) so abandoned clients release
///   resources without an explicit DELETE. Redis / `SQLite`
///   backing is a 14.7 polish item.
pub fn mount_routes(engine: Engine) -> Router {
    let handler = OxidHomeMcpHandler::new(engine).to_mcp_server_handler();
    let state = Arc::new(McpAppState {
        session_store: Arc::new(InMemorySessionStore::with_limits(
            Some(MAX_SESSIONS),
            Some(SESSION_IDLE_TTL),
        )),
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
        // JSON responses on the streamable-HTTP path — matches
        // what the CLI walkthrough (`curl -X POST /api/v1/mcp`)
        // and the integration test drive. SSE upgrade lands in
        // 14.5 together with stdio.
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
/// so a bogus body fails cheap instead of paying the SDK's
/// parse cost. See the module doc for why we don't route this
/// through `rust-mcp-axum`.
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
    forward(&http_handler, state, Method::POST, uri, headers, Some(body)).await
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
