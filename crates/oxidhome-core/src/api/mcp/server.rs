//! MCP mount for the host axum router.
//!
//! This module owns the "BYO-server" glue described in
//! [`rust_mcp_axum::mcp_routes`](rust_mcp_axum::mcp_routes) — it
//! builds the [`McpAppState`], the [`McpHttpHandler`], and the
//! [`McpMountOptions`], and returns a plain [`axum::Router`] the
//! main API server merges alongside its REST + Connect routes so
//! MCP shares one listener + one bind address with everything else
//! the host exposes.
//!
//! We deliberately do **not** use [`rust_mcp_axum::create_axum_server`]:
//! it spawns its own [`axum_server`] on a separate socket, which
//! would duplicate the bind/tls/signal handling the host already
//! runs. Owning the state + handler here also lets 14.4 slot our
//! own bearer-token guard in front of `/mcp` without waiting on
//! upstream OAuth wiring.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use rust_mcp_axum::mcp_routes;
use rust_mcp_sdk::{
    ToMcpServerHandler,
    id_generator::{FastIdGenerator, UuidGenerator},
    mcp_http::{McpAppState, McpHttpHandler, McpMountOptions},
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
/// transport; `sse` and `messages` (14.5) land at
/// `MCP_ENDPOINT/sse` and `MCP_ENDPOINT/messages`. Kept public so
/// the CLI walkthrough + integration tests point clients at one
/// string instead of a magic literal that could drift.
pub const MCP_ENDPOINT: &str = "/api/v1/mcp";

/// Internal streamable-HTTP mount path. `mount_routes` returns a
/// router whose streamable endpoint sits at `/`; the top-level
/// `build_router` [`nests`](axum::Router::nest) it under
/// [`MCP_ENDPOINT`] so a POST to `/api/v1/mcp` resolves as
/// nested `/`. Nesting is the mount strategy we use instead of
/// `merge` because `rust_mcp_axum::mcp_routes` installs its own
/// 404 fallback for the MCP subtree and axum refuses to merge
/// two routers that both carry a fallback.
const INNER_STREAMABLE_HTTP_ENDPOINT: &str = "/";
const INNER_SSE_ENDPOINT: &str = "/sse";
const INNER_SSE_MESSAGES_ENDPOINT: &str = "/messages";

/// Server-side "who we are" + declared capabilities. Kept in a
/// helper so tests can assert on the exact `InitializeResult`
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
/// - Only the streamable-HTTP transport is mounted (`/api/v1/mcp`).
///   SSE + stdio adapters land in 14.5.
/// - No auth guard — the SDK's built-in `auth` middleware is left
///   out on purpose. 14.4 wraps this router in our bearer-token
///   layer so the same token store gates MCP + REST.
/// - Session store is the SDK's bounded in-memory default. Redis
///   or `SQLite` backing is a 14.7 polish item.
pub fn mount_routes(engine: Engine) -> Router {
    let handler = OxidHomeMcpHandler::new(engine).to_mcp_server_handler();
    let state = Arc::new(McpAppState {
        session_store: Arc::new(InMemorySessionStore::default()),
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

    // No auth provider (14.4 wraps the mount in our bearer
    // layer) and no middlewares — see the module doc.
    let http_handler = McpHttpHandler::new(None, Vec::new(), None);

    let mount = McpMountOptions {
        streamable_http_endpoint: INNER_STREAMABLE_HTTP_ENDPOINT.to_string(),
        // 14.5 wires the SSE + messages transports; the SDK
        // requires paths here even when they're not merged in
        // for streamable-HTTP-only mounts.
        sse_endpoint: INNER_SSE_ENDPOINT.to_string(),
        sse_messages_endpoint: INNER_SSE_MESSAGES_ENDPOINT.to_string(),
        health_endpoint: None,
        ..Default::default()
    };

    mcp_routes(state, &mount, http_handler)
}
