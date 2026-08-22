//! MCP mount for the host axum router.
//!
//! Builds an [`rmcp`] [`StreamableHttpService`] with a bounded
//! [`BoundedSessionManager`], mounts it at exactly
//! [`MCP_ENDPOINT`] (no subtree), and wraps the mount in an
//! [`admission_gate`] axum layer that returns `503 Service
//! Unavailable` before the SDK sees a request when the session
//! cap is reached.
//!
//! # Two things this module owns
//!
//! - **Exact-path mount.** `axum::Router::route_service`
//!   (round-4 F1) — the earlier `nest_service` matched every
//!   descendant path, which reintroduced the deferred SSE +
//!   messages endpoints the SDK does not expose here.
//! - **Admission gate.** Pre-request 503 for new-session POSTs
//!   past cap (round-4 F2). The SDK would otherwise map a
//!   `SessionManager` error to `500 Internal Server Error` and
//!   log an ERROR line for every overload — both wrong: 503 is
//!   the spec-shaped overload signal, and expected overload
//!   shouldn't hit ERROR.
//!
//! # What `rmcp` gives us for free
//!
//! - Notification / response HTTP shape matching the MCP HTTP
//!   spec: `202 Accepted` with no body.
//! - `Origin` + `Host` DNS-rebinding guard via
//!   [`StreamableHttpServerConfig::allowed_hosts`] /
//!   [`StreamableHttpServerConfig::with_allowed_origins`].
//! - Public [`SessionManager::close_session`] that terminates
//!   the session worker and drops the transport, plus
//!   `LocalSessionManager`'s 5-minute idle keep-alive.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::Engine;

use super::handler::OxidHomeMcpHandler;
use super::session_store::BoundedSessionManager;

/// URL path the MCP surface mounts on. **Exact match** — no
/// subtree. Kept public so the CLI walkthrough + integration
/// tests point clients at one string.
pub const MCP_ENDPOINT: &str = "/api/v1/mcp";

/// Maximum concurrent MCP sessions. Sized for a home hub with
/// one operator; a session count beyond this is either an
/// abuser or a client bug. 14.4 wires per-token limits, at
/// which point this becomes a config knob.
pub(super) const MAX_SESSIONS: usize = 128;

/// Header the SDK's streamable-HTTP transport uses to
/// address existing sessions (request in), and to advertise a
/// freshly-minted session (response out).
const SESSION_ID_HEADER: &str = "mcp-session-id";

/// Build the MCP mount. Ready to `.merge` into the main
/// [`crate::api::build_router`].
pub fn mount_routes(engine: &Engine) -> Router {
    mount_routes_with_cap(engine, MAX_SESSIONS)
}

/// Variant of [`mount_routes`] with an explicit session cap.
/// Public so integration tests can drive the 503-shape
/// admission gate without spinning up 128 real sessions.
/// Production callers stick with [`mount_routes`].
pub fn mount_routes_with_cap(engine: &Engine, cap: usize) -> Router {
    let session_manager = Arc::new(BoundedSessionManager::new(
        LocalSessionManager::default(),
        cap,
    ));
    let handler_engine = engine.clone();
    let config = StreamableHttpServerConfig::default()
        // Defense-in-depth alongside the (default) `Host`
        // loopback allow-list: browser-driven cross-origin
        // requests must also carry a loopback `Origin`.
        .with_allowed_origins([
            "http://localhost",
            "https://localhost",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://[::1]",
            "https://[::1]",
        ]);
    let service = StreamableHttpService::new(
        move || Ok(OxidHomeMcpHandler::new(handler_engine.clone())),
        session_manager.clone(),
        config,
    );

    // `route_service` — the exact `/api/v1/mcp` path only, no
    // subtree. `nest_service` would match `/api/v1/mcp/sse`,
    // `/api/v1/mcp/messages`, and every other descendant, and
    // `StreamableHttpService` happily starts sessions on all
    // of them, which reintroduces the deferred-endpoints
    // exposure (round-4 F1).
    Router::new()
        .route_service(MCP_ENDPOINT, service)
        .layer(from_fn_with_state(session_manager, admission_gate))
}

/// Middleware: reserve an admission slot before requests that
/// could create a new session reach the SDK. Emits
/// `503 Service Unavailable` at cap so the SDK never has to
/// error out via its 500-shaped `internal_error_response`
/// path (which also logs at ERROR level).
///
/// The reservation lives across the response. If the response
/// header carries [`SESSION_ID_HEADER`], the SDK really did
/// admit a session and the slot is committed via
/// [`super::session_store::Admission::commit`]; otherwise the
/// `Admission` handle drops and returns the slot to the pool.
async fn admission_gate(
    State(mgr): State<Arc<BoundedSessionManager>>,
    request: Request,
    next: Next,
) -> Response {
    // Only POST-without-session-id can drive
    // `SessionManager::create_session`. Every other shape
    // either targets an existing session or is rejected by
    // the SDK before it touches the manager.
    let is_new_session =
        request.method() == Method::POST && !request.headers().contains_key(SESSION_ID_HEADER);
    if !is_new_session {
        return next.run(request).await;
    }
    let Some(admission) = mgr.try_admit() else {
        tracing::warn!(
            cap = mgr.cap(),
            "MCP session cap reached — replying 503 Service Unavailable",
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "30")],
            Body::from(r#"{"error":"MCP session cap reached; retry later"}"#),
        )
            .into_response();
    };
    let response = next.run(request).await;
    if response.status().is_success() && response.headers().contains_key(SESSION_ID_HEADER) {
        // Real session admitted — commit the slot to it.
        // Anything else (SDK rejected, discover-style
        // request that produces no session) leaves the
        // `Admission` to drop and auto-release.
        admission.commit();
    }
    response
}
