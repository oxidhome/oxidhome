//! MCP mount for the host axum router.
//!
//! Builds an [`rmcp`] [`StreamableHttpService`] with a bounded
//! [`BoundedSessionManager`], mounts it at exactly
//! [`MCP_ENDPOINT`] (no subtree), and wraps the mount in an
//! [`admission_gate`] axum layer that:
//!
//! 1. Buffers the request body under a bounded deadline so a
//!    slow-stream attacker cannot hold session slots by never
//!    finishing their `initialize` body (round-5 F2). Only
//!    once the body is fully in memory do we…
//! 2. …try to reserve a live-session permit. At cap the mount
//!    returns `503 Service Unavailable` before the SDK sees
//!    the request — no ERROR log, no half-created session.
//! 3. Commits the permit to the session id the SDK returned in
//!    the response header, so
//!    [`SessionManager::close_session`] can release exactly
//!    that session's slot later (round-5 F1 is enforced by
//!    the store, but the middleware supplies the id here).
//!
//! # Two things this module owns
//!
//! - **Exact-path mount.** `axum::Router::route_service` —
//!   `nest_service` matched every descendant path, which
//!   would reintroduce the deferred SSE + messages endpoints
//!   the SDK does not expose here.
//! - **Admission gate.** Pre-request body deadline + 503 for
//!   new-session POSTs past cap. The SDK would otherwise map
//!   a `SessionManager` error to `500 Internal Server Error`
//!   and log an ERROR line for every overload — both wrong:
//!   `503` is the spec-shaped overload signal, and expected
//!   overload shouldn't hit ERROR.
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
use std::time::Duration;

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

/// Maximum time we will wait for the client to finish sending
/// its request body before returning `408 Request Timeout`.
/// Legitimate `initialize` bodies complete in single-digit
/// milliseconds; the deadline exists to prevent a slow-stream
/// attacker from holding admission slots by never finishing
/// their body (round-5 F2). 5 seconds is far above realistic
/// client latency and below any operator patience threshold.
pub(super) const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(5);

/// Maximum accepted request-body size before we return
/// `413 Payload Too Large`. Mirrors `rmcp`'s own default
/// (`DEFAULT_MAX_REQUEST_BODY_BYTES`) so a body the middleware
/// accepts won't be rejected downstream on size grounds.
pub(super) const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Header the SDK's streamable-HTTP transport uses to
/// address existing sessions (request in), and to advertise a
/// freshly-minted session (response out).
const SESSION_ID_HEADER: &str = "mcp-session-id";

/// Build the MCP mount with production defaults. Ready to
/// `.merge` into the main [`crate::api::build_router`].
pub fn mount_routes(engine: &Engine) -> Router {
    mount_routes_with_limits(engine, MAX_SESSIONS, REQUEST_BODY_DEADLINE)
}

/// Variant of [`mount_routes`] with an explicit session cap.
/// Public so integration tests can drive the 503-shape
/// admission gate without spinning up 128 real sessions.
/// Production callers stick with [`mount_routes`].
pub fn mount_routes_with_cap(engine: &Engine, cap: usize) -> Router {
    mount_routes_with_limits(engine, cap, REQUEST_BODY_DEADLINE)
}

/// Full-control variant — cap AND request-body deadline
/// exposed. Public because the F2 regression test needs a
/// short deadline to run in reasonable time; production
/// callers use [`mount_routes`].
pub fn mount_routes_with_limits(
    engine: &Engine,
    cap: usize,
    request_body_deadline: Duration,
) -> Router {
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

    let state = GateState {
        manager: session_manager,
        body_deadline: request_body_deadline,
    };

    // `route_service` — the exact `/api/v1/mcp` path only, no
    // subtree. `nest_service` would match `/api/v1/mcp/sse`,
    // `/api/v1/mcp/messages`, and every other descendant, and
    // `StreamableHttpService` happily starts sessions on all
    // of them (round-4 F1).
    Router::new()
        .route_service(MCP_ENDPOINT, service)
        .layer(from_fn_with_state(state, admission_gate))
}

/// Shared state the [`admission_gate`] middleware pulls out
/// via `State`. Keeps the manager + deadline together so a
/// per-mount test can drive both.
#[derive(Clone)]
struct GateState {
    manager: Arc<BoundedSessionManager>,
    body_deadline: Duration,
}

/// Middleware: on a new-session POST, buffer the body first
/// (bounded by [`Self::body_deadline`] + [`MAX_REQUEST_BODY_BYTES`]),
/// then reserve an admission slot. Any other request shape
/// passes through untouched.
///
/// Body-first ordering (round-5 F2) means a slow-stream
/// attacker cannot hold a session permit while they trickle
/// bytes: their read hits the deadline, we return
/// `408 Request Timeout`, and no admission slot was ever
/// reserved on their behalf.
///
/// The reservation lives across the response. If the response
/// header carries [`SESSION_ID_HEADER`], the SDK really did
/// admit a session and the slot is committed to that specific
/// id via [`super::session_store::Admission::commit`];
/// otherwise the `Admission` handle drops and returns the slot
/// to the pool.
async fn admission_gate(State(state): State<GateState>, request: Request, next: Next) -> Response {
    // Only POST-without-session-id can drive
    // `SessionManager::create_session`. Every other shape
    // either targets an existing session or is rejected by
    // the SDK before it touches the manager.
    let is_new_session =
        request.method() == Method::POST && !request.headers().contains_key(SESSION_ID_HEADER);
    if !is_new_session {
        return next.run(request).await;
    }

    // Body first, then admit. A slow-stream attacker never
    // gets to reserve a slot; a legitimate init's body is in
    // memory within ms.
    let (parts, body) = request.into_parts();
    let buffered = match tokio::time::timeout(
        state.body_deadline,
        axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            // `to_bytes` returns Err on both size-cap and
            // read errors; both surface as a client bug.
            tracing::warn!(%err, "MCP init: failed to read request body");
            return (StatusCode::BAD_REQUEST, "Failed to read MCP request body").into_response();
        }
        Err(_) => {
            tracing::warn!(
                deadline_ms = u64::try_from(state.body_deadline.as_millis()).unwrap_or(u64::MAX),
                "MCP init: request body exceeded deadline",
            );
            return (
                StatusCode::REQUEST_TIMEOUT,
                "MCP init: request body deadline exceeded",
            )
                .into_response();
        }
    };

    let Some(admission) = state.manager.try_admit() else {
        tracing::warn!(
            cap = state.manager.cap(),
            "MCP session cap reached — replying 503 Service Unavailable",
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "30")],
            Body::from(r#"{"error":"MCP session cap reached; retry later"}"#),
        )
            .into_response();
    };

    let request = Request::from_parts(parts, Body::from(buffered));
    let response = next.run(request).await;

    // Commit the admission to the concrete session id the SDK
    // returned. Any non-success response (or a success that
    // didn't mint a session — e.g. a `discover` shape) drops
    // the `Admission`, auto-releasing the permit.
    if response.status().is_success()
        && let Some(id) = response
            .headers()
            .get(SESSION_ID_HEADER)
            .and_then(|v| v.to_str().ok())
    {
        admission.commit(id.into());
    }
    response
}
