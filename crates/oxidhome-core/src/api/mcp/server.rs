//! MCP mount for the host axum router.
//!
//! Builds an [`rmcp`] [`StreamableHttpService`] with a bounded
//! [`BoundedSessionManager`], mounts it at exactly
//! [`MCP_ENDPOINT`] (no subtree), and wraps the mount in an
//! [`admission_gate`] axum layer with three tiers of protection:
//!
//! 1. **Pending-body gate** — every POST first tries to acquire
//!    one of [`PENDING_BODY_GATE`] concurrent-body permits. This
//!    caps memory allocated for buffering (`≤ PENDING_BODY_GATE *
//!    MAX_REQUEST_BODY_BYTES`) so an unauthenticated client
//!    can't blow the RSS budget just by opening enough sockets
//!    (round-6 F1). Round-4 F1 on PR #122 extended the permit's
//!    lifetime: the permit rides on the response body via a
//!    [`PermitBody`] wrapper, so it isn't released until the
//!    SSE / JSON body has actually been sent to the client.
//!    Round-5 F1 on PR #122 added a per-response byte cap
//!    ([`MAX_RESPONSE_BODY_BYTES`]) enforced by the same
//!    wrapper: a runaway serializer terminates the stream
//!    rather than pushing arbitrarily many MiB through a slot.
//!    That caps in-transit response memory to
//!    `PENDING_BODY_GATE * MAX_RESPONSE_BODY_BYTES` — a slow
//!    client accepting a blob response holds a slot until it
//!    finishes reading, but the slot's cost is bounded.
//! 2. **Body deadline + size cap** — inside the pending gate we
//!    buffer the body under [`REQUEST_BODY_DEADLINE`] and
//!    [`MAX_REQUEST_BODY_BYTES`]. Deadline miss ⇒ `408`, size
//!    miss ⇒ `413` (round-6 F2 — the pre-fix path lumped size
//!    into `400`).
//! 3. **Live-session gate** — only new-session POSTs (no
//!    `mcp-session-id` header) then try to reserve one of
//!    [`MAX_SESSIONS`] live-session permits. Existing-session
//!    POSTs skip this tier (they don't create a session) but
//!    still go through the first two.
//!
//! # Two things this module owns beyond the SDK
//!
//! - **Exact-path mount.** `axum::Router::route_service` —
//!   `nest_service` matched every descendant path, which
//!   would reintroduce the deferred SSE + messages endpoints
//!   the SDK does not expose here.
//! - **Admission gate.** Pre-request body deadline, size cap,
//!   pending-body gate, and 503 for new-session POSTs past cap.
//!   The SDK would otherwise map a `SessionManager` error to
//!   `500 Internal Server Error` and log an ERROR line for
//!   every overload — both wrong for expected overload.
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
use tokio::sync::Semaphore;

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

/// Maximum concurrent POST bodies alive on the mount at any
/// moment — from the moment the request enters the middleware
/// until the response body finishes streaming (round-4 F1 on
/// PR #122 attached the permit to the response body). Sized to
/// a small home-hub memory budget:
///
/// - **Request-buffering:** `PENDING_BODY_GATE *
///   MAX_REQUEST_BODY_BYTES` = 16 MiB worst-case buffered.
/// - **Response-transmission:** each response is capped at
///   [`MAX_RESPONSE_BODY_BYTES`] by the [`PermitBody`]
///   byte-count wrapper (round-5 F1 on PR #122 — before that,
///   `resources/read` on `oxidhome://events?limit=1000` could
///   serialize ~62 MiB per response). Aggregate:
///   `PENDING_BODY_GATE * MAX_RESPONSE_BODY_BYTES` = 128 MiB
///   worst-case in-transit response memory.
pub(super) const PENDING_BODY_GATE: usize = 16;

/// Maximum time we will wait for the client to finish sending
/// its request body before returning `408 Request Timeout`.
/// Legitimate MCP bodies complete in single-digit milliseconds;
/// the deadline exists to prevent a slow-stream attacker from
/// holding a pending-body permit or a live-session slot by
/// never finishing their body. 5 seconds is far above realistic
/// client latency and below any operator patience threshold.
pub(super) const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(5);

/// Maximum accepted request-body size before we return
/// `413 Payload Too Large`. MCP JSON-RPC messages are tiny
/// (the largest realistic payload is a `resources/read`
/// response, which flows the *other* way anyway); 1 MiB is
/// still an order of magnitude above what any published tool
/// or resource dispatch produces on the request side, and it
/// caps the memory bill under [`PENDING_BODY_GATE`] to
/// `PENDING_BODY_GATE * MAX_REQUEST_BODY_BYTES` (round-7 F1
/// — rmcp's own default is 4 MiB, more than we need).
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

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
/// exposed. Public because the R5 F2 regression test needs a
/// short deadline to run in reasonable time; production
/// callers use [`mount_routes`]. Uses the production
/// [`PENDING_BODY_GATE`] cap; see
/// [`mount_routes_with_all_limits`] to override that too.
pub fn mount_routes_with_limits(
    engine: &Engine,
    cap: usize,
    request_body_deadline: Duration,
) -> Router {
    mount_routes_with_all_limits(engine, cap, request_body_deadline, PENDING_BODY_GATE)
}

/// Mount variant that overrides the per-token rate limiter.
/// Public so 14.7b's integration test can drive the 429 shape
/// with a capacity of 1 rather than the production 60. All
/// other limits stay at production defaults.
pub fn mount_routes_with_rate_limiter(
    engine: &Engine,
    rate_limit_capacity: u32,
    rate_limit_refill_per_second: f64,
) -> Router {
    mount_inner(
        engine,
        MAX_SESSIONS,
        REQUEST_BODY_DEADLINE,
        PENDING_BODY_GATE,
        super::rate_limit::RateLimiterState::with_capacity_and_refill(
            rate_limit_capacity,
            rate_limit_refill_per_second,
        ),
    )
}

/// Fully-parametrized mount — session cap, body deadline, AND
/// concurrent-body-buffer permits. Public so the R6 F1
/// regression test can exhaust the pending-body gate without
/// firing 256 requests. Uses the production per-token rate
/// limiter; see [`mount_routes_with_rate_limiter`] to override
/// that too.
pub fn mount_routes_with_all_limits(
    engine: &Engine,
    cap: usize,
    request_body_deadline: Duration,
    pending_body_gate: usize,
) -> Router {
    mount_inner(
        engine,
        cap,
        request_body_deadline,
        pending_body_gate,
        super::rate_limit::RateLimiterState::new(),
    )
}

/// Internal mount that takes every knob. Every `mount_*` public
/// variant delegates here.
fn mount_inner(
    engine: &Engine,
    cap: usize,
    request_body_deadline: Duration,
    pending_body_gate: usize,
    rate_limiter: super::rate_limit::RateLimiterState,
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
        pending: Arc::new(Semaphore::new(pending_body_gate)),
        body_deadline: request_body_deadline,
    };

    // Bearer-auth layer — the same `require_token` middleware
    // the JSON / Connect surfaces already wear. Wraps the
    // whole MCP mount so an unauthenticated caller can't
    // enumerate devices / plugins / instances (round-1 F1
    // on PR #120). The middleware also inserts the resolved
    // [`Actor`](crate::auth::Actor) into the request
    // extensions, which the resource dispatch pulls back out
    // via `RequestContext.extensions.get::<Parts>()`. 14.4
    // adds per-token scope enforcement on top of this basic
    // "must have a valid token" check.
    let auth_state = super::super::auth::AuthState {
        tokens: engine.auth_tokens(),
        audit_log: engine.audit_log(),
    };

    // `route_service` — the exact `/api/v1/mcp` path only, no
    // subtree. `nest_service` would match `/api/v1/mcp/sse`,
    // `/api/v1/mcp/messages`, and every other descendant, and
    // `StreamableHttpService` happily starts sessions on all
    // of them (round-4 F1).
    //
    // Outer to inner: bearer auth → admission gate → MCP
    // service. Layers are applied bottom-up per axum's
    // ordering, so the LAST `.layer(...)` runs first —
    // `require_token` sees the raw request and rejects
    // unauthenticated callers with 401 before the admission
    // gate ever buffers a body. That closes the round-2 F2
    // starvation vector: 16 unauthenticated slow POSTs
    // otherwise held the pending-body permits for the full
    // `REQUEST_BODY_DEADLINE`, blocking legitimate clients.
    // The token-store lookup cost per request is the price
    // of that safety; on a home hub with one operator it's
    // trivial.
    // 14.7b: per-bearer rate limit. Round-2 P1 on PR #140 moved
    // this OUTSIDE `require_token` so a rejected request does
    // zero SQLite writes — no `last_used_ms` update, no audit
    // intent, no audit finalize. The limiter keys on a
    // SHA-256 fingerprint of the raw bearer (or a shared
    // "anonymous" sentinel), which is available before the
    // auth layer runs. Tests that need to drive the 429 shape
    // override the limiter via `mount_routes_with_rate_limiter`.
    //
    // Layer order (bottom-up in code = outer-to-inner at
    // runtime):
    //   request → rate_limit → require_token → admission_gate → service
    Router::new()
        .route_service(MCP_ENDPOINT, service)
        .layer(from_fn_with_state(state, admission_gate))
        .layer(from_fn_with_state(
            auth_state,
            super::super::auth::require_token,
        ))
        .layer(from_fn_with_state(
            rate_limiter,
            super::rate_limit::rate_limit,
        ))
}

/// Shared state the [`admission_gate`] middleware pulls out
/// via `State`. Keeps the manager, pending-body gate, and
/// deadline together so a per-mount test can drive all three.
#[derive(Clone)]
struct GateState {
    manager: Arc<BoundedSessionManager>,
    /// Bounded concurrent-body-buffer permits. See
    /// [`PENDING_BODY_GATE`].
    pending: Arc<Semaphore>,
    body_deadline: Duration,
}

/// Middleware: enforces the three tiers described in the
/// module doc. GET / DELETE (no bodies) pass through
/// untouched.
async fn admission_gate(State(state): State<GateState>, request: Request, next: Next) -> Response {
    // GET / DELETE have no body to buffer or account for.
    if request.method() != Method::POST {
        return next.run(request).await;
    }

    // Tier 1: pending-body permit. Bounds worst-case memory
    // allocated for buffering across ALL concurrent MCP
    // POSTs (round-6 F1). Held only across the buffering
    // step below — dropped before the potentially long-lived
    // downstream response.
    let Ok(pending_permit) = state.pending.clone().try_acquire_owned() else {
        tracing::warn!(
            cap = PENDING_BODY_GATE,
            "MCP pending-body gate full — replying 503 Service Unavailable",
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            Body::from(r#"{"error":"MCP is at concurrent-request capacity; retry shortly"}"#),
        )
            .into_response();
    };

    // Tier 2: body deadline + size cap. Distinguishes
    // "too big" (413) from "malformed / read error" (400)
    // from "deadline exceeded" (408) — round-6 F2.
    let (parts, body) = request.into_parts();
    let buffered = match tokio::time::timeout(
        state.body_deadline,
        axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            // `to_bytes` sets a `LengthLimitError` on the
            // error's `source()` when the size cap is hit;
            // anything else is a genuine read failure.
            let hit_size_cap = is_length_limit_error(&err);
            if hit_size_cap {
                tracing::warn!(
                    limit = MAX_REQUEST_BODY_BYTES,
                    "MCP request body exceeded size cap — replying 413 Payload Too Large",
                );
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "MCP request body exceeded size cap",
                )
                    .into_response();
            }
            tracing::warn!(%err, "MCP: failed to read request body");
            return (StatusCode::BAD_REQUEST, "Failed to read MCP request body").into_response();
        }
        Err(_) => {
            tracing::warn!(
                deadline_ms = u64::try_from(state.body_deadline.as_millis()).unwrap_or(u64::MAX),
                "MCP request body exceeded deadline — replying 408 Request Timeout",
            );
            return (
                StatusCode::REQUEST_TIMEOUT,
                "MCP request body deadline exceeded",
            )
                .into_response();
        }
    };

    // The pending permit rides through `next.run` (bounds the
    // SDK's re-parse) and then onto the response body via
    // [`attach_permit_to_body`] (bounds transmission-phase
    // memory — round-4 F1 on PR #122). A slow client accepting
    // an SSE frame keeps its slot until the connection drains
    // or drops, which is what we want the cap to reflect.

    // Tier 3: live-session gate. Only POSTs that could mint
    // a new session (no `mcp-session-id` header) reserve one
    // of MAX_SESSIONS permits. Existing-session POSTs go
    // straight through — they don't create sessions.
    let is_new_session = !parts.headers.contains_key(SESSION_ID_HEADER);
    let request = Request::from_parts(parts, Body::from(buffered));
    if !is_new_session {
        let response = next.run(request).await;
        // Round-4 F1 on PR #122: hand the pending permit off
        // to the response body so the slot doesn't release
        // until the SSE stream is fully consumed (or the
        // client disconnects). Pre-fix, the permit dropped
        // as soon as `next.run` returned, letting a slow
        // client accumulate arbitrarily many in-transit blob
        // response bodies while fresh POSTs kept taking
        // permits.
        return attach_permit_to_body(response, pending_permit);
    }

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
    // Same body wrap as the existing-session path — the
    // pending permit rides on the response body until it's
    // fully sent (round-4 F1 on PR #122).
    attach_permit_to_body(response, pending_permit)
}

/// Per-response ceiling on serialized body bytes for the MCP
/// mount. Round-5 F1 on PR #122: without a per-response cap,
/// the reviewer showed how a `resources/read` on
/// `oxidhome://events?limit=1000` could serialize ~62 MiB
/// (`1_000` event rows × 64 KiB payload each) and 16 concurrent such
/// responses could approach 1 GiB. The source-level query caps
/// were tightened to make normal responses fit; this cap is the
/// defense-in-depth backstop that terminates the stream if a
/// response somehow exceeds it.
///
/// Sized to comfortably fit the tightest source-level cap:
/// events at 100 records × 64 KiB per payload + framing ≈
/// 6.5 MiB, blobs at 4 MiB base64 ≈ 5.4 MiB. 8 MiB gives
/// headroom for wire framing (SSE `data:` prefix, JSON-RPC
/// envelope, `_meta`) without allowing a run-away serializer
/// to burn through host RAM.
///
/// Aggregate bound: `PENDING_BODY_GATE * MAX_RESPONSE_BODY_BYTES`
/// = 16 × 8 MiB = 128 MiB worst-case in-transit response
/// memory across the whole mount.
pub(super) const MAX_RESPONSE_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Wrap the response body with a [`PermitBody`] that owns the
/// caller's [`OwnedSemaphorePermit`] — the permit drops when
/// axum/hyper finishes writing the body OR the client
/// disconnects, whichever happens first. This is the mechanism
/// that gives [`PENDING_BODY_GATE`] a transmission-lifetime
/// bound rather than a handler-lifetime one.
fn attach_permit_to_body(
    response: Response,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response {
    let (parts, body) = response.into_parts();
    let wrapped = Body::new(PermitBody {
        inner: body,
        _permit: permit,
        bytes_seen: 0,
        max_bytes: MAX_RESPONSE_BODY_BYTES,
        truncated: false,
    });
    Response::from_parts(parts, wrapped)
}

/// [`http_body::Body`] wrapper that keeps an
/// [`tokio::sync::OwnedSemaphorePermit`] alive for the full
/// lifetime of the response body AND enforces a per-response
/// byte ceiling ([`MAX_RESPONSE_BODY_BYTES`]).
///
/// The permit drops when the wrapper drops — either the body
/// was fully consumed OR the axum/hyper layer dropped the
/// response because the connection went away.
///
/// The byte ceiling is defense-in-depth: source-level query
/// caps (see e.g. `EVENTS_QUERY_MAX_LIMIT` in
/// [`crate::api::mcp::resources`]) are the primary bound;
/// this wrapper catches any response that slips past them.
/// On overflow we surface an [`axum::Error`] on the next
/// `poll_frame`, which terminates the stream. The client
/// sees a truncated body — worse UX than a clean 413, but
/// there's no way to send a fresh HTTP response after headers
/// have flushed. The tracing warn line at truncation time is
/// the operator signal.
///
/// The wrapper carries `Bytes` as its data type because that's
/// the frame shape `axum::body::Body` yields; the trait's error
/// type is `axum::Error` for the same reason. Every downstream
/// consumer of an axum `Response` handles those exact types
/// already, so wrapping is transparent.
struct PermitBody {
    inner: Body,
    _permit: tokio::sync::OwnedSemaphorePermit,
    bytes_seen: u64,
    max_bytes: u64,
    truncated: bool,
}

// Both `Body` and `OwnedSemaphorePermit` are `Unpin`, so the
// wrapper is `Unpin` too — the auto-derive kicks in, and the
// `poll_frame` impl below uses `Pin::new` on the field without
// any unsafe. Explicit assertion so a future field addition
// that isn't `Unpin` fails at compile time here rather than
// at some downstream `poll_frame` call.
const _: fn() = || {
    fn assert_unpin<T: Unpin>() {}
    assert_unpin::<PermitBody>();
};

impl http_body::Body for PermitBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        // Sticky truncation: once we've refused a frame, keep
        // ending the stream so a well-behaved consumer stops
        // polling instead of hitting the same error path
        // repeatedly.
        if this.truncated {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(frame))) => {
                // Only data frames count toward the byte cap;
                // trailer frames are tiny by construction and
                // pass through unchanged.
                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    let next = this.bytes_seen.saturating_add(n);
                    if next > this.max_bytes {
                        this.truncated = true;
                        tracing::warn!(
                            cap = this.max_bytes,
                            seen = this.bytes_seen,
                            frame = n,
                            "MCP response body exceeded MAX_RESPONSE_BODY_BYTES — terminating stream",
                        );
                        return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::other(
                            format!(
                                "MCP response body exceeded per-response cap ({} bytes)",
                                this.max_bytes,
                            ),
                        )))));
                    }
                    this.bytes_seen = next;
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.truncated || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// True if the error surfaced from
/// [`axum::body::to_bytes`] is `axum`'s size-cap signal
/// (`http_body_util::LengthLimitError` on the error source).
/// See the `to_bytes` doc example.
fn is_length_limit_error(err: &axum::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> =
        std::error::Error::source(err as &dyn std::error::Error);
    while let Some(source) = current {
        if source.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        current = source.source();
    }
    false
}

#[cfg(test)]
mod permit_body_tests {
    use super::{MAX_RESPONSE_BODY_BYTES, PermitBody};
    use axum::body::Body;
    use http_body_util::BodyExt as _;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    /// Build a `PermitBody` around a fixed-size body plus a
    /// live semaphore permit. Every test does this dance;
    /// helper keeps them focused on the byte-cap logic.
    fn wrap(bytes: bytes::Bytes, cap: u64) -> PermitBody {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore
            .clone()
            .try_acquire_owned()
            .expect("permit available");
        PermitBody {
            inner: Body::from(bytes),
            _permit: permit,
            bytes_seen: 0,
            max_bytes: cap,
            truncated: false,
        }
    }

    /// A response smaller than the cap streams through the
    /// wrapper unchanged — the byte counter is defense-in-depth,
    /// not a normal-path bottleneck.
    #[tokio::test]
    async fn body_under_cap_passes_through() {
        let payload = vec![0u8; 1024];
        let body = wrap(payload.clone().into(), 2 * 1024);
        let collected = body
            .collect()
            .await
            .expect("collect must succeed under cap")
            .to_bytes();
        assert_eq!(collected.len(), payload.len());
    }

    /// Round-5 F1 on PR #122: a body that pushes past the cap
    /// terminates via an `axum::Error` on `poll_frame`. The
    /// error's `Display` names the enforced cap so an operator
    /// grepping logs can tell the wrapper triggered.
    #[tokio::test]
    async fn body_over_cap_is_terminated() {
        // 4 KiB payload, 1 KiB cap: the very first data frame
        // trips the limit.
        let payload = vec![0u8; 4 * 1024];
        let body = wrap(payload.into(), 1024);
        let err = body
            .collect()
            .await
            .expect_err("collect must surface the cap error");
        let msg = err.to_string();
        assert!(
            msg.contains("per-response cap") && msg.contains("1024"),
            "error must name the enforced cap; got {msg}",
        );
    }

    /// The mount's advertised cap value (a compile-time constant
    /// so the doc math holds together) is exactly what the
    /// wrapper enforces. Sanity check to keep the two in sync.
    #[test]
    fn max_response_body_bytes_is_advertised_value() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 8 * 1024 * 1024);
    }
}
