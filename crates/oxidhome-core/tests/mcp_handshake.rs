//! Phase 14.1 — MCP handshake end-to-end test.
//!
//! Drives [`api::build_router`] via [`tower::ServiceExt::oneshot`]
//! (no TCP bind) against the `rmcp` streamable-HTTP service:
//!
//! 1. `POST /api/v1/mcp initialize` completes the handshake:
//!    `200 OK`, `mcp-session-id` header set, first SSE frame
//!    carries an `InitializeResult` with our `serverInfo` and
//!    declared capabilities.
//! 2. `notifications/initialized` returns `202 Accepted` per
//!    MCP HTTP spec — the SDK gets this right natively (round-3
//!    F1 regression against the pre-switch stack).
//! 3. An untrusted `Origin` is rejected (`403 Forbidden`) by
//!    the SDK's own DNS-rebinding guard (round-2 F2 regression).
//! 4. A loopback `Origin` passes.
//! 5. Malformed JSON on a notification-shaped POST surfaces as
//!    a 4xx error (round-3 F1 — spec compliance).
//!
//! `_` prefix on `support` because 14.1 doesn't touch the shared
//! plugin-staging helpers, but the harness treats every module in
//! `tests/` as a build target — importing `support.rs` gives it
//! the same target roster as the other integration tests so we
//! don't diverge.

#[path = "support.rs"]
mod _support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use serde_json::Value;
use tower::ServiceExt;

const MCP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_CONTENT_TYPE: &str = "application/json";
/// `tower::ServiceExt::oneshot` builds a request with no `Host`
/// header. `rmcp`'s streamable-HTTP service requires one (part
/// of its DNS-rebinding guard) and defaults to accepting the
/// loopback family — so every test sets a loopback `Host` to
/// match production traffic against a `127.0.0.1` bind.
const MCP_HOST: &str = "localhost";

fn initialize_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "oxidhome-mcp-integration-test",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    })
    .to_string()
}

fn base_request(method: &str, bearer: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(MCP_ENDPOINT)
        .header(header::HOST, MCP_HOST)
        .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
        .header(header::ACCEPT, MCP_ACCEPT)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
}

/// Mints a wildcard-scope test bearer against an engine's
/// token store and returns its plaintext. The MCP mount now
/// (round-1 F1 on PR #120) sits behind
/// `crate::api::auth::require_token`, so every integration
/// test needs to authenticate. Wildcard scope keeps the tests
/// focused on the transport / resource shape rather than
/// per-scope policy (14.4 lands the scope-per-resource
/// gates).
fn mint_bearer(engine: &Engine) -> String {
    engine
        .auth_tokens()
        .create("test", b"[\"*\"]")
        .expect("mint bearer")
        .plaintext
}

/// Peels the SSE stream from an `initialize` response and parses
/// the first `data:` frame as JSON-RPC. The stream is persistent
/// so we cannot `to_bytes` it; we time each frame read to bound
/// a real hang.
async fn read_first_sse_data(response: axum::response::Response) -> Value {
    let mut body = response.into_body();
    let mut buf = String::new();
    let deadline = Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout(deadline, body.frame())
            .await
            .expect("timed out waiting for the first SSE frame")
            .expect("stream ended before a data frame arrived")
            .expect("frame read error");
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.push_str(&String::from_utf8_lossy(&data));
        while let Some(event_end) = buf.find("\n\n") {
            let event = buf[..event_end].to_string();
            buf.drain(..=event_end + 1);
            for line in event.lines() {
                let Some(payload) = line.strip_prefix("data:") else {
                    // `retry:` priming, comment (`:` prefix),
                    // `event:` type, or trailing blank —
                    // ignore, keep scanning.
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() {
                    // SSE keep-alive framed as an empty
                    // `data:` line; the SDK emits these
                    // periodically to hold the socket open.
                    continue;
                }
                return serde_json::from_str(payload)
                    .unwrap_or_else(|e| panic!("SSE data line is not JSON: {e}: {payload}"));
            }
        }
    }
}

/// Full handshake: `initialize` returns 200 + SSE + a session
/// id, and the first data frame is a well-formed
/// `InitializeResult` with our declared `serverInfo` and the
/// tools/resources/prompts capability blocks.
#[tokio::test(flavor = "current_thread")]
async fn initialize_returns_session_and_advertises_capabilities() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("mcp-session-id").is_some(),
        "server must mint a session id on initialize so the client can pin follow-up requests",
    );

    let init = read_first_sse_data(response).await;
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    let result = &init["result"];
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "oxidhome");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let caps = &result["capabilities"];
    assert!(caps["tools"].is_object(), "capabilities.tools missing");
    assert!(
        caps["resources"].is_object(),
        "capabilities.resources missing",
    );
    assert!(caps["prompts"].is_object(), "capabilities.prompts missing");
}

/// MCP HTTP spec: notifications MUST return `202 Accepted` with
/// no body. `rmcp` gets this natively — this test guards
/// against regressions if we ever wrap the mount in a layer
/// that would rewrite the shape.
#[tokio::test(flavor = "current_thread")]
async fn initialized_notification_returns_202() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    // 1. Handshake and grab the session id.
    let init = router
        .clone()
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    let session_id = init
        .headers()
        .get("mcp-session-id")
        .expect("session id on initialize")
        .to_str()
        .expect("session id is ASCII")
        .to_string();
    // Fully drain the initialize's first frame so the session
    // is marked initialized before we send the notification.
    let _ = read_first_sse_data(init).await;

    // 2. Notification with that session — expect 202 + empty body.
    let notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
    .to_string();
    let response = router
        .oneshot(
            base_request("POST", &bearer)
                .header("mcp-session-id", &session_id)
                .body(Body::from(notification))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "notification response must have no body; got {:?}",
        String::from_utf8_lossy(&body),
    );
}

/// DNS-rebinding guard: a request with an `Origin` header
/// outside the loopback allow-list is rejected `403 Forbidden`
/// by `rmcp`'s own middleware. We configure the allow-list at
/// `mount_routes` time.
#[tokio::test(flavor = "current_thread")]
async fn untrusted_origin_is_403() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST", &bearer)
                .header(header::ORIGIN, "https://attacker.example")
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "MCP transport spec: reject requests with untrusted Origin",
    );
}

/// Companion to [`untrusted_origin_is_403`]: a legitimate
/// loopback `Origin` (a browser same-origin against a local hub)
/// passes through, so the DNS-rebind layer doesn't break the
/// intended use case.
#[tokio::test(flavor = "current_thread")]
async fn loopback_origin_passes() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST", &bearer)
                .header(header::ORIGIN, "http://127.0.0.1:8080")
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "loopback Origin must pass the DNS-rebind allow-list",
    );
}

/// Round-4 F1: the earlier `nest_service` mount matched every
/// descendant path (`/api/v1/mcp/sse`, `/messages`,
/// `/arbitrary`), and `StreamableHttpService` happily started
/// sessions on all of them. The exact-path `route_service`
/// mount closes that hole — any path deeper than
/// `/api/v1/mcp` must NOT return `200`.
#[tokio::test(flavor = "current_thread")]
async fn descendant_paths_are_not_mounted() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    for suffix in ["/sse", "/messages", "/arbitrary", "/"] {
        let uri = format!("{MCP_ENDPOINT}{suffix}");
        // Bearer set so the assertion is meaningful — if we
        // sent no auth, every descendant would 401 for the
        // wrong reason and the test would trivially pass.
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::HOST, MCP_HOST)
                    .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                    .header(header::ACCEPT, MCP_ACCEPT)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::from(initialize_body()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "descendant path {uri} must NOT be reachable — `route_service` mounts an exact path only",
        );
    }
}

/// Round-4 F2: initialize past the cap MUST return
/// `503 Service Unavailable`, not the SDK's default `500`.
/// The admission middleware short-circuits before the SDK
/// runs, so this path is exercised without any SDK ERROR log
/// or half-created session leaking to the client.
#[tokio::test(flavor = "current_thread")]
async fn initialize_past_cap_returns_503() {
    // Filling the production cap (128) here would slow the
    // suite for no coverage gain — the semaphore semantics
    // are the same at 128 as at 3. Drop `build_router` and
    // exercise a small-cap mount directly against the MCP
    // module.
    use oxidhome_core::api::mcp::mount_routes_with_cap;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = mount_routes_with_cap(&engine, 3);

    let post_init = || {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    let sessions: Vec<_> = {
        let mut out = Vec::new();
        for _ in 0..3 {
            let response = post_init().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "under-cap admissions");
            let session_id = response
                .headers()
                .get("mcp-session-id")
                .expect("session id on init")
                .to_str()
                .unwrap()
                .to_string();
            // Drain the first frame so the session flips to
            // initialized before the next probe.
            let _ = read_first_sse_data(response).await;
            out.push(session_id);
        }
        out
    };

    // Cap = 3, three admitted. The next init must 503.
    let overflow = post_init().await.unwrap();
    assert_eq!(
        overflow.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "over-cap init must reply 503 (admission middleware), not the SDK's default 500",
    );
    assert_eq!(
        overflow
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header on 503")
            .to_str()
            .unwrap(),
        "30",
    );

    // Sanity: unrelated paths on the mount aren't 503'd —
    // only *new session* POSTs go through the gate. (This
    // GET now also carries a bearer since the mount sits
    // behind `require_token`; without it the request 401s
    // before the admission gate even runs, which would tell
    // us the wrong thing about the pending semaphore.)
    let get = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::ACCEPT, MCP_ACCEPT)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        get.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "GET with no session id is not an init, admission gate must pass through",
    );

    // Explicitly hold the session ids across the block so
    // the SDK doesn't reap them before the overflow probe.
    drop(sessions);
}

/// Round-5 F2: a client that opens a request but never
/// finishes sending its body MUST NOT be able to hold an
/// admission slot. The middleware buffers the body under a
/// deadline before reserving a slot, so a slow-stream attacker
/// (or a legitimately-broken client) gets `408 Request Timeout`
/// while every admission slot stays available for real clients.
///
/// The test uses a body backed by a `pending` stream that never
/// yields; without the body-first ordering, this would tie up
/// a session slot until the SDK's own timeouts fire (if any).
#[tokio::test(flavor = "current_thread")]
async fn slow_body_returns_408_without_holding_a_slot() {
    use oxidhome_core::api::mcp::mount_routes_with_limits;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    // Cap = 1 so any "held" slot from the slow request would
    // immediately cause the follow-up init to 503. Short
    // body deadline so the test finishes fast.
    let router = mount_routes_with_limits(&engine, 1, Duration::from_millis(200));

    // Body backed by a `pending` stream — never emits a frame
    // or ends, so `axum::body::to_bytes` would await forever
    // without the middleware's `tokio::time::timeout`.
    let never_ending_body = || {
        Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >())
    };

    let slow = router
        .clone()
        .oneshot(
            base_request("POST", &bearer)
                .body(never_ending_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        slow.status(),
        StatusCode::REQUEST_TIMEOUT,
        "slow-body init must surface as 408 Request Timeout, not hang",
    );

    // Slot must have stayed available — a fresh init succeeds
    // even at cap = 1 because the slow request never reserved
    // a permit.
    let fresh = router
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        fresh.status(),
        StatusCode::OK,
        "cap=1 mount must still admit a real init after a slow-body attacker times out — \
         admission must NOT have been reserved before the body finished",
    );
}

/// Body that emits `Poll::Pending` forever AND fires a
/// [`tokio::sync::Notify`] on its first poll. Used by
/// [`pending_body_gate_bounds_concurrent_buffering`] as a
/// deterministic barrier: once the middleware's
/// `axum::body::to_bytes` polls this body for the first
/// frame, we know it has already acquired the pending
/// permit — no scheduler guessing.
struct SignalingPendingBody {
    notify: std::sync::Arc<tokio::sync::Notify>,
    polled: bool,
}

impl futures_util::Stream for SignalingPendingBody {
    type Item = Result<axum::body::Bytes, std::io::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if !self.polled {
            self.polled = true;
            self.notify.notify_one();
        }
        std::task::Poll::Pending
    }
}

/// Round-6 F1 / round-7 F2: caps concurrent buffering so
/// worst-case memory is bounded to
/// `PENDING_BODY_GATE * MAX_REQUEST_BODY_BYTES`. The test
/// wires a mount at `pending_body_gate = 1`, ties up that
/// permit with a [`SignalingPendingBody`], and only then
/// fires the overflow request — no `yield_now` scheduler
/// assumptions (round-7 F2 rewrite: `yield_now` gave no
/// guarantee that the spawned task had grabbed the permit).
#[tokio::test(flavor = "current_thread")]
async fn pending_body_gate_bounds_concurrent_buffering() {
    use std::sync::Arc;

    use oxidhome_core::api::mcp::mount_routes_with_all_limits;
    use tokio::sync::Notify;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    // Deadline long enough for the overflow POST to slip in
    // while the holder is still parked on its body; pending
    // gate = 1 so the overflow is forced to compete for it.
    let router =
        mount_routes_with_all_limits(&engine, MAX_SESSIONS_FOR_TESTS, Duration::from_secs(5), 1);

    let notify = Arc::new(Notify::new());
    let notify_for_body = notify.clone();

    // Fire the pending-permit-holding request but DON'T
    // await it — its body never emits a frame, so the
    // middleware sits inside `to_bytes` holding the permit
    // until the deadline fires or the task is aborted.
    let hold = tokio::spawn({
        let router = router.clone();
        let bearer = bearer.clone();
        async move {
            router
                .oneshot(
                    base_request("POST", &bearer)
                        .body(Body::from_stream(SignalingPendingBody {
                            notify: notify_for_body,
                            polled: false,
                        }))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    });

    // Deterministic barrier: the body's first poll fires
    // the notifier, and the middleware has by then acquired
    // the semaphore permit. Any pending permit read from
    // this point is guaranteed to see cap = 0.
    notify.notified().await;

    // Overflow POST — same mount, real body. Pending gate
    // is exhausted, so this MUST reject at the gate.
    let overflow = router
        .clone()
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        overflow.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "pending-body gate at cap must reply 503 without allocating a buffer",
    );

    // Cancel the holder so the test doesn't leak the join
    // handle waiting for its body deadline.
    hold.abort();
}

/// A safe default for tests that don't want to exhaust the
/// live-session cap — well above what any single test asks
/// for, but a real number so no accidental unbounded behaviour
/// slips in.
const MAX_SESSIONS_FOR_TESTS: usize = 16;

/// Round-6 F2: bodies larger than
/// [`api::mcp::MAX_REQUEST_BODY_BYTES`] MUST return `413
/// Payload Too Large` — not `400`, which misclassifies the
/// failure as malformed input. Pulls the constant from the
/// module so this test tracks a config change (round-7 F1
/// tightened it from 4 MiB to 1 MiB).
#[tokio::test(flavor = "current_thread")]
async fn oversized_body_returns_413() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    // Smallest payload that exceeds the middleware cap.
    let oversized = vec![b'x'; oxidhome_core::api::mcp::MAX_REQUEST_BODY_BYTES + 1];
    let response = router
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "over-cap body must be 413 Payload Too Large, not 400 (round-6 F2)",
    );
}

/// SDK errors on non-request payloads MUST NOT be normalized to
/// 202 — the pre-switch review flagged malformed JSON /
/// unknown-session / wrong-Content-Type as silently returning
/// 202. This test walks two of those (malformed JSON, unknown
/// session) and confirms each surfaces as an error status.
#[tokio::test(flavor = "current_thread")]
async fn sdk_errors_on_non_requests_are_preserved() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);

    // Malformed JSON body.
    let malformed = router
        .clone()
        .oneshot(
            base_request("POST", &bearer)
                .body(Body::from("{this-is-not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        malformed.status().is_client_error() || malformed.status().is_server_error(),
        "malformed JSON must surface as a real error, not 202; got {}",
        malformed.status(),
    );
    assert_ne!(malformed.status(), StatusCode::ACCEPTED);

    // Notification bound to a session id that was never
    // minted — the SDK should reject rather than accept it.
    let unknown_session = router
        .oneshot(
            base_request("POST", &bearer)
                .header("mcp-session-id", "does-not-exist")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        unknown_session.status().is_client_error(),
        "unknown session id on a notification must surface as a 4xx error, not 202; got {}",
        unknown_session.status(),
    );
    assert_ne!(unknown_session.status(), StatusCode::ACCEPTED);
}

/// 14.7b: per-token rate limit. Two initialize calls against
/// a capacity-1 mount: the first succeeds, the second lands as
/// `429 Too Many Requests` with a `Retry-After` header. Refill
/// is disabled (rate=0) so the second call can't win a race.
#[tokio::test(flavor = "current_thread")]
async fn rate_limit_exceeded_returns_429() {
    use oxidhome_core::api::mcp::mount_routes_with_rate_limiter;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = mount_routes_with_rate_limiter(&engine, 1, 0.0);

    let post_init = || {
        router.clone().oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    // First request drains the single token.
    let first = post_init().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK, "first request must succeed");

    // Second request has no tokens left.
    let second = post_init().await.unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "over-limit request must reply 429",
    );
    let retry_after = second
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After header on 429")
        .to_str()
        .unwrap();
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "Retry-After must be a positive integer seconds value; got `{retry_after}`",
    );
}

/// 14.7b: rate limit is per-bearer, not global. A second
/// bearer past the first one's exhaustion still gets served —
/// round-2 P1 on PR #140 rekeys the limiter on a SHA-256
/// fingerprint of the presented bearer (so it can run OUTSIDE
/// `require_token` and skip the audit path on reject); this
/// test proves independence across bearers is preserved.
#[tokio::test(flavor = "current_thread")]
async fn rate_limit_is_per_token_not_global() {
    use oxidhome_core::api::mcp::mount_routes_with_rate_limiter;

    let engine = Engine::new().expect("engine");
    let bearer_a = engine
        .auth_tokens()
        .create("token-a", b"[\"*\"]")
        .expect("mint bearer a")
        .plaintext;
    let bearer_b = engine
        .auth_tokens()
        .create("token-b", b"[\"*\"]")
        .expect("mint bearer b")
        .plaintext;
    let router = mount_routes_with_rate_limiter(&engine, 1, 0.0);

    let init_with = |bearer: String| {
        router.clone().oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    // token-a drains its bucket then hits 429.
    assert_eq!(
        init_with(bearer_a.clone()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        init_with(bearer_a).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS,
    );

    // token-b's bucket is untouched — still gets served.
    assert_eq!(
        init_with(bearer_b).await.unwrap().status(),
        StatusCode::OK,
        "second token must not inherit the first's rate-limit state",
    );
}

/// Round-2 P1 on PR #140: a rate-limited request must NOT
/// reach the audit path. Pre-fix, the rate limiter sat AFTER
/// `require_token`, so every 429 still cost three `SQLite`
/// writes (`last_used_ms` + audit intent + audit finalize). The
/// fix moved the limiter OUTSIDE the auth layer so a rejected
/// request costs nothing durable. This test proves it: drain
/// the bucket with one accepted request, fire N more 429s,
/// and assert the audit ledger only sees the accepted call
/// (path `mcp.session.init` or similar — one row, not N+1).
#[tokio::test(flavor = "multi_thread")]
async fn rate_limited_requests_bypass_the_audit_ledger() {
    use oxidhome_core::api::mcp::mount_routes_with_rate_limiter;
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = mount_routes_with_rate_limiter(&engine, 1, 0.0);

    let post_init = || {
        router.clone().oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    let baseline = {
        let audit = engine.audit_log();
        tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
            .await
            .expect("audit query join")
            .expect("audit query")
            .len()
    };

    // First request succeeds and audits.
    assert_eq!(post_init().await.unwrap().status(), StatusCode::OK);
    // Fire five 429s.
    for _ in 0..5 {
        assert_eq!(
            post_init().await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let after = {
        let audit = engine.audit_log();
        tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
            .await
            .expect("audit query join")
            .expect("audit query")
    };
    let delta = after.len() - baseline;
    // Exactly one new audit row for the ONE accepted request.
    // A pre-fix limiter would have added 6 (or 12 with intent
    // + finalize). Any delta > 1 means at least one rate-
    // limited request slipped through to the audit path.
    assert!(
        delta <= 1,
        "expected at most 1 new audit row for the one accepted request; got {delta} \
         (rate-limited requests are leaking into the audit ledger)",
    );
}

/// Round-3 P1 on PR #140: rotating garbage bearers must NOT
/// bypass the rate limiter. Pre-fix, keying on the raw bearer
/// fingerprint gave every `Bearer garbage-N` its own fresh
/// capacity-60 bucket, so 429s never triggered and every
/// request cost one anonymous audit row. Post-fix, every
/// unrecognized bearer collapses to the shared
/// `UNAUTHENTICATED_KEY` bucket, so a rotating attacker
/// exhausts that ONE bucket quickly.
#[tokio::test(flavor = "current_thread")]
async fn rotating_garbage_bearers_share_one_bucket_end_to_end() {
    use oxidhome_core::api::mcp::mount_routes_with_rate_limiter;

    let engine = Engine::new().expect("engine");
    let router = mount_routes_with_rate_limiter(&engine, 2, 0.0);

    let post_with = |bearer: String| {
        router.clone().oneshot(
            base_request("POST", &bearer)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    // First two garbage bearers pass rate-limit (they hit 401
    // downstream, but the limiter admits them). The third
    // must hit 429 — the shared bucket is exhausted.
    assert_ne!(
        post_with("oxh_garbage-1".into()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first garbage bearer must reach auth (and 401 there)",
    );
    assert_ne!(
        post_with("oxh_garbage-2".into()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS,
    );
    assert_eq!(
        post_with("oxh_garbage-3".into()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS,
        "third distinct garbage bearer must hit the shared unauthenticated bucket's 429 \
         — pre-fix, each fresh bearer got its own capacity-2 bucket",
    );
}

/// Round-3 P1 on PR #140: the rate limiter must parse
/// Authorization identically to the auth layer. `Bearer tok`,
/// `Bearer  tok` (double space), and `bearer tok` (lowercase
/// scheme) all resolve to the same token per RFC 6750 § 2.1
/// and `crate::api::auth::extract_bearer`. They must therefore
/// hit the SAME rate-limit bucket, not distinct ones a caller
/// could rotate through to reset their limit.
#[tokio::test(flavor = "current_thread")]
async fn equivalent_authorization_headers_share_one_bucket() {
    use oxidhome_core::api::mcp::mount_routes_with_rate_limiter;

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = mount_routes_with_rate_limiter(&engine, 1, 0.0);

    let post_with_header = |auth_value: String| {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
                .header(header::AUTHORIZATION, auth_value)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
    };

    // Canonical shape — first request drains the bucket.
    assert_eq!(
        post_with_header(format!("Bearer {bearer}"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
    );
    // Double space, lowercase scheme — all authenticate as
    // the same token, so all should hit 429.
    for variant in [
        format!("Bearer  {bearer}"),
        format!("bearer {bearer}"),
        format!("BEARER {bearer}"),
    ] {
        assert_eq!(
            post_with_header(variant.clone()).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "variant `{variant}` must hit the SAME bucket as `Bearer <token>`; \
             pre-fix, distinct headers got distinct buckets",
        );
    }
}
