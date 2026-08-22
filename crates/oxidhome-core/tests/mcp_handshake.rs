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

fn base_request(method: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(MCP_ENDPOINT)
        .header(header::HOST, MCP_HOST)
        .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
        .header(header::ACCEPT, MCP_ACCEPT)
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
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST")
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
    let router = build_router(engine);

    // 1. Handshake and grab the session id.
    let init = router
        .clone()
        .oneshot(
            base_request("POST")
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
            base_request("POST")
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
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST")
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
    let router = build_router(engine);

    let response = router
        .oneshot(
            base_request("POST")
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
    let router = build_router(engine);

    for suffix in ["/sse", "/messages", "/arbitrary", "/"] {
        let uri = format!("{MCP_ENDPOINT}{suffix}");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::HOST, MCP_HOST)
                    .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                    .header(header::ACCEPT, MCP_ACCEPT)
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
    let router = mount_routes_with_cap(&engine, 3);

    let post_init = || {
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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
    // only *new session* POSTs go through the gate.
    let get = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::ACCEPT, MCP_ACCEPT)
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
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::HOST, MCP_HOST)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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

/// SDK errors on non-request payloads MUST NOT be normalized to
/// 202 — the pre-switch review flagged malformed JSON /
/// unknown-session / wrong-Content-Type as silently returning
/// 202. This test walks two of those (malformed JSON, unknown
/// session) and confirms each surfaces as an error status.
#[tokio::test(flavor = "current_thread")]
async fn sdk_errors_on_non_requests_are_preserved() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    // Malformed JSON body.
    let malformed = router
        .clone()
        .oneshot(
            base_request("POST")
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
            base_request("POST")
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
