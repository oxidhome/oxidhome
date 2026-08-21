//! Phase 14.1 — MCP handshake end-to-end test.
//!
//! Drives [`api::build_router`] via [`tower::ServiceExt::oneshot`]
//! (no TCP bind) to prove the MCP mount is wired correctly:
//!
//! 1. `POST /api/v1/mcp` without an `Accept: text/event-stream`
//!    header returns `406 Not Acceptable` (SDK contract).
//! 2. A well-formed `initialize` JSON-RPC call returns
//!    `200 OK` + `Content-Type: text/event-stream` + a
//!    `mcp-session-id` header.
//! 3. The first SSE `data:` frame carries an
//!    [`InitializeResult`](rust_mcp_sdk::schema::InitializeResult)
//!    whose `serverInfo`, declared capabilities, and protocol
//!    version match what [`api::mcp::server::initialize_result`]
//!    emits — a regression flag on any silent capability shrink.
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

/// Round-1 regression (PR #119 F3): the deferred SSE + messages
/// endpoints are NOT mounted. A pre-fix build merged
/// `rust-mcp-axum::mcp_routes(...)` wholesale, which unmounted
/// GET `/api/v1/mcp/sse` (persistent session, unauthenticated)
/// and POST `/api/v1/mcp/messages` (broken URL — advertised
/// path didn't match the nesting prefix). This test proves
/// both surfaces respond as if they don't exist. 14.5 will
/// re-add them under the same bearer + scope guard as the
/// streamable route.
#[tokio::test(flavor = "current_thread")]
async fn deferred_sse_and_messages_endpoints_are_not_mounted() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let sse = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/mcp/sse")
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        sse.status(),
        StatusCode::OK,
        "SSE endpoint must not be reachable in the streamable-only 14.1 mount",
    );

    let messages = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/mcp/messages?sessionId=whatever")
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        messages.status(),
        StatusCode::ACCEPTED,
        "SSE `/messages` endpoint must not be reachable in the streamable-only 14.1 mount",
    );
}

/// SDK contract: streamable-HTTP POST that doesn't accept both
/// JSON and SSE returns 406.
#[tokio::test(flavor = "current_thread")]
async fn post_without_sse_accept_is_406() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, "application/json")
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_ACCEPTABLE,
        "streamable-HTTP requires both application/json and text/event-stream in Accept",
    );
}

/// Full handshake: initialize returns 200 + SSE stream + a
/// session id header. First data frame contains our
/// [`InitializeResult`] with the expected capability shape.
#[tokio::test(flavor = "current_thread")]
async fn initialize_returns_session_and_advertises_capabilities() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ctype = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("Content-Type")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        ctype.starts_with("text/event-stream"),
        "initialize returns an SSE stream even when the JSON path is enabled for followups; got {ctype}"
    );
    assert!(
        response.headers().get("mcp-session-id").is_some(),
        "server must mint a session id on initialize so the client can pin follow-up requests",
    );

    // The SSE body is a persistent stream — `to_bytes` would
    // block forever waiting for EOF. Peel frames one at a time
    // (with a per-frame timeout to bound a real hang) until we
    // see the first `data:` line, which carries the
    // JSON-RPC `initialize` result.
    let mut body = response.into_body();
    let mut buf = String::new();
    let mut initialize_json: Option<Value> = None;
    let deadline = Duration::from_secs(5);
    while initialize_json.is_none() {
        let frame = tokio::time::timeout(deadline, body.frame())
            .await
            .expect("timed out waiting for the first initialize SSE frame")
            .expect("stream ended before an initialize frame arrived")
            .expect("frame read error");
        let Ok(data) = frame.into_data() else {
            // trailers / non-data frames — SSE keep-alives arrive
            // as data frames so a non-data frame here is either a
            // trailer or noise; skip and keep reading.
            continue;
        };
        buf.push_str(&String::from_utf8_lossy(&data));
        // SSE frames end in a blank line (`\n\n`). Once we see
        // one, look for a `data:` prefix and parse.
        while let Some(event_end) = buf.find("\n\n") {
            let event = buf[..event_end].to_string();
            buf.drain(..=event_end + 1);
            for line in event.lines() {
                if let Some(payload) = line.strip_prefix("data:") {
                    let parsed: Value = serde_json::from_str(payload.trim()).unwrap_or_else(|e| {
                        panic!("initialize SSE data line is not JSON: {e}: {payload}");
                    });
                    initialize_json = Some(parsed);
                    break;
                }
            }
            if initialize_json.is_some() {
                break;
            }
        }
    }

    let initialize_json = initialize_json.expect("initialize result");
    assert_eq!(initialize_json["jsonrpc"], "2.0");
    assert_eq!(initialize_json["id"], 1);
    let result = &initialize_json["result"];
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "oxidhome");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    // Declared capability blocks: 14.1 advertises tools + resources
    // + prompts even though the lists are empty. Any regression
    // that silently drops one shows up here.
    let caps = &result["capabilities"];
    assert!(caps["tools"].is_object(), "capabilities.tools missing");
    assert!(
        caps["resources"].is_object(),
        "capabilities.resources missing"
    );
    assert!(caps["prompts"].is_object(), "capabilities.prompts missing");
}

/// Round-2 regression (PR #119 F1): the `notifications/initialized`
/// notification MUST return `202 Accepted` with no body per the
/// MCP HTTP spec. The pre-fix build handed it straight to
/// `McpHttpHandler::handle_streamable_http`, whose JSON-response
/// path waits for a stream reply and 500s with
/// "End of the transport stream reached" when the runtime
/// (correctly) produces no output for a notification.
///
/// This drives the full lifecycle:
///   1. POST `initialize` → pull the `mcp-session-id` header.
///   2. POST `notifications/initialized` bound to that session
///      → expect `202 Accepted` with an empty body.
#[tokio::test(flavor = "current_thread")]
async fn initialized_notification_returns_202() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let init = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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
    // We don't need to drain the SSE body — the session is
    // registered as soon as the handler responds; the stream
    // stays open for server-initiated messages we don't
    // exercise here.
    drop(init);

    let notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
    .to_string();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
                .header("mcp-session-id", &session_id)
                .body(Body::from(notification))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "MCP HTTP spec requires 202 for notifications; SDK's JSON path returns 500 without our normalization",
    );
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "notification response must have no body; got {:?}",
        String::from_utf8_lossy(&body),
    );
}

/// Round-2 regression (PR #119 F2): a request with an untrusted
/// `Origin` header MUST be rejected with `403 Forbidden` to
/// close the DNS-rebinding hole against a loopback bind.
#[tokio::test(flavor = "current_thread")]
async fn untrusted_origin_is_403() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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

/// Round-2 companion (PR #119 F2): a legitimate loopback
/// `Origin` (browser same-origin against a local hub) passes
/// through, so the DNS-rebind layer doesn't break the
/// intended use case.
#[tokio::test(flavor = "current_thread")]
async fn loopback_origin_passes() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_ENDPOINT)
                .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
                .header(header::ACCEPT, MCP_ACCEPT)
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
