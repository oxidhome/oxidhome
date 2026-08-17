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
