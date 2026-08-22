//! Phase 14.2a — MCP `resources/*` integration tests.
//!
//! Drives [`api::build_router`] via [`tower::ServiceExt::oneshot`]
//! (no TCP bind) through the full MCP request lifecycle:
//!
//! 1. `initialize` → session id.
//! 2. `notifications/initialized` → 202.
//! 3. `resources/list` → asserts the fixed-URI catalog exposes
//!    `oxidhome://devices` and `oxidhome://plugins` with our
//!    expected mime + description.
//! 4. `resources/templates/list` → asserts
//!    `oxidhome://devices/{device_id}` and
//!    `oxidhome://plugins/{plugin_id}` are advertised.
//! 5. `resources/read` on the two fixed URIs → asserts each
//!    returns a `text` content block that parses back into
//!    the expected JSON shape.
//! 6. `resources/read` on `oxidhome://plugins/does-not-exist`
//!    → asserts JSON-RPC error code `-32002` (resource not
//!    found).
//! 7. Audit log carries one `mcp.resource.<name>` row per
//!    read, regardless of outcome.
//!
//! The tests hit real handlers on a real router — no mocks —
//! so a change to the URI schema, the wire body, or the audit
//! shape shows up here.

#[path = "support.rs"]
mod _support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use oxidhome_core::state::AuditQuery;
use serde_json::{Value, json};
use tower::ServiceExt;

const MCP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_CONTENT_TYPE: &str = "application/json";
const MCP_HOST: &str = "localhost";

fn base_request(method: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(MCP_ENDPOINT)
        .header(header::HOST, MCP_HOST)
        .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
        .header(header::ACCEPT, MCP_ACCEPT)
}

fn initialize_body() -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "oxidhome-mcp-resources-test",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    })
    .to_string()
}

/// Peel the first `data:` line from an SSE response body and
/// return its JSON payload. Times each frame read so a real
/// hang bounds fast.
async fn read_first_sse_data(response: axum::response::Response) -> Value {
    let mut body = response.into_body();
    let mut buf = String::new();
    let deadline = Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout(deadline, body.frame())
            .await
            .expect("timed out waiting for SSE frame")
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
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() {
                    continue;
                }
                return serde_json::from_str(payload).unwrap_or_else(|e| {
                    panic!("SSE data line is not JSON: {e}: {payload}");
                });
            }
        }
    }
}

/// Complete the handshake and return the router + minted
/// session id. Every test starts here.
async fn handshake(router: axum::Router) -> (axum::Router, String) {
    let init = router
        .clone()
        .oneshot(
            base_request("POST")
                .body(Body::from(initialize_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init.status(), StatusCode::OK, "initialize failed");
    let session_id = init
        .headers()
        .get("mcp-session-id")
        .expect("session id on initialize response")
        .to_str()
        .unwrap()
        .to_string();
    let _ = read_first_sse_data(init).await;

    // Ship the `initialized` notification so the session
    // flips to Ready before we start hitting resource
    // methods.
    let notified = router
        .clone()
        .oneshot(
            base_request("POST")
                .header("mcp-session-id", &session_id)
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(notified.status(), StatusCode::ACCEPTED);

    (router, session_id)
}

/// Send a JSON-RPC method call on the given session and
/// return its parsed response body.
async fn call(router: &axum::Router, session_id: &str, method: &str, params: Value) -> Value {
    let response = router
        .clone()
        .oneshot(
            base_request("POST")
                .header("mcp-session-id", session_id)
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": rand_id(),
                        "method": method,
                        "params": params,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "MCP call {method} failed"
    );
    read_first_sse_data(response).await
}

fn rand_id() -> u64 {
    // Any stable-per-call id is fine for oneshot tests; we
    // don't correlate responses.
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(100);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// `resources/list` advertises the fixed-URI catalog.
#[tokio::test(flavor = "current_thread")]
async fn list_resources_advertises_devices_and_plugins() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    let response = call(&router, &session, "resources/list", json!({})).await;
    let resources = response["result"]["resources"]
        .as_array()
        .expect("resources array");
    let uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().expect("uri string"))
        .collect();
    assert!(
        uris.contains(&"oxidhome://devices"),
        "resources/list missing oxidhome://devices; got {uris:?}",
    );
    assert!(
        uris.contains(&"oxidhome://plugins"),
        "resources/list missing oxidhome://plugins; got {uris:?}",
    );

    let devices = resources
        .iter()
        .find(|r| r["uri"] == "oxidhome://devices")
        .unwrap();
    assert_eq!(devices["mimeType"], "application/json");
    assert!(
        devices["description"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

/// `resources/templates/list` advertises the parametric
/// families for per-device and per-plugin drill-down.
#[tokio::test(flavor = "current_thread")]
async fn list_resource_templates_advertises_detail_shapes() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    let response = call(&router, &session, "resources/templates/list", json!({})).await;
    let templates = response["result"]["resourceTemplates"]
        .as_array()
        .expect("resourceTemplates array");
    let uris: Vec<&str> = templates
        .iter()
        .map(|t| t["uriTemplate"].as_str().expect("uriTemplate string"))
        .collect();
    assert!(
        uris.contains(&"oxidhome://devices/{device_id}"),
        "missing device detail template; got {uris:?}",
    );
    assert!(
        uris.contains(&"oxidhome://plugins/{plugin_id}"),
        "missing plugin detail template; got {uris:?}",
    );
}

/// Reading `oxidhome://devices` on a fresh engine returns an
/// empty JSON list under the expected mime type.
#[tokio::test(flavor = "current_thread")]
async fn read_devices_returns_json_list_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    let response = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;
    let contents = response["result"]["contents"]
        .as_array()
        .expect("contents array");
    assert_eq!(contents.len(), 1, "expected exactly one content block");
    let block = &contents[0];
    assert_eq!(block["uri"], "oxidhome://devices");
    assert_eq!(block["mimeType"], "application/json");
    let body: Value = serde_json::from_str(block["text"].as_str().expect("text payload"))
        .expect("MCP resource body must be JSON");
    assert!(
        body["devices"].as_array().is_some_and(Vec::is_empty),
        "fresh engine must return an empty devices list; got {body}",
    );
}

/// Reading `oxidhome://plugins` on a fresh engine returns an
/// empty JSON list.
#[tokio::test(flavor = "current_thread")]
async fn read_plugins_returns_json_list_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    let response = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;
    let body: Value = serde_json::from_str(
        response["result"]["contents"][0]["text"]
            .as_str()
            .expect("text payload"),
    )
    .expect("MCP resource body must be JSON");
    assert!(
        body["plugins"].as_array().is_some_and(Vec::is_empty),
        "fresh engine must return an empty plugins list; got {body}",
    );
}

/// Unknown URIs surface as JSON-RPC `-32002` (resource not
/// found). `rmcp` maps [`ErrorData::resource_not_found`] to
/// that code, which is the MCP spec's canonical
/// `resource-not-found` value.
#[tokio::test(flavor = "current_thread")]
async fn unknown_uri_returns_resource_not_found() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    let response = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins/definitely-not-a-plugin"}),
    )
    .await;
    let error = &response["error"];
    assert_eq!(error["code"], -32002, "MCP resource-not-found code");
    assert!(
        error["message"].as_str().is_some_and(|m| !m.is_empty()),
        "resource-not-found error should carry a human message; got {error}",
    );
}

/// Every resource read (success + failure) records one audit
/// row with `path = "mcp.resource.<family>"`. This test
/// walks devices → plugins → unknown and asserts three
/// distinct audit rows landed with the expected shape.
#[tokio::test(flavor = "current_thread")]
async fn resource_reads_land_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let audit = engine.audit_log();
    let router = build_router(engine);
    let (router, session) = handshake(router).await;

    // Reads:
    let _ = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;
    let _ = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;
    let _ = call(
        &router,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins/ghost"}),
    )
    .await;

    // Query the ledger. `path` LIKE-scan not exposed; grab
    // recent rows and filter here.
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
        .await
        .expect("audit query join")
        .expect("audit query");

    let mcp_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.path.starts_with("mcp.resource."))
        .collect();
    assert!(
        mcp_rows.len() >= 3,
        "expected ≥3 audit rows for the three resource reads; got {} — {:?}",
        mcp_rows.len(),
        mcp_rows
            .iter()
            .map(|r| (&r.path, r.status))
            .collect::<Vec<_>>(),
    );
    // The rows must include one success for devices, one
    // for plugins, and one 404 for the ghost id.
    let paths_statuses: Vec<(&str, u16)> = mcp_rows
        .iter()
        .map(|r| (r.path.as_str(), r.status))
        .collect();
    assert!(
        paths_statuses.contains(&("mcp.resource.devices", 200)),
        "missing successful devices row; got {paths_statuses:?}",
    );
    assert!(
        paths_statuses.contains(&("mcp.resource.plugins", 200)),
        "missing successful plugins row; got {paths_statuses:?}",
    );
    assert!(
        paths_statuses.contains(&("mcp.resource.plugins.detail", 404)),
        "missing 404 row for ghost plugin; got {paths_statuses:?}",
    );
    // Every row records `actor_kind = "mcp"` so a forensic
    // sweep can filter MCP reads distinctly from REST /
    // Connect requests.
    for row in &mcp_rows {
        assert_eq!(
            row.actor_kind, "mcp",
            "audit rows must stamp actor_kind=mcp"
        );
        assert_eq!(row.method, "MCP", "audit rows must stamp method=MCP");
    }
}
