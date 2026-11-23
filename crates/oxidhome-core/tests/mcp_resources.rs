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

fn base_request(method: &str, bearer: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(MCP_ENDPOINT)
        .header(header::HOST, MCP_HOST)
        .header(header::CONTENT_TYPE, MCP_CONTENT_TYPE)
        .header(header::ACCEPT, MCP_ACCEPT)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
}

/// Mints a wildcard-scope test bearer — satisfies every
/// per-resource scope check (round-2 F1). Tests that need
/// to exercise scope-denial paths call
/// [`mint_bearer_with_scopes`] instead.
fn mint_bearer(engine: &Engine) -> String {
    mint_bearer_with_scopes(engine, "wildcard", &["*"])
}

/// Mints a bearer with a specific scope list. Scopes are
/// stored as a JSON array on the token record, so we render
/// them here rather than in every caller.
fn mint_bearer_with_scopes(engine: &Engine, id: &str, scopes: &[&str]) -> String {
    let scope_json = serde_json::to_vec(scopes).expect("scopes serialize");
    engine
        .auth_tokens()
        .create(id, &scope_json)
        .expect("mint bearer")
        .plaintext
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
async fn handshake(router: axum::Router, bearer: &str) -> (axum::Router, String) {
    let init = router
        .clone()
        .oneshot(
            base_request("POST", bearer)
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
            base_request("POST", bearer)
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
async fn call(
    router: &axum::Router,
    bearer: &str,
    session_id: &str,
    method: &str,
    params: Value,
) -> Value {
    let response = router
        .clone()
        .oneshot(
            base_request("POST", bearer)
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
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "resources/list", json!({})).await;
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

    // 14.2b adds events + logs to the same catalog.
    assert!(
        uris.contains(&"oxidhome://events"),
        "resources/list missing oxidhome://events (14.2b); got {uris:?}",
    );
    assert!(
        uris.contains(&"oxidhome://logs"),
        "resources/list missing oxidhome://logs (14.2b); got {uris:?}",
    );

    // 14.2c adds status.
    assert!(
        uris.contains(&"oxidhome://status"),
        "resources/list missing oxidhome://status (14.2c); got {uris:?}",
    );
    let config = resources
        .iter()
        .find(|r| r["uri"] == "oxidhome://config")
        .unwrap_or_else(|| panic!("resources/list missing oxidhome://config; got {uris:?}"));
    assert_eq!(config["mimeType"], "application/json");
}

/// 14.2b — `oxidhome://events` on a fresh engine returns an
/// empty JSON list under the expected mime type. Confirms the
/// resource is dispatched (scope + audit paths run) and the
/// wire body matches the REST `GET /api/v1/events` shape.
#[tokio::test(flavor = "current_thread")]
async fn read_events_returns_empty_list_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://events"}),
    )
    .await;
    let body: Value = serde_json::from_str(
        response["result"]["contents"][0]["text"]
            .as_str()
            .expect("text payload"),
    )
    .expect("events resource body must be JSON");
    assert!(
        body["events"].as_array().is_some_and(Vec::is_empty),
        "fresh engine must return an empty events list; got {body}",
    );
}

/// 14.2b — same shape for logs.
#[tokio::test(flavor = "current_thread")]
async fn read_logs_returns_empty_list_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://logs"}),
    )
    .await;
    let body: Value = serde_json::from_str(
        response["result"]["contents"][0]["text"]
            .as_str()
            .expect("text payload"),
    )
    .expect("logs resource body must be JSON");
    assert!(
        body["logs"].as_array().is_some_and(Vec::is_empty),
        "fresh engine must return an empty logs list; got {body}",
    );
}

/// 14.2b — `oxidhome://events` requires `events:read`; a
/// bearer with a wildcard-adjacent-but-wrong scope
/// (`devices:list`) is refused. Mirrors the REST
/// `GET /api/v1/events` gate.
#[tokio::test(flavor = "current_thread")]
async fn events_resource_requires_events_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://events"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy events:read; got {response}",
    );
}

/// 14.2b — companion for logs.
#[tokio::test(flavor = "current_thread")]
async fn logs_resource_requires_logs_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "events-only", &["events:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://logs"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "events:read must not satisfy logs:read; got {response}",
    );
}

/// 14.2b — a bogus `level` on the logs resource surfaces as
/// `INVALID_PARAMS` (JSON-RPC `-32602`) and names the bad
/// value so the client can correct it. Round-1 F4 on PR #121:
/// pre-fix, this returned `-32002 resource-not-found`, which
/// is the wrong error class for malformed input.
#[tokio::test(flavor = "current_thread")]
async fn logs_resource_rejects_unknown_level() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://logs?level=Verbose"}),
    )
    .await;
    let error = &response["error"];
    assert_eq!(
        error["code"], -32602,
        "bad level must surface as INVALID_PARAMS, not NotFound or a filtered success; got {response}",
    );
    assert!(
        error["message"]
            .as_str()
            .expect("error message")
            .contains("Verbose"),
        "error must name the bad value so the client can correct it; got {error}",
    );
}

/// Round-1 F2 on PR #121: any query key outside the family's
/// documented set (e.g. `min_level` on logs or `since_ms` on
/// events, both old REST-style names) is rejected as
/// `INVALID_PARAMS`. Silently ignoring unknowns is what let a
/// documented request like `?level=Error&device=front-door`
/// return unfiltered rows before the fix (the impl only knew
/// `min_level` + `device_id`).
#[tokio::test(flavor = "current_thread")]
async fn logs_resource_rejects_unknown_filter_key() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        // `min_level` is the pre-fix REST-style name; the
        // documented MCP name is `level`. Refusing this
        // catches clients still on the old contract.
        json!({"uri": "oxidhome://logs?min_level=Info"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "unknown filter key must surface as INVALID_PARAMS; got {response}",
    );
}

// Note: R1 F1 (spawn_blocking) and R1 F3 (percent-decoding)
// used to have shallow integration tests here. Round-2 review
// on PR #121 correctly pointed out neither test would fail
// against the pre-fix implementation — a fresh in-memory store
// returns zero rows whether the value is decoded or not, and
// eight fast in-memory queries complete quickly whether the
// SQLite call runs on the worker or the blocking pool. The
// meaningful coverage lives with the parsers themselves:
// `parse_query` percent-decoding is unit-tested inside
// `resources.rs`, and `parse_duration_ms` UTF-8-safety is
// unit-tested there too. Round-1 F1 remains enforced by the
// code review of the events_read/logs_read call sites (they
// visibly call `tokio::task::spawn_blocking`).

/// Round-1 F4 on PR #121: malformed typed filters (bad
/// `since`, bad `limit`, bad `after_id`) all surface as
/// `INVALID_PARAMS`, not silently defaulted-away. Covers all
/// three parse points in one test — one JSON-RPC call each,
/// checked for the `-32602` code.
#[tokio::test(flavor = "current_thread")]
async fn events_resource_rejects_malformed_typed_filters() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for uri in [
        "oxidhome://events?since=nope",
        "oxidhome://events?since=99z",
        "oxidhome://events?limit=oops",
        "oxidhome://events?after_id=-1",
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "resources/read",
            json!({"uri": uri}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "malformed typed filter in {uri} must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// `resources/templates/list` advertises the parametric
/// families for per-device and per-plugin drill-down.
#[tokio::test(flavor = "current_thread")]
async fn list_resource_templates_advertises_detail_shapes() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/templates/list",
        json!({}),
    )
    .await;
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
    // 14.2c: blobs template.
    assert!(
        uris.contains(&"oxidhome://blobs/{instance_id}/{name}"),
        "missing blob template (14.2c); got {uris:?}",
    );
}

/// Reading `oxidhome://devices` on a fresh engine returns an
/// empty JSON list under the expected mime type.
#[tokio::test(flavor = "current_thread")]
async fn read_devices_returns_json_list_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
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
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
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
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
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

/// Round-1 F1 on PR #120 regression: the MCP mount MUST NOT
/// serve requests without a bearer token. Pre-fix, anyone
/// reaching the listener could enumerate the resource catalog
/// (and by extension, every device / plugin id).
#[tokio::test(flavor = "current_thread")]
async fn missing_bearer_is_401() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);

    // Deliberately skip `mint_bearer` + skip the AUTHORIZATION
    // header — the mount MUST refuse before it hits the SDK.
    let response = router
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
        response.status(),
        StatusCode::UNAUTHORIZED,
        "MCP mount must require a bearer — no anonymous inventory access",
    );
}

/// Round-2 F1 on PR #120 regression: a valid token with an
/// empty scope list MUST NOT be able to read the devices or
/// plugins resources. Pre-fix, the handler only checked
/// authentication (any valid bearer) and ignored scopes.
#[tokio::test(flavor = "current_thread")]
async fn empty_scope_bearer_is_denied_on_resource_read() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "no-scopes", &[]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;

    let error = &response["error"];
    assert_eq!(
        error["code"], -32001,
        "empty-scope bearer must be refused with the scope-denied code",
    );
}

/// Round-2 F1 on PR #120 regression: a token holding an
/// unrelated scope (`logs:read`) MUST NOT enumerate devices
/// or plugins.
#[tokio::test(flavor = "current_thread")]
async fn unrelated_scope_bearer_is_denied_on_resource_read() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "logs-only", &["logs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;

    let error = &response["error"];
    assert_eq!(
        error["code"], -32001,
        "logs:read alone must not satisfy plugins:list; got {response}",
    );
    // Response body must not name the required scope — the
    // audit row does, but leaking it here would let a
    // probing caller enumerate the scope map.
    assert!(
        !error["message"]
            .as_str()
            .expect("error message")
            .contains("plugins:list"),
        "scope-denied message must not name the required scope; got {}",
        error["message"],
    );
}

/// Round-2 F1 companion: the scope-deny audit row records
/// `decision = deny`, `status = 403`, AND the required scope
/// (so a forensic sweep can distinguish "logs-only token
/// probed devices resource" from other 403 paths).
#[tokio::test(flavor = "current_thread")]
async fn scope_denied_row_records_required_scope() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let audit = engine.audit_log();
    let bearer = mint_bearer_with_scopes(&engine, "logs-only", &["logs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;

    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
        .await
        .expect("audit query join")
        .expect("audit query");
    let denied = rows
        .iter()
        .find(|r| r.path == "mcp.resource.devices" && r.decision == "deny")
        .expect("scope-denied audit row on devices read");
    assert_eq!(denied.status, 403);
    assert_eq!(
        denied.required_scope.as_deref(),
        Some("devices:list"),
        "required_scope column must name the missing scope",
    );
}

/// Round-2 F1 companion: a bearer with only `devices:list`
/// can read `oxidhome://devices` but is denied
/// `oxidhome://plugins` (which requires `plugins:list`).
/// Proves scope enforcement is per-resource, not
/// all-or-nothing.
#[tokio::test(flavor = "current_thread")]
async fn per_resource_scopes_enforce_boundaries() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let devices = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;
    assert!(
        devices["result"]["contents"].is_array(),
        "devices:list bearer must read the devices resource; got {devices}",
    );

    let plugins = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;
    assert_eq!(
        plugins["error"]["code"], -32001,
        "devices:list bearer must be refused plugins:list; got {plugins}",
    );
}

/// Round-3 F1 on PR #120 regression: the device-detail
/// resource returns registration metadata (owner, name,
/// manufacturer, model, capabilities). It shares the
/// `devices:list` scope with the collection read — a bearer
/// that can list devices must be able to follow any listed id
/// into its detail resource, and a `devices:read` bearer
/// (reserved for the H9 device-state projection) must NOT
/// gain metadata access it wasn't granted.
#[tokio::test(flavor = "current_thread")]
async fn device_detail_uses_devices_list_scope_not_devices_read() {
    // Bearer with ONLY `devices:list` must reach the detail
    // URI (unknown device id => 404, but scope check must
    // succeed first). If the detail were still gated on
    // `devices:read`, this would return `-32001` instead.
    let engine = Engine::new().expect("engine");
    let list_bearer = mint_bearer_with_scopes(&engine, "devices-list-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &list_bearer).await;

    let response = call(
        &router,
        &list_bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices/dev-notexist"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32002,
        "devices:list bearer must reach device-detail dispatch (unknown id → -32002 \
         resource-not-found), NOT the scope-denied -32001; got {response}",
    );

    // Companion: a bearer with only `devices:read` must be
    // REFUSED metadata access — that scope is reserved for
    // the state projection, not registration data.
    let engine = Engine::new().expect("engine");
    let read_bearer = mint_bearer_with_scopes(&engine, "devices-read-only", &["devices:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &read_bearer).await;

    let response = call(
        &router,
        &read_bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices/dev-notexist"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:read alone must NOT satisfy the device-detail metadata scope; got {response}",
    );
}

/// Round-1 F3 on PR #120 regression: the plugin-detail
/// resource must include the manifest `content_digest` and
/// `installation_uuid` fields the template's description
/// promises. Pre-fix, the wire shape silently dropped both
/// even though `InstalledPlugin` carries them.
///
/// This test installs one plugin so the detail path finds an
/// entry, then reads the detail resource and asserts the
/// digest is a non-empty string.
#[tokio::test(flavor = "current_thread")]
async fn plugin_detail_includes_content_digest_and_installation_uuid() {
    // Stage + install the simulated-switch example so
    // `plugins/{plugin_id}` has an installed row to detail.
    // Same pattern as `manifest_loader.rs::installed_load_refused_*`.
    let wasm_src = _support::build_example("simulated-switch", "simulated_switch.wasm");
    let state_dir = _support::tempdir("mcp-plugin-detail-state");
    let source = _support::tempdir("mcp-plugin-detail-src");
    std::fs::copy(&wasm_src, source.path().join("simulated_switch.wasm"))
        .expect("copy wasm to source");
    std::fs::write(
        source.path().join("manifest.toml"),
        r#"manifest_version = 1
[plugin]
id = "example.mcp-plugin-detail"
name = "MCP plugin detail test"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "simulated_switch.wasm"
[capabilities]
declares_devices = ["switch"]
"#,
    )
    .expect("write source manifest");

    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let installed = engine
        .installed_plugins()
        .install(source.path())
        .expect("install plugin");
    let plugin_id = installed.plugin_id.to_string();
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": format!("oxidhome://plugins/{plugin_id}")}),
    )
    .await;
    let body: Value = serde_json::from_str(
        response["result"]["contents"][0]["text"]
            .as_str()
            .expect("text payload"),
    )
    .expect("plugin detail must be JSON");

    // `content_digest` is the SHA-256 of the installed
    // bytes; hex-encoded, so at least 32 hex chars.
    let digest = body["content_digest"]
        .as_str()
        .expect("content_digest missing");
    assert!(
        !digest.is_empty(),
        "content_digest must be non-empty for an installed plugin; got {body}",
    );

    let uuid = body["installation_uuid"]
        .as_str()
        .expect("installation_uuid missing");
    assert!(
        uuid.starts_with("inst-"),
        "installation_uuid must use the `inst-` prefix; got {uuid}",
    );
}

/// Every resource read (success + failure) records one audit
/// row with `path = "mcp.resource.<family>"`. This test
/// walks devices → plugins → unknown and asserts three
/// distinct audit rows landed with the expected shape.
#[tokio::test(flavor = "current_thread")]
async fn resource_reads_land_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let audit = engine.audit_log();
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    // Reads:
    let _ = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://devices"}),
    )
    .await;
    let _ = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;
    let _ = call(
        &router,
        &bearer,
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

// ── 14.2c: status + blobs ──────────────────────────────────────

/// `oxidhome://status` on a fresh in-memory engine returns a
/// well-shaped JSON body: crate version, `ok=true` from the
/// in-memory `SQLite` handle, and zeros for every count. Also
/// asserts the mime type + successful decode of the inline
/// `text` payload — the same pattern the other JSON resources
/// use.
#[tokio::test(flavor = "current_thread")]
async fn read_status_returns_json_snapshot_on_fresh_engine() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "status-only", &["status:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://status"}),
    )
    .await;
    let contents = &response["result"]["contents"][0];
    assert_eq!(
        contents["mimeType"], "application/json",
        "status must be JSON; got {response}",
    );
    let body: Value = serde_json::from_str(contents["text"].as_str().expect("text"))
        .expect("status body decodes as JSON");
    assert_eq!(
        body["version"],
        env!("CARGO_PKG_VERSION"),
        "status must carry the crate version",
    );
    assert_eq!(body["ok"], true, "fresh in-memory db must ping ok");
    assert_eq!(body["installed_plugins"], 0);
    assert_eq!(body["running_instances"], 0);
    assert_eq!(body["devices"], 0);
    // H3: event-mirror health is part of the status body.
    assert_eq!(body["event_log"]["degraded"], false);
    assert_eq!(body["event_log"]["unrecorded_total"], 0);
    // 14.2c round-4 F3: uptime is a required field on the
    // status body. On a fresh engine the value is small but
    // non-negative; we don't pin the exact number because
    // wall-clock between `Engine::new` and this assertion
    // varies with test-runner load.
    let uptime = body["uptime_ms"]
        .as_u64()
        .expect("uptime_ms must be a non-negative integer");
    assert!(
        uptime < 60_000,
        "fresh-engine uptime unexpectedly large: {uptime}"
    );
}

/// A token without `status:read` cannot read the status
/// resource. Same enforcement pattern as the other
/// per-resource scopes in 14.2a/b.
#[tokio::test(flavor = "current_thread")]
async fn status_resource_requires_status_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://status"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy status:read; got {response}",
    );
}

// ── oxidhome://config ─────────────────────────────────────────

/// Installs the process-wide daemon snapshot the config surfaces
/// serve. The state dir carries a credential-looking segment so the
/// tests can see M7 redaction applied. Idempotent: every caller
/// installs the same value, so test order doesn't matter.
fn install_test_daemon_config() {
    use oxidhome_core::api::mcp::{DaemonConfig, DaemonMode, install_daemon_config};
    use oxidhome_core::state::RetentionConfig;

    let addr = "127.0.0.1:7780".parse().expect("addr");
    let _ = install_daemon_config(
        DaemonConfig::resolve(
            DaemonMode::Http,
            std::path::Path::new("/srv/password=hunter2/state"),
            &RetentionConfig::default(),
        )
        .with_listener(addr, addr),
    );
}

fn assert_config_body(body: &Value) {
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["sdk_version"], oxidhome_core::OXIDHOME_SDK_VERSION);
    assert_eq!(
        body["wit_version"],
        oxidhome_core::runtime::contract::host_contract_version()
    );
    let daemon = &body["daemon"];
    assert_eq!(daemon["mode"], "http");
    assert_eq!(daemon["listen_addr"], "127.0.0.1:7780");
    assert_eq!(daemon["bind"]["value"], "127.0.0.1:7780");
    assert_eq!(daemon["bind"]["env"], "OXIDHOME_BIND");
    assert!(
        matches!(daemon["bind"]["source"].as_str(), Some("default" | "env")),
        "bind source must be default/env; got {}",
        daemon["bind"],
    );
    let state_dir = daemon["state_dir"]["value"].as_str().expect("state_dir");
    assert!(
        state_dir.starts_with("/srv/"),
        "path stays readable: {state_dir}"
    );
    assert!(
        !state_dir.contains("hunter2"),
        "credential-looking path segment must be redacted: {state_dir}",
    );
    assert_eq!(
        daemon["event_log_retention"]["max_rows"]["env"],
        "OXIDHOME_EVENT_LOG_MAX_ROWS"
    );
    assert_eq!(daemon["log_filter"]["env"], "RUST_LOG");
    assert_eq!(body["mcp"]["max_sessions"]["source"], "default");
    assert!(body["mcp"]["rate_limit"]["per_bearer_burst"]["value"].is_u64());
}

/// `oxidhome://config` returns the installed daemon snapshot with
/// sources, the build/contract versions and the MCP limits, redacted,
/// and records one `mcp.resource.config` audit row.
#[tokio::test(flavor = "current_thread")]
async fn read_config_returns_redacted_snapshot() {
    install_test_daemon_config();
    let engine = Engine::new().expect("engine");
    let audit = engine.audit_log();
    let bearer = mint_bearer_with_scopes(&engine, "status-only", &["status:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://config"}),
    )
    .await;
    let contents = &response["result"]["contents"][0];
    assert_eq!(contents["mimeType"], "application/json", "got {response}");
    let body: Value = serde_json::from_str(contents["text"].as_str().expect("text"))
        .expect("config body decodes as JSON");
    assert_config_body(&body);

    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
        .await
        .expect("audit query join")
        .expect("audit query");
    assert!(
        rows.iter()
            .any(|r| r.path == "mcp.resource.config" && r.status == 200),
        "missing mcp.resource.config audit row",
    );
}

/// `oxidhome://config` shares `status:read`; any other scope is denied.
#[tokio::test(flavor = "current_thread")]
async fn config_resource_requires_status_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "logs-only", &["logs:read", "plugins:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://config"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "config must require status:read; got {response}",
    );
}

/// REST parity: `GET /api/v1/config` serves the same redacted body
/// under the same scope.
#[tokio::test(flavor = "current_thread")]
async fn rest_config_matches_mcp_gate_and_body() {
    install_test_daemon_config();
    let engine = Engine::new().expect("engine");
    let allowed = mint_bearer_with_scopes(&engine, "status-only", &["status:read"]);
    let denied = mint_bearer_with_scopes(&engine, "logs-only", &["logs:read"]);
    let router = build_router(engine);

    let get = |bearer: &str| {
        Request::builder()
            .method("GET")
            .uri("/api/v1/config")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("request")
    };
    let response = router.clone().oneshot(get(&denied)).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router.oneshot(get(&allowed)).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("config body is JSON");
    assert_config_body(&body);
}

/// A malformed blobs URI (missing the `<name>` half) surfaces
/// as `-32002 resource-not-found` with a message that names
/// the expected shape — helps a client repair the URI without
/// having to grep the design doc.
#[tokio::test(flavor = "current_thread")]
async fn blobs_uri_without_name_returns_not_found() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://blobs/inst-abc"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32002,
        "path-shape error must surface as resource_not_found; got {response}",
    );
    let msg = response["error"]["message"]
        .as_str()
        .expect("error message");
    assert!(
        msg.contains("<instance_id>/<name>"),
        "error must describe the expected URI shape; got {msg}",
    );
}

/// A blobs URI for an instance that isn't running returns
/// resource-not-found with a message naming the instance id.
/// The scope check has already succeeded here (the token
/// carries `blobs:read`), so this is the not-found path — not
/// the deny path.
#[tokio::test(flavor = "current_thread")]
async fn blobs_uri_for_unknown_instance_returns_not_found() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "blobs-only", &["blobs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://blobs/inst-nope/snap.jpg"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32002,
        "unknown instance must surface as resource_not_found; got {response}",
    );
    let msg = response["error"]["message"]
        .as_str()
        .expect("error message");
    assert!(
        msg.contains("inst-nope"),
        "error must name the missing instance id; got {msg}",
    );
}

/// A token without `blobs:read` cannot reach the blobs
/// resource, even for an unknown instance — the scope check
/// runs before the not-found dispatch so a probing caller
/// can't enumerate live instances by the difference between
/// `-32001` and `-32002`.
#[tokio::test(flavor = "current_thread")]
async fn blobs_resource_requires_blobs_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://blobs/inst-abc/snap.jpg"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy blobs:read; got {response}",
    );
}

/// H4: a pruned `after_id` on `oxidhome://events` fails with the
/// `cursor_expired` error instead of silently returning the rows
/// after the gap.
#[tokio::test(flavor = "current_thread")]
async fn events_resource_reports_pruned_cursor() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload,
    };

    let engine = Engine::new().expect("engine");
    for n in 1..=4 {
        let event = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: "com.example.res".into(),
            origin_instance_id: "res-a".into(),
            row_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: "res.expire".into(),
                payload: String::new(),
            }),
        };
        engine
            .event_log()
            .record(n, &event, "res-a", "com.example.res")
            .expect("record");
    }
    engine.event_log().trim_older_than(4).expect("trim");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://events?after_id=2"}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32005, "{response}");
    assert_eq!(
        response["error"]["data"]["cursor_expired"],
        json!({"after_id": 2, "oldest_id": 4, "head_id": 4}),
    );
    let response = call(
        &router,
        &bearer,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://events?after_id=3"}),
    )
    .await;
    assert!(response["error"].is_null(), "{response}");
}

/// H6 slice 2: a camera instance's blobs are camera bytes. The
/// wildcard scope (and plain `blobs:read`) no longer reaches them; a
/// token with an explicit `camera` grant does, and the read leaves a
/// `warn` audit row.
#[tokio::test(flavor = "current_thread")]
async fn camera_blobs_need_the_camera_grant() {
    use oxidhome_core::api::sensitive_admin::grant_sensitive;
    use oxidhome_core::auth::SensitiveCategory;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;

    let engine = Engine::new().expect("engine");
    engine.devices().register(
        "u",
        "cam-inst".into(),
        DeviceInfo {
            local_id: "front".into(),
            name: "Front camera".into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: vec![CapabilitySpec::VideoStream],
            initial_state: Vec::new(),
            metadata: Vec::new(),
        },
    );
    let wildcard = mint_bearer(&engine);
    let reader = mint_bearer_with_scopes(&engine, "reader", &["blobs:read"]);
    let viewer = engine
        .auth_tokens()
        .create("viewer", br#"["blobs:read"]"#)
        .unwrap();
    grant_sensitive(
        &engine.auth_tokens(),
        &engine.audit_log(),
        &viewer.id,
        SensitiveCategory::Camera,
        &[],
    )
    .unwrap();
    let router = build_router(engine.clone());
    let uri = json!({"uri": "oxidhome://blobs/cam-inst/snap.jpg"});

    // An encoded spelling of the instance names the same blobs.
    let encoded = json!({"uri": "oxidhome://blobs/%63am-inst/snap.jpg"});
    for bearer in [&wildcard, &reader] {
        for uri in [&uri, &encoded] {
            let (router, session) = handshake(router.clone(), bearer).await;
            let response = call(&router, bearer, &session, "resources/read", uri.clone()).await;
            assert_eq!(response["error"]["code"], -32001, "{response}");
        }
    }
    // A non-camera instance's blobs are unchanged for the wildcard.
    let (r, session) = handshake(router.clone(), &wildcard).await;
    let response = call(
        &r,
        &wildcard,
        &session,
        "resources/read",
        json!({"uri": "oxidhome://blobs/lamp-inst/snap.jpg"}),
    )
    .await;
    assert_ne!(response["error"]["code"], -32001, "{response}");

    let (router, session) = handshake(router, &viewer.plaintext).await;
    let response = call(&router, &viewer.plaintext, &session, "resources/read", uri).await;
    assert_ne!(response["error"]["code"], -32001, "{response}");
    let warn = engine
        .audit_log()
        .query(
            &AuditQuery {
                level: Some("warn".into()),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert_eq!(warn.len(), 1, "{warn:?}");
    assert_eq!(warn[0].token_id, viewer.id);
    assert_eq!(warn[0].required_scope.as_deref(), Some("sensitive:camera"));
    // The resource row carries the same call id as the warn row.
    let call_id = warn[0].call_id.clone().expect("warn row call id");
    let joined = engine
        .audit_log()
        .query(
            &AuditQuery {
                call_id: Some(call_id),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert!(
        joined.iter().any(|e| e.path == "mcp.resource.blobs"),
        "{joined:?}"
    );
}
