//! Phase 14.3 — MCP `tools/*` integration tests.
//!
//! Drives [`api::build_router`] via [`tower::ServiceExt::oneshot`]
//! (no TCP bind) through `tools/list` and `tools/call`:
//!
//! 1. `initialize` → session id.
//! 2. `notifications/initialized` → 202.
//! 3. `tools/list` → asserts `device.send_command` is
//!    advertised with its input schema.
//! 4. `tools/call` on `device.send_command`:
//!    - a live plugin instance dispatch succeeds and returns
//!      the wire `command-result` shape.
//!    - an unknown device returns a tool-level error
//!      (`is_error: true`) with a message but not a JSON-RPC
//!      protocol error.
//!    - an unknown tool name returns `-32601` method-not-found.
//!    - a token missing `devices:command` gets `-32001`.
//! 5. Every call lands in the audit ledger under a
//!    `mcp.tool.<name>` path.

#[path = "support.rs"]
mod _support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use oxidhome_core::state::AuditQuery;
use oxidhome_core::{Engine, PluginInstance};
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

fn mint_bearer(engine: &Engine) -> String {
    mint_bearer_with_scopes(engine, "wildcard", &["*"])
}

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
                "name": "oxidhome-mcp-tools-test",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    })
    .to_string()
}

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
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(100);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// `tools/list` advertises `device.send_command` with its
/// input JSON Schema. Locks in the tool's advertised name,
/// title, and the top-level schema shape so an accidental
/// contract change surfaces here.
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_device_send_command() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert!(
        names.contains(&"device.send_command"),
        "tools/list missing device.send_command; got {names:?}",
    );

    let tool = tools
        .iter()
        .find(|t| t["name"] == "device.send_command")
        .unwrap();
    assert_eq!(tool["title"], "Send device command");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    let required = schema["required"].as_array().expect("required is an array");
    for field in ["device_id", "capability", "action"] {
        assert!(
            required.iter().any(|v| v == field),
            "input schema must require `{field}`; got {required:?}",
        );
    }
}

/// A `tools/call` on an unknown tool name returns
/// `-32601` method-not-found (rmcp's standard for absent
/// tools/methods).
#[tokio::test(flavor = "current_thread")]
async fn call_tool_unknown_name_returns_method_not_found() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "device.does_not_exist", "arguments": {}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32601,
        "unknown tool must surface as METHOD_NOT_FOUND; got {response}",
    );
}

/// A token without `devices:command` cannot invoke
/// `device.send_command` — mirrors the REST endpoint's
/// scope gate. `-32001` is our per-mount `SCOPE_DENIED_CODE`.
#[tokio::test(flavor = "current_thread")]
async fn device_send_command_requires_devices_command_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-list-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": "any",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy devices:command; got {response}",
    );
}

/// Malformed arguments (missing required field) surface as
/// `-32602 INVALID_PARAMS`.
#[tokio::test(flavor = "current_thread")]
async fn device_send_command_missing_field_returns_invalid_params() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "device.send_command", "arguments": {"device_id": "d1"}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "missing required arg must surface as INVALID_PARAMS; got {response}",
    );
}

/// An unknown `device_id` surfaces as a TOOL-LEVEL error
/// (`is_error: true` in the result) — not a JSON-RPC
/// protocol error. Matches the REST endpoint's shape (200
/// with a `CommandResult::Err` in the body).
#[tokio::test(flavor = "multi_thread")]
async fn device_send_command_unknown_device_returns_exec_error() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": "ghost",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "unknown device must be a tool-level error, not a protocol error; got {response}",
    );
    let content = result["content"].as_array().expect("content array");
    let text = content[0]["text"].as_str().expect("text content");
    assert!(
        text.contains("ghost"),
        "error message must name the missing device id; got {text}",
    );
}

/// End-to-end: boot a real `simulated-switch` instance,
/// dispatch a `toggle` via `tools/call`, assert the wire
/// `command-result` shape lands as `structuredContent` and
/// carries the expected `kind: "ok_with_state"` +
/// state map.
#[tokio::test(flavor = "multi_thread")]
async fn device_send_command_end_to_end_toggles_a_switch() {
    let _wasm = _support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = _support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);

    // Boot the switch via `Engine::start_instance` so the
    // supervisor pins `installation_uuid`, registers a device,
    // and the device→instance lookup path the tool relies on
    // is populated.
    let handle = engine
        .start_instance(switch_dir, "switch-mcp", None)
        .await
        .expect("start_instance");
    handle.wait_for_running().await.expect("running");

    let device_id = engine
        .devices()
        .list()
        .into_iter()
        .find(|d| d.owner_instance == "switch-mcp")
        .expect("switch registered a device")
        .id
        .clone();

    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": device_id.clone(),
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "toggle must succeed; got {response}",
    );
    let structured = &result["structuredContent"];
    assert_eq!(
        structured["kind"], "ok_with_state",
        "simulated-switch's toggle returns ok_with_state; got {structured}",
    );
    let state = structured["state"].as_object().expect("state is an object");
    // simulated-switch reports `state: bool` after toggle
    // (see the plugin's `published_state_change`).
    let state_kv = state.get("state").expect("state carries `state` key");
    assert_eq!(state_kv["t"], "Bool");
    assert!(
        matches!(state_kv["v"], Value::Bool(_)),
        "state.v must be a Bool; got {state_kv:?}",
    );

    // Round-2 F3 on PR #123: a plugin-reached
    // success stamps `execution_outcome = "success"` on
    // the audit row.
    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let toggle_row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.device.send_command" && r.status == 200)
        .expect("toggle audit row");
    assert_eq!(
        toggle_row.execution_outcome.as_deref(),
        Some("success"),
        "plugin-reached success must stamp execution_outcome=success (contract per audit_log.rs docs); got {:?}",
        toggle_row.execution_outcome,
    );
    assert!(
        toggle_row.domain_error.is_none(),
        "success has no domain_error; got {:?}",
        toggle_row.domain_error,
    );

    handle.stop().await.expect("stop");
    // Prove PluginInstance::load isn't accidentally
    // imported unused (compiler check).
    let _ = std::marker::PhantomData::<PluginInstance>;
    // CommandResult ditto.
    let _ = std::marker::PhantomData::<CommandResult>;
}

/// Every tool call — regardless of outcome — records an
/// audit row under `mcp.tool.<family>` with `actor_kind =
/// "mcp"`. Drives one success (unknown-device: audit path
/// = `mcp.tool.device.send_command`, status 200 because the
/// dispatch ran, decision "allow") and one scope-denied
/// call, and verifies both lands.
#[tokio::test(flavor = "multi_thread")]
async fn tool_calls_land_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let bearer_denied = mint_bearer_with_scopes(&engine, "devices-list-only", &["devices:list"]);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    // Fire an unknown-device call (exec-error → 200).
    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": "ghost",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;

    // Fire a scope-denied call from a different session (a
    // fresh bearer needs its own initialize handshake).
    let (router, session2) = handshake(router, &bearer_denied).await;
    let _ = call(
        &router,
        &bearer_denied,
        &session2,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": "ghost",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 256))
        .await
        .expect("audit query join")
        .expect("audit query");
    let tool_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.path.starts_with("mcp.tool."))
        .collect();
    assert!(
        tool_rows.len() >= 2,
        "expected ≥2 tool audit rows; got {} — {:?}",
        tool_rows.len(),
        tool_rows
            .iter()
            .map(|r| (&r.path, r.status, r.decision.as_str()))
            .collect::<Vec<_>>(),
    );
    let paths_statuses: Vec<(&str, u16, &str)> = tool_rows
        .iter()
        .map(|r| (r.path.as_str(), r.status, r.decision.as_str()))
        .collect();
    assert!(
        paths_statuses.contains(&("mcp.tool.device.send_command", 200, "allow")),
        "missing exec-run row; got {paths_statuses:?}",
    );
    assert!(
        paths_statuses.contains(&("mcp.tool.device.send_command", 403, "deny")),
        "missing scope-denied row; got {paths_statuses:?}",
    );
    for row in &tool_rows {
        assert_eq!(row.actor_kind, "mcp");
        assert_eq!(row.method, "MCP");
        // Round-1 F1 on PR #123: every finalize-path row has
        // `finalized_ms` set. Rows that took the two-phase
        // dispatch path also have `intent_ms < finalized_ms`
        // (monotonic host clock, ms-resolution — the write
        // path stamps two separate `now_unix_ms()` calls).
        if row.status == 200 {
            let finalized = row
                .finalized_ms
                .expect("dispatch rows must be finalized after intent");
            assert!(
                row.intent_ms <= finalized,
                "intent_ms ({}) must be ≤ finalized_ms ({}); intent should come first",
                row.intent_ms,
                finalized,
            );
        }
    }
}

/// Round-2 F3 on PR #123: audit `execution_outcome` matches
/// the ledger contract on
/// [`crate::state::audit_log::AuditEntry`]:
///
/// - `Some("success")` — plugin returned `Ok`/`OkWithState`.
/// - `Some("failed")` — plugin returned `CommandResult::Err`,
///   with `domain_error` naming the WIT kind.
/// - `None` — execution never reached the plugin (e.g.
///   unknown device: the tool body refused before
///   `execute_command`).
///
/// The unknown-device path never invokes the plugin, so
/// this test asserts `execution_outcome = None` +
/// `domain_error = None` on that path.
#[tokio::test(flavor = "multi_thread")]
async fn tool_audit_row_execution_outcome_null_when_plugin_not_reached() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({
            "name": "device.send_command",
            "arguments": {
                "device_id": "ghost-exec",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.device.send_command")
        .expect("tool row");
    assert_eq!(
        row.status, 200,
        "unknown-device still audits as 200 (tool body ran)"
    );
    assert_eq!(row.decision, "allow", "the tool ran");
    assert!(
        row.execution_outcome.is_none(),
        "unknown-device never reached the plugin — execution_outcome must be NULL; got {:?}",
        row.execution_outcome,
    );
    assert!(
        row.domain_error.is_none(),
        "unknown-device is not a plugin-classified error; got {:?}",
        row.domain_error,
    );
}
