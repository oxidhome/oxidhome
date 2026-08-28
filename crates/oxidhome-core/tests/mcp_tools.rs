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
    // 30 s covers the worst-case end-to-end plugin-supervised
    // boot on a busy CI host — several boot-a-real-plugin
    // tests (14.3e/f) run concurrently under cargo test, and
    // wasmtime instantiation can contend under parallel load
    // even when each individual test is quick in isolation.
    let deadline = Duration::from_secs(30);
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

/// Round-3 F1 on PR #123: the input schema declares
/// `additionalProperties: false`, so unknown top-level
/// fields (e.g. a made-up `dry_run: true` safety modifier)
/// must be rejected with `-32602 INVALID_PARAMS` — not
/// silently swallowed by serde while the tool still
/// actuates the device.
#[tokio::test(flavor = "current_thread")]
async fn device_send_command_rejects_unknown_top_level_field() {
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
                "device_id": "d1",
                "capability": "switch",
                "action": "toggle",
                // No such field on `DeviceSendCommandArgs`.
                "dry_run": true,
            }
        }),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "unknown top-level field must surface as INVALID_PARAMS; got {response}",
    );
}

/// Same round-3 F1 story for the nested `WireValue` shape —
/// a stray field inside `{t, v}` (or the outer key/value
/// wrapper) must fail deserialisation.
#[tokio::test(flavor = "current_thread")]
async fn device_send_command_rejects_unknown_value_field() {
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
                "device_id": "d1",
                "capability": "dimmer",
                "action": "set",
                "args": [
                    {
                        "key": "level",
                        "value": {
                            "t": "Int",
                            "v": 50,
                            // Not a field on WireValue.
                            "hint": "percent",
                        }
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "stray value field must be rejected; got {response}",
    );
}

/// Round-3 F2 on PR #123: the `initialize` instructions
/// promise that mutating tools carry an `oxidhome.audit`
/// note. `device.send_command` must attach `_meta` with
/// `intent_id` + audit `path` so clients can correlate the
/// response to the row it wrote.
#[tokio::test(flavor = "multi_thread")]
async fn device_send_command_response_carries_audit_meta() {
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
                "device_id": "ghost-meta",
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;
    let audit = &response["result"]["_meta"]["oxidhome.audit"];
    assert!(
        audit.is_object(),
        "response must carry an `oxidhome.audit` meta note; got {response}",
    );
    assert_eq!(
        audit["path"], "mcp.tool.device.send_command",
        "audit meta must include the ledger path; got {audit}",
    );
    let intent_id = audit["intent_id"]
        .as_u64()
        .expect("audit meta must include a numeric intent_id");
    assert!(intent_id > 0, "intent_id must be a real row id");
}

// ── 14.3b — logs.query ──────────────────────────────────────────

/// `tools/list` advertises `logs.query` with its input
/// schema. Locks in the tool's advertised name, title, and
/// the fact that `since` is optional (no `required` array).
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_logs_query() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "logs.query")
        .expect("logs.query in the catalogue");
    assert_eq!(tool["title"], "Query log history");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    // No required fields: an empty-arg call is valid.
    assert!(
        schema["required"].is_null() || schema["required"].as_array().is_none_or(Vec::is_empty),
        "logs.query must not require any fields; got {schema}",
    );
    // Level enum is present and complete.
    let level_enum = schema["properties"]["level"]["enum"]
        .as_array()
        .expect("level.enum array");
    for want in ["Trace", "Debug", "Info", "Warn", "Error"] {
        assert!(
            level_enum.iter().any(|v| v == want),
            "logs.query level enum must include `{want}`; got {level_enum:?}",
        );
    }
}

/// A token without `logs:read` cannot invoke `logs.query`.
/// Mirrors the resource-side scope check on
/// `oxidhome://logs`.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_requires_logs_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-list-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "logs.query", "arguments": {}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy logs:read; got {response}",
    );
}

/// Empty-arg `logs.query` on a fresh engine returns
/// `structuredContent = {"logs": []}` — proves the tool
/// dispatches, the wire body has the resource-side shape,
/// and the outcome maps to `structured` (not `error`).
#[tokio::test(flavor = "current_thread")]
async fn logs_query_empty_engine_returns_empty_list() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "logs.query", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "empty engine + empty filter must succeed; got {response}",
    );
    let structured = &result["structuredContent"];
    let logs = structured["logs"]
        .as_array()
        .expect("structuredContent.logs must be an array");
    assert!(logs.is_empty(), "fresh engine has no rows; got {logs:?}");
}

/// Malformed typed filters land as `-32602 INVALID_PARAMS` —
/// a bogus `since` value, unknown `level`, and unknown
/// top-level field are all rejected without touching the
/// store.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_rejects_malformed_filters() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("bad since", json!({"since": "nope"})),
        ("bad level", json!({"level": "Verbose"})),
        ("unknown field", json!({"since": "1h", "min_level": "Info"})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "logs.query", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// A `logs.query` call lands in the audit ledger as
/// `mcp.tool.logs.query` with `decision = "allow"`, no
/// `execution_outcome` (reads don't fill it), and the audit
/// row's finalize is complete (`finalized_ms >= intent_ms`).
#[tokio::test(flavor = "multi_thread")]
async fn logs_query_lands_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "logs.query", "arguments": {"level": "Info"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.logs.query")
        .expect("logs.query row");
    assert_eq!(row.status, 200);
    assert_eq!(row.decision, "allow");
    // Round-2 F3 on PR #124: read tools (no plugin reached)
    // leave `execution_outcome` NULL per the ledger
    // contract — `"success"` is reserved for plugin
    // Ok/OkWithState. `domain_error` stays None too.
    assert!(
        row.execution_outcome.is_none(),
        "read tools must leave execution_outcome NULL; got {:?}",
        row.execution_outcome,
    );
    assert!(row.domain_error.is_none());
    assert!(row.finalized_ms.is_some(), "finalize must have landed");
    assert!(row.intent_ms <= row.finalized_ms.unwrap());
}

/// Round-2 F1 + round-3 F1 on PR #124: every successful
/// tool response keeps `CallToolResult`'s text mirror
/// alongside `structuredContent`. Round-2 originally
/// dropped the mirror on read tools to save memory; round-3
/// restored it universally (with a tighter
/// `MAX_TOOL_BODY_BYTES`) because legacy MCP clients that
/// predate `structuredContent` still consume
/// `content[0].text`. This test proves the mirror is
/// present for the mutating path (`device.send_command`);
/// [`logs_query_response_keeps_text_mirror_for_legacy_clients`]
/// covers the read path.
#[tokio::test(flavor = "multi_thread")]
async fn device_send_command_success_keeps_text_mirror() {
    let _wasm = _support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = _support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);

    let handle = engine
        .start_instance(switch_dir, "switch-mirror", None)
        .await
        .expect("start_instance");
    handle.wait_for_running().await.expect("running");

    let device_id = engine
        .devices()
        .list()
        .into_iter()
        .find(|d| d.owner_instance == "switch-mirror")
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
                "device_id": device_id,
                "capability": "switch",
                "action": "toggle",
            }
        }),
    )
    .await;
    let result = &response["result"];
    let content = result["content"].as_array().expect("content array");
    assert!(
        !content.is_empty(),
        "plugin-reaching successes must keep the text mirror; got {response}",
    );
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).expect("text mirror is JSON");
    assert_eq!(parsed["kind"], "ok_with_state");

    handle.stop().await.expect("stop");
}

/// Round-3 F1 on PR #124: `logs.query` responses keep the
/// text mirror for legacy MCP clients that predate
/// `structuredContent`. The per-body cap
/// (`MAX_TOOL_BODY_BYTES` = 2.5 MiB) is sized so the
/// mirror + structured + framing still fit under the 8 MiB
/// transport ceiling. Round-2 F1's optimisation to skip
/// the mirror on read tools broke supported legacy clients
/// — restored here.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_response_keeps_text_mirror_for_legacy_clients() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "logs.query", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(result["isError"], true);
    let content = result["content"].as_array().expect("content array");
    assert!(
        !content.is_empty(),
        "legacy clients must receive `content[0].text` too; got {content:?}",
    );
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).expect("text mirror is JSON");
    assert!(
        parsed["logs"].is_array(),
        "text mirror must carry the same body as structuredContent; got {text}",
    );
    // And structuredContent still carries the parsed body
    // for modern clients.
    assert!(
        result["structuredContent"]["logs"].is_array(),
        "structuredContent must still carry the parsed body; got {response}",
    );
}

/// Round-2 F4 on PR #124: `logs.query` advertises
/// `read_only_hint = true`, `destructive_hint = false`,
/// `open_world_hint = false` — planner-style clients rely
/// on these hints to decide whether they can call a tool
/// speculatively.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_advertises_read_only_annotations() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tool = response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "logs.query")
        .expect("logs.query catalogued");
    let annotations = &tool["annotations"];
    assert_eq!(annotations["readOnlyHint"], true);
    assert_eq!(annotations["destructiveHint"], false);
    assert_eq!(annotations["openWorldHint"], false);
}

/// 14.3c: `events.history` is catalogued with a JSON Schema
/// that has no required fields, an `additionalProperties:
/// false` guard, and read-only annotations. Parallels
/// [`list_tools_advertises_logs_query`].
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_events_history() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "events.history")
        .expect("events.history in the catalogue");
    assert_eq!(tool["title"], "Query event history");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(
        schema["required"].is_null() || schema["required"].as_array().is_none_or(Vec::is_empty),
        "events.history must not require any fields; got {schema}",
    );
    // Cursor fields are exposed with a sane lower bound.
    assert_eq!(schema["properties"]["after_id"]["minimum"], 0);
    assert_eq!(schema["properties"]["before_id"]["minimum"], 0);
}

/// 14.3c: `events.history` advertises the read-only
/// annotation triplet. Parallels
/// [`logs_query_advertises_read_only_annotations`].
#[tokio::test(flavor = "current_thread")]
async fn events_history_advertises_read_only_annotations() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tool = response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "events.history")
        .expect("events.history catalogued");
    let annotations = &tool["annotations"];
    assert_eq!(annotations["readOnlyHint"], true);
    assert_eq!(annotations["destructiveHint"], false);
    assert_eq!(annotations["openWorldHint"], false);
}

/// 14.3c: a token without `events:read` cannot invoke
/// `events.history`. Parallels
/// [`logs_query_requires_logs_read_scope`].
#[tokio::test(flavor = "current_thread")]
async fn events_history_requires_events_read_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-list-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "events.history", "arguments": {}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "devices:list must not satisfy events:read; got {response}",
    );
}

/// 14.3c: empty-arg `events.history` on a fresh engine
/// returns `structuredContent = {"events": []}`. Proves
/// dispatch works and the wire body has the resource-side
/// shape.
#[tokio::test(flavor = "current_thread")]
async fn events_history_empty_engine_returns_empty_list() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "events.history", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "empty engine + empty filter must succeed; got {response}",
    );
    let structured = &result["structuredContent"];
    let events = structured["events"]
        .as_array()
        .expect("structuredContent.events must be an array");
    assert!(
        events.is_empty(),
        "fresh engine has no rows; got {events:?}",
    );
}

/// 14.3c: malformed typed filters land as `-32602
/// INVALID_PARAMS` — bogus `since`, non-integer `after_id`,
/// and unknown top-level fields are all rejected without
/// touching the store.
#[tokio::test(flavor = "current_thread")]
async fn events_history_rejects_malformed_filters() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("bad since", json!({"since": "nope"})),
        ("non-integer after_id", json!({"after_id": "abc"})),
        ("unknown field", json!({"topic": "switch", "topik": "typo"})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "events.history", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// 14.3c: `events.history` lands in the audit ledger as
/// `mcp.tool.events.history` with `decision = "allow"` and
/// `execution_outcome = NULL` (read tools never reach a
/// plugin). Parallels [`logs_query_lands_in_the_audit_log`].
#[tokio::test(flavor = "multi_thread")]
async fn events_history_lands_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "events.history", "arguments": {"topic_prefix": "automation."}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.events.history")
        .expect("events.history row");
    assert_eq!(row.status, 200);
    assert_eq!(row.decision, "allow");
    assert!(
        row.execution_outcome.is_none(),
        "read tools must leave execution_outcome NULL; got {:?}",
        row.execution_outcome,
    );
    assert!(row.domain_error.is_none());
    assert!(row.finalized_ms.is_some(), "finalize must have landed");
    assert!(row.intent_ms <= row.finalized_ms.unwrap());
}

/// Round-1 P2 on PR #130: cursor IDs deserialize as `u64` but
/// the store binds them as `SQLite` `INTEGER` (signed 64-bit);
/// anything above `i64::MAX` is clamped to `i64::MAX` by the
/// store, so e.g. `before_id: u64::MAX` would silently become
/// `id < i64::MAX` — a broadening. Enforce the schema's
/// `maximum: i64::MAX` at the tool boundary so over-cap
/// cursors land as `INVALID_PARAMS` instead.
#[tokio::test(flavor = "current_thread")]
async fn events_history_rejects_out_of_range_cursors() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let over_cap: u64 = (i64::MAX as u64) + 1;
    for (label, arguments) in [
        ("after_id over cap", json!({"after_id": over_cap})),
        ("before_id over cap", json!({"before_id": over_cap})),
        ("u64::MAX before_id", json!({"before_id": u64::MAX})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "events.history", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: cursor above i64::MAX must surface as INVALID_PARAMS; got {response}",
        );
    }

    // Boundary — exactly `i64::MAX` is accepted (the schema
    // says `maximum: i64::MAX`, inclusive).
    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "events.history", "arguments": {"before_id": i64::MAX as u64}}),
    )
    .await;
    assert_ne!(
        response["result"]["isError"], true,
        "i64::MAX cursor is the inclusive ceiling; must succeed. got {response}",
    );
}

/// 14.3c: `events.history` responses keep the text mirror
/// alongside `structuredContent` — same rule as `logs.query`:
/// legacy MCP clients that predate `structuredContent` still
/// consume `content[0].text`.
#[tokio::test(flavor = "current_thread")]
async fn events_history_response_keeps_text_mirror_for_legacy_clients() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "events.history", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(result["isError"], true);
    let content = result["content"].as_array().expect("content array");
    assert!(
        !content.is_empty(),
        "legacy clients must receive `content[0].text` too; got {content:?}",
    );
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).expect("text mirror is JSON");
    assert!(
        parsed["events"].is_array(),
        "text mirror must carry the same body as structuredContent; got {text}",
    );
    assert!(
        result["structuredContent"]["events"].is_array(),
        "structuredContent must still carry the parsed body; got {response}",
    );
}

// ── 14.3d — plugins.list + plugins.show ─────────────────────────

/// 14.3d: both plugin tools are catalogued with read-only
/// annotations and appropriate schemas — `plugins.list` takes
/// no arguments, `plugins.show` requires `plugin_id`.
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_plugins_list_and_show() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");

    let list = tools
        .iter()
        .find(|t| t["name"] == "plugins.list")
        .expect("plugins.list in the catalogue");
    assert_eq!(list["title"], "List plugins");
    assert_eq!(list["annotations"]["readOnlyHint"], true);
    assert_eq!(list["annotations"]["destructiveHint"], false);
    assert_eq!(list["annotations"]["openWorldHint"], false);
    assert_eq!(list["inputSchema"]["additionalProperties"], false);
    assert!(
        list["inputSchema"]["required"].is_null()
            || list["inputSchema"]["required"]
                .as_array()
                .is_none_or(Vec::is_empty),
        "plugins.list takes no arguments; got {list}",
    );

    let show = tools
        .iter()
        .find(|t| t["name"] == "plugins.show")
        .expect("plugins.show in the catalogue");
    assert_eq!(show["title"], "Show plugin detail");
    assert_eq!(show["annotations"]["readOnlyHint"], true);
    assert_eq!(show["annotations"]["destructiveHint"], false);
    assert_eq!(show["annotations"]["openWorldHint"], false);
    let required = show["inputSchema"]["required"]
        .as_array()
        .expect("plugins.show has required fields");
    assert!(
        required.iter().any(|v| v == "plugin_id"),
        "plugins.show must require plugin_id; got {required:?}",
    );
}

/// 14.3d: a token without `plugins:list` cannot invoke either
/// tool.
#[tokio::test(flavor = "current_thread")]
async fn plugins_tools_require_plugins_list_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "devices-only", &["devices:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for name in ["plugins.list", "plugins.show"] {
        let arguments = if name == "plugins.show" {
            json!({"plugin_id": "example.mcp-plugins-scope"})
        } else {
            json!({})
        };
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32001,
            "{name}: devices:list must not satisfy plugins:list; got {response}",
        );
    }
}

/// 14.3d: `plugins.list` on a fresh engine returns
/// `structuredContent = {"plugins": []}`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_list_empty_engine_returns_empty_list() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.list", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "fresh engine list must succeed; got {response}"
    );
    let plugins = result["structuredContent"]["plugins"]
        .as_array()
        .expect("structuredContent.plugins must be an array");
    assert!(
        plugins.is_empty(),
        "fresh engine has no plugins; got {plugins:?}",
    );
}

/// 14.3d: `plugins.show` on an unknown plugin returns an
/// application-level `isError = true` (not a JSON-RPC
/// protocol error) — mirrors the resource-side `NotFound`
/// shape. Message is human-readable.
#[tokio::test(flavor = "current_thread")]
async fn plugins_show_unknown_returns_tool_level_error() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.show", "arguments": {"plugin_id": "example.does-not-exist"}}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "not-found is tool-level, not protocol; got {response}"
    );
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "must surface as tool-level error; got {response}"
    );
    let content = result["content"].as_array().expect("content array");
    let text = content[0]["text"].as_str().expect("text content");
    assert!(
        text.contains("example.does-not-exist"),
        "error must name the missing plugin; got {text}",
    );
}

/// 14.3d: `plugins.show` rejects missing / empty / unknown
/// fields as `-32602 INVALID_PARAMS` — the standard tool
/// argument-validation contract.
#[tokio::test(flavor = "current_thread")]
async fn plugins_show_rejects_malformed_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("missing plugin_id", json!({})),
        ("empty plugin_id", json!({"plugin_id": ""})),
        ("unknown field", json!({"plugin_id": "x", "extra": 1})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.show", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// 14.3d: `plugins.list` lands in the audit ledger under
/// `mcp.tool.plugins.list` with `decision = "allow"` and
/// `execution_outcome = NULL` (host-state read, no plugin
/// reached).
#[tokio::test(flavor = "multi_thread")]
async fn plugins_list_lands_in_the_audit_log() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.list", "arguments": {}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.list")
        .expect("plugins.list row");
    assert_eq!(row.status, 200);
    assert_eq!(row.decision, "allow");
    assert!(
        row.execution_outcome.is_none(),
        "read tools leave outcome NULL"
    );
    assert!(row.finalized_ms.is_some(), "finalize must have landed");
}

/// 14.3d: `plugins.show` on a not-found target still audits
/// as `status = 200` + `decision = "allow"` (the caller was
/// authorised; the target just didn't exist). Same shape as
/// the resource-side `NotFound` handling.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_show_not_found_still_audits_as_allow() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.show", "arguments": {"plugin_id": "example.audit-nf"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.show")
        .expect("plugins.show row");
    assert_eq!(row.status, 200);
    assert_eq!(row.decision, "allow");
    assert!(row.finalized_ms.is_some(), "finalize must have landed");
}

/// Round-1 P2 on PR #131: `plugins.list` advertises
/// `additionalProperties: false` in its schema but the pre-fix
/// dispatch discarded `request.arguments`, letting unknown
/// fields silently succeed. Enforce the empty-args contract at
/// the tool boundary so a client sending anything besides `{}`
/// (or nothing) gets `-32602 INVALID_PARAMS`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_list_rejects_unknown_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("unknown top-level field", json!({"junk": 1})),
        ("multiple unknown fields", json!({"a": "b", "c": 2})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.list", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: unknown fields must surface as INVALID_PARAMS; got {response}",
        );
    }

    // Boundary — `{}` and omitting `arguments` altogether are
    // both accepted (the schema has no required fields).
    for arguments_value in [Some(json!({})), None] {
        let mut params = json!({"name": "plugins.list"});
        if let Some(args) = arguments_value {
            params["arguments"] = args;
        }
        let response = call(&router, &bearer, &session, "tools/call", params).await;
        assert_ne!(
            response["result"]["isError"], true,
            "empty / absent arguments must succeed; got {response}",
        );
    }
}

/// 14.3d: `plugins.list` and `plugins.show` responses keep
/// the text mirror alongside `structuredContent` for legacy
/// clients — same rule as the other read tools.
#[tokio::test(flavor = "current_thread")]
async fn plugins_list_response_keeps_text_mirror_for_legacy_clients() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.list", "arguments": {}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(result["isError"], true);
    let content = result["content"].as_array().expect("content array");
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).expect("text mirror is JSON");
    assert!(
        parsed["plugins"].is_array(),
        "text mirror must carry the same body; got {text}"
    );
    assert!(
        result["structuredContent"]["plugins"].is_array(),
        "structuredContent must still carry the parsed body; got {response}",
    );
}

// ── 14.3e — plugins.stop + plugins.uninstall ────────────────────

fn stage_switch_source(prefix: &str, plugin_id: &str) -> _support::TempDir {
    let wasm_src = _support::build_example("simulated-switch", "simulated_switch.wasm");
    let source = _support::tempdir(prefix);
    std::fs::copy(&wasm_src, source.path().join("simulated_switch.wasm")).expect("copy wasm");
    std::fs::write(
        source.path().join("manifest.toml"),
        format!(
            r#"manifest_version = 1
[plugin]
id = "{plugin_id}"
name = "MCP plugins.stop/uninstall test"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "simulated_switch.wasm"
[capabilities]
declares_devices = ["switch"]
"#,
        ),
    )
    .expect("write manifest");
    source
}

/// 14.3e: both admin tools are catalogued with `destructive`
/// annotations and require a `plugin_id`.
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_plugins_stop_and_uninstall_with_destructive_annotations() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");

    for name in ["plugins.stop", "plugins.uninstall"] {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} in the catalogue"));
        assert_eq!(tool["annotations"]["readOnlyHint"], false, "{name}");
        assert_eq!(tool["annotations"]["destructiveHint"], true, "{name}");
        assert_eq!(tool["annotations"]["openWorldHint"], false, "{name}");
        let required = tool["inputSchema"]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} has required fields"));
        assert!(
            required.iter().any(|v| v == "plugin_id"),
            "{name} must require plugin_id; got {required:?}",
        );
    }
}

/// 14.3e: `plugins.stop` requires `plugins:stop`; devices:list
/// alone (or even plugins:list) does not satisfy it.
#[tokio::test(flavor = "current_thread")]
async fn plugins_stop_requires_plugins_stop_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "list-only", &["plugins:list"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {"plugin_id": "example.does-not-exist"}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "plugins:list must not satisfy plugins:stop; got {response}",
    );
}

/// 14.3e: `plugins.uninstall` requires `plugins:uninstall`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_uninstall_requires_plugins_uninstall_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "stop-only", &["plugins:stop"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.uninstall", "arguments": {"plugin_id": "example.does-not-exist"}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "plugins:stop must not satisfy plugins:uninstall; got {response}",
    );
}

/// 14.3e: `plugins.stop` rejects missing / empty / unknown
/// arguments. Same shape as the other admin tools.
#[tokio::test(flavor = "current_thread")]
async fn plugins_stop_rejects_malformed_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("missing plugin_id", json!({})),
        ("empty plugin_id", json!({"plugin_id": ""})),
        (
            "empty instance_id",
            json!({"plugin_id": "x", "instance_id": ""}),
        ),
        ("unknown field", json!({"plugin_id": "x", "extra": 1})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.stop", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// 14.3e: `plugins.stop` on a plugin with no running instances
/// succeeds idempotently with an empty `stopped` list.
#[tokio::test(flavor = "current_thread")]
async fn plugins_stop_no_running_instances_returns_empty_list() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {"plugin_id": "example.absent"}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "no-op stop must succeed; got {response}"
    );
    let stopped = result["structuredContent"]["stopped"]
        .as_array()
        .expect("structuredContent.stopped array");
    assert!(
        stopped.is_empty(),
        "no-op stop returns empty list; got {stopped:?}"
    );
}

/// 14.3e: `plugins.stop` end-to-end — boots a real supervised
/// instance, stops it via the tool, verifies the response
/// carries the stopped id AND the registry is cleared.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_stop_end_to_end_halts_a_running_instance() {
    let _wasm = _support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = _support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);

    let handle = engine
        .start_instance(switch_dir, "switch-stop-e2e", None)
        .await
        .expect("start_instance");
    handle.wait_for_running().await.expect("running");
    let plugin_id = handle.plugin_id().to_string();

    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {"plugin_id": plugin_id}}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(result["isError"], true, "stop must succeed; got {response}");
    let stopped: Vec<&str> = result["structuredContent"]["stopped"]
        .as_array()
        .expect("stopped array")
        .iter()
        .map(|v| v.as_str().expect("id string"))
        .collect();
    assert!(
        stopped.contains(&"switch-stop-e2e"),
        "stopped list must name the halted instance; got {stopped:?}",
    );
    assert!(
        engine.instances().get("switch-stop-e2e").is_none(),
        "registry entry must clear post-stop",
    );
}

/// 14.3e: `plugins.uninstall` on a not-installed plugin
/// surfaces as an application-level `isError: true` with
/// `domain_kind = "not_installed"` — mirrors the REST 404
/// shape without leaking JSON-RPC protocol errors for a
/// state-driven condition.
#[tokio::test(flavor = "current_thread")]
async fn plugins_uninstall_unknown_plugin_returns_tool_level_error() {
    // `Engine::new()` has no plugins root and would return
    // `no_plugins_root` first; give the engine a state dir so
    // uninstall reaches the `not_installed` check.
    let state_dir = _support::tempdir("mcp-uninstall-nf-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.uninstall", "arguments": {"plugin_id": "example.absent-uninstall"}}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "not-found is tool-level; got {response}"
    );
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "must be tool-level error; got {response}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["kind"], "not_installed");
    assert_eq!(structured["plugin_id"], "example.absent-uninstall");
}

/// 14.3e: `plugins.uninstall` refuses when the plugin has
/// supervised instances still running — carries structured
/// `kind = "instances_running"` + the offending `running`
/// list so the caller can call `plugins.stop` and retry.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_uninstall_refuses_with_running_instances() {
    let plugin_id = "example.mcp-stop-uninstall";
    let source = stage_switch_source("mcp-uninstall-running", plugin_id);
    let state_dir = _support::tempdir("mcp-uninstall-state");

    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);

    let installed = engine
        .installed_plugins()
        .install(source.path())
        .expect("install plugin");
    let installation_uuid = std::sync::Arc::clone(&installed.installation_uuid);
    let handle = engine
        .start_installed_instance(
            installed.path.clone(),
            "switch-live-1",
            None,
            installation_uuid,
        )
        .await
        .expect("start installed instance");
    handle.wait_for_running().await.expect("running");

    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.uninstall", "arguments": {"plugin_id": plugin_id}}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "instances-running is tool-level; got {response}"
    );
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "must be tool-level error; got {response}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["kind"], "instances_running");
    let running: Vec<&str> = structured["running"]
        .as_array()
        .expect("running array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    assert!(
        running.contains(&"switch-live-1"),
        "running list must name the blocking instance; got {running:?}",
    );

    // Clean up: stop and let the handle drop.
    handle.stop().await.expect("stop");
}

/// 14.3e + Round-1 P2 on PR #132: mutating admin tools land in
/// the audit ledger under `mcp.tool.plugins.<action>` with
/// `decision = "allow"`. `execution_outcome` and `domain_error`
/// are plugin-command taxonomy fields — stop / uninstall
/// manipulate host state (supervisor lifecycle, FS + SQL
/// registry rows), no plugin `execute-command` runs, so both
/// slots stay NULL to keep the audit taxonomy uncorrupted.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_stop_lands_in_the_audit_log_with_null_execution_outcome() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {"plugin_id": "example.noop"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.stop")
        .expect("plugins.stop row");
    assert_eq!(row.status, 200);
    assert_eq!(row.decision, "allow");
    assert!(
        row.execution_outcome.is_none(),
        "host lifecycle op must leave execution_outcome NULL; got {:?}",
        row.execution_outcome,
    );
    assert!(row.domain_error.is_none());
    assert!(row.finalized_ms.is_some());
}

/// Round-1 P2 on PR #132: uninstall's tool-level error paths
/// (instances-running, not-installed, no-plugins-root) are
/// host-state conditions — no plugin was invoked — so
/// `domain_error` stays NULL. The clients still get
/// `structuredContent.kind` for a machine-readable tag; only
/// the audit slot is uncorrupted.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_uninstall_not_installed_leaves_domain_error_null() {
    let state_dir = _support::tempdir("mcp-uninstall-audit-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.uninstall", "arguments": {"plugin_id": "example.audit-nf-uninstall"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.uninstall")
        .expect("plugins.uninstall row");
    assert_eq!(row.decision, "allow");
    assert!(
        row.domain_error.is_none(),
        "host lifecycle preconditions must not populate domain_error; got {:?}",
        row.domain_error,
    );
}

/// Round-1 P1 on PR #132: explicit JSON `null` on
/// `instance_id` must be rejected, not silently coerced to
/// `None` (which would widen a targeted stop into stop-all
/// and bypass the caller's intent).
#[tokio::test(flavor = "current_thread")]
async fn plugins_stop_rejects_explicit_null_instance_id() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {
            "plugin_id": "example.null-guard",
            "instance_id": null,
        }}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "explicit null must surface as INVALID_PARAMS; got {response}",
    );

    // Sanity: the same call with `instance_id` OMITTED still
    // succeeds (default → None → stop-all), so the fix only
    // shuts down the ambiguous null case.
    let ok = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.stop", "arguments": {"plugin_id": "example.null-guard"}}),
    )
    .await;
    assert_ne!(
        ok["result"]["isError"], true,
        "omitted instance_id must still work; got {ok}"
    );
}

// ── 14.3f — plugins.start ───────────────────────────────────────

/// 14.3f: `plugins.start` is catalogued with `destructive`
/// annotations, requires `plugin_id`, and accepts optional
/// `instance_id` + `config_overrides`.
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_plugins_start_with_destructive_annotations() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "plugins.start")
        .expect("plugins.start in the catalogue");
    assert_eq!(tool["title"], "Start plugin instance");
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
    assert_eq!(tool["annotations"]["destructiveHint"], true);
    assert_eq!(tool["annotations"]["openWorldHint"], false);
    let required = tool["inputSchema"]["required"]
        .as_array()
        .expect("required array");
    assert!(
        required.iter().any(|v| v == "plugin_id"),
        "plugins.start must require plugin_id; got {required:?}",
    );
}

/// 14.3f: `plugins.start` requires `plugins:start`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_start_requires_plugins_start_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "stop-only", &["plugins:stop"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.start", "arguments": {"plugin_id": "example.no-scope"}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "plugins:stop must not satisfy plugins:start; got {response}",
    );
}

/// 14.3f: `plugins.start` rejects malformed argument shapes —
/// missing / empty `plugin_id`, unknown fields, an explicit
/// `null` on the optional `instance_id`, and unsafe FS-segment
/// `instance_id`s (path traversal, absolute paths).
#[tokio::test(flavor = "current_thread")]
async fn plugins_start_rejects_malformed_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("missing plugin_id", json!({})),
        ("empty plugin_id", json!({"plugin_id": ""})),
        (
            "empty instance_id",
            json!({"plugin_id": "x", "instance_id": ""}),
        ),
        (
            "null instance_id",
            json!({"plugin_id": "x", "instance_id": null}),
        ),
        (
            "path traversal",
            json!({"plugin_id": "x", "instance_id": "../escape"}),
        ),
        (
            "absolute path",
            json!({"plugin_id": "x", "instance_id": "/etc/passwd"}),
        ),
        ("unknown field", json!({"plugin_id": "x", "extra": 1})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.start", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// 14.3f: `plugins.start` on a not-installed plugin surfaces
/// as an application-level `isError: true` with structured
/// `kind = "not_installed"` — same shape the read tools use for
/// missing plugins.
#[tokio::test(flavor = "current_thread")]
async fn plugins_start_unknown_plugin_returns_tool_level_error() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.start", "arguments": {"plugin_id": "example.absent-start"}}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "not-found is tool-level; got {response}"
    );
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["kind"], "not_installed");
    assert_eq!(
        result["structuredContent"]["plugin_id"],
        "example.absent-start"
    );
}

/// 14.3f: `plugins.start` end-to-end — install a plugin, start
/// it via the tool, verify the response's shape and that the
/// instance reached `Running` in the registry.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_start_end_to_end_boots_an_installed_plugin() {
    let plugin_id = "example.mcp-start-e2e";
    let source = stage_switch_source("mcp-start-e2e-src", plugin_id);
    let state_dir = _support::tempdir("mcp-start-e2e-state");

    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let _installed = engine
        .installed_plugins()
        .install(source.path())
        .expect("install plugin");

    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.start", "arguments": {
            "plugin_id": plugin_id,
            "instance_id": "switch-start-e2e",
        }}),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "start must succeed; got {response}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["plugin_id"], plugin_id);
    assert_eq!(structured["instance_id"], "switch-start-e2e");
    // `state` should reflect that we reached Running.
    assert_eq!(structured["state"], "Running");

    // Sanity: the registry has the fresh handle.
    let handle = engine
        .instances()
        .get("switch-start-e2e")
        .expect("registry has the started instance");
    handle.stop().await.expect("stop");
}

/// Round-1 P1 on PR #133: `config_overrides` is documented as
/// `type: "object"`. Explicit JSON `null`, scalars, and arrays
/// must land as `INVALID_PARAMS` at the tool boundary — not
/// silently coerce to `None` (which would start with manifest
/// defaults) and not slip past into the loader (where scalars
/// and arrays only fail after a supervisor has been spawned).
/// Omission remains valid (`None` → manifest defaults, as
/// designed).
#[tokio::test(flavor = "current_thread")]
async fn plugins_start_rejects_non_object_config_overrides() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, config_overrides) in [
        ("null", json!(null)),
        ("string scalar", json!("value")),
        ("integer scalar", json!(42)),
        ("boolean scalar", json!(true)),
        ("array", json!(["a", "b"])),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.start", "arguments": {
                "plugin_id": "example.config-guard",
                "config_overrides": config_overrides,
            }}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: non-object config_overrides must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// Round-1 P1 boundary on PR #133: omitting `config_overrides`
/// still works (the field is optional; `None` → manifest
/// defaults). Locks in that the fix only shuts down the
/// non-object shapes, not the "no overrides" happy path.
#[tokio::test(flavor = "current_thread")]
async fn plugins_start_omitted_config_overrides_still_valid() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    // No plugin installed; the response should still be a
    // tool-level `not_installed` error, not an INVALID_PARAMS
    // — proving args deserialisation succeeded past the point
    // where `config_overrides = null` would have failed pre-fix.
    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.start", "arguments": {"plugin_id": "example.absent-omit"}}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "omitted config_overrides must not be INVALID_PARAMS; got {response}",
    );
    assert_eq!(
        response["result"]["structuredContent"]["kind"],
        "not_installed"
    );
}

/// 14.3f + Round-1 P2 lessons: `plugins.start` lands in the
/// audit ledger with `execution_outcome` + `domain_error` NULL
/// — host lifecycle actions, no plugin `execute-command`
/// invocation.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_start_not_installed_leaves_audit_taxonomy_clean() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.start", "arguments": {"plugin_id": "example.absent-audit-start"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.start")
        .expect("plugins.start row");
    assert_eq!(row.decision, "allow");
    assert!(row.execution_outcome.is_none());
    assert!(row.domain_error.is_none());
}

// ── 14.3g — plugins.install ─────────────────────────────────────

/// Stage a source dir for `plugins.install` to consume — same
/// shape as [`stage_switch_source`] but returns the *source*
/// (not-yet-installed) directory rather than one already
/// staged for `installed_plugins().install()`.
fn stage_install_source(prefix: &str, plugin_id: &str) -> _support::TempDir {
    stage_switch_source(prefix, plugin_id)
}

/// 14.3g: `plugins.install` is catalogued with `destructive`
/// annotations and requires `source_dir`.
#[tokio::test(flavor = "current_thread")]
async fn list_tools_advertises_plugins_install_with_destructive_annotations() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "plugins.install")
        .expect("plugins.install in the catalogue");
    assert_eq!(tool["title"], "Install plugin");
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
    assert_eq!(tool["annotations"]["destructiveHint"], true);
    assert_eq!(tool["annotations"]["openWorldHint"], false);
    let required = tool["inputSchema"]["required"]
        .as_array()
        .expect("required array");
    assert!(
        required.iter().any(|v| v == "source_dir"),
        "plugins.install must require source_dir; got {required:?}",
    );
}

/// 14.3g: `plugins.install` requires `plugins:install` — even
/// a token with every other admin scope short of install is
/// denied.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_requires_plugins_install_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(
        &engine,
        "no-install",
        &[
            "plugins:list",
            "plugins:start",
            "plugins:stop",
            "plugins:uninstall",
        ],
    );
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.install", "arguments": {"source_dir": "/nowhere"}}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32001,
        "other admin scopes must not satisfy plugins:install; got {response}",
    );
}

/// 14.3g: `plugins.install` rejects malformed argument shapes.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_rejects_malformed_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, arguments) in [
        ("missing source_dir", json!({})),
        ("empty source_dir", json!({"source_dir": ""})),
        ("null source_dir", json!({"source_dir": null})),
        ("unknown field", json!({"source_dir": "/x", "extra": 1})),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.install", "arguments": arguments}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: must surface as INVALID_PARAMS; got {response}",
        );
    }
}

/// Round-1 P2 on PR #134: the schema advertises `source_dir`
/// as an absolute path. Relative paths (`.`, `../staged`) must
/// land as `-32602 INVALID_PARAMS` at the tool boundary —
/// letting them through would resolve against the daemon's
/// process working directory, making identical calls behave
/// differently depending on how the daemon was launched.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_rejects_relative_source_dir() {
    let state_dir = _support::tempdir("mcp-install-relpath-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (label, source_dir) in [
        ("bare dot", "."),
        ("parent traversal", "../staged-plugin"),
        ("bare name", "staged-plugin"),
        ("dot slash", "./staged-plugin"),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "tools/call",
            json!({"name": "plugins.install", "arguments": {"source_dir": source_dir}}),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "{label}: relative source_dir `{source_dir}` must be INVALID_PARAMS; got {response}",
        );
    }
}

/// Round-2 P2 on PR #134: `BadManifest.reason` bakes
/// absolute paths into its own string via
/// `parsing {path.display()}: …`, so surfacing it in either
/// `message` or `structuredContent.reason` defeats the path
/// redaction the outer arm attempts. Return a path-free
/// generic tag and log the full detail server-side. This test
/// stages a truly malformed manifest and asserts NEITHER the
/// source parent NOR the state root appears anywhere in the
/// wire response.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_bad_manifest_response_carries_no_paths() {
    let source = _support::tempdir("mcp-install-bad-manifest-src");
    // Malformed TOML that will fail `toml::from_str`.
    std::fs::write(
        source.path().join("manifest.toml"),
        "this is not = valid TOML: [[[[",
    )
    .expect("write bad manifest");
    let state_dir = _support::tempdir("mcp-install-bad-manifest-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let source_display = source.path().display().to_string();
    let source_parent_display = source
        .path()
        .parent()
        .expect("source has a parent")
        .display()
        .to_string();
    let state_display = state_dir.path().display().to_string();

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.install", "arguments": {"source_dir": source_display}}),
    )
    .await;
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "malformed manifest must be tool-level error"
    );
    assert_eq!(result["structuredContent"]["kind"], "bad_manifest");

    let wire = serde_json::to_string(&response).expect("response serialises");
    for needle in [source_parent_display.as_str(), state_display.as_str()] {
        assert!(
            !wire.contains(needle),
            "wire response must not leak host path fragment `{needle}`; got:\n{wire}",
        );
    }
    // And the structured reason is deliberately absent — a
    // machine consumer sees only `kind`, no free-form reason
    // that might be regenerated with paths in a future refactor.
    assert!(
        result["structuredContent"]["reason"].is_null(),
        "structured payload must not carry a reason string; got {result}",
    );
}

/// 14.3g: `plugins.install` against a source dir that doesn't
/// exist lands as a tool-level `isError: true` with structured
/// `kind = "source_missing"`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_source_missing_returns_tool_level_error() {
    let state_dir = _support::tempdir("mcp-install-nf-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.install", "arguments": {
            "source_dir": "/definitely/does/not/exist",
        }}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "source-missing is tool-level; got {response}"
    );
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["kind"], "source_missing");
}

/// 14.3g: an in-memory engine (no `<state_dir>/plugins/` root)
/// surfaces install as `kind = "no_plugins_root"`.
#[tokio::test(flavor = "current_thread")]
async fn plugins_install_no_plugins_root_returns_tool_level_error() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    // Stage a real source dir so we get past the
    // source-missing check and hit the no-plugins-root arm.
    let source = stage_install_source("mcp-install-no-root", "example.no-root");
    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.install", "arguments": {
            "source_dir": source.path().display().to_string(),
        }}),
    )
    .await;
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["kind"], "no_plugins_root");
}

/// 14.3g end-to-end: stage a real plugin, install it via the
/// tool, verify the response body carries `plugin_id`,
/// `version`, and an `installed_path` that lives under the
/// engine's state dir. A follow-up `plugins.install` for the
/// same id returns `kind = "already_installed"` (idempotence
/// check).
#[tokio::test(flavor = "multi_thread")]
async fn plugins_install_end_to_end_and_rejects_duplicate() {
    let plugin_id = "example.mcp-install-e2e";
    let source = stage_install_source("mcp-install-e2e-src", plugin_id);
    let state_dir = _support::tempdir("mcp-install-e2e-state");

    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let install_args = json!({"name": "plugins.install", "arguments": {
        "source_dir": source.path().display().to_string(),
    }});

    // First install: success.
    let response = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        install_args.clone(),
    )
    .await;
    let result = &response["result"];
    assert_ne!(
        result["isError"], true,
        "install must succeed; got {response}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["plugin_id"], plugin_id);
    let installed_path = structured["installed_path"]
        .as_str()
        .expect("installed_path string");
    assert!(
        installed_path.starts_with(&state_dir.path().display().to_string()),
        "installed_path must live under the engine's state dir; got {installed_path}",
    );

    // The registry sees it too.
    assert!(
        engine.installed_plugins().get(plugin_id).is_some(),
        "installed_plugins() must reflect the fresh install",
    );

    // Second install of the same id: `already_installed` tool-
    // level error (locks in that install is not idempotent —
    // the operator must uninstall first).
    let response = call(&router, &bearer, &session, "tools/call", install_args).await;
    let result = &response["result"];
    assert_eq!(
        result["isError"], true,
        "duplicate install must be tool-level error"
    );
    assert_eq!(result["structuredContent"]["kind"], "already_installed");
    assert_eq!(result["structuredContent"]["plugin_id"], plugin_id);
}

/// 14.3g + Round-1 P2 lessons: `plugins.install` lands in the
/// audit ledger with `execution_outcome` + `domain_error` NULL
/// (host lifecycle, not a plugin `execute-command`).
#[tokio::test(flavor = "multi_thread")]
async fn plugins_install_audit_taxonomy_stays_clean() {
    let state_dir = _support::tempdir("mcp-install-audit-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    // Deliberately point at a bogus path so we exercise the
    // source-missing ExecErr path — the taxonomy rule applies
    // uniformly, error or success.
    let _ = call(
        &router,
        &bearer,
        &session,
        "tools/call",
        json!({"name": "plugins.install", "arguments": {"source_dir": "/absent-audit-install"}}),
    )
    .await;

    let audit = engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit.query(&AuditQuery::default(), 64))
        .await
        .expect("audit query join")
        .expect("audit query");
    let row = rows
        .iter()
        .find(|r| r.path == "mcp.tool.plugins.install")
        .expect("plugins.install row");
    assert_eq!(row.decision, "allow");
    assert!(
        row.execution_outcome.is_none(),
        "install is host-lifecycle; execution_outcome must be NULL; got {:?}",
        row.execution_outcome,
    );
    assert!(row.domain_error.is_none());
}
