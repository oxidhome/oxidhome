//! Phase 14.6 — MCP `prompts/*` integration tests.
//!
//! Drives [`api::build_router`] via [`tower::ServiceExt::oneshot`]
//! through `prompts/list` and `prompts/get`, asserting:
//!
//! - Every prompt is catalogued with its title + description
//!   + declared arguments.
//! - `prompts/get` on an unknown name returns
//!   `INVALID_PARAMS` (-32602).
//! - `prompts/get` on `draft_automation` without required
//!   arguments returns `INVALID_PARAMS`.
//! - Per-prompt scope gating: a token missing the required
//!   scope lands as `SCOPE_DENIED` (-32001).
//! - A wildcard-scoped token gets the rendered messages and
//!   the interpolated arguments appear verbatim.

#[path = "support.rs"]
mod _support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
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
                "name": "oxidhome-mcp-prompts-test",
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

/// 14.6: `prompts/list` catalogues every prompt with its
/// title, description, and — for `draft_automation` — the
/// declared arguments.
#[tokio::test(flavor = "current_thread")]
async fn list_prompts_advertises_all_three_with_metadata() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "prompts/list", json!({})).await;
    let prompts = response["result"]["prompts"]
        .as_array()
        .expect("prompts array");
    let names: Vec<&str> = prompts
        .iter()
        .map(|p| p["name"].as_str().expect("prompt name"))
        .collect();
    for expected in [
        "summarize_today",
        "draft_automation",
        "explain_recent_errors",
    ] {
        assert!(
            names.contains(&expected),
            "prompts/list missing `{expected}`; got {names:?}",
        );
    }

    let draft = prompts
        .iter()
        .find(|p| p["name"] == "draft_automation")
        .expect("draft_automation catalogued");
    assert_eq!(draft["title"], "Draft a household automation");
    let args = draft["arguments"].as_array().expect("arguments array");
    let arg_names: Vec<&str> = args.iter().map(|a| a["name"].as_str().unwrap()).collect();
    assert!(
        arg_names.contains(&"trigger"),
        "trigger arg missing; got {arg_names:?}"
    );
    assert!(
        arg_names.contains(&"action"),
        "action arg missing; got {arg_names:?}"
    );
    for arg in args {
        assert_eq!(
            arg["required"], true,
            "draft_automation args must be required; got {arg}"
        );
    }
}

/// 14.6: `prompts/list` is public — a token with NO scopes
/// still sees the full catalogue. Scope gating only kicks in
/// at `prompts/get`. Matches the tool-side behavior.
#[tokio::test(flavor = "current_thread")]
async fn list_prompts_is_public_regardless_of_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "no-scopes", &[]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(&router, &bearer, &session, "prompts/list", json!({})).await;
    let prompts = response["result"]["prompts"]
        .as_array()
        .expect("prompts array");
    assert_eq!(
        prompts.len(),
        3,
        "no-scope token must still see all 3 prompts; got {prompts:?}",
    );
}

/// 14.6: `prompts/get` on an unknown prompt name surfaces as
/// `-32602 INVALID_PARAMS` (not `method_not_found` — the
/// `prompts/get` method itself exists).
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_unknown_name_returns_invalid_params() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "does_not_exist"}),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "unknown prompt must surface as INVALID_PARAMS; got {response}",
    );
}

/// 14.6: `summarize_today` requires `events:read` + `logs:read`.
/// A token holding only one lands as `-32001 SCOPE_DENIED` and
/// the message names the missing scope so a caller can react.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_summarize_today_requires_both_scopes() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "logs-only", &["logs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "summarize_today"}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32001);
    let message = response["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("events:read"),
        "denied message must name the missing scope; got `{message}`",
    );
}

/// 14.6: `draft_automation` requires `plugins:list` AND both
/// `trigger` + `action` arguments. Missing arguments land as
/// `-32602`; missing scope as `-32001`.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_draft_automation_rejects_missing_args_and_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    // Missing arguments entirely.
    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation"}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);

    // Missing `action`.
    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {"trigger": "front door unlocks"}}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);

    // Empty `trigger`.
    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": "",
            "action": "turn on the hallway lights",
        }}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);
}

/// 14.6: `draft_automation` under a token WITHOUT `plugins:list`
/// scope but WITH valid arguments still lands as `-32001` —
/// argument shape is validated BEFORE scope check, but scope
/// is still enforced.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_draft_automation_requires_plugins_list_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "no-plugins", &["logs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": "the front door unlocks",
            "action": "turn on the hallway lights",
        }}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32001);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("plugins:list"),
    );
}

/// 14.6: `draft_automation` with wildcard scope + valid
/// arguments returns rendered messages. The interpolated
/// `trigger` and `action` MUST appear verbatim in the user
/// message, and the result carries a description.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_draft_automation_interpolates_arguments() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let trigger = "when the front door unlocks after sunset";
    let action = "turn on the hallway lights and start the porch camera";

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": trigger,
            "action": action,
        }}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "wildcard + valid args must succeed; got {response}",
    );
    let result = &response["result"];
    assert!(
        result["description"].is_string(),
        "result must carry a description; got {result}",
    );
    let messages = result["messages"].as_array().expect("messages array");
    assert!(!messages.is_empty(), "must return at least one message");
    let text = messages[0]["content"]["text"]
        .as_str()
        .expect("text content");
    assert!(
        text.contains(trigger),
        "trigger must be interpolated verbatim; got:\n{text}",
    );
    assert!(
        text.contains(action),
        "action must be interpolated verbatim; got:\n{text}",
    );
}

/// 14.6: `summarize_today` and `explain_recent_errors` with
/// the right scopes return messages that reference the
/// resources they compose (so a client can follow the
/// template without additional hinting).
#[tokio::test(flavor = "current_thread")]
async fn get_prompts_reference_the_composed_resources() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    for (name, expected_uri_fragment) in [
        ("summarize_today", "oxidhome://events"),
        ("explain_recent_errors", "oxidhome://logs"),
    ] {
        let response = call(
            &router,
            &bearer,
            &session,
            "prompts/get",
            json!({"name": name}),
        )
        .await;
        assert!(
            response["error"].is_null(),
            "{name}: must succeed; got {response}"
        );
        let text = response["result"]["messages"][0]["content"]["text"]
            .as_str()
            .expect("text");
        assert!(
            text.contains(expected_uri_fragment),
            "{name} must reference `{expected_uri_fragment}`; got:\n{text}",
        );
    }
}

/// Round-1 P1 on PR #135: `draft_automation` must be able to
/// discover real device ids + capabilities, so it needs
/// `devices:list` + `devices:read` alongside `plugins:list` —
/// plugin metadata alone doesn't identify a switch or a lock.
/// A token holding `plugins:list` but not the devices scopes
/// lands as `-32001 SCOPE_DENIED` and the message names the
/// missing scope.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_draft_automation_requires_devices_scopes() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "plugins-only", &["plugins:list"]);
    let router = build_router(engine.clone());
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": "front door unlocks",
            "action": "turn on hallway lights",
        }}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32001);
    let message = response["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("devices:list"),
        "denied message must name the missing devices scope; got `{message}`",
    );

    // Adding `devices:list` isn't enough — the prompt also
    // needs `devices:read` to drill into individual devices.
    let bearer = mint_bearer_with_scopes(
        &engine,
        "plugins-and-devices-list",
        &["plugins:list", "devices:list"],
    );
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;
    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": "front door unlocks",
            "action": "turn on hallway lights",
        }}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32001);
    let message = response["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("devices:read"),
        "denied message must name devices:read as the still-missing scope; got `{message}`",
    );
}

/// Round-1 P1 + P2 on PR #135: the `draft_automation` template
/// body must (a) direct the client to real devices via
/// `oxidhome://devices` (P1: plugin metadata doesn't identify
/// devices) and (b) name the correct scope `devices:command`
/// for the executed action (P2: there is no `plugins:command`
/// scope).
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_draft_automation_body_references_devices_and_correct_scope() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "draft_automation", "arguments": {
            "trigger": "front door unlocks",
            "action": "turn on hallway lights",
        }}),
    )
    .await;
    let text = response["result"]["messages"][0]["content"]["text"]
        .as_str()
        .expect("text");
    assert!(
        text.contains("oxidhome://devices"),
        "draft_automation must direct client to the devices resource; got:\n{text}",
    );
    assert!(
        text.contains("devices:command"),
        "draft_automation must name `devices:command` (not `plugins:command`); got:\n{text}",
    );
    assert!(
        !text.contains("plugins:command"),
        "`plugins:command` is not a real scope; got:\n{text}",
    );
}

/// Round-1 P1 on PR #135: event rows carry state transitions,
/// not command failures — `WireHistoricalEvent` has no domain-
/// error field. Command outcomes live in the audit ledger,
/// which the MCP surface does not yet expose. So the prompt
/// must NOT direct the client at `oxidhome://events` under a
/// false promise it can find failures there; keep it to
/// `oxidhome://logs` and be explicit about the scope.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_explain_recent_errors_does_not_reference_events_for_failures() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer(&engine);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "explain_recent_errors"}),
    )
    .await;
    let text = response["result"]["messages"][0]["content"]["text"]
        .as_str()
        .expect("text");
    // Must fetch logs.
    assert!(
        text.contains("oxidhome://logs"),
        "must fetch logs; got:\n{text}"
    );
    // Must NOT direct the client at events for failures — the
    // pre-fix body did, and events don't carry that data.
    assert!(
        !text.contains("oxidhome://events"),
        "explain_recent_errors must not point at oxidhome://events for failure data; got:\n{text}",
    );
}

/// Round-1 P1 on PR #135: `explain_recent_errors` no longer
/// needs `events:read` since it doesn't read events; scope
/// requirement is `logs:read` alone.
#[tokio::test(flavor = "current_thread")]
async fn get_prompt_explain_recent_errors_requires_only_logs_read() {
    let engine = Engine::new().expect("engine");
    let bearer = mint_bearer_with_scopes(&engine, "logs-only-explain", &["logs:read"]);
    let router = build_router(engine);
    let (router, session) = handshake(router, &bearer).await;

    let response = call(
        &router,
        &bearer,
        &session,
        "prompts/get",
        json!({"name": "explain_recent_errors"}),
    )
    .await;
    assert!(
        response["error"].is_null(),
        "logs:read alone must satisfy explain_recent_errors post-fix; got {response}",
    );
    assert!(
        !response["result"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
