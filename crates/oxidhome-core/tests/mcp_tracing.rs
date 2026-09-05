//! Phase 14.7c — MCP structured completion tracing.
//!
//! Drives one `tools/call`, one `resources/read`, and one
//! `prompts/get` through the MCP mount with a custom tracing
//! layer attached. Asserts the standardised
//! `mcp.resource.complete` / `mcp.tool.complete` /
//! `mcp.prompt.complete` completion
//! events land with the expected field shape
//! (`mcp_name`, `mcp_actor_id`, `mcp_outcome`,
//! `mcp_duration_ms`).

#[path = "support.rs"]
mod _support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::subscriber::with_default;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

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
    engine
        .auth_tokens()
        .create("test", b"[\"*\"]")
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
            "clientInfo": {"name": "oxidhome-mcp-tracing-test", "version": env!("CARGO_PKG_VERSION")}
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
            .expect("stream ended")
            .expect("frame read");
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.push_str(&String::from_utf8_lossy(&data));
        while let Some(end) = buf.find("\n\n") {
            let event = buf[..end].to_string();
            buf.drain(..=end + 1);
            for line in event.lines() {
                let Some(payload) = line.strip_prefix("data:") else {
                    continue;
                };
                let p = payload.trim();
                if p.is_empty() {
                    continue;
                }
                return serde_json::from_str(p).unwrap_or_else(|e| panic!("SSE JSON: {e}: {p}"));
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
    assert_eq!(init.status(), StatusCode::OK);
    let session = init
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .unwrap()
        .to_string();
    let _ = read_first_sse_data(init).await;
    let notified = router
        .clone()
        .oneshot(
            base_request("POST", bearer)
                .header("mcp-session-id", &session)
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(notified.status(), StatusCode::ACCEPTED);
    (router, session)
}

async fn call(
    router: &axum::Router,
    bearer: &str,
    session: &str,
    method: &str,
    params: Value,
) -> Value {
    let response = router
        .clone()
        .oneshot(
            base_request("POST", bearer)
                .header("mcp-session-id", session)
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "id": 42, "method": method, "params": params})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "call {method} failed");
    read_first_sse_data(response).await
}

/// Captured completion event — one row per emitted tracing
/// event under an `mcp.*` target.
#[derive(Debug, Clone)]
struct CapturedEvent {
    target: String,
    fields: HashMap<String, String>,
}

#[derive(Default)]
struct FieldCollector {
    fields: HashMap<String, String>,
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

struct McpCaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> Layer<S> for McpCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let target = event.metadata().target();
        if !target.ends_with(".complete") || !target.starts_with("mcp.") {
            return;
        }
        let mut collector = FieldCollector::default();
        event.record(&mut collector);
        self.events.lock().unwrap().push(CapturedEvent {
            target: target.to_string(),
            fields: collector.fields,
        });
    }
}

fn setup_capture() -> (
    impl tracing::Subscriber + Send + Sync,
    Arc<Mutex<Vec<CapturedEvent>>>,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let layer = McpCaptureLayer {
        events: Arc::clone(&events),
    };
    let subscriber = Registry::default().with(layer);
    (subscriber, events)
}

fn assert_shape(ev: &CapturedEvent, expected_name: &str, expected_outcome: &str) {
    assert_eq!(
        ev.fields.get("mcp_name").map(String::as_str),
        Some(expected_name),
        "mcp_name field; got {:?}",
        ev.fields,
    );
    assert_eq!(
        ev.fields.get("mcp_outcome").map(String::as_str),
        Some(expected_outcome),
        "mcp_outcome field; got {:?}",
        ev.fields,
    );
    let actor_id = ev
        .fields
        .get("mcp_actor_id")
        .expect("mcp_actor_id field present");
    assert!(!actor_id.is_empty(), "mcp_actor_id must not be empty");
    let dur = ev
        .fields
        .get("mcp_duration_ms")
        .expect("mcp_duration_ms field present");
    dur.parse::<u64>()
        .expect("mcp_duration_ms must parse as u64");
}

/// 14.7c: every dispatched MCP request emits exactly one
/// completion event under a stable target with a stable field
/// shape. Fire one of each (tools/call, resources/read,
/// prompts/get) and assert the three events land.
#[test]
fn dispatched_requests_emit_completion_events() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (subscriber, events) = setup_capture();

    with_default(subscriber, || {
        rt.block_on(async {
            let engine = Engine::new().expect("engine");
            let bearer = mint_bearer(&engine);
            let router = build_router(engine);
            let (router, session) = handshake(router, &bearer).await;

            // resources/read on a valid, empty catalogue URI.
            let _ = call(
                &router,
                &bearer,
                &session,
                "resources/read",
                json!({"uri": "oxidhome://devices"}),
            )
            .await;

            // tools/call on a read-only tool that always
            // succeeds on a fresh engine.
            let _ = call(
                &router,
                &bearer,
                &session,
                "tools/call",
                json!({"name": "logs.query", "arguments": {}}),
            )
            .await;

            // prompts/get on a scope-satisfied prompt.
            let _ = call(
                &router,
                &bearer,
                &session,
                "prompts/get",
                json!({"name": "summarize_today"}),
            )
            .await;
        });
    });

    let captured = events.lock().unwrap().clone();
    let resource_ev = captured
        .iter()
        .find(|e| e.target == "mcp.resource.complete")
        .expect("mcp.resource.complete event missing");
    let tool_ev = captured
        .iter()
        .find(|e| e.target == "mcp.tool.complete")
        .expect("mcp.tool.complete event missing");
    let prompt_ev = captured
        .iter()
        .find(|e| e.target == "mcp.prompt.complete")
        .expect("mcp.prompt.complete event missing");

    // P1 (round-1 review of PR #144): `mcp_name` for resources
    // is the routed family slug, not the caller-controlled
    // URI. `oxidhome://devices` routes to family `devices`.
    assert_shape(resource_ev, "devices", "ok");
    assert_shape(tool_ev, "logs.query", "ok");
    assert_shape(prompt_ev, "summarize_today", "ok");
}

/// 14.7c: error paths map to stable outcome tags. A
/// no-scope token hitting a scope-gated tool lands as
/// `denied`; an unknown prompt name lands as
/// `invalid_params`.
#[test]
fn error_paths_carry_stable_outcome_tags() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (subscriber, events) = setup_capture();

    with_default(subscriber, || {
        rt.block_on(async {
            let engine = Engine::new().expect("engine");
            let scope_json = serde_json::to_vec(&Vec::<String>::new()).unwrap();
            let bearer = engine
                .auth_tokens()
                .create("no-scope", &scope_json)
                .unwrap()
                .plaintext;
            let router = build_router(engine);
            let (router, session) = handshake(router, &bearer).await;

            // Scope-gated tool: no scope → denied.
            let _ = call(
                &router,
                &bearer,
                &session,
                "tools/call",
                json!({"name": "logs.query", "arguments": {}}),
            )
            .await;

            // Unknown prompt → invalid_params.
            let _ = call(
                &router,
                &bearer,
                &session,
                "prompts/get",
                json!({"name": "does-not-exist"}),
            )
            .await;
        });
    });

    let captured = events.lock().unwrap().clone();
    let denied = captured
        .iter()
        .find(|e| e.target == "mcp.tool.complete")
        .expect("mcp.tool.complete event");
    assert_eq!(
        denied.fields.get("mcp_outcome").map(String::as_str),
        Some("denied"),
        "no-scope tools/call must classify as denied; got {:?}",
        denied.fields,
    );

    let bad_prompt = captured
        .iter()
        .find(|e| e.target == "mcp.prompt.complete")
        .expect("mcp.prompt.complete event");
    assert_eq!(
        bad_prompt.fields.get("mcp_outcome").map(String::as_str),
        Some("invalid_params"),
        "unknown prompt must classify as invalid_params; got {:?}",
        bad_prompt.fields,
    );
    // Round-2 P1 on PR #144: even for an unknown prompt name,
    // `mcp_name` must be the bounded sentinel `"unknown"` — not
    // the caller-supplied string.
    assert_eq!(
        bad_prompt.fields.get("mcp_name").map(String::as_str),
        Some("unknown"),
        "P1 regression: unknown prompt name must map to \"unknown\", not the raw string; got {:?}",
        bad_prompt.fields,
    );
}

/// 14.7c round-1 P1: `mcp_name` on `mcp.resource.complete`
/// must be the routed family slug — a bounded closed set —
/// not the caller-controlled URI. Fires three URIs whose
/// only difference is the id/query segment and asserts every
/// captured event lands on the same family label. If someone
/// later plumbs the raw URI back through, this test blows up
/// with three distinct `mcp_name` values and forces the
/// discussion.
#[test]
fn resource_completion_uses_bounded_family_slug() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (subscriber, events) = setup_capture();

    with_default(subscriber, || {
        rt.block_on(async {
            let engine = Engine::new().expect("engine");
            let bearer = mint_bearer(&engine);
            let router = build_router(engine);
            let (router, session) = handshake(router, &bearer).await;

            // Same family, three different unbounded suffixes:
            // - a made-up device id
            // - a plausible-looking uuid
            // - a query string
            // On the raw-URI path all three would be distinct
            // `mcp_name` values; on the family path they all
            // collapse to `devices.detail`.
            for uri in [
                "oxidhome://devices/dev-a",
                "oxidhome://devices/00000000-0000-0000-0000-000000000000",
                "oxidhome://devices/dev-b?refresh=true",
            ] {
                let _ = call(
                    &router,
                    &bearer,
                    &session,
                    "resources/read",
                    json!({"uri": uri}),
                )
                .await;
            }
        });
    });

    let captured = events.lock().unwrap().clone();
    let resource_events: Vec<_> = captured
        .iter()
        .filter(|e| e.target == "mcp.resource.complete")
        .collect();
    assert_eq!(
        resource_events.len(),
        3,
        "three resources/read calls must produce three completion events; got {captured:#?}",
    );
    for ev in &resource_events {
        assert_eq!(
            ev.fields.get("mcp_name").map(String::as_str),
            Some("devices.detail"),
            "P1 regression: mcp_name must be the family slug, not the URI; got {:?}",
            ev.fields,
        );
    }
}

/// 14.7c round-2 P1: unknown tool/prompt names come from the
/// caller and are unbounded. `mcp_name` must collapse them to
/// the sentinel `"unknown"` so a hostile or bugged client
/// can't blow up a dashboard label index.
#[test]
fn unknown_tool_and_prompt_names_collapse_to_unknown() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let (subscriber, events) = setup_capture();

    with_default(subscriber, || {
        rt.block_on(async {
            let engine = Engine::new().expect("engine");
            let bearer = mint_bearer(&engine);
            let router = build_router(engine);
            let (router, session) = handshake(router, &bearer).await;

            // Two nonsense tool names — different unbounded
            // strings that must both land as `mcp_name =
            // "unknown"`.
            for tool in [
                "not-a-real-tool",
                "hostile-💥-\u{1f4a5}-emoji-name-that-would-explode-label-cardinality",
            ] {
                let _ = call(
                    &router,
                    &bearer,
                    &session,
                    "tools/call",
                    json!({"name": tool, "arguments": {}}),
                )
                .await;
            }

            // Two nonsense prompt names — same idea.
            for prompt in ["no-such-prompt", "another/garbage?name"] {
                let _ = call(
                    &router,
                    &bearer,
                    &session,
                    "prompts/get",
                    json!({"name": prompt}),
                )
                .await;
            }
        });
    });

    let captured = events.lock().unwrap().clone();
    let tool_evs: Vec<_> = captured
        .iter()
        .filter(|e| e.target == "mcp.tool.complete")
        .collect();
    assert_eq!(
        tool_evs.len(),
        2,
        "two unknown-tool calls must produce two completion events; got {captured:#?}",
    );
    for ev in &tool_evs {
        assert_eq!(
            ev.fields.get("mcp_name").map(String::as_str),
            Some("unknown"),
            "P1 regression: unknown tool name must map to \"unknown\", not the raw string; got {:?}",
            ev.fields,
        );
    }

    let prompt_evs: Vec<_> = captured
        .iter()
        .filter(|e| e.target == "mcp.prompt.complete")
        .collect();
    assert_eq!(
        prompt_evs.len(),
        2,
        "two unknown-prompt calls must produce two completion events; got {captured:#?}",
    );
    for ev in &prompt_evs {
        assert_eq!(
            ev.fields.get("mcp_name").map(String::as_str),
            Some("unknown"),
            "P1 regression: unknown prompt name must map to \"unknown\", not the raw string; got {:?}",
            ev.fields,
        );
    }
}
