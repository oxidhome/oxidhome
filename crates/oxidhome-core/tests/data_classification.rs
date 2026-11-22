//! M7 end-to-end: secret config fields, bytes withholding, redaction.
//!
//! - A `type = "secret"` config value reaches the instance but comes
//!   back masked (`"***"` + `set` flag) from REST `GET /api/v1/instances`,
//!   Connect `ListInstances`, and the MCP `oxidhome://plugins/{id}`
//!   resource.
//! - `bytes-val` event fields are withheld from a token without
//!   `blobs:read` and delivered to one with it (REST + MCP).

#[path = "support.rs"]
mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
    Event, EventPayload, StateChange,
};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "hunter2-very-secret";

fn secret_manifest() -> String {
    r#"manifest_version = 1

[plugin]
id = "example.simulated-switch"
name = "Simulated Switch"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"

[runtime]
wasm = "simulated_switch.wasm"

[capabilities]
declares_devices = ["switch"]

[config.default_state]
type = "bool"
default = false

[config.api_key]
type = "secret"
description = "Cloud API key."

[config.optional_token]
type = "secret"
required = false
"#
    .to_owned()
}

fn mint(engine: &Engine, id: &str, scopes: &[&str]) -> String {
    engine
        .auth_tokens()
        .create(id, &serde_json::to_vec(scopes).unwrap())
        .expect("mint token")
        .plaintext
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 body")
}

async fn get(router: &axum::Router, uri: &str, bearer: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_text(response).await)
}

// ── Minimal MCP client ──────────────────────────────────────────────

fn mcp_request(bearer: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(MCP_ENDPOINT)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
}

async fn first_sse_data(response: axum::response::Response) -> Value {
    let mut body = response.into_body();
    let mut buf = String::new();
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(10), body.frame())
            .await
            .expect("timed out waiting for SSE frame")
            .expect("stream ended before a data frame")
            .expect("frame read error");
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.push_str(&String::from_utf8_lossy(&data));
        for line in buf.lines() {
            if let Some(payload) = line.strip_prefix("data:")
                && !payload.trim().is_empty()
                && let Ok(v) = serde_json::from_str::<Value>(payload.trim())
            {
                return v;
            }
        }
    }
}

async fn mcp_session(router: &axum::Router, bearer: &str) -> String {
    let init = router
        .clone()
        .oneshot(
            mcp_request(bearer)
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {"name": "m7-test", "version": "0"}
                        }
                    })
                    .to_string(),
                ))
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
        .to_owned();
    let _ = first_sse_data(init).await;
    let notified = router
        .clone()
        .oneshot(
            mcp_request(bearer)
                .header("mcp-session-id", &session)
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(notified.status(), StatusCode::ACCEPTED);
    session
}

async fn mcp_read(router: &axum::Router, bearer: &str, uri: &str) -> Value {
    let session = mcp_session(router, bearer).await;
    let response = router
        .clone()
        .oneshot(
            mcp_request(bearer)
                .header("mcp-session-id", &session)
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "resources/read",
                        "params": {"uri": uri}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rpc = first_sse_data(response).await;
    let text = rpc["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("resource text missing: {rpc}"));
    serde_json::from_str(text).expect("resource body is JSON")
}

// ── Secret config ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn secret_config_is_masked_on_every_read_surface() {
    let wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let staged = support::stage_plugin(
        "m7-secret",
        &wasm,
        "simulated_switch.wasm",
        &secret_manifest(),
    );
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str(&format!("api_key = \"{SECRET}\"")).unwrap();
    let handle = engine
        .start_instance(
            staged.path().to_path_buf(),
            "secret-switch",
            Some(overrides),
        )
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");

    let expected = json!({
        "default_state": false,
        "api_key": {"secret": true, "set": true, "value": "***"},
        "optional_token": {"secret": true, "set": false, "value": null},
    });

    let bearer = mint(&engine, "lister", &["instances:list", "plugins:list"]);
    let router = build_router(engine.clone());

    // REST
    let (status, text) = get(&router, "/api/v1/instances", &bearer).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!text.contains(SECRET), "REST leaked the secret: {text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["instances"][0]["config"], expected);

    // Connect
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/ListInstances")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let text = body_text(response).await;
    assert!(!text.contains(SECRET), "Connect leaked the secret: {text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    let config_json = body["instances"][0]["configJson"]
        .as_str()
        .unwrap_or_else(|| panic!("configJson missing: {body}"));
    assert_eq!(
        serde_json::from_str::<Value>(config_json).unwrap(),
        expected
    );

    // MCP
    let detail = mcp_read(
        &router,
        &bearer,
        "oxidhome://plugins/example.simulated-switch",
    )
    .await;
    assert!(!detail.to_string().contains(SECRET), "MCP leaked: {detail}");
    assert_eq!(detail["instances"][0]["config"], expected);

    handle.stop().await.expect("stop");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_required_secret_fails_the_load_without_echoing() {
    let wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let staged = support::stage_plugin(
        "m7-missing",
        &wasm,
        "simulated_switch.wasm",
        &secret_manifest(),
    );
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str("api_key = 12345678").unwrap();
    let handle = engine
        .start_instance(staged.path().to_path_buf(), "bad-switch", Some(overrides))
        .await
        .expect("start returns a handle");
    let err = handle
        .wait_for_running()
        .await
        .expect_err("a non-string secret must fail the load");
    let text = format!("{err:?}");
    assert!(text.contains("api_key"), "{text}");
    assert!(
        !text.contains("12345678"),
        "load error echoed the value: {text}"
    );
}

// ── Bytes withholding ───────────────────────────────────────────────

fn record_snapshot_event(engine: &Engine) {
    let event = Event {
        device: Some("cam-1".into()),
        timestamp: 0,
        origin_plugin_id: "example.camera".into(),
        origin_instance_id: "cam".into(),
        row_id: None,
        payload: EventPayload::StateChanged(StateChange {
            capability: "camera".into(),
            fields: vec![
                KeyValue {
                    key: "snapshot".into(),
                    value: WitValue::BytesVal(vec![0xff, 0xd8, 0xff]),
                },
                KeyValue {
                    key: "motion".into(),
                    value: WitValue::BoolVal(true),
                },
            ],
        }),
    };
    engine
        .event_log()
        .record(1, &event, "cam", "example.camera")
        .expect("record event");
}

fn snapshot_field(events: &Value) -> Value {
    let fields = events["events"][0]["payload"]["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("fields missing: {events}"));
    fields
        .iter()
        .find(|f| f["key"] == "snapshot")
        .expect("snapshot field")["value"]
        .clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn bytes_need_blobs_read_on_rest_and_mcp() {
    let engine = Engine::new().expect("engine");
    record_snapshot_event(&engine);
    let router = build_router(engine.clone());
    let narrow = mint(&engine, "narrow", &["events:read"]);
    let with_blobs = mint(&engine, "blobs", &["events:read", "blobs:read"]);
    let admin = mint(&engine, "admin", &["*"]);

    let withheld = json!({
        "t": "Json",
        "v": r#"{"withheld":"bytes","size_bytes":3,"required_scope":"blobs:read"}"#,
    });
    let raw = json!({"t": "Bytes", "v": [255, 216, 255]});

    let (status, text) = get(&router, "/api/v1/events", &narrow).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(snapshot_field(&body), withheld);
    for bearer in [&with_blobs, &admin] {
        let (_, text) = get(&router, "/api/v1/events", bearer).await;
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(snapshot_field(&body), raw);
    }

    let body = mcp_read(&router, &narrow, "oxidhome://events").await;
    assert_eq!(snapshot_field(&body), withheld);
    let body = mcp_read(&router, &with_blobs, "oxidhome://events").await;
    assert_eq!(snapshot_field(&body), raw);
}
