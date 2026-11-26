//! H6 slice 5b: a plugin's sensitive grants (camera bytes, through
//! `reads_state[].sensitive` and `sensitive_event_bytes`) are shown and
//! approved at install. A manifest requesting one installs only when
//! the request approves every category it requests, which is the
//! owner's (`policy.manage`); the listings show what the grant holds.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::{MCP_ENDPOINT, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;

const PLUGIN_ID: &str = "example.nvr";

const MANIFEST: &str = r#"manifest_version = 1
[plugin]
id = "example.nvr"
name = "NVR"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
[capabilities]
subscribes_events = true
reads_event_bytes = true
sensitive_event_bytes = ["camera"]
[[capabilities.reads_state]]
plugin = "*"
capabilities = ["*"]
bytes = true
sensitive = ["camera"]
"#;

async fn api_status(
    router: &axum::Router,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(if body.is_null() {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct Fixture {
    _state: support::TempDir,
    source: support::TempDir,
    _wasm: support::TempDir,
    engine: Engine,
    owner: String,
    installer: String,
    router: axum::Router,
}

/// An engine with the owner token and a non-owner wildcard token
/// (which holds `plugins:install`), and the plugin staged.
fn fixture(prefix: &str) -> Fixture {
    let state = support::tempdir(prefix);
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let issued = oxidhome_core::state::TokenStore::generate();
    assert!(
        engine
            .auth_tokens()
            .insert_owner_if_empty(&issued, "admin", br#"["*"]"#)
            .expect("owner")
    );
    let installer = engine
        .auth_tokens()
        .create("installer", br#"["*"]"#)
        .unwrap()
        .plaintext;
    let wasm = support::tempdir(&format!("{prefix}-wasm"));
    let wasm_path = wasm.path().join("plugin.wasm");
    std::fs::write(&wasm_path, b"\0asm\x01\x00\x00\x00").expect("wasm");
    let source = support::stage_plugin(
        &format!("{prefix}-src"),
        &wasm_path,
        "plugin.wasm",
        MANIFEST,
    );
    let router = build_router(engine.clone());
    Fixture {
        _state: state,
        source,
        _wasm: wasm,
        engine,
        owner: issued.plaintext,
        installer,
        router,
    }
}

fn installed(engine: &Engine) -> bool {
    engine
        .installed_plugins()
        .list()
        .iter()
        .any(|p| &*p.plugin_id == PLUGIN_ID)
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_grants_are_approved_at_install_over_rest() {
    let f = fixture("sensitive-install-rest");
    let source = f.source.path().display().to_string();

    // Not approved: refused, naming the categories; nothing installed.
    for bearer in [&f.owner, &f.installer] {
        let (status, body) = api_status(
            &f.router,
            bearer,
            "POST",
            "/api/v1/plugins",
            json!({"source_dir": source}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body,
            json!({"error": "sensitive_not_approved", "plugin_id": PLUGIN_ID, "categories": ["camera"]})
        );
        assert!(!installed(&f.engine));
    }
    // Approving is the owner's alone.
    let approve = json!({"source_dir": source, "approve_sensitive": ["camera"]});
    let (status, _) = api_status(
        &f.router,
        &f.installer,
        "POST",
        "/api/v1/plugins",
        approve.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!installed(&f.engine));
    // A positional body is refused, not read as an approval.
    let (status, _) = api_status(
        &f.router,
        &f.owner,
        "POST",
        "/api/v1/plugins",
        json!([source, ["camera"]]),
    )
    .await;
    assert!(status.is_client_error(), "{status}");
    assert!(!installed(&f.engine));
    // An unknown category is refused.
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        "/api/v1/plugins",
        json!({"source_dir": source, "approve_sensitive": ["camera", "cameras"]}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    // A token-only category is no plugin grant.
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        "/api/v1/plugins",
        json!({"source_dir": source, "approve_sensitive": ["camera", "lock"]}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(!installed(&f.engine));

    let (status, body) = api_status(&f.router, &f.owner, "POST", "/api/v1/plugins", approve).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sensitive"], json!(["camera"]));
    let (status, list) =
        api_status(&f.router, &f.owner, "GET", "/api/v1/plugins", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["plugins"][0]["sensitive"], json!(["camera"]), "{list}");
    let grant = f
        .engine
        .installed_plugins()
        .list()
        .into_iter()
        .find(|p| &*p.plugin_id == PLUGIN_ID)
        .expect("installed")
        .granted_capabilities;
    assert_eq!(grant.sensitive_event_bytes, ["camera"]);
    assert_eq!(grant.reads_state[0].sensitive, ["camera"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_grants_are_approved_at_install_over_connect() {
    let f = fixture("sensitive-install-connect");
    let uri = "/oxidhome.v1.PluginsService/InstallPlugin";
    let source = f.source.path().display().to_string();
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        uri,
        json!({"sourceDir": source}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "permission_denied", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("camera"),
        "{body}"
    );
    let approve = json!({"sourceDir": source, "approveSensitive": ["camera"]});
    let (status, body) = api_status(&f.router, &f.installer, "POST", uri, approve.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!installed(&f.engine));
    let (status, body) = api_status(&f.router, &f.owner, "POST", uri, approve).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sensitive"], json!(["camera"]), "{body}");
    let (status, list) = api_status(
        &f.router,
        &f.owner,
        "POST",
        "/oxidhome.v1.PluginsService/ListPlugins",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["plugins"][0]["sensitive"], json!(["camera"]), "{list}");
}

// ── MCP plumbing (Streamable HTTP, one SSE frame per call) ─────────

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
        let frame = tokio::time::timeout(Duration::from_secs(30), body.frame())
            .await
            .expect("timed out waiting for SSE frame")
            .expect("stream ended")
            .expect("frame read error");
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.push_str(&String::from_utf8_lossy(&data));
        for line in buf.lines() {
            if let Some(payload) = line.strip_prefix("data:")
                && !payload.trim().is_empty()
                && let Ok(value) = serde_json::from_str(payload.trim())
            {
                return value;
            }
        }
    }
}

async fn mcp_session(router: &axum::Router, bearer: &str) -> String {
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "plugin-sensitive-test", "version": "0"}
        }
    });
    let response = router
        .clone()
        .oneshot(
            mcp_request(bearer)
                .body(Body::from(init.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = first_sse_data(response).await;
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

async fn mcp_call(
    router: &axum::Router,
    bearer: &str,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let response = router
        .clone()
        .oneshot(
            mcp_request(bearer)
                .header("mcp-session-id", session)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "MCP {method}");
    first_sse_data(response).await
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_grants_are_approved_at_install_over_mcp() {
    let f = fixture("sensitive-install-mcp");
    let source = f.source.path().display().to_string();
    let install = |bearer: &str, session: &str, id: u64, arguments: Value| {
        let (router, bearer, session) = (f.router.clone(), bearer.to_owned(), session.to_owned());
        let params = json!({"name": "plugins.install", "arguments": arguments});
        async move { mcp_call(&router, &bearer, &session, id, "tools/call", params).await }
    };
    let owner = mcp_session(&f.router, &f.owner).await;
    let refused = install(&f.owner, &owner, 2, json!({"source_dir": source})).await;
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    assert_eq!(
        refused["result"]["structuredContent"],
        json!({"kind": "sensitive_not_approved", "plugin_id": PLUGIN_ID, "categories": ["camera"]}),
        "{refused}"
    );
    assert!(!installed(&f.engine));
    let approve = json!({"source_dir": source, "approve_sensitive": ["camera"]});
    let installer = mcp_session(&f.router, &f.installer).await;
    let denied = install(&f.installer, &installer, 2, approve.clone()).await;
    assert!(denied["error"].is_object(), "{denied}");
    assert!(!installed(&f.engine));
    let ok = install(&f.owner, &owner, 3, approve).await;
    assert_eq!(
        ok["result"]["structuredContent"]["sensitive"],
        json!(["camera"]),
        "{ok}"
    );
    let shown = mcp_call(
        &f.router,
        &f.owner,
        &owner,
        4,
        "tools/call",
        json!({"name": "plugins.show", "arguments": {"plugin_id": PLUGIN_ID}}),
    )
    .await;
    assert_eq!(
        shown["result"]["structuredContent"]["sensitive"],
        json!(["camera"]),
        "{shown}"
    );
}
