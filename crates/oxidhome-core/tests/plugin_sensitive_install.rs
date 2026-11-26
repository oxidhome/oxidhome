//! H6 slice 5b: a plugin's sensitive grants (camera bytes, through
//! `reads_state[].sensitive` and `sensitive_event_bytes`) are shown and
//! approved at install. A manifest requesting one installs only when
//! the request approves every category it requests, which is the
//! owner's (`policy.manage`); the listings show what the grant holds.

#[path = "support.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use oxidhome_core::Engine;
use oxidhome_core::api::build_router;
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
