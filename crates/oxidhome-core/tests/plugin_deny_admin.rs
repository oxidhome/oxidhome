//! H6 slice 5: the owner's deny list over a plugin on every surface —
//! REST `GET` / `PUT` / `DELETE /api/v1/plugins/{plugin_id}/deny`,
//! Connect `GetPluginDeny` / `SetPluginDeny` / `ResetPluginDeny`, MCP
//! `plugins.set_deny` / `plugins.reset_deny`, and the offline
//! `oxidhome plugin deny`. Owner only (`policy.manage`), audited with
//! the old and new list, applied to the engine's store at once.

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

const PLUGIN_ID: &str = "example.fenced";

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

/// One authenticated JSON request against the REST / Connect router.
async fn api_json(
    router: &axum::Router,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Body,
) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{method} {uri}");
    json_body(response).await
}

/// One authenticated JSON request; its status and JSON body (`null`
/// when the body isn't JSON).
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
                .body(Body::from(body.to_string()))
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

/// The owner token (`policy.manage`) and a non-owner wildcard token.
fn owner_and_wildcard(engine: &Engine) -> (String, String) {
    let issued = oxidhome_core::state::TokenStore::generate();
    assert!(
        engine
            .auth_tokens()
            .insert_owner_if_empty(&issued, "admin", br#"["*"]"#)
            .expect("owner")
    );
    let wildcard = engine
        .auth_tokens()
        .create("wildcard", br#"["*"]"#)
        .unwrap()
        .plaintext;
    (issued.plaintext, wildcard)
}

/// The audit paths of the deny list changes so far, oldest first.
fn deny_audit_paths(engine: &Engine) -> Vec<String> {
    let mut rows = engine
        .audit_log()
        .query(&oxidhome_core::state::AuditQuery::default(), 1024)
        .expect("audit query");
    rows.sort_by_key(|r| r.id);
    rows.into_iter()
        .filter(|r| r.path.contains(".plugin.deny."))
        .map(|r| {
            assert_eq!(r.decision, "allow", "{r:?}");
            r.path
        })
        .collect()
}

struct Fixture {
    _state: support::TempDir,
    engine: Engine,
    owner: String,
    wildcard: String,
    router: axum::Router,
}

fn fixture(prefix: &str) -> Fixture {
    let state = support::tempdir(prefix);
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let (owner, wildcard) = owner_and_wildcard(&engine);
    let router = build_router(engine.clone());
    Fixture {
        _state: state,
        engine,
        owner,
        wildcard,
        router,
    }
}

/// The list the engine applies, as JSON.
fn applied(engine: &Engine) -> Value {
    json!(
        engine
            .plugin_denies()
            .get(PLUGIN_ID)
            .map_or_else(Vec::new, |l| l
                .iter()
                .map(oxidhome_core::auth::DenyRule::to_json)
                .collect::<Vec<_>>())
    )
}

fn lock_reads() -> Value {
    json!([{"actions": ["blob.read", "state.read"], "category": ["lock"]}])
}

fn detail(old: &Value, new: &Value) -> String {
    json!({"old": old, "new": new}).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_sets_and_resets_a_deny_list_over_rest() {
    let f = fixture("plugin-deny-rest");
    let uri = format!("/api/v1/plugins/{PLUGIN_ID}/deny");
    let body = json!({"deny": lock_reads()});
    let (status, _) = api_status(&f.router, &f.wildcard, "PUT", &uri, body.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api_status(&f.router, &f.wildcard, "GET", &uri, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Refusals: an action a plugin doesn't take, a bad plugin id, an
    // unknown field.
    for (uri, body) in [
        (
            uri.clone(),
            json!({"deny": [{"actions": ["device.command"]}]}),
        ),
        (
            "/api/v1/plugins/fenced/deny".to_owned(),
            json!({"deny": lock_reads()}),
        ),
        (uri.clone(), json!({"deny": [], "extra": 1})),
    ] {
        let (status, got) = api_status(&f.router, &f.owner, "PUT", &uri, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {got}");
    }
    assert_eq!(applied(&f.engine), json!([]));
    let (status, _) = api_status(
        &f.router,
        &f.owner,
        "GET",
        "/api/v1/plugins/fenced/deny",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The plugin isn't installed: the list is set anyway.
    let (status, got) = api_status(&f.router, &f.owner, "PUT", &uri, body).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got, json!({"plugin_id": PLUGIN_ID, "deny": lock_reads()}));
    assert_eq!(applied(&f.engine), lock_reads());
    let shown = api_json(&f.router, &f.owner, "GET", &uri, Body::empty()).await;
    assert_eq!(shown["deny"], lock_reads());
    // A positional body is refused, not read as an empty list.
    for positional in [
        json!([[]]),
        json!({"deny": [[["state.read"], null, null, null]]}),
    ] {
        let (status, got) = api_status(&f.router, &f.owner, "PUT", &uri, positional).await;
        assert!(status.is_client_error(), "{status}: {got}");
        assert_eq!(applied(&f.engine), lock_reads(), "kept");
    }

    // `*` means every plugin action.
    let all = json!({"deny": [{"actions": ["*"]}]});
    let (status, got) = api_status(&f.router, &f.owner, "PUT", &uri, all).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let every =
        json!([{"actions": ["event.subscribe", "blob.read", "service.call", "state.read"]}]);
    assert_eq!(got["deny"], every);

    let (status, got) = api_status(&f.router, &f.owner, "DELETE", &uri, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["deny"], json!([]));
    assert_eq!(applied(&f.engine), json!([]));
    assert_eq!(
        deny_audit_paths(&f.engine),
        [
            format!(
                "api.plugin.deny.set/{PLUGIN_ID}/{}",
                detail(&json!([]), &lock_reads())
            ),
            format!(
                "api.plugin.deny.set/{PLUGIN_ID}/{}",
                detail(&lock_reads(), &every)
            ),
            format!(
                "api.plugin.deny.reset/{PLUGIN_ID}/{}",
                detail(&every, &json!([]))
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_sets_and_resets_a_deny_list_over_connect() {
    let f = fixture("plugin-deny-connect");
    let connect = |rpc: &str| format!("/oxidhome.v1.PluginsService/{rpc}");
    let selector = json!([{"actions": ["blob.read", "state.read"], "category": ["lock"]}]);
    let (status, _) = api_status(
        &f.router,
        &f.wildcard,
        "POST",
        &connect("SetPluginDeny"),
        json!({"pluginId": PLUGIN_ID, "deny": selector}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        &connect("SetPluginDeny"),
        json!({"pluginId": PLUGIN_ID, "deny": [{"actions": ["host.logs"]}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_argument", "{body}");
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        &connect("SetPluginDeny"),
        json!({"pluginId": PLUGIN_ID, "deny": selector}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pluginId"], PLUGIN_ID);
    assert_eq!(body["deny"], selector, "{body}");
    assert_eq!(applied(&f.engine), lock_reads());
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        &connect("GetPluginDeny"),
        json!({"pluginId": PLUGIN_ID}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deny"], selector, "{body}");
    let (status, body) = api_status(
        &f.router,
        &f.owner,
        "POST",
        &connect("ResetPluginDeny"),
        json!({"pluginId": PLUGIN_ID}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(applied(&f.engine), json!([]));
    assert_eq!(
        deny_audit_paths(&f.engine),
        [
            format!(
                "connect.plugin.deny.set/{PLUGIN_ID}/{}",
                detail(&json!([]), &lock_reads())
            ),
            format!(
                "connect.plugin.deny.reset/{PLUGIN_ID}/{}",
                detail(&lock_reads(), &json!([]))
            ),
        ]
    );
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
            "clientInfo": {"name": "plugin-deny-test", "version": "0"}
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
async fn the_owner_sets_and_resets_a_deny_list_over_mcp() {
    let f = fixture("plugin-deny-mcp");
    let call = |bearer: &str, session: &str, id: u64, name: &str, arguments: Value| {
        let (router, bearer, session) = (f.router.clone(), bearer.to_owned(), session.to_owned());
        let params = json!({"name": name, "arguments": arguments});
        async move { mcp_call(&router, &bearer, &session, id, "tools/call", params).await }
    };
    let session = mcp_session(&f.router, &f.wildcard).await;
    let denied = call(
        &f.wildcard,
        &session,
        2,
        "plugins.set_deny",
        json!({"plugin_id": PLUGIN_ID, "deny": lock_reads()}),
    )
    .await;
    assert!(denied["error"].is_object(), "{denied}");

    let session = mcp_session(&f.router, &f.owner).await;
    let tools = mcp_call(&f.router, &f.owner, &session, 2, "tools/list", json!({})).await;
    for name in ["plugins.set_deny", "plugins.reset_deny"] {
        let tool = tools["result"]["tools"]
            .as_array()
            .and_then(|t| t.iter().find(|t| t["name"] == name))
            .unwrap_or_else(|| panic!("{name} in {tools}"));
        assert_eq!(tool["annotations"]["readOnlyHint"], false, "{tool}");
    }
    let bad = call(
        &f.owner,
        &session,
        3,
        "plugins.set_deny",
        json!({"plugin_id": PLUGIN_ID, "deny": [{"actions": ["device.command"]}]}),
    )
    .await;
    assert!(bad["error"].is_object(), "{bad}");
    let set = call(
        &f.owner,
        &session,
        4,
        "plugins.set_deny",
        json!({"plugin_id": PLUGIN_ID, "deny": lock_reads()}),
    )
    .await;
    assert_eq!(
        set["result"]["structuredContent"]["deny"],
        lock_reads(),
        "{set}"
    );
    assert_eq!(applied(&f.engine), lock_reads());
    let reset = call(
        &f.owner,
        &session,
        5,
        "plugins.reset_deny",
        json!({"plugin_id": PLUGIN_ID}),
    )
    .await;
    assert_eq!(
        reset["result"]["structuredContent"]["deny"],
        json!([]),
        "{reset}"
    );
    assert_eq!(applied(&f.engine), json!([]));
    assert_eq!(deny_audit_paths(&f.engine).len(), 2);
}

#[test]
fn the_cli_sets_and_resets_a_deny_list_offline() {
    let state = support::tempdir("plugin-deny-cli");
    // Create the database.
    drop(Engine::with_state_dir(state.path()).expect("engine"));
    let cli = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_oxidhome-core"))
            .arg("plugin")
            .args(args)
            .env("OXIDHOME_STATE_DIR", state.path())
            .output()
            .expect("run oxidhome")
    };
    let out = cli(&["deny", PLUGIN_ID, "state.read,blob.read@lock"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with(&format!("{PLUGIN_ID}\n\tdeny\t")),
        "{stdout}"
    );

    for (args, needle) in [
        (&["deny", PLUGIN_ID, "device.command"][..], "can only name"),
        (&["deny", "fenced", "*"], "not a plugin id"),
        (&["deny", PLUGIN_ID], "usage:"),
        (&["deny", PLUGIN_ID, "--reset", "x"], "usage:"),
    ] {
        let out = cli(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(needle),
            "{args:?}: {out:?}"
        );
    }

    // The daemon's next start loads the list.
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    assert_eq!(applied(&engine), lock_reads());
    drop(engine);
    let out = cli(&["deny", PLUGIN_ID, "--reset"]);
    assert!(out.status.success(), "{out:?}");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    assert_eq!(applied(&engine), json!([]));
    let verbs: Vec<String> = deny_audit_paths(&engine)
        .iter()
        .map(|p| p.split('/').next().unwrap().to_owned())
        .collect();
    assert_eq!(verbs, ["cli.plugin.deny.set", "cli.plugin.deny.reset"]);
}
