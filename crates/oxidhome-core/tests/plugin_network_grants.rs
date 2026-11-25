//! Phase 8.5: plugin listings show each installation's network rules
//! (requested by the manifest, granted by the operator, effective after
//! narrowing by containment) the same way on every surface: REST,
//! Connect, MCP (resources and tools) and the offline CLI listing.

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

const PLUGIN_ID: &str = "example.net-grants";
const REQUESTED: [&str; 2] = ["tcp://192.168.0.0/16:554", "https://api.example.com"];
/// The operator's grant: one camera out of the requested subnet, and a
/// rule the request doesn't cover (grants nothing).
const GRANTED: [&str; 2] = ["tcp://192.168.1.20:554", "udp://10.0.0.0/8:53"];
const EFFECTIVE: [&str; 1] = ["tcp://192.168.1.20:554"];

fn manifest() -> String {
    let rules = REQUESTED
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"manifest_version = 1
[plugin]
id = "{PLUGIN_ID}"
name = "Network Grants"
version = "0.3.0"
world = "streaming-plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "kv_counter.wasm"
[capabilities]
storage_quota_kb = 4
network = [{rules}]
"#
    )
}

/// Install the plugin, then narrow its persisted grant the way an
/// operator-side edit would, and reopen the engine so the registry
/// reads it back.
fn installed_and_narrowed(state: &support::TempDir) -> Engine {
    let wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let source = support::stage_plugin("net-grants-src", &wasm, "kv_counter.wasm", &manifest());
    {
        let engine = Engine::with_state_dir(state.path()).expect("engine");
        engine
            .installed_plugins()
            .install(source.path())
            .expect("install");
    }
    let db = state.path().join(oxidhome_core::state::db::DB_FILE_NAME);
    let conn = rusqlite::Connection::open(db).expect("open db");
    let grant: String = conn
        .query_row(
            "SELECT granted_capabilities_json FROM plugin_installation WHERE plugin_id = ?1",
            [PLUGIN_ID],
            |row| row.get(0),
        )
        .expect("grant row");
    let mut grant: Value = serde_json::from_str(&grant).expect("grant json");
    assert_eq!(
        grant["network"],
        json!(REQUESTED),
        "install grants the request"
    );
    grant["network"] = json!(GRANTED);
    conn.execute(
        "UPDATE plugin_installation SET granted_capabilities_json = ?1 WHERE plugin_id = ?2",
        (grant.to_string(), PLUGIN_ID),
    )
    .expect("narrow grant");
    drop(conn);
    Engine::with_state_dir(state.path()).expect("reopen engine")
}

fn expected_network() -> Value {
    json!({"requested": REQUESTED, "granted": GRANTED, "effective": EFFECTIVE})
}

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

fn row<'a>(body: &'a Value, field: &str) -> &'a Value {
    body[field]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["plugin_id"] == PLUGIN_ID || r["pluginId"] == PLUGIN_ID)
        })
        .unwrap_or_else(|| panic!("no {PLUGIN_ID} row in {body}"))
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
            "clientInfo": {"name": "net-grants-test", "version": "0"}
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

fn resource_json(response: &Value) -> Value {
    serde_json::from_str(
        response["result"]["contents"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("resource text in {response}")),
    )
    .expect("resource json")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_listing_shows_requested_granted_and_effective_rules() {
    let state = support::tempdir("net-grants");
    let engine = installed_and_narrowed(&state);
    let installed = engine
        .installed_plugins()
        .get(PLUGIN_ID)
        .expect("installed");
    assert_eq!(
        serde_json::to_value(installed.network_grants()).unwrap(),
        expected_network()
    );
    let bearer = engine
        .auth_tokens()
        .create("admin", b"[\"*\"]")
        .unwrap()
        .plaintext;
    let router = build_router(engine.clone());

    // REST, and Connect (JSON codec: proto3 JSON field names).
    let rest = api_json(&router, &bearer, "GET", "/api/v1/plugins", Body::empty()).await;
    assert_eq!(row(&rest, "plugins")["network"], expected_network());
    let connect = api_json(
        &router,
        &bearer,
        "POST",
        "/oxidhome.v1.PluginsService/ListPlugins",
        Body::from("{}"),
    )
    .await;
    assert_eq!(row(&connect, "plugins")["network"], expected_network());

    // MCP: the list and detail resources, and the matching tools.
    let session = mcp_session(&router, &bearer).await;
    let list = mcp_call(
        &router,
        &bearer,
        &session,
        2,
        "resources/read",
        json!({"uri": "oxidhome://plugins"}),
    )
    .await;
    assert_eq!(
        row(&resource_json(&list), "plugins")["network"],
        expected_network()
    );
    let detail = mcp_call(
        &router,
        &bearer,
        &session,
        3,
        "resources/read",
        json!({"uri": format!("oxidhome://plugins/{PLUGIN_ID}")}),
    )
    .await;
    assert_eq!(resource_json(&detail)["network"], expected_network());
    let tool = mcp_call(
        &router,
        &bearer,
        &session,
        4,
        "tools/call",
        json!({"name": "plugins.list", "arguments": {}}),
    )
    .await;
    assert_eq!(
        row(&tool["result"]["structuredContent"], "plugins")["network"],
        expected_network()
    );
    let tool = mcp_call(
        &router,
        &bearer,
        &session,
        5,
        "tools/call",
        json!({"name": "plugins.show", "arguments": {"plugin_id": PLUGIN_ID}}),
    )
    .await;
    assert_eq!(
        tool["result"]["structuredContent"]["network"],
        expected_network()
    );
    drop(router);
    drop(engine);

    // The offline listing (`oxidhome plugin list`) reads the same rules
    // without the registry.
    let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
    let offline =
        oxidhome_core::state::list_installations_offline(&state.path().join("plugins"), &db)
            .expect("offline listing");
    assert_eq!(offline.len(), 1, "{offline:?}");
    assert_eq!(offline[0].plugin_id, PLUGIN_ID);
    let (version, network) = offline[0].status.clone().expect("listed");
    assert_eq!(version, "0.3.0");
    assert_eq!(serde_json::to_value(network).unwrap(), expected_network());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_offline_listing_reports_a_changed_package_without_touching_it() {
    let state = support::tempdir("net-grants-drift");
    drop(installed_and_narrowed(&state));
    let manifest = state
        .path()
        .join("plugins")
        .join(PLUGIN_ID)
        .join("manifest.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, text.replace("0.3.0", "0.3.1")).unwrap();
    let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
    let listing = |db| {
        oxidhome_core::state::list_installations_offline(&state.path().join("plugins"), db)
            .expect("offline listing")
    };
    let offline = listing(&db);
    assert_eq!(offline.len(), 1, "{offline:?}");
    let why = offline[0].status.clone().expect_err("quarantined");
    assert!(why.contains("changed since install"), "{why}");
    // Read-only: the row is still live and listed the same way.
    assert_eq!(listing(&db), offline);
}
