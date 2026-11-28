//! Phase 8.5: plugin listings show each installation's network rules
//! (requested by the manifest, granted by the operator, effective after
//! narrowing by containment) the same way on every surface: REST,
//! Connect, MCP (resources and tools) and the offline CLI listing. The
//! owner narrows a grant (or resets it to the request) on the same
//! surfaces; running instances restart under it.

#[path = "support.rs"]
mod support;

use support::Mint;

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

/// Install the plugin (its grant is the request).
fn install(state: &support::TempDir) {
    let wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let source = support::stage_plugin("net-grants-src", &wasm, "kv_counter.wasm", &manifest());
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    engine
        .installed_plugins()
        .install(source.path())
        .expect("install");
}

/// Install the plugin, then narrow its persisted grant by hand (a rule
/// the request doesn't cover included, which the API would refuse), and
/// reopen the engine so the registry reads it back.
fn installed_and_narrowed(state: &support::TempDir) -> Engine {
    install(state);
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

/// The owner token (`policy.manage`) and a non-owner `*` token.
fn owner_and_wildcard(engine: &Engine) -> (String, String) {
    let issued = oxidhome_core::state::TokenStore::generate();
    assert!(
        engine
            .auth_tokens()
            .insert_owner_if_empty(&issued, "admin")
            .expect("owner")
    );
    let wildcard = engine
        .auth_tokens()
        .mint("wildcard", &["*"])
        .unwrap()
        .plaintext;
    (issued.plaintext, wildcard)
}

/// The audit paths of the grant changes recorded so far, oldest first.
fn grant_audit_paths(engine: &Engine) -> Vec<String> {
    let mut rows = engine
        .audit_log()
        .query(&oxidhome_core::state::AuditQuery::default(), 1024)
        .expect("audit query");
    rows.sort_by_key(|r| r.id);
    rows.into_iter()
        .filter(|r| r.path.contains(".plugin.network_grant."))
        .map(|r| {
            assert_eq!(r.decision, "allow", "{r:?}");
            // The row names the caller's kind, whatever the surface.
            let kind = match r.path.split('.').next() {
                Some("cli") => "cli",
                Some("mcp") => "mcp",
                _ => "api",
            };
            assert_eq!(r.actor_kind, kind, "{r:?}");
            r.path
        })
        .collect()
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
        .mint("admin", &["*"])
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

#[tokio::test(flavor = "multi_thread")]
async fn the_offline_listing_flags_what_scan_would_quarantine() {
    let offline = |state: &support::TempDir| {
        let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
        oxidhome_core::state::list_installations_offline(&state.path().join("plugins"), &db)
            .expect("offline listing")
    };
    let reason = |state: &support::TempDir| {
        let listed = offline(state);
        assert_eq!(listed.len(), 1, "{listed:?}");
        listed[0].status.clone().expect_err("quarantined")
    };

    // A second directory claiming the id, even one without its wasm.
    let state = support::tempdir("net-grants-dup");
    drop(installed_and_narrowed(&state));
    let copy = state.path().join("plugins").join(".camera");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(copy.join("manifest.toml"), manifest()).unwrap();
    assert!(reason(&state).contains("more than one package"));

    // The package directory is gone.
    let state = support::tempdir("net-grants-gone");
    drop(installed_and_narrowed(&state));
    std::fs::remove_dir_all(state.path().join("plugins").join(PLUGIN_ID)).unwrap();
    assert!(reason(&state).contains("no readable package"));

    // The persisted grant is unusable.
    let state = support::tempdir("net-grants-null");
    drop(installed_and_narrowed(&state));
    let db = state.path().join(oxidhome_core::state::db::DB_FILE_NAME);
    rusqlite::Connection::open(db)
        .unwrap()
        .execute(
            "UPDATE plugin_installation SET granted_capabilities_json = NULL",
            [],
        )
        .unwrap();
    assert!(reason(&state).contains("grant or content digest"));
}

#[test]
fn the_cli_prints_the_listing_and_rejects_bad_arguments() {
    let state = support::tempdir("net-grants-cli");
    drop(installed_and_narrowed(&state));
    let cli = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_oxidhome-core"))
            .args(args)
            .env("OXIDHOME_STATE_DIR", state.path())
            .output()
            .expect("run oxidhome")
    };
    let out = cli(&["plugin".as_ref(), "list".as_ref()]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = stdout.lines();
    assert!(
        lines
            .next()
            .is_some_and(|l| l.starts_with(&format!("{PLUGIN_ID}\t0.3.0\tinstallation=inst-"))),
        "{stdout}"
    );
    let rules: Vec<&str> = lines.collect();
    let expected: Vec<String> = [
        ("requested", &REQUESTED[..]),
        ("granted", &GRANTED[..]),
        ("effective", &EFFECTIVE[..]),
    ]
    .iter()
    .flat_map(|(tag, rules)| rules.iter().map(move |r| format!("\t{tag}\t{r}")))
    .collect();
    assert_eq!(rules, expected);

    let out = cli(&["plugin".as_ref(), "lst".as_ref()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: oxidhome plugin list"));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let out = cli(&["plugin".as_ref(), std::ffi::OsStr::from_bytes(b"\xff")]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage: oxidhome plugin list"));
    }
}

fn network(granted: &[&str]) -> Value {
    json!({"requested": REQUESTED, "granted": granted, "effective": granted})
}

/// An installed plugin (grant = request), the owner and a wildcard
/// token, and a router.
struct Granting {
    state: support::TempDir,
    engine: Engine,
    owner: String,
    wildcard: String,
    router: axum::Router,
}

fn granting(prefix: &str) -> Granting {
    let state = support::tempdir(prefix);
    install(&state);
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let (owner, wildcard) = owner_and_wildcard(&engine);
    let router = build_router(engine.clone());
    Granting {
        state,
        engine,
        owner,
        wildcard,
        router,
    }
}

impl Granting {
    /// The audit path detail of a change from `old` to `new`.
    fn detail(&self, old: &[&str], new: &[&str]) -> String {
        let uuid = self
            .engine
            .installed_plugins()
            .get(PLUGIN_ID)
            .unwrap()
            .installation_uuid;
        let rule = |r: &&str| r.parse::<oxidhome_manifest::NetworkRule>().unwrap();
        oxidhome_core::state::NetworkGrantChange {
            installation_uuid: uuid,
            old: old.iter().map(rule).collect(),
            network: oxidhome_core::state::NetworkGrants::new(
                &[],
                &new.iter().map(rule).collect::<Vec<_>>(),
            ),
        }
        .audit_detail()
    }

    async fn listed(&self) -> Value {
        let rest = api_json(
            &self.router,
            &self.owner,
            "GET",
            "/api/v1/plugins",
            Body::empty(),
        )
        .await;
        row(&rest, "plugins")["network"].clone()
    }
}

const CAMERA: [&str; 1] = ["tcp://192.168.1.20:554"];
const API: [&str; 1] = ["https://api.example.com"];

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_narrows_and_resets_the_grant_over_rest() {
    let g = granting("net-grants-rest");
    let uri = format!("/api/v1/plugins/{PLUGIN_ID}/network-grant");
    let put = |bearer: &str, body: Value| {
        let (router, uri, bearer) = (g.router.clone(), uri.clone(), bearer.to_owned());
        async move { api_status(&router, &bearer, "PUT", &uri, body).await }
    };

    // Owner only.
    let (status, _) = put(&g.wildcard, json!({"rules": CAMERA})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api_status(&g.router, &g.wildcard, "DELETE", &uri, Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = put(&g.owner, json!({"rules": CAMERA})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"plugin_id": PLUGIN_ID, "network": network(&CAMERA), "restarted": [], "not_restarted": []})
    );
    assert_eq!(g.listed().await, network(&CAMERA));

    // Widening, a rule only partly inside the request, a rule that
    // doesn't parse, an unknown field, an unknown plugin: refused, and
    // the grant is unchanged.
    for (rules, error) in [
        (json!(["udp://10.0.0.0/8:53"]), "widens_request"),
        (json!(["tcp://192.168.0.0/15:554"]), "widens_request"),
        (json!(["tcp://192.168.1.20:1-1000"]), "widens_request"),
        (json!(["not a rule"]), "bad_request"),
    ] {
        let (status, body) = put(&g.owner, json!({"rules": rules})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rules}: {body}");
        assert_eq!(body["error"], error, "{rules}: {body}");
    }
    let (status, _) = put(&g.owner, json!({"rules": [], "all": true})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api_status(
        &g.router,
        &g.owner,
        "PUT",
        "/api/v1/plugins/example.missing/network-grant",
        json!({"rules": []}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(g.listed().await, network(&CAMERA));

    // Every change is audited with the old and new grant; refusals
    // aren't.
    let (status, body) = api_status(&g.router, &g.owner, "DELETE", &uri, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["network"], expected_reset());
    assert_eq!(
        grant_audit_paths(&g.engine),
        [
            format!(
                "api.plugin.network_grant.set/{PLUGIN_ID}/{}",
                g.detail(&REQUESTED, &CAMERA)
            ),
            format!(
                "api.plugin.network_grant.reset/{PLUGIN_ID}/{}",
                g.detail(&CAMERA, &REQUESTED)
            ),
        ]
    );

    // A restart of the engine (a rescan) keeps the grant.
    let (status, _) = put(&g.owner, json!({"rules": API})).await;
    assert_eq!(status, StatusCode::OK);
    let Granting {
        state,
        engine,
        router,
        ..
    } = g;
    drop(router);
    drop(engine);
    // Only `network` changed in the stored grant.
    let grant: String =
        rusqlite::Connection::open(state.path().join(oxidhome_core::state::db::DB_FILE_NAME))
            .unwrap()
            .query_row(
                "SELECT granted_capabilities_json FROM plugin_installation WHERE plugin_id = ?1",
                [PLUGIN_ID],
                |row| row.get(0),
            )
            .unwrap();
    let grant: Value = serde_json::from_str(&grant).unwrap();
    assert_eq!(grant["storage_quota_kb"], 4, "{grant}");
    assert_eq!(grant["network"], json!(API), "{grant}");
    let engine = Engine::with_state_dir(state.path()).expect("reopen engine");
    assert_eq!(
        serde_json::to_value(
            engine
                .installed_plugins()
                .get(PLUGIN_ID)
                .unwrap()
                .network_grants()
        )
        .unwrap(),
        network(&API)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_narrows_and_resets_the_grant_over_connect() {
    let g = granting("net-grants-connect");
    let connect = |rpc: &str| format!("/oxidhome.v1.PluginsService/{rpc}");
    let (status, _) = api_status(
        &g.router,
        &g.wildcard,
        "POST",
        &connect("ResetPluginNetworkGrant"),
        json!({"pluginId": PLUGIN_ID}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // JSON with an unknown key or a `null` is refused before anything
    // is stored. (The proto name `plugin_id` is accepted below.)
    for body in [
        json!({"plugin_id": PLUGIN_ID, "rule": []}),
        json!({"pluginId": PLUGIN_ID, "rules": null}),
        json!([PLUGIN_ID, null]),
    ] {
        let (status, reply) = api_status(
            &g.router,
            &g.owner,
            "POST",
            &connect("SetPluginNetworkGrant"),
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {reply}");
        assert_eq!(reply["code"], "invalid_argument", "{body}: {reply}");
    }
    assert_eq!(grant_audit_paths(&g.engine), Vec::<String>::new());
    // A caller without `policy.manage` is denied first.
    let (status, _) = api_status(
        &g.router,
        &g.wildcard,
        "POST",
        &connect("SetPluginNetworkGrant"),
        json!({"pluginId": PLUGIN_ID, "rule": []}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = api_status(
        &g.router,
        &g.owner,
        "POST",
        &connect("SetPluginNetworkGrant"),
        json!({"pluginId": PLUGIN_ID, "rules": ["udp://10.0.0.0/8:53"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_argument", "{body}");
    let (status, body) = api_status(
        &g.router,
        &g.owner,
        "POST",
        &connect("SetPluginNetworkGrant"),
        json!({"pluginId": "example.missing", "rules": []}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = api_status(
        &g.router,
        &g.owner,
        "POST",
        &connect("SetPluginNetworkGrant"),
        json!({"plugin_id": PLUGIN_ID, "rules": API}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["change"]["network"], network(&API));
    let listed = api_json(
        &g.router,
        &g.owner,
        "POST",
        &connect("ListPlugins"),
        Body::from("{}"),
    )
    .await;
    assert_eq!(row(&listed, "plugins")["network"], network(&API));
    let (status, body) = api_status(
        &g.router,
        &g.owner,
        "POST",
        &connect("ResetPluginNetworkGrant"),
        json!({"pluginId": PLUGIN_ID}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["change"]["network"], expected_reset());
    assert_eq!(
        grant_audit_paths(&g.engine),
        [
            format!(
                "connect.plugin.network_grant.set/{PLUGIN_ID}/{}",
                g.detail(&REQUESTED, &API)
            ),
            format!(
                "connect.plugin.network_grant.reset/{PLUGIN_ID}/{}",
                g.detail(&API, &REQUESTED)
            ),
        ]
    );
}

/// Both grant tools are listed as writes.
fn assert_write_annotations(tools: &Value) {
    for name in ["plugins.set_network_grant", "plugins.reset_network_grant"] {
        let tool = tools["result"]["tools"]
            .as_array()
            .and_then(|t| t.iter().find(|t| t["name"] == name))
            .unwrap_or_else(|| panic!("{name} in {tools}"));
        assert_eq!(tool["annotations"]["readOnlyHint"], false, "{tool}");
        assert_eq!(tool["annotations"]["destructiveHint"], true, "{tool}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_narrows_and_resets_the_grant_over_mcp() {
    let g = granting("net-grants-mcp");
    let call = |bearer: &str, session: &str, id: u64, name: &str, arguments: Value| {
        let (router, bearer, session) = (g.router.clone(), bearer.to_owned(), session.to_owned());
        let params = json!({"name": name, "arguments": arguments});
        async move { mcp_call(&router, &bearer, &session, id, "tools/call", params).await }
    };
    let session = mcp_session(&g.router, &g.wildcard).await;
    let denied = call(
        &g.wildcard,
        &session,
        2,
        "plugins.set_network_grant",
        json!({"plugin_id": PLUGIN_ID, "rules": []}),
    )
    .await;
    assert!(denied["error"].is_object(), "{denied}");

    let session = mcp_session(&g.router, &g.owner).await;
    let tools = mcp_call(&g.router, &g.owner, &session, 2, "tools/list", json!({})).await;
    assert_write_annotations(&tools);
    let widened = call(
        &g.owner,
        &session,
        3,
        "plugins.set_network_grant",
        json!({"plugin_id": PLUGIN_ID, "rules": ["udp://10.0.0.0/8:53"]}),
    )
    .await;
    assert!(widened["error"].is_object(), "{widened}");
    let extra = call(
        &g.owner,
        &session,
        7,
        "plugins.reset_network_grant",
        json!({"plugin_id": PLUGIN_ID, "rules": null}),
    )
    .await;
    assert!(extra["error"].is_object(), "{extra}");
    let missing = call(
        &g.owner,
        &session,
        8,
        "plugins.reset_network_grant",
        json!({"plugin_id": "example.missing"}),
    )
    .await;
    let result = &missing["result"];
    assert_eq!(result["isError"], true, "{missing}");
    assert_eq!(result["structuredContent"]["kind"], "not_installed");
    let set = call(
        &g.owner,
        &session,
        4,
        "plugins.set_network_grant",
        json!({"plugin_id": PLUGIN_ID, "rules": []}),
    )
    .await;
    assert_eq!(
        set["result"]["structuredContent"]["network"],
        network(&[]),
        "{set}"
    );
    let shown = call(
        &g.owner,
        &session,
        5,
        "plugins.show",
        json!({"plugin_id": PLUGIN_ID}),
    )
    .await;
    assert_eq!(
        shown["result"]["structuredContent"]["network"],
        network(&[])
    );
    let undone = call(
        &g.owner,
        &session,
        6,
        "plugins.reset_network_grant",
        json!({"plugin_id": PLUGIN_ID}),
    )
    .await;
    assert_eq!(
        undone["result"]["structuredContent"]["network"],
        expected_reset(),
        "{undone}"
    );
    assert_eq!(
        grant_audit_paths(&g.engine),
        [
            format!(
                "mcp.plugin.network_grant.set/{PLUGIN_ID}/{}",
                g.detail(&REQUESTED, &[])
            ),
            format!(
                "mcp.plugin.network_grant.reset/{PLUGIN_ID}/{}",
                g.detail(&[], &REQUESTED)
            ),
        ]
    );
}

fn expected_reset() -> Value {
    json!({"requested": REQUESTED, "granted": REQUESTED, "effective": REQUESTED})
}

/// A TCP server that answers each connection's first line with `pong`
/// and counts connections.
struct LineServer {
    port: u16,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl LineServer {
    fn start() -> Self {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = std::sync::Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut line = String::new();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let _ = reader.read_line(&mut line);
                let _ = stream.write_all(b"pong\n");
            }
        });
        Self { port, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    // Generous: the whole workspace suite may be loading wasm at once.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !done() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The grant change restarted `probe`: it ran within the change's wait
/// limit, or (on a loaded machine) was still starting when it ended,
/// which the caller's next wait covers.
fn assert_restarted(body: &Value) {
    if body["restarted"] == json!(["probe"]) {
        assert_eq!(body["not_restarted"], json!([]), "{body}");
        return;
    }
    assert_eq!(body["restarted"], json!([]), "{body}");
    let slow = &body["not_restarted"][0];
    assert_eq!(slow["instance_id"], "probe", "{body}");
    assert!(
        slow["reason"]
            .as_str()
            .is_some_and(|r| r.contains("still starting")),
        "{body}"
    );
}

/// A net-probe manifest requesting `rules`.
fn probe_manifest(id: &str, allowed: &str, elsewhere: &str) -> String {
    format!(
        r#"manifest_version = 1
[plugin]
id = "{id}"
name = "Net Probe"
version = "0.1.0"
world = "streaming-plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "net_probe.wasm"
[capabilities]
storage_quota_kb = 16
network = ["{allowed}", "{elsewhere}"]
[config.ops]
type = "string"
default = ""
"#
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_change_restarts_running_instances_with_their_config() {
    const PROBE: &str = "example.net-probe";
    let server = LineServer::start();
    let allowed = format!("tcp://127.0.0.1:{}", server.port);
    // Another port the request covers, so the grant can move off the
    // server's.
    let elsewhere = format!("tcp://127.0.0.1:{}", server.port.wrapping_add(1).max(1));
    let manifest = probe_manifest(PROBE, &allowed, &elsewhere);
    let wasm = support::build_example("net-probe", "net_probe.wasm");
    let source = support::stage_plugin("net-grants-probe", &wasm, "net_probe.wasm", &manifest);
    let state = support::tempdir("net-grants-restart");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    engine
        .installed_plugins()
        .install(source.path())
        .expect("install");
    let (owner, _) = owner_and_wildcard(&engine);
    let router = build_router(engine.clone());

    // The instance's config tells it what to connect to on init.
    let ops = format!("tcp 127.0.0.1:{}", server.port);
    let (status, body) = api_status(
        &router,
        &owner,
        "POST",
        &format!("/api/v1/plugins/{PROBE}/start"),
        json!({"instance_id": "probe", "config_overrides": {"ops": ops}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    wait_until("the first connect", || server.accepted() == 1).await;

    // Narrowed off the server's port: the instance restarts, runs its
    // init with the same config, and the connect is refused.
    let uri = format!("/api/v1/plugins/{PROBE}/network-grant");
    let (status, body) =
        api_status(&router, &owner, "PUT", &uri, json!({"rules": [elsewhere]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_restarted(&body);
    let target = format!("127.0.0.1:{}", server.port);
    wait_until("the refused connect", || {
        engine
            .audit_log()
            .query(&oxidhome_core::state::AuditQuery::default(), 1024)
            .expect("audit")
            .iter()
            .any(|r| {
                r.method == "NET"
                    && r.decision == "deny"
                    && r.path.contains("/probe/")
                    && r.path.contains(&target)
            })
    })
    .await;
    assert_eq!(server.accepted(), 1);
    let handle = engine
        .instances()
        .list()
        .into_iter()
        .find(|h| h.instance_id() == "probe")
        .expect("restarted instance registered");
    assert!(!handle.state().is_terminal(), "{:?}", handle.state());
    // The same grant again, or the same rules in another order,
    // changes nothing instances get: no restart.
    let (status, body) =
        api_status(&router, &owner, "PUT", &uri, json!({"rules": [elsewhere]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["restarted"], json!([]), "{body}");

    // Reset: restarted again, and the connect goes through.
    let (status, body) = api_status(&router, &owner, "DELETE", &uri, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_restarted(&body);
    wait_until("the connect after the reset", || server.accepted() == 2).await;
    let (status, body) = api_status(
        &router,
        &owner,
        "PUT",
        &uri,
        json!({"rules": [elsewhere, allowed]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["restarted"], json!([]), "reordered: {body}");

    // A restart that fails (the package changed on disk) keeps the
    // stored grant and names the instance in `not_restarted`.
    let installed = engine.installed_plugins().get(PROBE).expect("installed");
    let manifest_path = installed.path.join("manifest.toml");
    let text = std::fs::read_to_string(&manifest_path).unwrap();
    std::fs::write(&manifest_path, text.replace("0.1.0", "0.1.1")).unwrap();
    let (status, body) =
        api_status(&router, &owner, "PUT", &uri, json!({"rules": [elsewhere]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["restarted"], json!([]), "{body}");
    assert_eq!(body["not_restarted"][0]["instance_id"], "probe", "{body}");
    assert_eq!(body["network"]["granted"], json!([elsewhere]), "{body}");
    let _ = oxidhome_core::runtime::stop_and_wait_reaped(
        engine.instances().list(),
        Duration::from_secs(10),
    )
    .await;
}

#[test]
fn the_cli_sets_and_resets_the_grant_offline() {
    let state = support::tempdir("net-grants-cli-grant");
    install(&state);
    let cli = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_oxidhome-core"))
            .arg("plugin")
            .args(args)
            .env("OXIDHOME_STATE_DIR", state.path())
            .output()
            .expect("run oxidhome")
    };
    let out = cli(&["grant", PLUGIN_ID, "tcp://192.168.1.20:554"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with(&format!("{PLUGIN_ID}\tinstallation=inst-")),
        "{stdout}"
    );
    assert!(
        stdout.contains("\tgranted\ttcp://192.168.1.20:554\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\teffective\ttcp://192.168.1.20:554\n"),
        "{stdout}"
    );

    // Refusals: widening, a bad rule, an unknown plugin, bad usage.
    let out = cli(&["grant", PLUGIN_ID, "udp://10.0.0.0/8:53"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not within the plugin's requested"),
        "{out:?}"
    );
    let out = cli(&["grant", PLUGIN_ID, "nope"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a network rule"),
        "{out:?}"
    );
    let out = cli(&["grant", "example.missing", "--none"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not installed"),
        "{out:?}"
    );
    for args in [
        &["grant", PLUGIN_ID][..],
        &["grant", PLUGIN_ID, "--reset", "x"],
        &["grant"],
    ] {
        let out = cli(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage:"),
            "{args:?}: {out:?}"
        );
    }

    let listed = |state: &support::TempDir| {
        let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
        let listing =
            oxidhome_core::state::list_installations_offline(&state.path().join("plugins"), &db)
                .expect("offline listing");
        serde_json::to_value(listing[0].status.clone().expect("listed").1).unwrap()
    };
    assert_eq!(listed(&state), network(&["tcp://192.168.1.20:554"]));
    let out = cli(&["grant", PLUGIN_ID, "--none"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(listed(&state), network(&[]));
    let out = cli(&["grant", PLUGIN_ID, "--reset"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(listed(&state), expected_reset());

    // The daemon's next start loads the grant; each change was audited.
    let out = cli(&["grant", PLUGIN_ID, "https://api.example.com"]);
    assert!(out.status.success(), "{out:?}");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    assert_eq!(
        serde_json::to_value(
            engine
                .installed_plugins()
                .get(PLUGIN_ID)
                .unwrap()
                .network_grants()
        )
        .unwrap(),
        network(&["https://api.example.com"])
    );
    let paths = grant_audit_paths(&engine);
    let verbs: Vec<&str> = paths.iter().map(|p| p.split('/').next().unwrap()).collect();
    assert_eq!(
        verbs,
        [
            "cli.plugin.network_grant.set",
            "cli.plugin.network_grant.set",
            "cli.plugin.network_grant.reset",
            "cli.plugin.network_grant.set",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_offline_grant_refuses_a_changed_package() {
    let state = support::tempdir("net-grants-cli-drift");
    install(&state);
    let manifest = state
        .path()
        .join("plugins")
        .join(PLUGIN_ID)
        .join("manifest.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, text.replace("0.3.0", "0.3.1")).unwrap();
    let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
    let err = oxidhome_core::state::plan_network_grant_offline(
        &state.path().join("plugins"),
        &db,
        PLUGIN_ID,
        None,
    )
    .expect_err("changed package");
    assert!(err.to_string().contains("changed since install"), "{err}");
}
