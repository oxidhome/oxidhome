//! Tokens minted by role, end to end.
//!
//! The owner mints role tokens over REST and Connect (and the offline
//! CLI); nobody else can. A `dashboard` token lists, reads and commands
//! light devices only: a `simulated-switch` device is a `switch` until
//! the owner raises it to `light`, then a `lock`. Only a role grant
//! naming `lock` reaches it then.

#[path = "support.rs"]
mod support;

use support::Mint;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use oxidhome_core::Engine;
use oxidhome_core::api::{build_router, ensure_admin_token};
use oxidhome_core::state::AuditQuery;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    bearer: &str,
    body: &str,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method(method)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, json)
}

const TOGGLE: &str = r#"{"capability":"switch","action":"toggle","args":[]}"#;

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn role_tokens_minted_by_the_owner_reach_only_their_devices() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let state = support::tempdir("token-roles");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let owner = ensure_admin_token(&engine.auth_tokens(), &engine.audit_log(), state.path())
        .expect("bootstrap")
        .expect("first run mints the owner token");
    let handle = engine
        .start_instance(dir, "switch", None)
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let device = engine
        .devices()
        .list()
        .into_iter()
        .find(|m| m.owner_instance == "switch")
        .expect("device")
        .id
        .clone();
    let command_uri = format!("/api/v1/devices/{device}/command");
    let state_uri = format!("/api/v1/devices/{device}/state");
    let category_uri = format!("/api/v1/devices/{device}/category");
    let router = build_router(engine.clone());

    // Only the owner defines roles and mints; `admin` can't, and
    // neither list nor body shape leaks to it.
    let admin = engine.auth_tokens().create("ha", &["admin"]).unwrap();
    let read = json!([
        "device.list",
        "device.read",
        "event.read",
        "event.subscribe",
        "instance.read",
        "plugin.read",
        "host.status",
        "dashboard.read"
    ]);
    let roles = [
        json!({"name": "dashboard", "grants": [
            {"actions": ["device.list", "device.read", "device.command"], "category": ["light"]}]}),
        json!({"name": "monitor", "grants": [{"actions": read}]}),
        json!({"name": "assistant",
            "grants": [{"actions": read}, {"actions": ["device.command"], "category": ["light"]}]}),
        json!({"name": "resident", "grants": [{"actions": read},
            {"actions": ["device.command", "blob.read"]}]}),
    ];
    let (status, _) = send(
        &router,
        "POST",
        "/api/v1/roles",
        &admin.plaintext,
        &roles[0].to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&router, "GET", "/api/v1/roles", &admin.plaintext, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for role in &roles {
        let (status, body) = send(
            &router,
            "POST",
            "/api/v1/roles",
            &owner.plaintext,
            &role.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{role}: {body}");
    }
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/roles",
        &owner.plaintext,
        &roles[0].to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    for bad in [
        json!({"name": "owner", "grants": []}),
        json!({"name": "member", "grants": []}),
        json!({"name": "x", "grants": [{"actions": ["token.manage"]}]}),
        json!({"name": "x", "grants": [], "deny": []}),
        json!({"name": "x", "grants": [{"actions": ["device.read"], "category": ["door"]}]}),
    ] {
        let (status, body) = send(
            &router,
            "POST",
            "/api/v1/roles",
            &owner.plaintext,
            &bad.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let mint = json!({"label": "hall tablet", "roles": ["dashboard"]}).to_string();
    let (status, _) = send(&router, "POST", "/api/v1/tokens", &admin.plaintext, &mint).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&router, "POST", "/api/v1/tokens", &admin.plaintext, "{").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&router, "GET", "/api/v1/tokens", &admin.plaintext, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, created) = send(&router, "POST", "/api/v1/tokens", &owner.plaintext, &mint).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["roles"], json!(["dashboard"]));
    assert_eq!(created["owner"], false);
    let dashboard = created["token"].as_str().expect("secret").to_owned();
    let dashboard_id = created["token_id"].as_str().unwrap().to_owned();

    // Bad requests are 400s with a reason, and store nothing.
    for bad in [
        json!({"label": "x", "roles": ["owner"]}),
        json!({"label": "x", "roles": ["nope"]}),
        json!({"label": "admin", "roles": ["monitor"]}),
        json!({"label": "x", "roles": ["monitor"], "extra": 1}),
        json!({"label": "x", "roles": ["monitor"], "scopes": ["*"]}),
        json!({"label": "x", "roles": []}),
    ] {
        let (status, body) = send(
            &router,
            "POST",
            "/api/v1/tokens",
            &owner.plaintext,
            &bad.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    let (status, list) = send(&router, "GET", "/api/v1/tokens", &owner.plaintext, "").await;
    assert_eq!(status, StatusCode::OK);
    let rows = list["tokens"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{list}");
    assert_eq!(rows[0]["owner"], true);
    assert_eq!(rows[0]["roles"], json!([]));
    let row = rows.iter().find(|r| r["token_id"] == dashboard_id).unwrap();
    assert_eq!(row["label"], "hall tablet");
    assert!(
        row.get("token").is_none(),
        "a listing never carries a secret"
    );

    // The device is a `switch`: the dashboard token sees nothing of it.
    let (status, body) = send(&router, "GET", "/api/v1/devices", &dashboard, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["devices"], json!([]));
    let (status, _) = send(&router, "GET", &state_uri, &dashboard, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&router, "POST", &command_uri, &dashboard, TOGGLE).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Outside its role entirely.
    let (status, _) = send(&router, "GET", "/api/v1/logs", &dashboard, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The whole state feed releases every device: never for a role
    // narrowed to categories.
    let (status, _) = send(&router, "GET", "/api/v1/devices/state", &dashboard, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Connect filters and refuses the same way.
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.DevicesService/ListDevices",
        &dashboard,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains(&device), "{body}");
    let connect_toggle =
        json!({"deviceId": device, "capability": "switch", "action": "toggle"}).to_string();
    let (status, _) = send(
        &router,
        "POST",
        "/oxidhome.v1.DevicesService/ExecuteCommand",
        &dashboard,
        &connect_toggle,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Raised to `light`, it is listed, readable and commandable.
    let (status, _) = send(
        &router,
        "PUT",
        &category_uri,
        &owner.plaintext,
        r#"{"category":"light"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&router, "GET", "/api/v1/devices", &dashboard, "").await;
    assert_eq!(body["devices"][0]["device_id"], device, "{body}");
    let (status, _) = send(&router, "GET", &state_uri, &dashboard, "").await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(&router, "POST", &command_uri, &dashboard, TOGGLE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.DevicesService/ListDevices",
        &dashboard,
        "{}",
    )
    .await;
    assert!(body.to_string().contains(&device), "{body}");
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.DevicesService/ExecuteCommand",
        &dashboard,
        &connect_toggle,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An assistant can't command a lock: no grant of its role names it.
    let (_, created) = send(
        &router,
        "POST",
        "/api/v1/tokens",
        &owner.plaintext,
        &json!({"label": "llm", "roles": ["assistant"]}).to_string(),
    )
    .await;
    let assistant = created["token"].as_str().unwrap().to_owned();
    let (status, _) = send(&router, "POST", &command_uri, &assistant, TOGGLE).await;
    assert_eq!(status, StatusCode::OK, "a light is in the assistant's role");
    let (status, _) = send(
        &router,
        "PUT",
        &category_uri,
        &owner.plaintext,
        r#"{"category":"lock"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, "POST", &command_uri, &assistant, TOGGLE).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let denied = engine
        .audit_log()
        .query(
            &AuditQuery {
                path: Some(command_uri.clone()),
                decision: Some("deny".into()),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert!(
        denied
            .iter()
            .any(|r| r.required_scope.as_deref() == Some("device.command")),
        "{denied:?}"
    );

    // A resident reaches it once its role names `lock`.
    let (_, created) = send(
        &router,
        "POST",
        "/api/v1/tokens",
        &owner.plaintext,
        &json!({"label": "me", "roles": ["resident"]}).to_string(),
    )
    .await;
    let resident = created["token"].as_str().unwrap().to_owned();
    let (status, _) = send(&router, "POST", &command_uri, &resident, TOGGLE).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no grant names lock yet");
    let resident_id = created["token_id"].as_str().unwrap().to_owned();

    // Tokens hold a role by name: an edit applies from the next request.
    let (status, body) = send(
        &router,
        "PUT",
        "/api/v1/roles/resident",
        &owner.plaintext,
        &json!({"grants": [{"actions": read},
            {"actions": ["device.command"], "category": ["lock"]}]})
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(&router, "POST", &command_uri, &resident, TOGGLE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &router,
        "PUT",
        "/api/v1/roles/resident",
        &owner.plaintext,
        &json!({"grants": [{"actions": read}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tokens"], json!([resident_id]));
    let (status, _) = send(&router, "POST", &command_uri, &resident, TOGGLE).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the edit took effect");
    let (status, _) = send(&router, "GET", "/api/v1/devices", &resident, "").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        "PUT",
        "/api/v1/roles/nope",
        &owner.plaintext,
        r#"{"grants":[]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A held role can't be deleted; built-in roles can't be at all.
    let (status, body) = send(
        &router,
        "DELETE",
        "/api/v1/roles/resident",
        &owner.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = send(
        &router,
        "DELETE",
        "/api/v1/roles/admin",
        &owner.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, list) = send(&router, "GET", "/api/v1/roles", &owner.plaintext, "").await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = list["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "admin",
            "member",
            "guest",
            "agent",
            "assistant",
            "dashboard",
            "monitor",
            "resident"
        ]
    );
    let audit = engine
        .audit_log()
        .query(&AuditQuery::default(), 200)
        .unwrap();
    for path in [
        "api.auth.role.create:dashboard",
        "api.auth.role.update:resident",
    ] {
        assert!(audit.iter().any(|r| r.path == path), "{path}");
    }

    // Each mint left its own audit row naming the new token.
    let mints = engine
        .audit_log()
        .query(
            &AuditQuery {
                token_id: Some(dashboard_id.clone()),
                ..AuditQuery::default()
            },
            50,
        )
        .unwrap();
    let mint = mints
        .iter()
        .find(|r| r.path == "api.auth.mint:dashboard")
        .unwrap_or_else(|| panic!("{mints:?}"));
    assert!(
        mint.call_id
            .as_deref()
            .is_some_and(|c| c.starts_with("call-")),
        "the mint row joins the request: {mint:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn connect_tokens_service_is_owner_only() {
    let state = support::tempdir("token-roles-connect");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let owner = ensure_admin_token(&engine.auth_tokens(), &engine.audit_log(), state.path())
        .expect("bootstrap")
        .expect("owner");
    let wildcard = engine.auth_tokens().mint("ha", &["*"]).unwrap();
    let router = build_router(engine.clone());
    let visitor = json!({"name": "visitor", "grants": [
        {"actions": ["device.list", "device.read", "device.command"],
         "category": {"names": ["light", "media", "climate"]}}]})
    .to_string();
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/CreateRole",
        &wildcard.plaintext,
        &visitor,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/CreateRole",
        &owner.plaintext,
        &visitor,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"]["name"], "visitor");
    assert_eq!(
        body["role"]["grants"],
        json!(["device.list,device.read,device.command@light,media,climate"])
    );
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/CreateRole",
        &owner.plaintext,
        &visitor,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "already_exists");
    let create = json!({"label": "wall", "roles": ["visitor"]}).to_string();

    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.TokensService/CreateToken",
        &wildcard.plaintext,
        &create,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "permission_denied");

    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.TokensService/CreateToken",
        &owner.plaintext,
        &create,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = body["secret"].as_str().expect("secret");
    assert_eq!(body["token"]["roles"], json!(["visitor"]));
    let rec = engine.auth_tokens().verify(secret).expect("verifies");
    assert!(!rec.owner);

    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.TokensService/CreateToken",
        &owner.plaintext,
        &json!({"label": "x", "roles": ["owner"]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_argument");

    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.TokensService/ListTokens",
        &owner.plaintext,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tokens"].as_array().unwrap().len(), 3);
    let (status, _) = send(
        &router,
        "POST",
        "/oxidhome.v1.TokensService/ListTokens",
        secret,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Roles: list, update, delete (refused while held).
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/ListRoles",
        &owner.plaintext,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let visitor_row = body["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "visitor")
        .expect("visitor listed");
    assert_eq!(visitor_row["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(body["roles"][0]["builtin"], true);
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/UpdateRole",
        &owner.plaintext,
        &json!({"name": "visitor", "grants": [{"actions": ["device.list"]}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"]["grants"], json!(["device.list"]));
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/UpdateRole",
        &owner.plaintext,
        &json!({"name": "nope", "grants": []}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/DeleteRole",
        &owner.plaintext,
        &json!({"name": "visitor"}).to_string(),
    )
    .await;
    assert_eq!(body["code"], "failed_precondition", "{status} {body}");
    engine.auth_tokens().revoke(&rec.id).expect("revoke");
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.RolesService/DeleteRole",
        &owner.plaintext,
        &json!({"name": "visitor"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"]["name"], "visitor");
}

/// The offline CLI mints and lists role tokens.
#[test]
fn cli_creates_and_lists_role_tokens() {
    let state = support::tempdir("token-roles-cli");
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_oxidhome-core"))
            .args(args)
            .env("OXIDHOME_STATE_DIR", state.path())
            .output()
            .expect("run oxidhome");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    // An empty token table belongs to the daemon's owner bootstrap.
    drop(Engine::with_state_dir(state.path()).expect("engine creates the database"));
    let (ok, _, stderr) = run(&["token", "create", "early", "--role", "monitor"]);
    assert!(!ok);
    assert!(stderr.contains("no owner token yet"), "{stderr}");
    {
        let engine = Engine::with_state_dir(state.path()).expect("engine");
        ensure_admin_token(&engine.auth_tokens(), &engine.audit_log(), state.path())
            .expect("bootstrap")
            .expect("owner");
    }
    let (ok, _, stderr) = run(&["token", "create", "early", "--role", "monitor"]);
    assert!(!ok);
    assert!(stderr.contains("unknown role `monitor`"), "{stderr}");
    let (ok, stdout, stderr) = run(&[
        "role",
        "create",
        "monitor",
        r#"[{"actions":["device.list","event.read","event.subscribe"]}]"#,
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("monitor\tcustom\tgrants=device.list,event."),
        "{stdout}"
    );
    let (ok, _, stderr) = run(&["role", "create", "bad", r#"[{"actions":["host.logz"]}]"#]);
    assert!(!ok);
    assert!(stderr.contains("host.logz"), "{stderr}");
    let (ok, stdout, stderr) = run(&[
        "token",
        "create",
        "prometheus",
        "--role",
        "monitor",
        "--role",
        "guest",
    ]);
    assert!(ok, "{stderr}");
    let secret = stdout.trim();
    assert!(secret.starts_with("oxh_"), "{stdout}");

    let (ok, stdout, stderr) = run(&["token", "list"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("prometheus\t-\troles=monitor,guest"),
        "{stdout}"
    );
    assert!(!stdout.contains(secret), "a listing never shows a secret");

    let (ok, _, stderr) = run(&["token", "create", "x", "--role", "owner"]);
    assert!(!ok);
    assert!(stderr.contains("not assignable"), "{stderr}");

    let (ok, stdout, stderr) = run(&["role", "list"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("monitor\tcustom\t") && stdout.contains("tokens=1"),
        "{stdout}"
    );
    let (ok, _, stderr) = run(&["role", "delete", "monitor"]);
    assert!(!ok);
    assert!(stderr.contains("held by 1 live token"), "{stderr}");
    let (ok, _, _) = run(&["role", "delete", "guest"]);
    assert!(!ok, "a built-in role can't be deleted");

    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let rec = engine.auth_tokens().verify(secret).expect("verifies");
    assert_eq!(rec.label, "prometheus");
}
