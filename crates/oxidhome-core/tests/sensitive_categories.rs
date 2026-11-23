//! H6 slice 2: sensitive device categories end to end over REST.
//!
//! A `simulated-switch` device raised to `lock` by the operator stands
//! in for a lock (the raise is itself under test): the wildcard scope
//! no longer reaches it, an explicit grant does (rate limited, with a
//! `warn` audit row), a grant narrowed to another device doesn't leak,
//! and the bootstrap owner token keeps everything.

#[path = "support.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use oxidhome_core::Engine;
use oxidhome_core::api::sensitive_admin::grant_sensitive;
use oxidhome_core::api::{build_router, ensure_admin_token};
use oxidhome_core::auth::{DeviceCategory, SensitiveCategory};
use oxidhome_core::state::AuditQuery;
use serde_json::Value;
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

const TOGGLE: &str = r#"{"capability":"switch","action":"toggle","args":[]}"#;

fn warn_rows(engine: &Engine) -> Vec<oxidhome_core::state::AuditEntry> {
    engine
        .audit_log()
        .query(
            &AuditQuery {
                level: Some("warn".into()),
                ..AuditQuery::default()
            },
            100,
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn lock_commands_need_an_explicit_grant() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let state = support::tempdir("sensitive-rest");
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
    let category_uri = format!("/api/v1/devices/{device}/category");
    let router = build_router(engine.clone());

    let wildcard = engine.auth_tokens().create("ha", br#"["*"]"#).unwrap();
    let granted = engine
        .auth_tokens()
        .create("door", br#"["devices:command"]"#)
        .unwrap();
    let elsewhere = engine.auth_tokens().create("other", br#"["*"]"#).unwrap();
    grant_sensitive(
        &engine.auth_tokens(),
        &engine.audit_log(),
        &granted.id,
        SensitiveCategory::Lock,
        &[],
    )
    .unwrap();
    grant_sensitive(
        &engine.auth_tokens(),
        &engine.audit_log(),
        &elsewhere.id,
        SensitiveCategory::Lock,
        &["dev-ffffffffffffffff".into()],
    )
    .unwrap();

    // A switch is not sensitive: the wildcard reaches it.
    let (status, _) = send(&router, "POST", &command_uri, &wildcard.plaintext, TOGGLE).await;
    assert_eq!(status, StatusCode::OK);
    let before = warn_rows(&engine).len();
    assert_eq!(before, 0);

    // Only the owner raises a category; the wildcard can't.
    let (status, _) = send(
        &router,
        "PUT",
        &category_uri,
        &wildcard.plaintext,
        r#"{"category":"lock"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(
        &router,
        "PUT",
        &category_uri,
        &owner.plaintext,
        r#"{"category":"lock"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["category"], "lock");
    assert_eq!(body["sensitive"], serde_json::json!(["lock"]));
    let (_, list) = send(&router, "GET", "/api/v1/devices", &owner.plaintext, "").await;
    assert_eq!(list["devices"][0]["category"], "lock", "{list}");

    // Wildcard and a grant narrowed to another device: denied, audited
    // with the sensitive label, before the command runs.
    for token in [&wildcard, &elsewhere] {
        let (status, _) = send(&router, "POST", &command_uri, &token.plaintext, TOGGLE).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
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
    assert_eq!(denied.len(), 2);
    assert!(
        denied
            .iter()
            .all(|r| r.required_scope.as_deref() == Some("sensitive:lock"))
    );

    // The explicit grant reaches it, with a `warn` row joined to the
    // request's own row by call id.
    let (status, body) = send(&router, "POST", &command_uri, &granted.plaintext, TOGGLE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = warn_rows(&engine);
    assert_eq!(rows.len(), 1);
    let warn = &rows[0];
    assert_eq!(warn.token_id, granted.id);
    assert_eq!(warn.method, "AUTHZ");
    assert_eq!(warn.required_scope.as_deref(), Some("sensitive:lock"));
    let request_row = engine
        .audit_log()
        .query(
            &AuditQuery {
                call_id: warn.call_id.clone(),
                ..AuditQuery::default()
            },
            10,
        )
        .unwrap();
    assert!(
        request_row.iter().any(|r| r.path == command_uri),
        "{request_row:?}"
    );

    // The owner keeps every category and isn't rate limited, but is
    // still audited at `warn`.
    let (status, _) = send(&router, "POST", &command_uri, &owner.plaintext, TOGGLE).await;
    assert_eq!(status, StatusCode::OK);
    let owner_rows: Vec<_> = warn_rows(&engine)
        .into_iter()
        .filter(|r| r.token_id != granted.id)
        .collect();
    assert_eq!(owner_rows.len(), 1);
    assert_eq!(owner_rows[0].required_scope.as_deref(), Some("owner:lock"));

    // Rate limit: the granted token's lock allowance runs out.
    let mut limited = None;
    for _ in 0..20 {
        let (status, body) = send(&router, "POST", &command_uri, &granted.plaintext, TOGGLE).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(body);
            break;
        }
        assert_eq!(status, StatusCode::OK);
    }
    let limited = limited.expect("rate limited within the allowance");
    assert_eq!(limited["category"], "lock");
    assert!(limited["retry_after_secs"].as_u64().unwrap() >= 1);
    let granted_rows = warn_rows(&engine)
        .into_iter()
        .filter(|r| r.token_id == granted.id)
        .count();
    assert_eq!(granted_rows, 10, "one warn row per allowed command");

    // An empty body doesn't clear it: the field is required.
    let (status, _) = send(&router, "PUT", &category_uri, &owner.plaintext, "{}").await;
    assert!(status.is_client_error(), "{status}");
    let (status, _) = send(&router, "POST", &command_uri, &wildcard.plaintext, TOGGLE).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Clearing the raise puts the switch back in reach.
    let (status, _) = send(
        &router,
        "PUT",
        &category_uri,
        &owner.plaintext,
        r#"{"category":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, "POST", &command_uri, &wildcard.plaintext, TOGGLE).await;
    assert_eq!(status, StatusCode::OK);

    // An unknown category is refused.
    let (status, _) = send(
        &router,
        "PUT",
        &category_uri,
        &owner.plaintext,
        r#"{"category":"toaster"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    handle.stop().await.expect("stop");
}

/// The override survives a restart, and a raise never lowers what the
/// host derived.
#[test]
fn category_override_persists_and_only_raises() {
    let state = support::tempdir("sensitive-override");
    let id = "dev-0123456789abcdef";
    {
        let engine = Engine::with_state_dir(state.path()).expect("engine");
        oxidhome_core::api::sensitive_admin::set_device_category(
            &engine.audit_log(),
            engine.devices().meta(),
            id,
            Some(DeviceCategory::Opener),
        )
        .unwrap();
        assert!(set_bad_id(&engine).is_err());
    }
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let class = engine.devices().class_of(id);
    assert_eq!(class.category(), DeviceCategory::Opener);
    assert!(class.sensitive().contains(SensitiveCategory::Opener));
    let audit = engine
        .audit_log()
        .query(&AuditQuery::default(), 10)
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|r| r.path == "cli.device.category:opener" && r.token_id == id)
    );
}

fn set_bad_id(engine: &Engine) -> anyhow::Result<()> {
    oxidhome_core::api::sensitive_admin::set_device_category(
        &engine.audit_log(),
        engine.devices().meta(),
        "not-a-device",
        Some(DeviceCategory::Lock),
    )
    .map(drop)
}

/// Offline token / device commands don't migrate the database: that
/// is the daemon's job (some migrations come with on-disk cleanup).
#[test]
fn offline_commands_refuse_an_unmigrated_database() {
    use oxidhome_core::api::sensitive_admin::with_offline_stores;
    use oxidhome_core::state::db::schema_version;
    let state = support::tempdir("sensitive-offline-version");
    let db = oxidhome_core::state::Db::open_file(state.path()).expect("db");
    let set = |v: i64| {
        db.write(|c| c.pragma_update(None, "user_version", v))
            .expect("set version");
    };
    set(schema_version() - 1);
    let err = with_offline_stores(state.path(), |_| Ok(())).unwrap_err();
    assert!(err.to_string().contains("start the daemon"), "{err:#}");
    set(schema_version());
    with_offline_stores(state.path(), |s| Ok(s.tokens.list()?.len())).expect("current schema");
}
