//! Phase 12-API-a — HTTP API skeleton end-to-end test.
//!
//! Drives `build_router` directly via `tower::ServiceExt::oneshot`
//! (no TCP bind, no real socket) and verifies:
//!
//! 1. `GET /api/v1/health` — 200 with `{"status":"ok",...}` and no
//!    `Authorization` header required.
//! 2. `GET /api/v1/instances` without a token — 401 + the
//!    `WWW-Authenticate: Bearer` header.
//! 3. `GET /api/v1/instances` with a bogus token — 401.
//! 4. `GET /api/v1/instances` with a malformed token — 401.
//! 5. `GET /api/v1/instances` with a revoked token — 401.
//! 6. `GET /api/v1/instances` with a freshly-minted token — 200
//!    + `{"instances":[]}`.
//! 7. The mint-then-verify flow bumps `last_used_ms`.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use oxidhome_core::Engine;
use oxidhome_core::api::build_router;
use serde_json::Value;
use tower::ServiceExt;

async fn body_to_json(body: Body) -> Value {
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("collect body");
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

/// Pull `(decision, status)` out of an audit row's structured fields.
/// Used by `audit_log_records_one_event_per_authenticated_request`.
fn extract_audit_fields(
    fields: &[(String, oxidhome_core::state::LogValue)],
) -> (String, i64) {
    use oxidhome_core::state::LogValue;
    let mut decision: Option<String> = None;
    let mut token_id: Option<String> = None;
    let mut status: Option<i64> = None;
    for (k, v) in fields {
        match (k.as_str(), v) {
            ("decision", LogValue::String(s) | LogValue::Debug(s)) => {
                decision = Some(s.clone());
            }
            ("token_id", LogValue::String(s) | LogValue::Debug(s)) => {
                token_id = Some(s.clone());
            }
            ("status", LogValue::Int(n)) => status = Some(*n),
            ("status", LogValue::UInt(n)) => {
                status = Some(i64::try_from(*n).expect("status fits in i64"));
            }
            _ => {}
        }
    }
    assert!(token_id.is_some(), "token_id field present");
    (
        decision.expect("decision field present"),
        status.expect("status field present"),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn health_endpoint_is_anonymous_and_ok() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

#[tokio::test(flavor = "current_thread")]
async fn protected_route_requires_bearer_and_responds_with_www_authenticate() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let www_auth = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate header present on 401");
    assert_eq!(www_auth.to_str().unwrap(), "Bearer");
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_and_unknown_tokens_both_yield_401() {
    let engine = Engine::new().expect("engine");
    // Pre-seed one real token so an unknown-hash path goes through
    // the same code as a non-empty store.
    let _ = engine.auth_tokens().create("baseline", b"[]").unwrap();
    let router = build_router(engine);

    // Malformed: no `oxh_` prefix.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(header::AUTHORIZATION, "Bearer not-a-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Unknown: well-shaped prefix but no row matches the hash.
    // The full token is `oxh_` + base64url(32 bytes); pick all-zero bytes.
    let unknown = "oxh_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(header::AUTHORIZATION, format!("Bearer {unknown}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_token_yields_401() {
    let engine = Engine::new().expect("engine");
    let issued = engine.auth_tokens().create("temp", b"[]").unwrap();
    assert!(engine.auth_tokens().revoke(&issued.id).unwrap());
    let router = build_router(engine);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "current_thread")]
async fn valid_token_grants_access_and_bumps_last_used() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("admin", b"[\"instances:list\"]")
        .unwrap();
    let pre = engine.auth_tokens().get(&issued.id).unwrap().unwrap();
    assert!(pre.last_used_ms.is_none());

    let router = build_router(engine.clone());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert!(
        body["instances"].is_array(),
        "expected `instances` array, got {body:?}"
    );
    assert!(body["instances"].as_array().unwrap().is_empty());

    // `verify` set `last_used_ms`; rereading the row reflects it.
    let post = engine.auth_tokens().get(&issued.id).unwrap().unwrap();
    assert!(
        post.last_used_ms.is_some(),
        "expected last_used_ms to be set after a successful verify",
    );
}

// ── Scope-policy enforcement (Phase 12-API-b) ─────────────────────

/// A token without `instances:list` (but holding *some* other scope)
/// gets through auth but is **403** at the scope check. Pre-fix the
/// route would have returned 200 — this is the new behavior.
#[tokio::test(flavor = "current_thread")]
async fn instances_list_returns_403_without_scope() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("limited", b"[\"devices:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// `GET /api/v1/devices` requires `devices:list`. A token without
/// it returns 403; a token with the literal scope returns 200 and
/// an empty `devices` array (no devices registered on this fresh
/// engine).
#[tokio::test(flavor = "current_thread")]
async fn devices_list_enforces_scope() {
    let engine = Engine::new().expect("engine");
    let denied = engine
        .auth_tokens()
        .create("no-devices", b"[\"instances:list\"]")
        .unwrap();
    let allowed = engine
        .auth_tokens()
        .create("can-list-devices", b"[\"devices:list\"]")
        .unwrap();
    let router = build_router(engine);

    let denied_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", denied.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_resp.status(), StatusCode::FORBIDDEN);

    let ok_resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", allowed.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let body = body_to_json(ok_resp.into_body()).await;
    assert!(body["devices"].is_array(), "got {body:?}");
    assert!(body["devices"].as_array().unwrap().is_empty());
}

/// Every authenticated request lands one row in the log store with
/// `target = "api.<METHOD>-<path>"` and the structured fields the
/// CLI's `logs query --target api.* --field decision=deny` will
/// pivot on. Pins the audit-log contract end-to-end through the
/// `LogStore` layer.
#[test]
fn audit_log_records_one_event_per_authenticated_request() {
    use oxidhome_core::state::LogQuery;
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");

    let engine = Engine::new().expect("engine");
    let allow_token = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let deny_token = engine
        .auth_tokens()
        .create("no-instances", b"[\"devices:list\"]")
        .unwrap();

    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            // One allow + one deny so we can assert both audit rows.
            for secret in [&allow_token.plaintext, &deny_token.plaintext] {
                let _resp = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/api/v1/instances")
                            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
    });

    // Layer is async + bounded-channel; the writer thread drains
    // when the channel idles. The store's test helper blocks until
    // every queued row is committed.
    log_store.wait_drained_for_test();

    let rows = log_store
        .query(
            &LogQuery {
                target_prefix: Some("api.audit".into()),
                ..LogQuery::default()
            },
            32,
        )
        .expect("query api.audit");
    assert_eq!(
        rows.len(),
        2,
        "expected one audit row per authenticated request, got {rows:?}",
    );

    let mut decisions: Vec<String> = Vec::new();
    for row in &rows {
        assert_eq!(row.target, "api.audit");
        let (decision, status) = extract_audit_fields(&row.fields);
        match decision.as_str() {
            "allow" => assert_eq!(status, 200),
            "deny" => assert_eq!(status, 403),
            other => panic!("unexpected decision `{other}`"),
        }
        decisions.push(decision);
    }
    assert!(decisions.contains(&"allow".to_string()));
    assert!(decisions.contains(&"deny".to_string()));
}

/// The wildcard `["*"]` admin / bootstrap token satisfies every
/// scoped route. Pins the wildcard contract (see
/// `api::scopes::WILDCARD`) end-to-end through the HTTP path.
#[tokio::test(flavor = "current_thread")]
async fn wildcard_token_satisfies_every_scoped_route() {
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);

    for path in ["/api/v1/instances", "/api/v1/devices"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "wildcard token must satisfy {path}, got {:?}",
            response.status(),
        );
    }
}
