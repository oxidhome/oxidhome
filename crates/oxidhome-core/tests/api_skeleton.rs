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

#[path = "support.rs"]
mod support;

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

/// Snapshot of the audit fields a test cares about.
struct AuditFields {
    decision: String,
    status: i64,
    /// Empty string on allow / non-scope-deny rows; populated on
    /// scope-denial 403s with the missing scope name.
    required_scope: String,
}

/// Pull the structured fields out of an audit row.
/// Used by `audit_log_records_one_event_per_authenticated_request`.
fn extract_audit_fields(fields: &[(String, oxidhome_core::state::LogValue)]) -> AuditFields {
    use oxidhome_core::state::LogValue;
    let mut decision: Option<String> = None;
    let mut token_id: Option<String> = None;
    let mut status: Option<i64> = None;
    let mut required_scope: Option<String> = None;
    for (k, v) in fields {
        match (k.as_str(), v) {
            ("decision", LogValue::String(s) | LogValue::Debug(s)) => {
                decision = Some(s.clone());
            }
            ("token_id", LogValue::String(s) | LogValue::Debug(s)) => {
                token_id = Some(s.clone());
            }
            ("required_scope", LogValue::String(s) | LogValue::Debug(s)) => {
                required_scope = Some(s.clone());
            }
            ("status", LogValue::Int(n)) => status = Some(*n),
            ("status", LogValue::UInt(n)) => {
                status = Some(i64::try_from(*n).expect("status fits in i64"));
            }
            _ => {}
        }
    }
    assert!(token_id.is_some(), "token_id field present");
    AuditFields {
        decision: decision.expect("decision field present"),
        status: status.expect("status field present"),
        required_scope: required_scope.unwrap_or_default(),
    }
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
        let fields = extract_audit_fields(&row.fields);
        match fields.decision.as_str() {
            "allow" => {
                assert_eq!(fields.status, 200);
                // Allow rows don't carry a required_scope value
                // — the field is present (uniform shape) but
                // empty.
                assert_eq!(fields.required_scope, "");
            }
            "deny" => {
                assert_eq!(fields.status, 403);
                // Scope-denial 403s must surface *which* scope was
                // missing — the whole point of the response-
                // extension plumbing in `ScopeDenied`.
                assert_eq!(fields.required_scope, "instances:list");
            }
            other => panic!("unexpected decision `{other}`"),
        }
        decisions.push(fields.decision);
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

    for path in ["/api/v1/instances", "/api/v1/devices", "/api/v1/logs"] {
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

// ── Events tail (WebSocket) — Phase 12-API-c ─────────────────────
//
// **WS coverage note.** axum's `WebSocketUpgrade` extractor pulls a
// `hyper::upgrade::OnUpgrade` value out of the request extensions
// — populated only by hyper when a real TCP connection is upgraded.
// `tower::ServiceExt::oneshot` can't synthesize one, so even a
// syntactically-perfect handshake bounces with 426 at the
// extractor. Full WS round-trip coverage (real handshake, the
// streaming loop, the `Lagged` notice) lives in a follow-up
// integration test that spawns `serve(...)` on `127.0.0.1:0` and
// drives a real WS client. The oneshot test below verifies the
// route is wired and the auth middleware sits in front of it; the
// scope-check pattern itself is exhaustively covered by
// `instances_list_returns_403_without_scope` and
// `devices_list_enforces_scope`.

/// A non-WS probe hits axum's `WebSocketUpgrade` rejection at the
/// extractor *before* the scope check runs in the handler body.
/// That's intentional: a caller without a real handshake gets the
/// same "wrong shape" response regardless of scope, so the probing
/// signal "scope missing vs scope OK" only leaks through a real
/// WS handshake — which the caller has to commit to anyway.
#[tokio::test(flavor = "current_thread")]
async fn events_tail_non_websocket_probe_is_wrong_shape_not_403() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("limited", b"[\"devices:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/tail")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert!(
        status.is_client_error() && status != StatusCode::FORBIDDEN,
        "expected non-403 client error from axum's not-a-WS-request rejection, got {status}",
    );
}

// ── Logs query — Phase 12-API-c ──────────────────────────────────

/// A token without `logs:read` returns 403; an empty store + valid
/// scope returns 200 + `{"logs":[]}`.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_enforces_scope_and_returns_empty_array() {
    let engine = Engine::new().expect("engine");
    let denied = engine
        .auth_tokens()
        .create("no-logs", b"[\"devices:list\"]")
        .unwrap();
    let allowed = engine
        .auth_tokens()
        .create("reader", b"[\"logs:read\"]")
        .unwrap();
    let router = build_router(engine);

    let denied_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/logs")
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
                .uri("/api/v1/logs")
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
    assert!(body["logs"].is_array(), "got {body:?}");
    assert!(body["logs"].as_array().unwrap().is_empty());
}

/// Logs emitted via `tracing::info!` while the `LogStore` layer is
/// installed land in the `SQLite` table and are returned by
/// `GET /api/v1/logs`. Filters (`target_prefix`, `limit`) round-trip
/// through query-string params. Mirrors the audit-log test shape:
/// installs the `SqliteLayer`, drives a request through the layer's
/// scope, drains, queries.
#[test]
fn logs_query_returns_emitted_events_through_layer() {
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"logs:read\"]")
        .unwrap();

    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    with_default(subscriber, || {
        // Emit a recognisable log row through the layer.
        tracing::info!(
            target: "test.api_logs_query",
            kind = "manual-emit",
            "hello from the test",
        );
    });
    log_store.wait_drained_for_test();

    let response = rt.block_on(async {
        build_router(engine.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/logs?target_prefix=test.api_logs_query&limit=10")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", reader.plaintext),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    assert_eq!(response.status(), StatusCode::OK);
    let body = rt.block_on(body_to_json(response.into_body()));
    let logs = body["logs"].as_array().expect("logs array");
    assert!(!logs.is_empty(), "expected ≥1 log row, got {body:?}");
    assert_eq!(logs[0]["target"], "test.api_logs_query");
    assert_eq!(logs[0]["message"], "hello from the test");
}

/// `limit` is clamped to `LOGS_QUERY_MAX_LIMIT` (`1_000`). Passing
/// a higher value doesn't 400; it silently caps. Pins the contract
/// so a CLI that nudges the parameter up doesn't suddenly break.
#[tokio::test(flavor = "current_thread")]
async fn logs_query_accepts_overlarge_limit_without_400() {
    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"logs:read\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/logs?limit=999999")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", reader.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ── Device-command + plugins (Phase 12-API-d) ────────────────────

/// `POST /api/v1/devices/{id}/command` without `devices:command`
/// returns 403 — even with a real device id and a valid body.
#[tokio::test(flavor = "current_thread")]
async fn device_command_returns_403_without_scope() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("no-cmd", b"[\"devices:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/dev-0/command")
                .method("POST")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"capability":"switch","action":"toggle","args":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Sending to a non-existent device with the right scope returns
/// 404 (indistinguishable from "no such device id" — no
/// enumeration channel).
#[tokio::test(flavor = "current_thread")]
async fn device_command_unknown_device_returns_404() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("cmd", b"[\"devices:command\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/does-not-exist/command")
                .method("POST")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"capability":"switch","action":"toggle","args":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// End-to-end: spin up `simulated-switch`, find its device through
/// `/api/v1/devices`, send `switch.toggle` through
/// `/api/v1/devices/{id}/command`, observe the published
/// `state-changed` event. Proves the dispatch path routes through
/// the supervisor's `execute_command` and the plugin's WIT
/// `execute-command` export.
#[tokio::test(flavor = "multi_thread")]
async fn device_command_end_to_end_through_simulated_switch() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(switch_dir, "switch", None)
        .await
        .expect("start_instance");
    handle.wait_for_running().await.expect("reach Running");

    // Subscribe *after* `init` finished — `simulated-switch`
    // publishes a `state-changed` event only on `execute-command`,
    // so the bus is quiet until our toggle below. (Subscribing
    // before init wouldn't hurt; the broadcast channel just had
    // nothing to deliver, and the previous version of this test
    // hung trying to drain a never-published initial event.)
    let mut events = engine.events().subscribe_all();

    // Find the registered device id (the host minted `dev-N`).
    let device_id = engine
        .devices()
        .list()
        .into_iter()
        .find(|m| m.owner_instance == "switch")
        .expect("simulated-switch registered a device")
        .id
        .clone();

    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine.clone());
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/devices/{device_id}/command"))
                .method("POST")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"capability":"switch","action":"toggle","args":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "command dispatch should succeed for an admin token",
    );
    let body = body_to_json(response.into_body()).await;
    // The plugin returns either `Ok` or `OkWithState`; both are
    // structural successes — assert `kind` is present and not
    // `err`.
    let kind = body["kind"].as_str().expect("kind field on response");
    assert!(
        kind == "ok" || kind == "ok_with_state",
        "expected ok / ok_with_state, got kind={kind} body={body:?}",
    );
    // If the plugin returned state, each entry must use the tagged
    // `WireValue` shape (`{"t":..,"v":..}`) — pins the response-
    // side round-trip contract that 12-API-d's review surfaced.
    if kind == "ok_with_state" {
        let state = body["state"]
            .as_object()
            .expect("state object on ok_with_state");
        for (key, value) in state {
            assert!(
                value.get("t").and_then(Value::as_str).is_some(),
                "state[{key}] must carry tagged `t`, got {value:?}",
            );
            assert!(
                value.get("v").is_some(),
                "state[{key}] must carry tagged `v`, got {value:?}",
            );
        }
    }

    // The toggle should have published a `state-changed` event on
    // the bus carrying the new state.
    let post_toggle =
        tokio::time::timeout(std::time::Duration::from_secs(2), events.receiver.recv())
            .await
            .expect("toggle event delivered within 2s")
            .expect("event recv");
    assert_eq!(post_toggle.device.as_deref(), Some(device_id.as_str()));

    handle.stop().await.expect("stop");
}

/// `GET /api/v1/plugins` without `plugins:list` returns 403; with
/// the scope and no instances running, returns 200 + an empty
/// `plugins` array.
#[tokio::test(flavor = "current_thread")]
async fn plugins_list_enforces_scope_and_returns_empty_array() {
    let engine = Engine::new().expect("engine");
    let denied = engine
        .auth_tokens()
        .create("no-list", b"[\"devices:list\"]")
        .unwrap();
    let allowed = engine
        .auth_tokens()
        .create("lister", b"[\"plugins:list\"]")
        .unwrap();
    let router = build_router(engine);

    let denied_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/plugins")
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
                .uri("/api/v1/plugins")
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
    assert!(body["plugins"].is_array(), "got {body:?}");
    assert!(body["plugins"].as_array().unwrap().is_empty());
}

/// Plugins endpoint aggregates running instances by plugin id and
/// reports `instance_count` per plugin. Two instances of the same
/// plugin show as one row with `instance_count = 2`.
#[tokio::test(flavor = "multi_thread")]
async fn plugins_list_aggregates_running_instances() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let a = engine
        .start_instance(switch_dir.clone(), "switch-a", None)
        .await
        .expect("start switch-a");
    a.wait_for_running().await.expect("a Running");
    let b = engine
        .start_instance(switch_dir, "switch-b", None)
        .await
        .expect("start switch-b");
    b.wait_for_running().await.expect("b Running");

    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    let plugins = body["plugins"].as_array().expect("plugins array");
    assert_eq!(plugins.len(), 1, "expected one plugin row, got {body:?}");
    assert_eq!(plugins[0]["plugin_id"], "example.simulated-switch");
    assert_eq!(plugins[0]["instance_count"], 2);

    a.stop().await.expect("stop a");
    b.stop().await.expect("stop b");
}

/// `GET /api/v1/instances` carries `plugin_id` per instance now
/// that `InstanceHandle` exposes it (the deferred shape change
/// from 12-API-a).
#[tokio::test(flavor = "multi_thread")]
async fn instances_list_includes_plugin_id() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(switch_dir, "switch-one", None)
        .await
        .expect("start switch-one");
    handle.wait_for_running().await.expect("reach Running");

    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    let instances = body["instances"].as_array().expect("instances array");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0]["instance_id"], "switch-one");
    assert_eq!(instances[0]["plugin_id"], "example.simulated-switch");

    handle.stop().await.expect("stop");
}

/// Phase 12-API-e — real WS round-trip on `/api/v1/events/tail`.
///
/// Every previous WS coverage in this file goes through
/// `build_router(...).oneshot(...)` — `tower::ServiceExt` calls
/// `poll_ready` + `call`, so the HTTP handshake is exercised but
/// the connection never actually upgrades (the test client doesn't
/// drive the upgrade response into a real socket). That means the
/// `tail_events_loop` (the spawn target inside `upgrade.on_upgrade`)
/// has never been exercised in tests — backpressure, ping/pong,
/// disconnect handling all live there.
///
/// This test closes the loop: bind a real `127.0.0.1:0` listener,
/// spawn the daemon's `serve(engine, listener)`, connect via
/// `tokio-tungstenite` with a `Bearer` header, publish an event
/// through the in-process bus, and assert the JSON frame the
/// client reads back is the same shape `WireEvent` ships on the
/// `oneshot` path. Validates the bind/serve split, the WS handler's
/// scope gate, the supervisor-less bus → WS dispatch, and the JSON
/// payload all at once.
#[tokio::test(flavor = "multi_thread")]
async fn events_tail_ws_round_trip_with_real_listener() {
    use futures_util::StreamExt as _;
    use oxidhome_core::api::{ApiConfig, bind, serve};
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload,
    };
    use std::net::SocketAddr;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

    let engine = Engine::new().expect("engine");
    // `events:tail` only — the scope gate inside the handler
    // upgrades only if it passes.
    let token = engine
        .auth_tokens()
        .create("ws-test", br#"["events:tail"]"#)
        .expect("mint token");

    let listener = bind(ApiConfig {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
    })
    .await
    .expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");

    // Spawn the accept loop. Aborted at the end of the test so
    // the harness doesn't leak the task.
    let server_engine = engine.clone();
    let server = tokio::spawn(async move {
        serve(server_engine, listener).await.expect("serve");
    });

    // Connect the WS client with a Bearer header (the WS upgrade
    // request still goes through `require_token`).
    let url = format!("ws://{addr}/api/v1/events/tail");
    let mut request = url.into_client_request().expect("parse ws url");
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {}", token.plaintext)
            .parse()
            .expect("bearer header"),
    );
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws connect");

    // Publish an event the test can recognize. A `Custom` topic
    // is the simplest payload — no `device-state-changed` setup
    // needed.
    engine.events().publish(Event {
        device: None,
        timestamp: 0,
        payload: EventPayload::Custom(CustomEvent {
            topic: "api-e2e.toggle".into(),
            payload: String::new(),
        }),
    });

    // Pull one frame off the socket. 2 s is comfortably above
    // the publish → broadcast → handler → socket latency on any
    // realistic CI runner; below it points at a hang in the
    // dispatch path.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("ws frame within 2s")
        .expect("stream not closed")
        .expect("ws frame ok");
    let text = msg.into_text().expect("text frame");
    let json: Value = serde_json::from_str(&text).expect("json frame");
    // The same tagged-`WireEvent` shape the oneshot tests assert
    // on `/api/v1/events/tail`.
    assert_eq!(json["payload"]["kind"], "custom");
    assert_eq!(json["payload"]["topic"], "api-e2e.toggle");

    // Polite close, then abort the server task.
    let _ = ws.close(None).await;
    server.abort();
    let _ = server.await;
}
