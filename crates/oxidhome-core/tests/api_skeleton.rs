//! HTTP API skeleton end-to-end test.
//!
//! Drives `build_router` directly via `tower::ServiceExt::oneshot`
//! (no TCP bind, no real socket) and verifies:
//!
//! 1. `GET /api/v1/instances` without a token — 401 + the
//!    `WWW-Authenticate: Bearer` header.
//! 2. `GET /api/v1/instances` with a bogus token — 401.
//! 3. `GET /api/v1/instances` with a malformed token — 401.
//! 4. `GET /api/v1/instances` with a revoked token — 401.
//! 5. `GET /api/v1/instances` with a freshly-minted token — 200
//!    + `{"instances":[]}`.
//! 6. The mint-then-verify flow bumps `last_used_ms`.
//! 7. `POST /oxidhome.v1.HealthService/Check` (Connect, anonymous)
//!    returns the daemon version — the canonical liveness probe.

#[path = "support.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use oxidhome_core::Engine;
use oxidhome_core::api::build_router;
use serde_json::Value;
use tower::ServiceExt;

/// Serializes every test that installs a thread-local tracing
/// subscriber via `tracing::subscriber::with_default`.
///
/// **Why the whole file, not just the audit tests:** empirically
/// (see PR #50 review), the connect-side audit test can flake with
/// `sent=0` even though its own middleware emit ran on the same
/// thread as the `with_default` install, when a *sibling* connect
/// test runs concurrently and drives the same middleware path.
/// Solo passes were 20/20; parallel with the other Connect tests
/// on the review's box, ~1/3 saw the audit row lost. Serializing
/// the two `with_default` + connect-middleware-emit tests
/// eliminates the race window and is the same shape as the
/// reviewer's `--test-threads=1` workaround, targeted at the
/// specific set of tests that share the mechanism.
///
/// Poison recovery is intentional: a panic in one audit test
/// shouldn't cascade-fail every sibling; the mutex has no invariant
/// beyond exclusivity of the tracing install.
static TRACING_SUBSCRIBER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    {
        let _serial = TRACING_SUBSCRIBER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_default(subscriber, || {
            // Emit a recognisable log row through the layer.
            tracing::info!(
                target: "test.api_logs_query",
                kind = "manual-emit",
                "hello from the test",
            );
        });
    }
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

    // **Race-proof publish loop.** `connect_async` returning only
    // tells us the *client* received the HTTP 101 — the server's
    // `tail_events_loop` (where `engine.events().subscribe_all()`
    // is called) runs in the task spawned by `upgrade.on_upgrade(...)`
    // *after* the 101 frame is flushed. `tokio::broadcast` does
    // not buffer messages for not-yet-existing receivers, so a
    // single `publish` at this point can lose to the subscribe.
    // Fix: re-publish every 50 ms in a background task until the
    // recv side aborts us. Idempotent — the test inspects only
    // the first received frame.
    let publisher_engine = engine.clone();
    let publisher = tokio::spawn(async move {
        loop {
            publisher_engine.events().publish(Event {
                device: None,
                timestamp: 0,
                payload: EventPayload::Custom(CustomEvent {
                    topic: "api-e2e.toggle".into(),
                    payload: String::new(),
                }),
            });
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    });

    // Pull one frame off the socket. 2 s is comfortably above
    // the publish → broadcast → handler → socket latency on any
    // realistic CI runner with the re-publish loop above; below
    // it points at a hang in the dispatch path.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("ws frame within 2s")
        .expect("stream not closed")
        .expect("ws frame ok");
    publisher.abort();
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

// ── Phase 12-API-f — install / start / stop / uninstall ──────────

/// Build the SDK manifest the install endpoint can swallow. Mirrors
/// the kv-counter pattern (no tick) so the staged plugin doesn't
/// race the test's start/stop commands.
fn lifecycle_manifest(plugin_id: &str) -> String {
    format!(
        r#"manifest_version = 1
[plugin]
id = "{plugin_id}"
name = "Lifecycle Test Plugin"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "kv_counter.wasm"
[capabilities]
storage_quota_kb = 4
"#,
    )
}

/// Stage a tempdir mirroring what a real install would expect on
/// disk: `<dir>/manifest.toml` + `<dir>/kv_counter.wasm`. Avoids
/// touching the simulated-switch build output for tests that don't
/// need a real instance.
fn stage_install_source(prefix: &str, plugin_id: &str) -> support::TempDir {
    let wasm = support::build_example("kv-counter", "kv_counter.wasm");
    support::stage_plugin(
        prefix,
        &wasm,
        "kv_counter.wasm",
        &lifecycle_manifest(plugin_id),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn install_requires_plugins_install_scope() {
    let state_dir = support::tempdir("install-scope");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let token = engine
        .auth_tokens()
        .create("no-install", b"[\"plugins:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"source_dir":"/nope"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// In-memory engines (`Engine::new`) have no `<state_dir>/plugins/`
/// root — install must return 503 with a structured body so a CLI
/// can surface a helpful error rather than misreading it as
/// "source dir bad" or "unauthorized".
#[tokio::test(flavor = "multi_thread")]
async fn install_returns_503_on_in_memory_engine() {
    let engine = Engine::new().expect("engine");
    let token = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"source_dir":"/tmp/anything"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["error"], "no_plugins_root");
}

#[tokio::test(flavor = "multi_thread")]
async fn install_returns_404_when_source_dir_missing() {
    let state_dir = support::tempdir("install-missing");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"source_dir":"/no/such/dir/anywhere-on-this-host"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn install_returns_422_when_manifest_malformed() {
    let state_dir = support::tempdir("install-bad");
    let bad_source = support::tempdir("bad-source");
    std::fs::write(
        bad_source.path().join("manifest.toml"),
        "this is not [valid toml",
    )
    .unwrap();
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let body = serde_json::json!({"source_dir": bad_source.path().to_str().unwrap()});
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["error"], "bad_install");
}

#[tokio::test(flavor = "multi_thread")]
async fn install_succeeds_and_shows_up_in_listing() {
    let state_dir = support::tempdir("install-ok");
    let source = stage_install_source("kvc-source-ok", "example.kv-counter");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);

    let install_body = serde_json::json!({"source_dir": source.path().to_str().unwrap()});
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(install_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["plugin_id"], "example.kv-counter");
    assert_eq!(body["version"], "0.1.0");
    let installed_path = body["installed_path"].as_str().expect("installed_path");
    assert!(installed_path.contains("plugins/example.kv-counter"));
    assert!(
        std::path::Path::new(installed_path)
            .join("manifest.toml")
            .exists()
    );
    assert!(
        std::path::Path::new(installed_path)
            .join("kv_counter.wasm")
            .exists()
    );

    // Listing now shows it as installed, stopped (instance_count = 0).
    let list = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let listing = body_to_json(list.into_body()).await;
    let plugins = listing["plugins"].as_array().expect("plugins array");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0]["plugin_id"], "example.kv-counter");
    assert_eq!(plugins[0]["installed"], true);
    assert_eq!(plugins[0]["version"], "0.1.0");
    assert_eq!(plugins[0]["instance_count"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn install_returns_409_on_collision() {
    let state_dir = support::tempdir("install-collide");
    let source = stage_install_source("kvc-source-collide", "example.kv-counter");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let install_body = serde_json::json!({"source_dir": source.path().to_str().unwrap()});

    // First install succeeds.
    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(install_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Second install of the same plugin_id collides.
    let second = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(install_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = body_to_json(second.into_body()).await;
    assert_eq!(body["error"], "already_installed");
    assert_eq!(body["plugin_id"], "example.kv-counter");
}

#[tokio::test(flavor = "multi_thread")]
async fn start_requires_plugins_start_scope() {
    let state_dir = support::tempdir("start-scope");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let token = engine
        .auth_tokens()
        .create("no-start", b"[\"plugins:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/example.anything/start")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_returns_404_for_unknown_plugin() {
    let state_dir = support::tempdir("start-unknown");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/example.never-installed/start")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn uninstall_returns_409_when_instances_running() {
    let state_dir = support::tempdir("uninstall-busy");
    let source = stage_install_source("kvc-source-busy", "example.kv-counter");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine.clone());

    // Install + start.
    let install_body = serde_json::json!({"source_dir": source.path().to_str().unwrap()});
    let install = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(install_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(install.status(), StatusCode::OK);

    let start = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/example.kv-counter/start")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);

    // Uninstall while running -> 409 + offending instance ids.
    let uninstall = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/plugins/example.kv-counter")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uninstall.status(), StatusCode::CONFLICT);
    let body = body_to_json(uninstall.into_body()).await;
    assert_eq!(body["error"], "instances_running");
    let ids = body["instance_ids"].as_array().expect("ids array");
    assert!(ids.iter().any(|v| v == "example.kv-counter"));

    // Cleanup: stop everything before letting Engine drop.
    for handle in engine.instances().list() {
        let _ = handle.stop().await;
    }
}

/// Full happy-path round trip — install → start (reach Running) →
/// stop → uninstall — through the API surface. The most important
/// integration test for 12-API-f: confirms the four endpoints work
/// end-to-end together and that the daemon's state-dir layout
/// matches what `Engine::start_instance` reads.
#[tokio::test(flavor = "multi_thread")]
async fn install_start_stop_uninstall_end_to_end() {
    let state_dir = support::tempdir("lifecycle-e2e");
    let source = stage_install_source("kvc-source-e2e", "example.kv-counter");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine.clone());

    // 1. Install.
    let install_body = serde_json::json!({"source_dir": source.path().to_str().unwrap()});
    let install = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(install_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(install.status(), StatusCode::OK);

    // 2. Start. Expect 200 with the instance landing in Running.
    let start = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/example.kv-counter/start")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"instance_id": "kvc-1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let body = body_to_json(start.into_body()).await;
    assert_eq!(body["plugin_id"], "example.kv-counter");
    assert_eq!(body["instance_id"], "kvc-1");
    assert_eq!(body["state"], "Running");

    // List now shows instance_count = 1.
    let list = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listing = body_to_json(list.into_body()).await;
    let row = &listing["plugins"][0];
    assert_eq!(row["plugin_id"], "example.kv-counter");
    assert_eq!(row["installed"], true);
    assert_eq!(row["instance_count"], 1);

    // 3. Stop.
    let stop = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/example.kv-counter/stop")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stop.status(), StatusCode::OK);
    let body = body_to_json(stop.into_body()).await;
    assert_eq!(body["stopped"][0], "kvc-1");

    // 4. Uninstall.
    let uninstall = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/plugins/example.kv-counter")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uninstall.status(), StatusCode::OK);
    let body = body_to_json(uninstall.into_body()).await;
    assert_eq!(body["plugin_id"], "example.kv-counter");

    // List is now empty + the install dir is gone.
    let final_list = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/plugins")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listing = body_to_json(final_list.into_body()).await;
    assert!(listing["plugins"].as_array().unwrap().is_empty());
    assert!(!state_dir.path().join("plugins/example.kv-counter").exists());
}

// ── Connect RPC (mounted as fallback_service) ───────────────────

/// `POST /oxidhome.v1.HealthService/Check` with Connect's JSON wire
/// format must reach the new Connect dispatcher (mounted alongside
/// the existing JSON `/api/v1/*` router) and return the same
/// `status: "ok"` + `version` payload the JSON endpoint surfaces.
///
/// Anonymous, like the JSON `/api/v1/health` — Connect's path lives
/// outside the auth middleware via axum's `fallback_service` mount,
/// so this is the dual-protocol-on-one-listener proof that 15-a
/// promises.
#[tokio::test(flavor = "current_thread")]
async fn connect_health_check_returns_ok_with_version() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.HealthService/Check")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "ok");
    // `version` mirrors `oxidhome-core`'s `Cargo.toml` package
    // version; locked exact so the two protocols can't drift.
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

/// A non-allow-listed Connect path without an Authorization header
/// must trip the Connect-side auth interceptor and come back as a
/// Connect-shaped 401 (HTTP 401 + JSON body
/// `{"code":"unauthenticated", …}`), not the JSON middleware's
/// plain-text 401 + `WWW-Authenticate: Bearer`. The Connect dispatcher
/// is never reached, so the path doesn't have to be a real service —
/// the auth gate runs first.
#[tokio::test(flavor = "current_thread")]
async fn connect_unauth_path_without_token_returns_connect_unauthenticated() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/List")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(
        body["code"], "unauthenticated",
        "expected a Connect-shaped error JSON, got {body:?}",
    );
}

/// A Connect path with an *invalid* bearer comes back the same way
/// — `unauthenticated`. Distinguishing "no token" from "bad token"
/// to the caller would let a probing client enumerate the difference,
/// so the JSON middleware also collapses these two cases; the Connect
/// middleware matches.
#[tokio::test(flavor = "current_thread")]
async fn connect_unauth_path_with_bogus_token_returns_connect_unauthenticated() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let bogus = "oxh_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/List")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bogus}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["code"], "unauthenticated");
}

/// The Connect middleware returns transport-appropriate errors.
///
/// A gRPC-Web client hitting the middleware with `Content-Type:
/// application/grpc-web+proto` expects the gRPC-Web wire shape:
/// **HTTP 200** with `grpc-status` + `grpc-message` in trailers
/// (encoded in the body for gRPC-Web). A plain HTTP 401 + JSON
/// error body — which is right for a Connect unary client — is
/// wrong here: gRPC-Web tooling reads status-in-trailers and
/// surfaces the 401 as a *transport* failure rather than an
/// `Unauthenticated` RPC error.
///
/// Pins the fix from PR #50 review: the middleware now delegates
/// error-response construction to
/// [`ConnectError::into_http_response`], which detects the inbound
/// transport via the `Content-Type` header and picks the right
/// shape.
#[tokio::test(flavor = "current_thread")]
async fn connect_auth_failure_uses_grpc_shape_for_grpc_web_transport() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/List")
                .header(header::CONTENT_TYPE, "application/grpc-web+proto")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    // gRPC-Web returns HTTP 200 with the RPC error encoded in the
    // body/trailers, not an HTTP 401.
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "gRPC-Web transport must not surface auth failures as an HTTP 401",
    );
    // The trailers are either HTTP trailers or encoded in the body
    // per the gRPC-Web wire spec. Either way there must NOT be a
    // JSON body starting with `{"code":`, which would be the
    // Connect-unary shape leaking through.
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    assert!(
        !bytes.starts_with(b"{\"code\""),
        "gRPC-Web response body should not be a Connect-JSON error, got: {:?}",
        String::from_utf8_lossy(&bytes),
    );
}

/// Authenticated requests to a non-existent Connect method pass the
/// auth gate and reach the Connect dispatcher, which 404s. Pins the
/// contract: the middleware doesn't shadow real 404s on valid tokens,
/// and audit emission happens even for not-found cases (otherwise an
/// operator probing for endpoints with a valid token would leave no
/// trail).
// Sync `#[test]` (not `#[tokio::test]`) so the sync `MutexGuard`
// serializing against parallel audit tests doesn't sit across an
// `.await` in the outer async fn (clippy::await_holding_lock).
// Builds its own current-thread runtime the same way the audit
// tests do; the async work only happens inside `block_on`, where
// the guard being held on the same thread is fine.
#[test]
fn connect_valid_token_reaches_dispatcher_and_404s_unknown_method() {
    // Serialize against every audit test — this test authenticates
    // successfully and thus fires the `emit_audit → SqliteLayer`
    // path. Empirically that path racing a parallel
    // `with_default`-installed audit test loses the row on the
    // audit test's side (see TRACING_SUBSCRIBER_LOCK docstring).
    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let issued = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = rt.block_on(async {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oxidhome.v1.NoSuchService/Method")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", issued.plaintext),
                    )
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    // ConnectError::Unimplemented (the dispatcher's response for an
    // unknown method) maps to HTTP 501 per the Connect spec; ditto
    // 404 for unrouted. Either way it's not 401/403, which would
    // mean we shadowed a real status with auth.
    assert!(
        !matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "auth shouldn't intercept a valid-token call to an unknown method, got {}",
        response.status(),
    );
}

/// An authenticated Connect call lands one `api.audit` tracing row
/// with the same field shape the JSON middleware emits. Pins that
/// the two surfaces converge on a single audit-row contract — a
/// CLI query (`logs query --target api.audit --field token_id=…`)
/// returns Connect + JSON rows uniformly.
#[test]
fn connect_authenticated_call_emits_audit_row_in_same_shape_as_json() {
    use oxidhome_core::state::{LogQuery, LogValue};
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");

    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    // See `TRACING_SUBSCRIBER_LOCK` — audit tests share the mutex so
    // parallel `with_default` installs on the harness's thread pool
    // don't race the `emit_audit → SqliteLayer` path in the
    // middleware and lose the row to a NoSubscriber dispatch. Panic
    // recovery on the lock is intentional; a poisoned mutex means an
    // earlier audit test panicked mid-request and we still want to
    // run this one.
    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            let _resp = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oxidhome.v1.NoSuchService/Method")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
        });
    });

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
        1,
        "expected one audit row from the Connect call, got {rows:?}",
    );
    let fields = extract_audit_fields(&rows[0].fields);
    // The handler 404'd / 501'd (unknown method) — the audit row
    // records the actual status the dispatcher returned, with the
    // matching `deny` decision (decision logic mirrors the JSON
    // middleware: <400 → allow, 5xx → error, otherwise deny).
    let status = u16::try_from(fields.status).unwrap_or_default();
    let decision_ok = (status >= 400 && fields.decision == "deny")
        || (status >= 500 && fields.decision == "error");
    assert!(
        decision_ok,
        "unexpected status={status}, decision={}",
        fields.decision,
    );
    // No scoped Connect endpoints in 15-b, so the audit row never
    // carries a `required_scope` field yet — pin this so 15-c knows
    // to extend it.
    assert!(
        fields.required_scope.is_empty(),
        "no scoped Connect endpoints exist yet; required_scope should be empty",
    );
    // The audit target shape: `api.{METHOD}-{PATH}` — same as the
    // JSON side. Confirms Connect rows land under the same prefix
    // a CLI query would filter on.
    let target_field: Vec<_> = rows[0]
        .fields
        .iter()
        .filter(|(k, _)| k == "audit_target")
        .collect();
    assert_eq!(target_field.len(), 1, "audit_target field present");
    let target_str = match &target_field[0].1 {
        LogValue::String(s) | LogValue::Debug(s) => s.as_str(),
        other => panic!("audit_target should be a string, got {other:?}"),
    };
    assert_eq!(target_str, "api.POST-/oxidhome.v1.NoSuchService/Method");
}

/// Connect's `Health.Check` is anonymous *with or without* an
/// Authorization header — the allow-list is the source of truth, not
/// the presence of a token. Pins that a probing client which happens
/// to carry a token doesn't accidentally end up in the audit log.
#[tokio::test(flavor = "current_thread")]
async fn connect_health_check_remains_anonymous_even_with_token() {
    let engine = Engine::new().expect("engine");
    let issued = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.HealthService/Check")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ── Connect read cluster (15-c) ─────────────────────────────────

/// Every scoped Connect RPC in this cluster reads the `Actor` back
/// out of `ctx.extensions().get::<Actor>()`. That's the round-trip
/// through the connectrpc dispatcher (opencode #2 on PR #50). If
/// the middleware forgot to stamp or the dispatcher failed to
/// forward extensions, `require_scope_connect` would return
/// `ConnectError::internal("connect handler ran without an Actor
/// extension")` — HTTP 500 — instead of a 200 with the empty
/// listing. Any of the four happy-path tests below serves as that
/// smoke check; picking Instances.List (empty response) is the
/// simplest.
#[tokio::test(flavor = "current_thread")]
async fn connect_instances_list_reaches_handler_via_actor_extension_round_trip() {
    let engine = Engine::new().expect("engine");
    let admin = engine
        .auth_tokens()
        .create("admin", b"[\"instances:list\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/ListInstances")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    // Fresh engine → no instances. Connect's canonical protobuf-JSON
    // omits fields at their default value (empty repeated → no
    // key), so we accept either the missing key or an explicit empty
    // array; the semantic assertion is "no instances came back."
    let instances = body
        .get("instances")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, Clone::clone);
    assert!(instances.is_empty(), "got {body:?}");
}

/// Non-empty Instances.List: start a supervised plugin, then hit
/// the Connect endpoint and assert the `Instance` payload includes
/// both `instance_id` and `plugin_id` (12-API-d added the latter to
/// `InstanceHandle`; Connect exposes it via the proto message the
/// same way the JSON side does).
#[tokio::test(flavor = "multi_thread")]
async fn connect_instances_list_returns_running_instance_payload() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();

    let handle = engine
        .start_instance(switch_dir, "switch-one", None)
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");

    let router = build_router(engine.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.InstancesService/ListInstances")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    let instances = body["instances"].as_array().expect("instances array");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0]["instanceId"], "switch-one");
    assert_eq!(instances[0]["pluginId"], "example.simulated-switch");

    handle.stop().await.expect("stop");
}

/// Scope-deny on Connect returns `ConnectError::permission_denied`
/// which the Connect spec maps to HTTP 403 for the unary transport,
/// with the standard Connect-JSON body `{"code":"permission_denied",…}`.
/// One test per service; the paths differ but the shape doesn't.
#[tokio::test(flavor = "current_thread")]
async fn connect_instances_list_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.InstancesService/ListInstances",
        b"[\"devices:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_devices_list_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.DevicesService/ListDevices",
        b"[\"instances:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_plugins_list_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.PluginsService/ListPlugins",
        b"[\"instances:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_logs_query_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.LogsService/QueryLogs",
        b"[\"instances:list\"]",
    )
    .await;
}

/// Shared harness for the four scope-deny tests: mint a token with
/// a scope that *isn't* the one the target RPC requires, POST an
/// empty message body, assert 403 + Connect-JSON `permission_denied`.
async fn assert_connect_scope_denied(uri: &str, scope_json: &[u8]) {
    let engine = Engine::new().expect("engine");
    let issued = engine.auth_tokens().create("scoped", scope_json).unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "scope-deny on {uri} should be 403 (Connect PermissionDenied)",
    );
    let body = body_to_json(response.into_body()).await;
    assert_eq!(
        body["code"], "permission_denied",
        "expected Connect-shaped permission_denied on {uri}, got {body:?}",
    );
}

/// `Logs.QueryLogs` with a `min_level` value that isn't a known
/// enum variant must be rejected as `invalid_argument`, not
/// silently interpreted as "no filter." The proto3 default
/// (`LOG_LEVEL_UNSPECIFIED = 0`) means "no filter"; an unknown
/// numeric value is a client bug and should surface as such.
/// Pins the fix for PR #67 review finding #2.
#[tokio::test(flavor = "current_thread")]
async fn connect_logs_query_rejects_unknown_min_level_as_invalid_argument() {
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    // 999 is well past any known LogLevel variant. Connect's JSON
    // wire format accepts an int here; buffa lands it as
    // `EnumValue::Unknown(999)`.
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.LogsService/QueryLogs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(r#"{"minLevel":999}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // Connect's `InvalidArgument` maps to HTTP 400 on the unary
    // transport.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["code"], "invalid_argument");
    // Message includes the offending numeric value so a client can
    // diagnose without guessing.
    assert!(
        body["message"].as_str().unwrap_or_default().contains("999"),
        "expected offending value in error message, got {body:?}",
    );
}

/// The Connect audit row on a scope denial now carries the missing
/// scope name in `required_scope` — the JSON side has done this
/// since 12-API-b via a `DeniedScope` response-extension smuggle,
/// and the Connect side matches it via a request-extension slot
/// the handler's `require_scope_connect` writes to. Uses the sync
/// `#[test]` + `block_on` shape so the mutex guard doesn't sit
/// across an `.await` (`clippy::await_holding_lock`, same pattern as
/// the sibling audit tests).
#[test]
fn connect_scope_deny_audit_row_carries_required_scope() {
    use oxidhome_core::state::LogQuery;
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    // Token has `logs:read` but the RPC we hit requires
    // `devices:list` — a clean scope-deny with a known missing
    // scope name.
    let issued = engine
        .auth_tokens()
        .create("scoped", b"[\"logs:read\"]")
        .unwrap();
    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            let _resp = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oxidhome.v1.DevicesService/ListDevices")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer {}", issued.plaintext),
                        )
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
        });
    });
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
        1,
        "expected one audit row from the scope-denied Connect call, got {rows:?}",
    );
    let fields = extract_audit_fields(&rows[0].fields);
    assert_eq!(fields.status, 403);
    assert_eq!(fields.decision, "deny");
    assert_eq!(
        fields.required_scope, "devices:list",
        "audit row should name the missing scope, got fields {:?}",
        rows[0].fields
    );
}

/// Same scope-denied Connect call as
/// `connect_scope_deny_audit_row_carries_required_scope`, but on
/// the **gRPC-Web** transport. The Connect spec renders RPC errors
/// for gRPC / gRPC-Web as HTTP 200 with the status in body/trailers;
/// naively classifying the audit `decision` off `response.status()`
/// would call this `allow` even though the handler denied the
/// request — see PR #67 review finding #1. Pins the middleware's
/// transport-independent classification: when the handler
/// recorded a `DeniedScope`, the audit row is `deny` regardless of
/// the wire shape.
#[test]
fn connect_scope_deny_on_grpc_web_transport_still_audits_as_deny() {
    use oxidhome_core::state::LogQuery;
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("scoped", b"[\"logs:read\"]")
        .unwrap();
    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            // A well-formed gRPC-Web frame is required for the
            // dispatcher to reach the handler — otherwise the
            // dispatcher rejects on framing before scope check
            // runs and we never populate `DeniedScopeSlot`.
            // ListDevicesRequest is an empty proto3 message
            // (zero-byte payload); framing is 1 byte flags
            // (0 = uncompressed data frame) + 4 bytes big-endian
            // length (0) + 0 bytes payload = 5 bytes total.
            let frame = &[0u8, 0, 0, 0, 0][..];
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oxidhome.v1.DevicesService/ListDevices")
                        .header(header::CONTENT_TYPE, "application/grpc-web+proto")
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer {}", issued.plaintext),
                        )
                        .body(Body::from(frame.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            // gRPC-Web puts the RPC error in trailers on top of
            // HTTP 200 — the audit classifier must not mistake
            // that for a success.
            assert_eq!(response.status(), StatusCode::OK);
        });
    });
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
    assert_eq!(rows.len(), 1);
    let fields = extract_audit_fields(&rows[0].fields);
    assert_eq!(
        fields.decision, "deny",
        "gRPC-Web scope denial must audit as deny, got fields {:?}",
        rows[0].fields
    );
    assert_eq!(fields.required_scope, "devices:list");
}

// ── Connect write cluster (15-d) ─────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn connect_devices_execute_command_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.DevicesService/ExecuteCommand",
        b"[\"devices:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_plugins_install_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.PluginsService/InstallPlugin",
        b"[\"plugins:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_plugins_start_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.PluginsService/StartPlugin",
        b"[\"plugins:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_plugins_stop_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.PluginsService/StopPlugin",
        b"[\"plugins:list\"]",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_plugins_uninstall_scope_deny_returns_permission_denied() {
    assert_connect_scope_denied(
        "/oxidhome.v1.PluginsService/UninstallPlugin",
        b"[\"plugins:list\"]",
    )
    .await;
}

/// `ExecuteCommand` on an unknown device — the middleware sees a
/// Connect `NotFound` error, and the audit row records
/// `status=404, decision=deny` (via the outcome slot introduced
/// this slice; would otherwise mis-classify as `allow` on
/// non-unary transports). No enumeration leak — a real-but-not-
/// running device gets the same `NotFound`.
#[test]
fn connect_devices_execute_command_unknown_device_audits_as_deny() {
    use oxidhome_core::state::LogQuery;
    use tracing::subscriber::with_default;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let admin = engine
        .auth_tokens()
        .create("admin", b"[\"devices:command\"]")
        .unwrap();
    let log_store = engine.log_store();
    let subscriber = Registry::default().with(log_store.layer());

    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oxidhome.v1.DevicesService/ExecuteCommand")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                        .body(Body::from(
                            r#"{"deviceId":"nope","capability":"switch","action":"toggle"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = body_to_json(response.into_body()).await;
            assert_eq!(body["code"], "not_found");
        });
    });
    log_store.wait_drained_for_test();
    let rows = log_store
        .query(
            &LogQuery {
                target_prefix: Some("api.audit".into()),
                ..LogQuery::default()
            },
            8,
        )
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one audit row expected, got {rows:?}");
    let fields = extract_audit_fields(&rows[0].fields);
    assert_eq!(fields.status, 404);
    assert_eq!(fields.decision, "deny");
    // NotFound isn't a scope denial — required_scope stays empty.
    assert!(fields.required_scope.is_empty());
}

/// Full round-trip through Connect's Devices.ExecuteCommand: stage a
/// simulated-switch plugin, mint an admin token, send `switch.toggle`
/// via Connect JSON, assert the response carries the toggled state.
/// Verifies the WIT `Value` variant → proto `Value` oneof projection
/// and the reverse direction.
#[tokio::test(flavor = "multi_thread")]
async fn connect_devices_execute_command_end_to_end_through_simulated_switch() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let handle = engine
        .start_instance(switch_dir, "switch-one", None)
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");

    let device_id = engine
        .devices()
        .list()
        .first()
        .expect("switch registered a device")
        .id
        .clone();

    let router = build_router(engine.clone());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.DevicesService/ExecuteCommand")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(format!(
                    r#"{{"deviceId":"{device_id}","capability":"switch","action":"toggle"}}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    // The Connect JSON encoding of a message with an unset oneof
    // omits the field, so we accept either `ok` or `okWithState`.
    // simulated-switch's toggle returns state, so `okWithState` is
    // the expected variant; assert one of the two payload keys
    // exists rather than pinning to a specific variant name.
    let has_ok = body.get("ok").is_some();
    let has_state = body.get("okWithState").is_some();
    assert!(
        has_ok || has_state,
        "expected ok or okWithState payload, got {body:?}",
    );

    handle.stop().await.expect("stop");
}

/// Full install → start → stop → uninstall round-trip through
/// Connect. Mirrors the JSON-side end-to-end
/// (`install_start_stop_uninstall_end_to_end` in 12-API-f) so both
/// surfaces exercise the same operator workflow.
#[tokio::test(flavor = "multi_thread")]
async fn connect_plugins_install_start_stop_uninstall_end_to_end() {
    let state_dir = support::tempdir("connect-lifecycle-e2e");
    let source = stage_install_source("connect-kvc-source", "example.kv-counter");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine.clone());

    // 1. Install.
    let install = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.PluginsService/InstallPlugin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(format!(
                    r#"{{"sourceDir":"{}"}}"#,
                    source.path().display(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(install.status(), StatusCode::OK);
    let body = body_to_json(install.into_body()).await;
    assert_eq!(body["pluginId"], "example.kv-counter");

    // 2. Start with an explicit instance id.
    let start = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.PluginsService/StartPlugin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(
                    r#"{"pluginId":"example.kv-counter","instanceId":"kvc-1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let body = body_to_json(start.into_body()).await;
    assert_eq!(body["state"], "Running");

    // 3. Uninstall while running -> FailedPrecondition (Connect
    //    HTTP 400 status, per the spec's InvalidArgument /
    //    FailedPrecondition status mapping).
    let uninstall_busy = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.PluginsService/UninstallPlugin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(r#"{"pluginId":"example.kv-counter"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // Connect maps FailedPrecondition → HTTP 400 for the unary
    // transport. Body has code=failed_precondition.
    assert!(uninstall_busy.status().is_client_error());
    let body = body_to_json(uninstall_busy.into_body()).await;
    assert_eq!(body["code"], "failed_precondition");

    // 4. Stop.
    let stop = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.PluginsService/StopPlugin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(r#"{"pluginId":"example.kv-counter"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stop.status(), StatusCode::OK);
    let body = body_to_json(stop.into_body()).await;
    let stopped = body["stoppedIds"].as_array().expect("stoppedIds array");
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0], "kvc-1");

    // 5. Uninstall now works.
    let uninstall = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.PluginsService/UninstallPlugin")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(r#"{"pluginId":"example.kv-counter"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uninstall.status(), StatusCode::OK);
    assert!(!state_dir.path().join("plugins/example.kv-counter").exists());
}
