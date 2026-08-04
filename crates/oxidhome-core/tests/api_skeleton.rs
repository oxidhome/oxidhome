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

/// Serializes tests that install a thread-local tracing
/// subscriber via `tracing::subscriber::with_default`. Two
/// parallel `with_default` installs on the harness's thread pool
/// can race with each other and lose events; the mutex funnels
/// them through one at a time.
///
/// Poison recovery is intentional: a panic in one test shouldn't
/// cascade-fail every sibling; the mutex has no invariant beyond
/// exclusivity of the tracing install.
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

/// Every authenticated request lands exactly one row in the C3
/// audit ledger, with the outcome + fields the CLI's `logs query
/// --target api.audit` used to pivot on pre-C3-followup. Post-C3-
/// followup the mirror is gone; consumers read `AuditLog::query`
/// (surfaced via `GET /api/v1/audit` for external callers).
#[tokio::test(flavor = "current_thread")]
async fn audit_log_records_one_event_per_authenticated_request() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let allow_token = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let deny_token = engine
        .auth_tokens()
        .create("no-instances", b"[\"devices:list\"]")
        .unwrap();
    let audit_log = engine.audit_log();

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

    let rows = audit_log
        .query(&AuditQuery::default(), 32)
        .expect("query audit");
    assert_eq!(
        rows.len(),
        2,
        "expected one audit row per authenticated request, got {rows:?}",
    );

    let mut decisions: Vec<String> = Vec::new();
    for row in &rows {
        assert_eq!(row.path, "/api/v1/instances");
        match row.decision.as_str() {
            "allow" => {
                assert_eq!(row.status, 200);
                // Allow rows carry no required_scope — the field
                // is only populated on scope-deny 403s.
                assert!(row.required_scope.is_none());
            }
            "deny" => {
                assert_eq!(row.status, 403);
                // Scope-denial 403s must surface *which* scope was
                // missing — the whole point of the response-
                // extension plumbing in `ScopeDenied`.
                assert_eq!(row.required_scope.as_deref(), Some("instances:list"));
            }
            other => panic!("unexpected decision `{other}`"),
        }
        decisions.push(row.decision.clone());
    }
    assert!(decisions.contains(&"allow".to_string()));
    assert!(decisions.contains(&"deny".to_string()));
}

/// `GET /api/v1/audit` — the external query surface for the C3
/// ledger, replaces the pre-retirement
/// `logs query --target api.audit` path. Scoped on `audit:read`.
/// This test seeds two rows via authenticated requests (one allow,
/// one deny), then queries the endpoint and asserts both come back
/// in the expected `{status, decision, path, ...}` shape.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_returns_ledger_rows() {
    let engine = Engine::new().expect("engine");
    let allow_token = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let deny_token = engine
        .auth_tokens()
        .create("no-instances", b"[\"devices:list\"]")
        .unwrap();
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"audit:read\"]")
        .unwrap();
    let router = build_router(engine);

    // Seed two authenticated requests — one allow, one deny.
    for secret in [&allow_token.plaintext, &deny_token.plaintext] {
        let _ = router
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

    // Query the audit endpoint with the reader token.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit")
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
    let body = body_to_json(response.into_body()).await;
    let audit = body["audit"].as_array().expect("audit array");
    // 3 rows: the two seeded requests + this very audit-query call
    // itself (also authenticated → audited).
    assert!(
        audit.len() >= 2,
        "at least the two seeded rows, got {audit:?}"
    );
    let decisions: Vec<&str> = audit
        .iter()
        .filter_map(|row| row["decision"].as_str())
        .collect();
    assert!(decisions.contains(&"allow"));
    assert!(decisions.contains(&"deny"));
}

/// PR #85 review, F2 regression — the `send_command` docstring
/// advertises `?path=/api/v1/devices/.../command` as a forensic
/// drill-down. The pre-fix `AuditParams` didn't have a `path`
/// field, so axum silently ignored the query key and returned
/// unfiltered rows. Verifies the filter actually filters.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_path_filter_narrows() {
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"audit:read\"]")
        .unwrap();
    let router = build_router(engine);

    // Seed two distinct paths.
    for uri in ["/api/v1/instances", "/api/v1/devices"] {
        let _ = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Query with path filter — must return *only* the matching
    // path's row, not the whole ledger.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit?path=/api/v1/instances")
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
    let body = body_to_json(response.into_body()).await;
    let audit = body["audit"].as_array().expect("audit array");
    assert!(!audit.is_empty(), "path filter should return matching rows");
    for row in audit {
        assert_eq!(
            row["path"].as_str(),
            Some("/api/v1/instances"),
            "path filter must exclude non-matching rows; got {row:?}",
        );
    }
}

/// PR #85 review, F3 regression — the audit query is itself
/// audited (the middleware records the pending intent row *before*
/// running the handler), so an unfiltered `?limit=1` on an idle
/// system used to return the query's own pending row instead of
/// the preceding event. The middleware smuggles the pending id
/// through a request extension the handler reads and passes as
/// `AuditQuery::exclude_id`, dropping the self-audit from its own
/// results.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_excludes_self_referential_row() {
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"audit:read\"]")
        .unwrap();
    let router = build_router(engine);

    // Seed one real request.
    let _ = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/instances")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Query with limit=1 — must return the seeded /instances row,
    // NOT the query's own /audit pending row.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit?limit=1")
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
    let body = body_to_json(response.into_body()).await;
    let audit = body["audit"].as_array().expect("audit array");
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0]["path"].as_str(),
        Some("/api/v1/instances"),
        "self-referential row must be excluded; got {audit:?}",
    );
    // decision on the seeded row is "allow" (2xx); the pending
    // /audit row (had it leaked through) would be "pending".
    assert_eq!(audit[0]["decision"].as_str(), Some("allow"));
}

/// PR #85 review, F2 regression — page through the ledger by
/// following the `next_cursor` opaque cursor, verify no rows are
/// duplicated or skipped. The pre-fix endpoint exposed only
/// inclusive `until_ms` bounds; rows sharing a millisecond made
/// millisecond-based pagination inherently lossy.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_paginates_losslessly_via_cursor() {
    use std::collections::HashSet;

    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"audit:read\"]")
        .unwrap();
    let router = build_router(engine);

    // Seed enough rows that the same millisecond likely holds
    // several — the exact concurrency scenario the reviewer
    // pointed out that a `until_ms`-only paginator loses.
    for _ in 0..7 {
        let _ = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/instances")
                    .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Page with limit=2 until `next_cursor` disappears. Collect
    // every id we see; assert (a) no duplicates, (b) count matches
    // the total the ledger holds for the reader's view.
    let mut seen: HashSet<u64> = HashSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let uri = match &cursor {
            Some(c) => format!("/api/v1/audit?limit=2&before={c}"),
            None => "/api/v1/audit?limit=2".to_string(),
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
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
        let body = body_to_json(response.into_body()).await;
        let page = body["audit"].as_array().expect("audit array");
        for row in page {
            let id = row["id"].as_u64().expect("id present");
            assert!(
                seen.insert(id),
                "row id {id} returned twice — pagination is lossy"
            );
        }
        cursor = body
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    // 7 seeded rows + 1 pending row per audit-query call
    // (excluded by F3 self-exclusion, so not counted). Every one
    // of the 7 must have been seen once.
    assert!(
        seen.len() >= 7,
        "expected at least the 7 seeded rows, got {} unique ids: {seen:?}",
        seen.len(),
    );
}

/// `GET /api/v1/audit?before=<bad>` returns 400 rather than
/// silently ignoring the malformed cursor. Silent-ignore is the
/// axum default for unknown query params and it's exactly the
/// class of hole PR #85 review's F2 flagged for the missing
/// `path` param.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_rejects_malformed_cursor() {
    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"audit:read\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit?before=not-a-cursor")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", reader.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// `GET /api/v1/audit` refuses tokens without the `audit:read`
/// scope with 403. Locks the scope-gate — the audit ledger is
/// sensitive (every token id, path, decision), and any token
/// lacking `audit:read` must not enumerate it.
#[tokio::test(flavor = "current_thread")]
async fn audit_endpoint_requires_audit_read_scope() {
    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("no-audit", b"[\"logs:read\"]")
        .unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit")
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

/// Architecture-review C3 + follow-up guard. Pre-retirement,
/// `emit_audit` fired *both* a `tracing::info!(target = "api.audit",
/// ...)` mirror **and** an `AuditLog::record` — this test used to
/// prove the ledger row survived even when the tracing mirror lost
/// to `LogStore` channel saturation. Post-retirement the mirror is
/// gone, so this test now guards the retirement itself:
///
/// - An authenticated request lands exactly one row in the
///   `AuditLog`, fully finalized.
/// - The `LogStore` receives **zero** `api.audit`-target rows —
///   the mirror really is retired and no code path is silently
///   re-introducing it. A regression that re-adds the mirror
///   would trip the `assert_eq!(mirror_rows, 0, ...)` below.
#[test]
fn audit_ledger_is_sole_source_no_tracing_mirror() {
    use oxidhome_core::state::{AuditQuery, LogQuery};
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
    let audit_log = engine.audit_log();
    let subscriber = Registry::default().with(log_store.layer());

    let _serial = TRACING_SUBSCRIBER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    with_default(subscriber, || {
        rt.block_on(async {
            let router = build_router(engine.clone());
            let resp = router
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/instances")
                        .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    });
    log_store.wait_drained_for_test();

    // Ledger — the sole source, fully finalized.
    let rows = audit_log
        .query(&AuditQuery::default(), 8)
        .expect("query audit_log");
    assert_eq!(rows.len(), 1, "one ledger row expected, got {rows:?}");
    assert_eq!(rows[0].decision, "allow");
    assert_eq!(rows[0].status, 200);
    assert_eq!(rows[0].path, "/api/v1/instances");
    assert_eq!(rows[0].method, "GET");
    assert!(
        rows[0].finalized_ms.is_some(),
        "audit row must be finalized, not left pending; got {:?}",
        rows[0],
    );

    // Retirement guard — LogStore has zero `api.audit`-target rows.
    let mirror_rows = log_store
        .query(
            &LogQuery {
                target_prefix: Some("api.audit".into()),
                ..LogQuery::default()
            },
            8,
        )
        .expect("query mirror");
    assert!(
        mirror_rows.is_empty(),
        "`tracing::info!(target = \"api.audit\", ...)` mirror is retired — \
         no code path should re-emit it; got {mirror_rows:?}",
    );
}

/// F5 regression — the pre-C3 review-fixup surface. A request with
/// no `Authorization` header at all must land a `deny` row in the
/// ledger with `token_id = "anonymous"` and no credential
/// fingerprint (nothing was presented). Pre-fixup, credential
/// probes bypassed the ledger entirely.
#[test]
fn audit_records_anonymous_probe_for_missing_bearer() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let audit_log = engine.audit_log();

    rt.block_on(async {
        let router = build_router(engine.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/instances")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });

    let rows = audit_log
        .query(&oxidhome_core::state::AuditQuery::default(), 8)
        .expect("query");
    assert_eq!(rows.len(), 1, "missing-bearer probe must be audited");
    assert_eq!(rows[0].token_id, "anonymous");
    assert_eq!(rows[0].actor_kind, "anonymous");
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].status, 401);
    assert!(
        rows[0].credential_fp.is_none(),
        "no bearer was presented — no fingerprint to record; got {:?}",
        rows[0].credential_fp,
    );
    assert!(rows[0].finalized_ms.is_some());
}

/// F5 regression — same idea, but for a *presented but invalid*
/// bearer. The row must carry a short SHA-256 fingerprint of the
/// presented secret so a forensic sweep can correlate repeat probes
/// with the same fake credential, while never storing the raw
/// secret.
#[test]
fn audit_records_anonymous_probe_for_bogus_bearer() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let audit_log = engine.audit_log();

    let bogus_bearer = "definitely-not-a-real-token";
    rt.block_on(async {
        let router = build_router(engine.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/instances")
                    .header(header::AUTHORIZATION, format!("Bearer {bogus_bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });

    let rows = audit_log
        .query(&oxidhome_core::state::AuditQuery::default(), 8)
        .expect("query");
    assert_eq!(rows.len(), 1, "invalid-bearer probe must be audited");
    assert_eq!(rows[0].token_id, "anonymous");
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].status, 401);
    let fp = rows[0]
        .credential_fp
        .as_deref()
        .expect("invalid bearer must be recorded with a fingerprint");
    assert_eq!(fp.len(), 8, "fingerprint is 8 hex chars, got `{fp}`");
    assert!(fp.chars().all(|ch| ch.is_ascii_hexdigit()));
    // Never store the raw secret.
    assert!(
        !fp.contains(bogus_bearer),
        "fingerprint must not echo the presented secret; got `{fp}`",
    );
    // Fingerprint must be stable + non-trivial (SHA-256 of a fixed
    // string is deterministic — regressions would flip these bytes).
    // `sha2::Sha256("definitely-not-a-real-token")[..4]` = `7315a20c`.
    assert_eq!(fp, "7315a20c");
}

/// F1 regression — the two-phase invariant is that the intent row
/// lands at `record_intent` time, *before* `next.run(req).await`
/// starts. Directly exercising cancellation from an integration
/// test is racy (the handlers are fast); the unit test
/// `abandoned_intent_stays_visible_as_pending` in
/// `state::audit_log::tests` covers the pending-row shape at the
/// API layer. This test pins the finalize half of the contract for
/// a healthy request end-to-end: after the response returns,
/// exactly one row exists and every column carries the expected
/// finalized value (no pending rows leaking through).
#[test]
fn audit_ledger_row_is_finalized_end_to_end() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let allow_token = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let audit_log = engine.audit_log();

    rt.block_on(async {
        let router = build_router(engine.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/instances")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", allow_token.plaintext),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    });

    // Confirm exactly one row, finalized (not left pending).
    let all = audit_log
        .query(&oxidhome_core::state::AuditQuery::default(), 8)
        .expect("query all");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].decision, "allow");
    assert_eq!(all[0].status, 200);
    assert!(all[0].finalized_ms.is_some());
    assert!(all[0].credential_fp.is_none());

    // Confirm no pending rows leaked (the pending → finalized UPDATE
    // must have succeeded; a leaked pending row would show up here).
    let pending = audit_log
        .query(
            &oxidhome_core::state::AuditQuery {
                decision: Some("pending".into()),
                ..oxidhome_core::state::AuditQuery::default()
            },
            8,
        )
        .expect("query pending");
    assert!(
        pending.is_empty(),
        "no request should leave a pending row after finalize; got {pending:?}",
    );
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
            .expect("event recv")
            .expect_event();
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
                origin_plugin_id: String::new(),
                origin_instance_id: String::new(),
                row_id: None,
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

/// An authenticated Connect call lands one row in the C3 audit
/// ledger with the same field shape a JSON request would produce.
/// Pins that both surfaces converge on a single audit-row contract
/// — a forensic query over the ledger returns Connect and JSON
/// rows uniformly.
#[tokio::test(flavor = "current_thread")]
async fn connect_authenticated_call_emits_audit_row_in_same_shape_as_json() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let audit_log = engine.audit_log();

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

    let rows = audit_log
        .query(&AuditQuery::default(), 32)
        .expect("query audit");
    assert_eq!(
        rows.len(),
        1,
        "expected one audit row from the Connect call, got {rows:?}",
    );
    let row = &rows[0];
    // The handler 404'd / 501'd (unknown method) — the audit row
    // records the actual status the dispatcher returned, with the
    // matching decision (<400 → allow, 5xx → error, otherwise deny).
    let decision_ok = (row.status >= 400 && row.decision == "deny")
        || (row.status >= 500 && row.decision == "error");
    assert!(
        decision_ok,
        "unexpected status={}, decision={}",
        row.status, row.decision,
    );
    // Not a scope denial — required_scope stays None.
    assert!(row.required_scope.is_none());
    // Method + path landed verbatim; the audit-target derivation
    // that used to happen for the tracing mirror is gone.
    assert_eq!(row.method, "POST");
    assert_eq!(row.path, "/oxidhome.v1.NoSuchService/Method");
}

/// `GET /api/v1/readyz` is anonymous — no bearer, still 200 with
/// the `{status, version}` body an orchestrator (systemd,
/// docker, k8s) can probe against.
#[tokio::test(flavor = "current_thread")]
async fn readyz_returns_ok_without_auth() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["status"], "ok");
    // Version matches the `oxidhome-core` crate version — the
    // daemon binary lives in the same crate so this moves in
    // lockstep with workspace bumps.
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

/// The C3 audit ledger must not record `/readyz` — it's an
/// anonymous liveness probe, and every k8s pod / docker container
/// polling every second would otherwise flood the ledger. Pins
/// the `PUBLIC_PATHS` short-circuit above the audit path.
#[test]
fn readyz_leaves_no_audit_row() {
    use oxidhome_core::state::AuditQuery;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let engine = Engine::new().expect("engine");
    let audit_log = engine.audit_log();

    rt.block_on(async {
        let router = build_router(engine.clone());
        // Bang on it a handful of times, mirroring an orchestrator
        // probe cadence.
        for _ in 0..5 {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/readyz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    });

    // Ledger has *zero* rows — no anonymous probes, no denials.
    let rows = audit_log
        .query(&AuditQuery::default(), 16)
        .expect("audit query");
    assert!(
        rows.is_empty(),
        "/readyz probes must not be audited; got {rows:?}",
    );
}

/// PR-#83 review, F2 regression — `/readyz` is a GET-only public
/// route. The pre-fix `PUBLIC_PATHS` string-compare short-circuit
/// matched every HTTP method against the path, so POST / DELETE /
/// PUT `/api/v1/readyz` bypassed auth (invisibly today because
/// axum returns 405 for unregistered methods, but a hazard if
/// anyone later adds a handler on that path for a different
/// method). Router-level separation makes only GET reachable.
#[tokio::test(flavor = "current_thread")]
async fn readyz_non_get_methods_return_405() {
    let engine = Engine::new().expect("engine");
    let router = build_router(engine);
    for method in ["POST", "PUT", "DELETE"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/v1/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "expected 405 for {method} /api/v1/readyz",
        );
    }
}

/// `GET /api/v1/readyz` stays anonymous even when a bearer is
/// present. Mirrors `connect_health_check_remains_anonymous_even_with_token`:
/// the allow-list is the source of truth, not the presence of a
/// token, so a probing client that happens to carry one doesn't
/// end up in the audit log.
#[tokio::test(flavor = "current_thread")]
async fn readyz_remains_anonymous_even_with_token() {
    let engine = Engine::new().expect("engine");
    let issued = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let router = build_router(engine);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/readyz")
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

/// The Connect audit row on a scope denial carries the missing
/// scope name in `required_scope` — the JSON side has done this
/// since 12-API-b via a `DeniedScope` response-extension smuggle,
/// and the Connect side matches it via a request-extension slot
/// the handler's `require_scope_connect` writes to. Both surfaces
/// funnel into the C3 audit ledger; querying it directly returns
/// the same row shape regardless of transport.
#[tokio::test(flavor = "current_thread")]
async fn connect_scope_deny_audit_row_carries_required_scope() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    // Token has `logs:read` but the RPC we hit requires
    // `devices:list` — a clean scope-deny with a known missing
    // scope name.
    let issued = engine
        .auth_tokens()
        .create("scoped", b"[\"logs:read\"]")
        .unwrap();
    let audit_log = engine.audit_log();

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

    let rows = audit_log
        .query(&AuditQuery::default(), 32)
        .expect("query audit");
    assert_eq!(
        rows.len(),
        1,
        "expected one audit row from the scope-denied Connect call, got {rows:?}",
    );
    let row = &rows[0];
    assert_eq!(row.status, 403);
    assert_eq!(row.decision, "deny");
    assert_eq!(
        row.required_scope.as_deref(),
        Some("devices:list"),
        "audit row should name the missing scope, got {row:?}",
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
#[tokio::test(flavor = "current_thread")]
async fn connect_scope_deny_on_grpc_web_transport_still_audits_as_deny() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("scoped", b"[\"logs:read\"]")
        .unwrap();
    let audit_log = engine.audit_log();

    let router = build_router(engine.clone());
    // A well-formed gRPC-Web frame is required for the dispatcher
    // to reach the handler — otherwise the dispatcher rejects on
    // framing before scope check runs and we never populate
    // `DeniedScopeSlot`. ListDevicesRequest is an empty proto3
    // message (zero-byte payload); framing is 1 byte flags (0 =
    // uncompressed data frame) + 4 bytes big-endian length (0) +
    // 0 bytes payload = 5 bytes total.
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
    // gRPC-Web puts the RPC error in trailers on top of HTTP 200
    // — the audit classifier must not mistake that for a success.
    assert_eq!(response.status(), StatusCode::OK);

    let rows = audit_log
        .query(&AuditQuery::default(), 32)
        .expect("query audit");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row.decision, "deny",
        "gRPC-Web scope denial must audit as deny, got {row:?}",
    );
    assert_eq!(row.required_scope.as_deref(), Some("devices:list"));
}

/// **Non-scope** handler-returned Connect error on gRPC-Web still
/// audits as `deny`, not `allow`. Sibling of the scope-deny test
/// above — verifies the outcome slot fix (PR #74 review) covers
/// every `rpc_err(&ctx, ...)` path, not just the scope one.
///
/// Setup: valid token with `logs:read`, gRPC-Web POST to
/// `Logs.QueryLogs` carrying `min_level = 999` (unknown enum). The
/// handler `return Err(rpc_err(&ctx, ConnectError::invalid_argument(...)))`s,
/// which on gRPC-Web comes back as HTTP 200 with `grpc-status: 3`.
/// Without the outcome slot the audit would classify this as `allow`
/// (the very bug the PR review flagged as still present in this
/// handler after 15-d shipped).
#[tokio::test(flavor = "current_thread")]
async fn connect_non_scope_error_on_grpc_web_transport_still_audits_as_deny() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let issued = engine
        .auth_tokens()
        .create("reader", b"[\"logs:read\"]")
        .unwrap();
    let audit_log = engine.audit_log();

    let router = build_router(engine.clone());
    // Frame a `QueryLogsRequest{min_level: 999}` as a gRPC-Web
    // JSON message: 1-byte flag (0 = data) + 4-byte big-endian
    // length + JSON payload.
    let payload = br#"{"minLevel":999}"#;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0u8);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.LogsService/QueryLogs")
                .header(header::CONTENT_TYPE, "application/grpc-web+json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", issued.plaintext),
                )
                .body(Body::from(frame))
                .unwrap(),
        )
        .await
        .unwrap();
    // gRPC-Web transport pushes the RPC error into trailers on top
    // of HTTP 200 — the audit classifier must not read this as a
    // success.
    assert_eq!(response.status(), StatusCode::OK);

    let rows = audit_log
        .query(&AuditQuery::default(), 8)
        .expect("audit query");
    assert_eq!(
        rows.len(),
        1,
        "expected one audit row for the failed gRPC-Web query, got {rows:?}",
    );
    let row = &rows[0];
    assert_eq!(
        row.status, 400,
        "InvalidArgument should record as HTTP 400 in the audit row",
    );
    assert_eq!(
        row.decision, "deny",
        "gRPC-Web non-scope handler error must audit as deny, got {row:?}",
    );
    // Not a scope denial → required_scope stays None.
    assert!(row.required_scope.is_none());
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
#[tokio::test(flavor = "current_thread")]
async fn connect_devices_execute_command_unknown_device_audits_as_deny() {
    use oxidhome_core::state::AuditQuery;

    let engine = Engine::new().expect("engine");
    let admin = engine
        .auth_tokens()
        .create("admin", b"[\"devices:command\"]")
        .unwrap();
    let audit_log = engine.audit_log();

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

    let rows = audit_log
        .query(&AuditQuery::default(), 8)
        .expect("audit query");
    assert_eq!(rows.len(), 1, "one audit row expected, got {rows:?}");
    let row = &rows[0];
    assert_eq!(row.status, 404);
    assert_eq!(row.decision, "deny");
    // NotFound isn't a scope denial — required_scope stays None.
    assert!(row.required_scope.is_none());
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

/// F4 regression — JSON path. `POST /api/v1/devices/{id}/command`
/// sending an unknown action to a real registered device gets a
/// `CommandResult::Err(InvalidArgument)` back from the plugin
/// (simulated-switch's `execute_command` refuses any action that
/// isn't a `switch` toggle/on/off — see
/// `examples/simulated-switch/src/lib.rs:82`). The wire response
/// is HTTP 200 with the error inside the body, and — this is the
/// F4 invariant, revised on the PR-#79 review — the audit ledger
/// records the transport and authorization outcomes *independently*
/// from the execution outcome:
///
/// - `status = 200` (wire status)
/// - `decision = "allow"` (authorization passed — the plugin ran)
/// - `execution_outcome = "failed"` (plugin's domain result)
/// - `domain_error = "invalid_argument"` (WIT error kind)
///
/// An earlier cut of F4 collapsed the execution failure into
/// `decision = "deny"` + `status = 400`, which polluted forensic
/// authorization queries with plugin validation errors.
#[tokio::test(flavor = "multi_thread")]
async fn send_command_domain_error_audits_execution_failure() {
    use oxidhome_core::state::AuditQuery;

    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let audit_log = engine.audit_log();
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
    // The plugin's execute_command returns InvalidArgument for any
    // action other than the switch verbs — dispatch an unknown one.
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/devices/{device_id}/command"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", admin.plaintext))
                .body(Body::from(
                    r#"{"capability":"switch","action":"self-destruct","args":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // Wire response is HTTP 200 with the error inside the body —
    // that's the whole shape F4 is about. Confirm before checking
    // the audit ledger.
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["kind"], "err");

    // The audit row keeps authorization and execution outcomes
    // as distinct fields.
    let rows = audit_log.query(&AuditQuery::default(), 8).expect("audit");
    let hit = rows
        .iter()
        .find(|r| r.path == format!("/api/v1/devices/{device_id}/command"))
        .expect("command audit row present");
    assert_eq!(hit.status, 200, "wire status preserved, got {hit:?}");
    assert_eq!(hit.decision, "allow", "auth outcome, got {hit:?}");
    assert_eq!(
        hit.execution_outcome.as_deref(),
        Some("failed"),
        "execution outcome, got {hit:?}",
    );
    assert_eq!(
        hit.domain_error.as_deref(),
        Some("invalid_argument"),
        "domain error kind, got {hit:?}",
    );

    handle.stop().await.expect("stop");
}

/// F4 regression — Connect path. Same shape as the JSON test
/// above, dispatched via `Devices.ExecuteCommand`. Connect's Ok /
/// gRPC / gRPC-Web all ride HTTP 200 for a successful RPC even
/// when the response payload is `Outcome::Err`; the middleware
/// records the execution failure on the ledger's independent
/// `execution_outcome` / `domain_error` columns while leaving
/// `status = 200` and `decision = "allow"`.
#[tokio::test(flavor = "multi_thread")]
async fn connect_execute_command_domain_error_audits_execution_failure() {
    use oxidhome_core::state::AuditQuery;

    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");
    let admin = engine.auth_tokens().create("admin", b"[\"*\"]").unwrap();
    let audit_log = engine.audit_log();
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
                    r#"{{"deviceId":"{device_id}","capability":"switch","action":"self-destruct"}}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    // Wire response is HTTP 200 with `err` inside the Outcome oneof.
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_json(response.into_body()).await;
    assert!(
        body.get("err").is_some(),
        "expected err outcome, got {body:?}",
    );

    // Audit row records execution + authorization separately.
    let rows = audit_log.query(&AuditQuery::default(), 8).expect("audit");
    let hit = rows
        .iter()
        .find(|r| r.path == "/oxidhome.v1.DevicesService/ExecuteCommand")
        .expect("execute-command audit row present");
    assert_eq!(hit.status, 200, "wire status preserved, got {hit:?}");
    assert_eq!(hit.decision, "allow", "auth outcome, got {hit:?}");
    assert_eq!(
        hit.execution_outcome.as_deref(),
        Some("failed"),
        "got {hit:?}",
    );
    assert_eq!(
        hit.domain_error.as_deref(),
        Some("invalid_argument"),
        "got {hit:?}",
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

// ── Connect Events.TailEvents (15-e, streaming) ─────────────────

/// Wrap a JSON message payload in a Connect stream envelope frame:
/// 1 byte flag (0 = data) + 4 bytes big-endian length + payload.
/// The dispatcher expects this shape on `application/connect+json`
/// requests — a bare JSON body is rejected as
/// `incomplete request envelope` before any handler runs.
fn connect_stream_request_envelope(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0u8);
    frame.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("payload fits in u32")
            .to_be_bytes(),
    );
    frame.extend_from_slice(payload);
    frame
}

/// Scope-deny on a **streaming** Connect endpoint. The shared
/// `assert_connect_scope_denied` helper uses `application/json`
/// (Connect unary Content-Type), which the dispatcher rejects on
/// streaming methods with `unimplemented` — different code path.
/// This test sends `application/connect+json` (Connect streaming
/// Content-Type) so it reaches the handler; the scope check runs
/// before the stream is established and comes back as HTTP 200
/// with a gRPC-style trailer carrying `permission_denied`
/// (streaming errors ride in trailers, not on the HTTP status).
#[tokio::test(flavor = "current_thread")]
async fn connect_events_tail_scope_deny_returns_permission_denied() {
    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("scoped", b"[\"logs:read\"]")
        .unwrap();
    let router = build_router(engine);
    // Connect streaming expects a framed request envelope (5-byte
    // header + payload), same shape as the response frames — so a
    // bare `{}` body would be rejected by the dispatcher with
    // `incomplete request envelope` before the auth check runs.
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.EventsService/TailEvents")
                .header(header::CONTENT_TYPE, "application/connect+json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .body(Body::from(connect_stream_request_envelope(b"{}")))
                .unwrap(),
        )
        .await
        .unwrap();
    // Connect streaming puts errors in the response body/trailers
    // on top of HTTP 200, not on the HTTP status.
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    // The body must carry the `permission_denied` code in a
    // Connect end-stream envelope — a naive substring check is
    // enough here since the code appears verbatim in the JSON.
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        body_str.contains("permission_denied"),
        "expected permission_denied in streaming body, got: {body_str}",
    );
}

/// Publish an event via the in-process bus, then drain the
/// Connect server-streaming response body until the first Data
/// frame arrives. Parses the Connect JSON envelope:
/// 5-byte frame header (1 byte flag + 4 bytes big-endian length)
/// + N bytes JSON payload. Yields the first message's parsed JSON
/// so the test can assert the payload variant.
#[tokio::test(flavor = "multi_thread")]
async fn connect_events_tail_streams_a_custom_event() {
    use http_body_util::BodyExt as _;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload,
    };
    use std::time::Duration;

    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("streamer", b"[\"events:tail\"]")
        .unwrap();
    let router = build_router(engine.clone());

    // Race-proof publish loop — same shape as the JSON WS test.
    // `connect_async` returning tells us HTTP 200 + headers landed;
    // the handler's `subscribe_all` runs a moment after. A single
    // publish before the subscriber exists is dropped by
    // `tokio::broadcast`, so we publish on a 50 ms cadence until
    // the recv side aborts us. Idempotent — the test only inspects
    // the first frame.
    let publisher_engine = engine.clone();
    let publisher = tokio::spawn(async move {
        loop {
            publisher_engine.events().publish(Event {
                device: None,
                timestamp: 0,
                origin_plugin_id: String::new(),
                origin_instance_id: String::new(),
                row_id: None,
                payload: EventPayload::Custom(CustomEvent {
                    topic: "connect-e2e.toggle".into(),
                    payload: String::new(),
                }),
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.EventsService/TailEvents")
                .header(header::CONTENT_TYPE, "application/connect+json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .body(Body::from(connect_stream_request_envelope(b"{}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();

    // Drain body frames until we've read the first Connect message
    // (5-byte header + payload). Small messages usually arrive in a
    // single HTTP data frame, but nothing in axum guarantees that,
    // so buffer across frames.
    let mut buf: Vec<u8> = Vec::new();
    let message_json = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame_opt = body.frame().await;
            let Some(Ok(frame)) = frame_opt else {
                return None;
            };
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
            if buf.len() < 5 {
                continue;
            }
            // Frame header: 1 byte flag (0 = data, 2 = end-of-stream)
            // + 4 bytes big-endian length.
            let flag = buf[0];
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len {
                continue;
            }
            // Skip end-of-stream frames — we want a data frame with
            // the published event.
            if flag & 0x02 != 0 {
                buf.drain(..5 + len);
                continue;
            }
            let payload_bytes = buf[5..5 + len].to_vec();
            return Some(payload_bytes);
        }
    })
    .await
    .expect("first frame within 5s")
    .expect("frame body available");
    publisher.abort();

    let json: Value = serde_json::from_slice(&message_json).expect("json message");
    // The envelope carries `event.payload.custom.topic` for a
    // Custom event — same shape a Connect client sees via the
    // generated `TailEventsResponse` message.
    let custom = &json["event"]["custom"];
    assert!(
        !custom.is_null(),
        "expected a Custom event payload, got {json:?}",
    );
    assert_eq!(custom["topic"], "connect-e2e.toggle");
}

/// PR #75 review findings — `StateChanged` carries the WIT
/// `state-change.fields` list, and `Event.timestamp_ms` /
/// `Inference.frame_timestamp_ms` are `uint64` on the wire (not
/// `int64`), so plugin-supplied timestamps above `i64::MAX` don't
/// wrap negative in transit.
///
/// Publishes a `StateChanged` event with a `brightness = 42` field
/// AND a timestamp above `i64::MAX`; asserts the streamed proto
/// carries both the field and the unsigned timestamp verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn connect_events_tail_state_changed_preserves_fields_and_unsigned_timestamp() {
    use http_body_util::BodyExt as _;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        Event, EventPayload, StateChange,
    };
    // Rename the WIT `Value` on import so it doesn't shadow the
    // `serde_json::Value` alias `Value` this test file imports at
    // the top for JSON assertions.
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};
    use std::time::Duration;

    // A timestamp above `i64::MAX` — the previous `int64` proto
    // shape + `cast_signed` would render this as a negative value
    // on the wire.
    const BIG_TS: u64 = u64::MAX - 42;

    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("streamer", b"[\"events:tail\"]")
        .unwrap();
    let router = build_router(engine.clone());

    let publisher_engine = engine.clone();
    let publisher = tokio::spawn(async move {
        loop {
            publisher_engine.events().publish(Event {
                device: Some("switch-1".into()),
                timestamp: BIG_TS,
                origin_plugin_id: String::new(),
                origin_instance_id: String::new(),
                row_id: None,
                payload: EventPayload::StateChanged(StateChange {
                    capability: "switch".into(),
                    fields: vec![KeyValue {
                        key: "brightness".into(),
                        value: WitValue::IntVal(42),
                    }],
                }),
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.EventsService/TailEvents")
                .header(header::CONTENT_TYPE, "application/connect+json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .body(Body::from(connect_stream_request_envelope(b"{}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();

    let mut buf: Vec<u8> = Vec::new();
    let message_json = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame_opt = body.frame().await;
            let Some(Ok(frame)) = frame_opt else {
                return None;
            };
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
            if buf.len() < 5 {
                continue;
            }
            let flag = buf[0];
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len {
                continue;
            }
            if flag & 0x02 != 0 {
                buf.drain(..5 + len);
                continue;
            }
            let payload_bytes = buf[5..5 + len].to_vec();
            return Some(payload_bytes);
        }
    })
    .await
    .expect("first frame within 5s")
    .expect("frame body available");
    publisher.abort();

    let json: Value = serde_json::from_slice(&message_json).expect("json message");
    let event = &json["event"];
    // StateChanged variant lands under `event.stateChanged` in
    // Connect's canonical protobuf-JSON.
    let sc = &event["stateChanged"];
    assert!(
        !sc.is_null(),
        "expected a StateChanged payload, got {json:?}",
    );
    assert_eq!(sc["capability"], "switch");
    // `fields` was silently dropped by the previous handler shape.
    let fields = sc["fields"].as_array().expect("fields array");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["key"], "brightness");
    assert_eq!(fields[0]["value"]["intVal"], "42"); // int64 → JSON string per proto3 canonical
    // Timestamp preserved as an unsigned decimal string. Numeric
    // JSON strings are protobuf-JSON's canonical representation
    // for 64-bit integers; the important assertion is that the
    // value equals BIG_TS, not that it's a negative number.
    assert_eq!(event["timestampMs"], BIG_TS.to_string());
}

/// H5: `GET /api/v1/events` returns rows from the durable
/// `event_log` table, ordered newest-first, with the `id` field
/// each row carries — the same id a live tail message would ride.
/// Verifies the end-to-end wiring: record → query → JSON response
/// with the durable id in place.
#[tokio::test(flavor = "current_thread")]
async fn events_query_returns_recorded_rows_with_durable_ids() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload,
    };

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"events:read\"]")
        .unwrap();

    // Record two events directly through the store so the test
    // doesn't need a live plugin.
    let event_log = engine.event_log();
    let ev1 = Event {
        device: None,
        timestamp: 100,
        origin_plugin_id: "com.example.recorder".into(),
        origin_instance_id: "recorder-a".into(),
        row_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: "history.first".into(),
            payload: "{}".into(),
        }),
    };
    let ev2 = Event {
        device: None,
        timestamp: 200,
        origin_plugin_id: "com.example.recorder".into(),
        origin_instance_id: "recorder-a".into(),
        row_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: "history.second".into(),
            payload: "{}".into(),
        }),
    };
    let id1 = event_log
        .record(1_000, &ev1, "recorder-a", "com.example.recorder")
        .expect("record 1");
    let id2 = event_log
        .record(2_000, &ev2, "recorder-a", "com.example.recorder")
        .expect("record 2");
    assert!(id2 > id1, "second row must have a greater id");

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?topic_prefix=history.&limit=10")
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
    let body = body_to_json(response.into_body()).await;
    let events = body["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2, "expected 2 rows, got {body:?}");
    // Newest first — id2 leads.
    assert_eq!(events[0]["id"], id2);
    assert_eq!(events[0]["topic"], "history.second");
    assert_eq!(events[1]["id"], id1);
    assert_eq!(events[1]["topic"], "history.first");
    // Instance + plugin metadata surfaces the durable log's
    // host-attributed identity (not the plugin-set origin fields).
    assert_eq!(events[0]["instance_id"], "recorder-a");
    assert_eq!(events[0]["plugin_id"], "com.example.recorder");
}

/// H5: `GET /api/v1/events` refuses without the `events:read`
/// scope. A token that only carries `events:tail` (live-stream
/// scope) can't drop into history — same shape as logs:read vs
/// logs:tail (which doesn't exist yet, but the discipline lines
/// up).
#[tokio::test(flavor = "current_thread")]
async fn events_query_refuses_without_events_read_scope() {
    let engine = Engine::new().expect("engine");
    let tail_only = engine
        .auth_tokens()
        .create("tail_only", b"[\"events:tail\"]")
        .unwrap();

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", tail_only.plaintext),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// H5 round-2 P1 F2: `after_id` cursor. A tail reader that
/// records the last-seen row id can resume history without
/// duplicates: the returned rows must be strictly `id > cursor`.
/// The endpoint contract now supports this so a client can
/// bridge a reconnect gap deterministically.
#[tokio::test(flavor = "current_thread")]
async fn events_query_after_id_returns_only_newer_rows() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload,
    };

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"events:read\"]")
        .unwrap();
    let event_log = engine.event_log();
    let mut ids = Vec::new();
    for i in 0..4i64 {
        let ev = Event {
            device: None,
            #[allow(clippy::cast_sign_loss)]
            timestamp: (1_000 + i) as u64,
            origin_plugin_id: "com.example.cursor".into(),
            origin_instance_id: "cur-a".into(),
            row_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: format!("cursor.{i}"),
                payload: "{}".into(),
            }),
        };
        ids.push(
            event_log
                .record(2_000 + i, &ev, "cur-a", "com.example.cursor")
                .expect("record"),
        );
    }
    let cursor = ids[1];
    let uri = format!("/api/v1/events?topic_prefix=cursor.&after_id={cursor}");
    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri(&uri)
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
    let body = body_to_json(response.into_body()).await;
    let events = body["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        2,
        "expected 2 rows after cursor, got {body:?}"
    );
    assert_eq!(events[0]["id"], ids[3]);
    assert_eq!(events[1]["id"], ids[2]);
    for e in events {
        assert!(
            e["id"].as_u64().unwrap() > cursor,
            "row id {} not strictly greater than cursor {cursor}",
            e["id"],
        );
    }
}

/// H5 round-2 P1 F3: `StateChanged` history rows include the
/// changed `fields`. Pre-fix wire projection kept only the
/// capability tag, so two `StateChanged("switch")` rows with
/// different values looked identical to a history reader.
#[tokio::test(flavor = "current_thread")]
async fn events_query_state_changed_exposes_fields() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        Event, EventPayload, StateChange,
    };
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"events:read\"]")
        .unwrap();
    let event_log = engine.event_log();
    let ev = Event {
        device: Some("switch-7".into()),
        timestamp: 42,
        origin_plugin_id: "com.example.switch".into(),
        origin_instance_id: "sw-a".into(),
        row_id: None,
        payload: EventPayload::StateChanged(StateChange {
            capability: "switch".into(),
            fields: vec![KeyValue {
                key: "state".into(),
                value: WitValue::BoolVal(true),
            }],
        }),
    };
    event_log
        .record(100, &ev, "sw-a", "com.example.switch")
        .expect("record");

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?topic=switch")
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
    let body = body_to_json(response.into_body()).await;
    let events = body["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    let payload = &events[0]["payload"];
    assert_eq!(payload["kind"], "state_changed");
    assert_eq!(payload["capability"], "switch");
    let fields = payload["fields"].as_array().expect("fields array");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["key"], "state");
    // Tagged JSON via serde `#[serde(tag = "t", content = "v")]`.
    assert_eq!(fields[0]["value"]["t"], "Bool");
    assert_eq!(fields[0]["value"]["v"], true);
}

/// H5 round-2 P2 F1: publisher-order sequencer. Sequenced
/// publishes must never deliver events out of `event_log` id
/// order to a subscriber — a client using row id as a monotonic
/// cursor relies on the bus keeping delivery aligned with the
/// row-id sequence stamped on the durable log.
#[tokio::test(flavor = "current_thread")]
async fn publisher_order_sequencer_preserves_row_id_order() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventFilter, EventPayload,
    };
    use oxidhome_core::state::EventBus;
    use std::sync::Arc;

    let bus = Arc::new(EventBus::new());
    let mut sub = bus.subscribe(EventFilter {
        device: None,
        topic: None,
    });

    let expected: Vec<u64> = (1..=8).collect();
    for id in &expected {
        let gate = bus.publish_sequence();
        let _g = gate.lock().await;
        let ev = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: "com.example.seq".into(),
            origin_instance_id: "seq-a".into(),
            row_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: format!("seq.{id}"),
                payload: String::new(),
            }),
        };
        bus.publish_with_id(ev, Some(*id));
    }

    let mut observed = Vec::new();
    while let Some(msg) = sub.receiver.recv().await {
        let ev = msg.expect_event();
        observed.push(ev.row_id.expect("row_id stamped"));
        if observed.len() == expected.len() {
            break;
        }
    }
    assert_eq!(
        observed, expected,
        "publisher-order gate must preserve row-id ordering",
    );
}

// ── H9: device-state projection ──────────────────────────────────

/// H9: `GET /api/v1/devices/{id}/state` reflects state changes
/// written through the host-owned projection. Uses the engine's
/// `device_state()` handle directly (bypasses the WIT publish path)
/// so the test doesn't need a live plugin — the runtime integration
/// is covered separately.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_snapshot_reflects_applied_changes() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"devices:read\"]")
        .unwrap();

    let store = engine.device_state();
    store.apply_delta(
        "dev-42".into(),
        "alpha".into(),
        "switch".into(),
        vec![KeyValue {
            key: "state".into(),
            value: Value::BoolVal(true),
        }],
        1234,
        5678,
    );

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/dev-42/state")
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
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["device_id"], "dev-42");
    assert_eq!(body["revision"].as_u64().unwrap(), 1);
    // H9 round-6 finding 1: snapshot carries the store epoch so
    // clients can detect a daemon restart.
    assert!(body["epoch"].as_str().unwrap().starts_with("epoch-"));
    let caps = body["capabilities"].as_array().expect("capabilities");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0]["capability"], "switch");
    assert!(caps[0].get("entry_revision").is_none());
    assert_eq!(caps[0]["global_revision"].as_u64().unwrap(), 1);
    assert_eq!(caps[0]["quality"], "fresh");
    assert_eq!(caps[0]["received_ms"].as_i64().unwrap(), 5678);
    assert_eq!(caps[0]["observed_ms"].as_u64().unwrap(), 1234);
    let fields = caps[0]["fields"].as_array().expect("fields array");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["key"], "state");
    assert_eq!(fields[0]["value"]["t"], "Bool");
    assert_eq!(fields[0]["value"]["v"], true);
}

/// H9: `GET /api/v1/devices/state/changes` returns entries whose
/// `global_revision > since_revision`, sorted ascending, capped at
/// `limit`. This is a materialized-view read (latest value per
/// slot), not an append-only stream — a slot updated multiple
/// times between polls is coalesced. This test writes each slot
/// exactly once so the coalescing doesn't apply and the cursor
/// paging semantics are easy to observe.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_changes_returns_cursor_deltas() {
    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"devices:read\"]")
        .unwrap();

    let store = engine.device_state();
    for i in 0..4 {
        store.apply_delta(
            format!("dev-{i}"),
            "alpha".into(),
            "switch".into(),
            Vec::new(),
            0,
            0,
        );
    }

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/state/changes?since_revision=2&limit=10")
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
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["current_revision"].as_u64().unwrap(), 4);
    let changes = body["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), 2);
    // Ascending by global_revision so paging forward is well-defined.
    assert_eq!(changes[0]["global_revision"].as_u64().unwrap(), 3);
    assert_eq!(changes[1]["global_revision"].as_u64().unwrap(), 4);
    assert_eq!(changes[0]["device_id"], "dev-2");
    assert_eq!(changes[1]["device_id"], "dev-3");
    // H9 round-6 finding 1: normal cursor advance carries the
    // store epoch, and `reset_required` is false when the
    // caller's cursor is within the current revision.
    assert!(body["epoch"].as_str().unwrap().starts_with("epoch-"));
    assert_eq!(body["reset_required"], false);
}

/// H9 round-6 finding 1: `since_revision > current_revision` (as
/// happens when a client held a pre-restart cursor and the daemon
/// restarted, dropping the in-memory store back to revision 0)
/// returns `reset_required: true` with an empty `changes` and the
/// current store epoch. The client sees this and resyncs.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_changes_signals_reset_when_cursor_exceeds_current() {
    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"devices:read\"]")
        .unwrap();
    // Seed a few entries so current_revision = 2 (well below the
    // 999 cursor the client sends).
    let store = engine.device_state();
    store.apply_delta(
        "dev-1".into(),
        "alpha".into(),
        "switch".into(),
        Vec::new(),
        0,
        0,
    );
    store.apply_delta(
        "dev-2".into(),
        "alpha".into(),
        "switch".into(),
        Vec::new(),
        0,
        0,
    );

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/state/changes?since_revision=999")
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
    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["reset_required"], true);
    assert_eq!(body["changes"].as_array().unwrap().len(), 0);
    assert_eq!(body["current_revision"].as_u64().unwrap(), 2);
    assert!(body["epoch"].as_str().unwrap().starts_with("epoch-"));
}

/// H9: `GET /api/v1/devices/{id}/state` and
/// `GET /api/v1/devices/state/changes` both require the
/// `devices:read` scope. `devices:list` (registration snapshot)
/// does not satisfy — this is a distinct capability.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_endpoints_require_devices_read_scope() {
    let engine = Engine::new().expect("engine");
    let list_only = engine
        .auth_tokens()
        .create("list-only", b"[\"devices:list\"]")
        .unwrap();

    for path in [
        "/api/v1/devices/dev-1/state",
        "/api/v1/devices/state/changes",
    ] {
        let response = build_router(engine.clone())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", list_only.plaintext),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{path} must require devices:read",
        );
    }
}

/// H9 round-2 finding 2: partial state updates merge by key.
/// Applies an initial color-light state, then a subsequent update
/// with only `hue`, then asserts saturation / value survive.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_partial_updates_merge_untouched_fields() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};

    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"devices:read\"]")
        .unwrap();
    let store = engine.device_state();
    store.apply_delta(
        "dev-1".into(),
        "alpha".into(),
        "color-light".into(),
        vec![
            KeyValue {
                key: "hue".into(),
                value: Value::FloatVal(0.1),
            },
            KeyValue {
                key: "saturation".into(),
                value: Value::FloatVal(0.9),
            },
            KeyValue {
                key: "value".into(),
                value: Value::FloatVal(0.8),
            },
        ],
        0,
        0,
    );
    store.apply_delta(
        "dev-1".into(),
        "alpha".into(),
        "color-light".into(),
        vec![KeyValue {
            key: "hue".into(),
            value: Value::FloatVal(0.5),
        }],
        0,
        0,
    );

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/dev-1/state")
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
    let body = body_to_json(response.into_body()).await;
    let cap = &body["capabilities"][0];
    assert_eq!(cap["capability"], "color-light");
    let fields = cap["fields"].as_array().unwrap();
    let get = |k: &str| -> serde_json::Value {
        fields
            .iter()
            .find(|f| f["key"] == k)
            .expect("field present")["value"]
            .clone()
    };
    // hue updated to 0.5, saturation / value preserved.
    assert_eq!(get("hue")["t"], "Float");
    assert!((get("hue")["v"].as_f64().unwrap() - 0.5).abs() < 1e-9);
    assert!((get("saturation")["v"].as_f64().unwrap() - 0.9).abs() < 1e-9);
    assert!((get("value")["v"].as_f64().unwrap() - 0.8).abs() < 1e-9);
}

/// H9 round-2 finding 3: `mark_device_stale` flips every entry
/// for a device to `Stale` and bumps the store revision so a
/// delta poller catches the transition. Simulates a
/// `remove-device` at the store level.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_mark_device_stale_bumps_revision_and_flips_all_caps() {
    let engine = Engine::new().expect("engine");
    let reader = engine
        .auth_tokens()
        .create("reader", b"[\"devices:read\"]")
        .unwrap();
    let store = engine.device_state();
    store.apply_delta(
        "dev-1".into(),
        "alpha".into(),
        "switch".into(),
        Vec::new(),
        0,
        0,
    );
    store.apply_delta(
        "dev-1".into(),
        "alpha".into(),
        "dimmer".into(),
        Vec::new(),
        0,
        0,
    );
    assert_eq!(store.current_revision(), 2);
    let flipped = store.mark_device_stale("dev-1");
    assert_eq!(flipped, 2);
    assert_eq!(store.current_revision(), 4);

    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices/state/changes?since_revision=2&limit=10")
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
    let body = body_to_json(response.into_body()).await;
    let changes = body["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2);
    for change in changes {
        assert_eq!(change["device_id"], "dev-1");
        assert_eq!(change["quality"], "stale");
    }
}

/// H9 round-2 finding 3: `reconcile_capabilities` flips entries
/// whose capability was dropped, keeps entries whose capability
/// is still declared.
#[tokio::test(flavor = "current_thread")]
async fn devices_state_reconcile_capabilities_flips_only_dropped_caps() {
    let engine = Engine::new().expect("engine");
    let store = engine.device_state();
    for cap in ["switch", "dimmer", "color-light"] {
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            (*cap).into(),
            Vec::new(),
            0,
            0,
        );
    }
    // Drop `dimmer` from the live capability set.
    let flipped =
        store.reconcile_capabilities("dev-1", &["switch".to_string(), "color-light".to_string()]);
    assert_eq!(flipped, 1);
    assert_eq!(
        store
            .snapshot_capability("dev-1", "dimmer")
            .unwrap()
            .quality,
        oxidhome_core::state::StateQuality::Stale
    );
    assert_eq!(
        store
            .snapshot_capability("dev-1", "switch")
            .unwrap()
            .quality,
        oxidhome_core::state::StateQuality::Fresh
    );
}
