//! Bearer-token auth middleware.
//!
//! Every request the router serves goes through [`require_token`]
//! except for the explicit anonymous list ([`PUBLIC_PATHS`]). The
//! middleware:
//!
//! 1. Reads `Authorization: Bearer <token>` (case-insensitive on
//!    the scheme per RFC 6750 §1.1; one or more SP between scheme
//!    and credential).
//! 2. Calls [`TokenStore::verify`] — the store hashes the presented
//!    secret with SHA-256 and looks the row up by hash.
//! 3. On success, builds an [`Actor::api(token_id, scopes)`] from
//!    the matched row's `id` + parsed `scope_json`, attaches it to
//!    the request via `Extension`, records a **pending audit intent
//!    row** through [`AuditLog::record_intent`] (fail-closed: if
//!    that write errors the request 500s without executing the
//!    handler), then forwards to the route. After the handler
//!    returns [`AuditLog::finalize`] updates the intent row with the
//!    outcome.
//! 4. On any failure (missing header, malformed token, unknown
//!    secret, revoked) responds with **`401 Unauthorized`** with a
//!    `WWW-Authenticate: Bearer` header and an empty body. The
//!    variants are not distinguished externally so an attacker can't
//!    probe shape, validity, or revocation state. Each failed
//!    attempt is recorded as an anonymous audit row
//!    ([`record_anonymous_probe`]) with a short SHA-256
//!    fingerprint of the presented bearer (never the raw secret),
//!    so a forensic sweep can correlate probes.
//!
//! Anonymous routes (`PUBLIC_PATHS`) skip the bearer extraction and
//! the audit path entirely.
//!
//! ## Blocking discipline
//!
//! Every `AuditLog` call runs under a `std::sync::Mutex` over the
//! shared `rusqlite::Connection`. Calling it directly from an
//! `async fn` would park the tokio worker under contention. The
//! middleware wraps each of the three audit calls
//! (`record_intent`, `finalize`, `record_completed`) in
//! [`tokio::task::spawn_blocking`] so slow disks + log-store /
//! blob-store contention can't stall the runtime.
//!
//! ## Cancellation safety
//!
//! The pre-audit intent row commits *before* the handler runs. If
//! the client disconnects mid-handler — which cancels the request
//! future but leaves any `spawn_blocking` filesystem work the
//! handler kicked off to complete on the blocking pool
//! (`spawn_blocking` doesn't observe join-handle drops) — the
//! pending row stays behind as the ledger's evidence of intent. An
//! operator queries `decision = "pending"` for abandoned intents.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
use crate::state::{
    AuditEntry, AuditLog, TokenError, TokenRecord, TokenStore, credential_fingerprint,
};

/// Smuggled on a response's extension map by JSON handlers when the
/// wire response is HTTP 200 but the *plugin's domain outcome* is a
/// failure — the canonical case being `POST
/// /api/v1/devices/{id}/command` returning `WireCommandResult::Err`.
/// The auth middleware reads this back post-handler and populates
/// the audit row's `execution_outcome` and `domain_error` fields
/// (see [`crate::state::AuditEntry`]), leaving `status` at the wire
/// 200 and `decision` at the authorization outcome (`"allow"` — the
/// request was authorized before it reached the plugin).
///
/// **Independence** — architecture-review F4 pushback. An earlier
/// cut of this signal fed a synthesized status into the classifier,
/// which collapsed execution failure into `decision = "deny"` and
/// broke forensic queries: plugin validation errors mixed with real
/// authorization denials in `WHERE decision = 'deny'` results. The
/// current shape keeps authorization and execution outcomes as
/// distinct audit fields so operators can filter each independently.
///
/// The Connect side smuggles the same information via
/// [`super::connect_rpc::HandlerOutcomeSlot`] — a request-side
/// slot that already existed for gRPC / gRPC-Web scope-denial
/// classification.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DomainOutcome {
    /// The plugin's WIT error kind (`"not_found"`,
    /// `"invalid_argument"`, `"permission_denied"`, `"unavailable"`,
    /// `"internal"`), stamped when the handler returns
    /// `CommandResult::Err(<variant>)`.
    pub(crate) domain_error: &'static str,
}

/// WIT `error` variant → the stable `snake_case` tag written to the
/// audit ledger's `domain_error` column. The set of legal values
/// matches the WIT `error` variant one-for-one.
#[must_use]
pub(crate) fn wit_error_kind(err: &WitError) -> &'static str {
    match err {
        WitError::NotFound(_) => "not_found",
        WitError::InvalidArgument(_) => "invalid_argument",
        WitError::PermissionDenied(_) => "permission_denied",
        WitError::Unavailable(_) => "unavailable",
        WitError::Internal(_) => "internal",
    }
}

/// Routes that don't require a bearer token. The canonical Connect
/// liveness probe (`POST /oxidhome.v1.HealthService/Check`) is
/// mounted as a `fallback_service` **outside** the bearer-auth
/// middleware and doesn't need an entry here.
///
/// The JSON-side `GET /api/v1/readyz` mirror exists for
/// orchestrators that can't POST a Connect envelope (systemd's
/// `ExecStartPost`, docker's `HEALTHCHECK`, k8s's `httpGet`
/// probe) — same `{status, version}` body shape as `Health.Check`.
pub(crate) const PUBLIC_PATHS: &[&str] = &["/api/v1/readyz"];

/// Sentinel `token_id` used on audit rows for unauthenticated
/// probes — missing / malformed / unknown / revoked bearer.
pub(super) const ANONYMOUS_TOKEN_ID: &str = "anonymous";

/// Shared state the middleware needs. Held behind `Arc` and cloned
/// per request — every field is already `Arc`-backed, so the clone
/// is cheap.
#[derive(Clone)]
pub(crate) struct AuthState {
    pub tokens: Arc<TokenStore>,
    /// Dedicated audit ledger — architecture-review C3. See the
    /// module-level doc for the two-phase write contract and the
    /// blocking / cancellation-safety discipline.
    pub audit_log: Arc<AuditLog>,
}

/// Axum middleware. Wired via `axum::middleware::from_fn_with_state`
/// in `server::router`.
///
/// See the module doc for the full flow; the short version:
///
/// 1. `PUBLIC_PATHS` → pass through, no audit.
/// 2. Extract bearer; on failure record an anonymous probe row and
///    return 401 (see [`record_anonymous_probe`]).
/// 3. Verify token; on failure same as above (also 401).
/// 4. Record a `pending` intent row. Fail-closed on ledger error:
///    return 500 without running the handler — a mutation with no
///    audit trail is not acceptable.
/// 5. Run the handler.
/// 6. `finalize` the intent row with the handler's outcome. Best-
///    effort — the pending row is already committed as evidence of
///    intent.
///
/// `decision` values written to the ledger:
/// - `"allow"` — handler returned 2xx
/// - `"deny"` — handler returned 4xx (incl. scope failure 403s)
/// - `"error"` — handler returned 5xx
/// - `"pending"` — intent recorded; handler still running, or the
///   request was abandoned before finalize
pub(crate) async fn require_token(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    if PUBLIC_PATHS.iter().any(|p| *p == req.uri().path()) {
        return next.run(req).await;
    }

    let http_path = req.uri().path().to_string();
    let method = req.method().to_string();

    let Some(bearer) = extract_bearer(&req).map(str::to_owned) else {
        // No `Authorization` header at all — no fingerprint to
        // record (the client presented nothing). Still audit as
        // anonymous so the probe volume is visible.
        record_anonymous_probe(&state.audit_log, &method, &http_path, 401, None).await;
        return unauthorized();
    };

    let (token_id, actor_kind) = match state.tokens.verify(&bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            req.extensions_mut().insert(actor);
            (token_id, actor_kind)
        }
        Err(TokenError::Malformed | TokenError::Unknown | TokenError::Revoked) => {
            // Malformed / unknown / revoked — record the probe with
            // a fingerprint so a forensic sweep can correlate
            // repeats. Never store the raw secret.
            let fp = credential_fingerprint(&bearer);
            record_anonymous_probe(&state.audit_log, &method, &http_path, 401, Some(fp)).await;
            return unauthorized();
        }
        Err(TokenError::Sqlite(err)) => {
            tracing::error!(target: "api.auth", error = %err, "token verify failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // (F1) Pre-audit intent — commit the row *before* the handler
    // executes so a mid-handler cancellation still leaves evidence.
    // (F2) Fail-closed: ledger unreachable ⇒ refuse the request.
    let intent = AuditEntry {
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.clone(),
        actor_kind: actor_kind.clone(),
        method: method.clone(),
        path: http_path.clone(),
        status: 0,
        decision: "pending".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
    };
    let audit_id = match record_intent_blocking(&state.audit_log, intent).await {
        Ok(id) => id,
        Err(msg) => {
            // Backstop: `eprintln!` because the tracing side rides
            // the drop-tolerant `LogStore` and this is exactly the
            // moment we can't trust it. The ERROR-level tracing
            // event still fires alongside — most of the time it'll
            // land — but stderr is the ledger's parting words.
            eprintln!("oxidhome audit_log: record_intent failed; refusing request: {msg}");
            tracing::error!(
                target: "api.audit",
                error = %msg,
                token_id = %token_id,
                method = %method,
                path = %http_path,
                "audit-ledger intent write failed — refusing request",
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let response = next.run(req).await;
    let denied_scope = response
        .extensions()
        .get::<crate::api::scopes::DeniedScope>()
        .map(|d| d.0);
    // F4: handlers whose wire response is HTTP 200 but whose
    // *plugin domain outcome* is a failure stamp a `DomainOutcome`
    // response extension. The middleware records that in the
    // audit ledger's separate `execution_outcome` + `domain_error`
    // fields, leaving `status` at the wire status and `decision`
    // at the authorization outcome. See `DomainOutcome`'s
    // docstring for why authorization and execution outcomes are
    // kept independent.
    let domain_outcome = response.extensions().get::<DomainOutcome>().copied();
    let status = response.status();
    finalize_audit(
        &state.audit_log,
        audit_id,
        &token_id,
        &actor_kind,
        &method,
        &http_path,
        status,
        denied_scope,
        domain_outcome,
    )
    .await;
    response
}

/// Record an anonymous-probe audit row for a request that failed
/// authentication. Best-effort — the auth check has already decided
/// the outcome and no handler will run, so a ledger failure here
/// only loses this one row (no unaudited mutation).
pub(super) async fn record_anonymous_probe(
    audit_log: &Arc<AuditLog>,
    method: &str,
    path: &str,
    status: u16,
    credential_fp: Option<String>,
) {
    let entry = AuditEntry {
        intent_ms: 0,
        finalized_ms: None,
        token_id: ANONYMOUS_TOKEN_ID.into(),
        actor_kind: ANONYMOUS_TOKEN_ID.into(),
        method: method.to_owned(),
        path: path.to_owned(),
        status,
        decision: "deny".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: None,
        credential_fp,
    };
    let al = Arc::clone(audit_log);
    let join = tokio::task::spawn_blocking(move || al.record_completed(&entry)).await;
    match join {
        Ok(Ok(_id)) => {}
        Ok(Err(err)) => {
            eprintln!("oxidhome audit_log: record_completed (anonymous probe) failed: {err}");
            tracing::error!(
                target: "api.audit",
                error = %err,
                method = %method,
                path = %path,
                "audit-ledger anonymous-probe write failed",
            );
        }
        Err(join_err) => {
            eprintln!(
                "oxidhome audit_log: record_completed (anonymous probe) join failed: {join_err}",
            );
        }
    }
    // Best-effort tracing mirror so operators tailing stderr still
    // see the probe (and the existing `logs query --target api.audit`
    // API keeps returning it). This path can drop under load — the
    // ledger row above is the forensic source of truth.
    tracing::info!(
        target: "api.audit",
        audit_target = %format!("api.{method}-{path}"),
        token_id = %ANONYMOUS_TOKEN_ID,
        actor_kind = %ANONYMOUS_TOKEN_ID,
        method = %method,
        path = %path,
        status = status,
        decision = %"deny",
        required_scope = %"",
        "api request",
    );
}

/// Blocking-safe wrapper around [`AuditLog::record_intent`]. Runs the
/// insert on the blocking pool so the tokio worker isn't parked on
/// the shared `Db` mutex. Returns a `String` error on either the
/// SQL failure or a `spawn_blocking` join failure — the middleware
/// only needs "something went wrong" to fail-closed with a 500.
async fn record_intent_blocking(
    audit_log: &Arc<AuditLog>,
    entry: AuditEntry,
) -> Result<u64, String> {
    let al = Arc::clone(audit_log);
    match tokio::task::spawn_blocking(move || al.record_intent(&entry)).await {
        Ok(Ok(id)) => Ok(id),
        Ok(Err(err)) => Err(err.to_string()),
        Err(join_err) => Err(format!("spawn_blocking join: {join_err}")),
    }
}

/// Two-phase finalize + tracing mirror. Wraps [`AuditLog::finalize`]
/// on the blocking pool, then emits the same tracing target the
/// pre-C3 code used so operators tailing stderr keep seeing every
/// request and the current `logs query --target api.audit` API
/// path keeps working. Best-effort — the pending row is already
/// committed evidence of intent.
///
/// `pub(super)` so the Connect-side middleware calls the same
/// helper — single source of truth for the audit-row contract
/// across both surfaces.
#[allow(clippy::too_many_arguments)]
pub(super) async fn finalize_audit(
    audit_log: &Arc<AuditLog>,
    audit_id: u64,
    token_id: &str,
    actor_kind: &str,
    method: &str,
    path: &str,
    status: StatusCode,
    required_scope: Option<&'static str>,
    domain_outcome: Option<DomainOutcome>,
) {
    // Authorization outcome — depends *only* on the transport
    // status. A plugin returning `CommandResult::Err` on an
    // authorized request still records `decision = "allow"` here
    // (the auth check succeeded); the execution failure lives in
    // the separate `execution_outcome` / `domain_error` columns.
    let decision = if status.is_success() {
        "allow"
    } else if status.is_server_error() {
        "error"
    } else {
        "deny"
    };
    // Execution outcome — orthogonal to authorization. Populated
    // when the request reached the plugin and the plugin reported
    // a domain-level result; `None` when the request was rejected
    // at auth / dispatch (or when the handler doesn't expose a
    // domain outcome at all, which is every current endpoint
    // except device-command dispatch).
    let (execution_outcome, domain_error) = match (status.is_success(), domain_outcome) {
        (true, Some(o)) => (Some("failed"), Some(o.domain_error)),
        // Success without a `DomainOutcome` extension = the handler
        // has no domain-outcome contract or the plugin returned Ok.
        // Recording "success" here overreaches for handlers that
        // aren't in the domain-outcome contract at all (list /
        // query endpoints), so treat every other case as "not
        // applicable" and leave the columns NULL.
        _ => (None, None),
    };

    let al = Arc::clone(audit_log);
    let required = required_scope.map(str::to_owned);
    let status_u16 = status.as_u16();
    let decision_owned = decision.to_owned();
    let required_for_task = required.clone();
    let execution_for_task = execution_outcome.map(str::to_owned);
    let domain_error_for_task = domain_error.map(str::to_owned);
    let join = tokio::task::spawn_blocking(move || {
        al.finalize(
            audit_id,
            status_u16,
            &decision_owned,
            required_for_task.as_deref(),
            execution_for_task.as_deref(),
            domain_error_for_task.as_deref(),
        )
    })
    .await;
    match join {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("oxidhome audit_log: finalize failed: {err}");
            tracing::error!(
                target: "api.audit",
                error = %err,
                audit_id,
                token_id = %token_id,
                method = %method,
                path = %path,
                "audit-ledger finalize failed — pending row remains",
            );
        }
        Err(join_err) => {
            eprintln!("oxidhome audit_log: finalize join failed: {join_err}");
        }
    }

    // Tracing mirror — same shape the pre-C3 code emitted, so a
    // subscriber that installs the LogStore layer sees every request
    // live in `logs query --target api.audit`. Best-effort by
    // design. Includes the F4 execution-outcome fields so a stderr
    // tail carries the same distinction the ledger does.
    let audit_target = format!("api.{method}-{path}");
    let required_field = required.as_deref().unwrap_or("");
    let execution_field = execution_outcome.unwrap_or("");
    let domain_error_field = domain_error.unwrap_or("");
    tracing::info!(
        target: "api.audit",
        audit_target = %audit_target,
        token_id = %token_id,
        actor_kind = %actor_kind,
        method = %method,
        path = %path,
        status = status_u16,
        decision = %decision,
        required_scope = %required_field,
        execution_outcome = %execution_field,
        domain_error = %domain_error_field,
        "api request",
    );
}

/// Build an [`Actor`] from a verified record. Scopes are parsed
/// best-effort from `scope_json` (UTF-8 JSON array of strings).
/// Parse failure ⇒ empty scopes (deny-all) rather than a 500, so an
/// operator who saved a malformed scope blob with the CLI gets a
/// useful "every request is denied" signal in the audit log rather
/// than the entire API going down.
///
/// `pub(super)` so the Connect-side auth middleware reuses the
/// same record → actor projection.
pub(super) fn actor_from_record(rec: &TokenRecord) -> Actor {
    let scopes = parse_scopes(&rec.scope_json).unwrap_or_else(|| {
        tracing::warn!(
            target: "api.auth",
            token_id = %rec.id,
            "scope_json failed to parse; defaulting to deny-all",
        );
        Vec::new()
    });
    Actor::api(rec.id.clone(), scopes)
}

/// Parse `scope_json` as a JSON array of strings. Returns `None` on
/// any parse failure. The wildcard contract: an element equal to
/// `"*"` means "any scope" — 12-API-b's scope-policy enforcer
/// recognizes it. `pub(crate)` so the bootstrap test can pin the
/// admin-blob round trip (see [`crate::api`]).
pub(crate) fn parse_scopes(blob: &[u8]) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
    let arr = value.as_array()?;
    arr.iter()
        .map(|v| v.as_str().map(String::from))
        .collect::<Option<Vec<_>>>()
}

/// Pull the bearer secret out of an `Authorization: <scheme> …`
/// header. RFC 6750 §1.1 says the scheme name is case-insensitive
/// (`Bearer` / `bearer` / `BEARER` / mixed all parse). One or more
/// SP between the scheme and the credential are tolerated. `None`
/// if the header is missing, the scheme isn't `Bearer`, or the
/// credential is empty.
///
/// `pub(super)` so the Connect-side auth middleware uses exactly
/// the same extractor — case-handling drift between the two
/// surfaces would be a footgun.
pub(super) fn extract_bearer(req: &Request) -> Option<&str> {
    let h = req.headers().get(header::AUTHORIZATION)?;
    let s = h.to_str().ok()?;
    let (scheme, rest) = s.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let trimmed = rest.trim_start_matches(' ');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// 401 with `WWW-Authenticate: Bearer`.
fn unauthorized() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scopes_accepts_string_array() {
        let blob = br#"["devices:read","plugins:list"]"#;
        let scopes = parse_scopes(blob).expect("parse");
        assert_eq!(scopes, vec!["devices:read", "plugins:list"]);
    }

    #[test]
    fn parse_scopes_rejects_non_array_and_non_string_elements() {
        assert!(parse_scopes(b"{}").is_none());
        assert!(parse_scopes(br#"["ok", 7]"#).is_none());
        assert!(parse_scopes(b"not json").is_none());
    }

    #[test]
    fn extract_bearer_handles_case_variants() {
        let req_with = |h: &str| {
            Request::builder()
                .header(header::AUTHORIZATION, h)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        // Case-insensitive scheme (RFC 6750 §1.1).
        assert_eq!(extract_bearer(&req_with("Bearer abc")), Some("abc"));
        assert_eq!(extract_bearer(&req_with("bearer xyz")), Some("xyz"));
        assert_eq!(extract_bearer(&req_with("BEARER tok")), Some("tok"));
        assert_eq!(extract_bearer(&req_with("BeArEr tok")), Some("tok"));
        // Extra whitespace between scheme and credential is tolerated.
        assert_eq!(extract_bearer(&req_with("Bearer   tok")), Some("tok"));
        // Empty credential / wrong scheme / no SP rejected.
        assert!(extract_bearer(&req_with("Bearer ")).is_none());
        assert!(extract_bearer(&req_with("Bearer")).is_none());
        assert!(extract_bearer(&req_with("Basic foo")).is_none());
    }
}
