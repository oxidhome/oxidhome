//! Bearer-token auth middleware.
//!
//! Every request the router serves goes through [`require_token`]
//! except for anonymous routes that mount outside this middleware
//! (see `server::build_router` — currently `GET /api/v1/readyz`).
//! Everything on the authenticated router flows through this
//! middleware, which:
//!
//! 1. Reads `Authorization: Bearer <token>` (case-insensitive on
//!    the scheme per RFC 6750 §1.1; one or more SP between scheme
//!    and credential).
//! 2. Calls [`TokenStore::verify`] — the store hashes the presented
//!    secret with SHA-256 and looks the row up by hash.
//! 3. On success, builds an [`Actor`] from the matched row's `id`,
//!    owner flag and roles (see [`actor_from_record`]), attaches it to
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
//! Anonymous routes mount outside this middleware and don't touch
//! either the bearer path or the audit ledger.
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

use crate::auth::{Actor, InvocationContext, Principal};
use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
use crate::state::{
    AuditEntry, AuditLog, TokenError, TokenRecord, TokenStore, credential_fingerprint,
};

/// Smuggled from a device-command handler to the audit middleware
/// (F4, H5): the command id and explicit outcome of the dispatch. The
/// middleware records them in the audit row's `command_id` /
/// `command_outcome` columns, the coarse `execution_outcome` (`success`
/// / `failed` / NULL) and, for `rejected`, the WIT error kind in
/// `domain_error`.
///
/// **Independence** — architecture-review F4 pushback. Authorization
/// and execution outcomes are distinct audit fields so operators can
/// filter each independently: a dispatched command records
/// `decision = "allow"` (the request was authorized and reached the
/// plugin's queue) whatever its outcome and whatever HTTP status the
/// REST handler picked for that outcome.
///
/// The Connect side smuggles the same information via
/// [`super::connect_rpc::HandlerOutcomeSlot`]; MCP writes its own
/// rows from the same fields.
#[derive(Debug, Clone)]
pub(crate) struct DomainOutcome {
    /// Host-minted `cmd-<32 hex>` id.
    pub(crate) command_id: String,
    /// `CommandOutcome::as_str()`.
    pub(crate) outcome: &'static str,
    /// Coarse pre-H5 value: `success` / `failed` / `None`.
    pub(crate) execution_outcome: Option<&'static str>,
    /// WIT error kind (`"not_found"`, `"invalid_argument"`, …) of a
    /// `rejected` outcome.
    pub(crate) domain_error: Option<&'static str>,
}

impl DomainOutcome {
    pub(crate) fn from_report(report: &crate::runtime::CommandReport) -> Self {
        Self {
            command_id: report.command_id.clone(),
            outcome: report.outcome.as_str(),
            execution_outcome: report.outcome.execution_outcome(),
            domain_error: report.outcome.domain_error(),
        }
    }
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

// Anonymous routes are mounted **outside** this middleware — see
// `server::build_router`. The `PUBLIC_PATHS` inside-the-middleware
// short-circuit that briefly lived here (PR-#83 review, F2) matched
// only on path, so any HTTP method against a public path bypassed
// authentication. Physical router separation via `merge` gives
// per-(method, path) safety by construction.

/// Sentinel `token_id` used on audit rows for unauthenticated
/// probes — missing / malformed / unknown / revoked bearer.
pub(super) const ANONYMOUS_TOKEN_ID: &str = "anonymous";

/// Request-extension smuggle from [`require_token`] to a handler
/// that needs to see its own audit intent row's id (currently just
/// [`super::server::query_audit`], which excludes itself from the
/// result set to avoid returning the self-referential pending row).
/// PR-#85 review, F3 regression.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuditIntentId(pub(crate) u64);

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
    /// Transport this mount serves (H6). Recorded on the root
    /// [`crate::auth::Principal`] of every invocation the middleware
    /// mints.
    pub transport: crate::auth::Transport,
}

/// Axum middleware. Wired via `axum::middleware::from_fn_with_state`
/// in `server::router`.
///
/// See the module doc for the full flow; the short version:
///
/// 1. Extract bearer; on failure record an anonymous probe row and
///    return 401 (see [`record_anonymous_probe`]).
/// 2. Verify token; on failure same as above (also 401).
/// 3. Record a `pending` intent row. Fail-closed on ledger error:
///    return 500 without running the handler — a mutation with no
///    audit trail is not acceptable.
/// 4. Run the handler.
/// 5. `finalize` the intent row with the handler's outcome. Best-
///    effort — the pending row is already committed as evidence of
///    intent.
///
/// `decision` values written to the ledger:
/// - `"allow"` — handler returned 2xx
/// - `"deny"` — handler returned 4xx (incl. permission 403s)
/// - `"error"` — handler returned 5xx
/// - `"pending"` — intent recorded; handler still running, or the
///   request was abandoned before finalize
// Sequential state machine: pull inflight semaphore →
// extract bearer → resolve verify result (from cache or fresh)
// → branch on Ok/Denied/SqliteErr → audit intent → run
// handler → audit finalize. Splitting this into helpers would
// hide the ordering that the audit-ledger contract depends on
// (intent must commit before the handler runs, finalize must
// see the intent's id). Same allow-with-comment shape used
// elsewhere in the crate.
#[allow(clippy::too_many_lines)]
pub(crate) async fn require_token(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let http_path = req.uri().path().to_string();
    let method = req.method().to_string();

    // Round-6 P1 on PR #140: on the MCP mount, the rate
    // limiter injects a shared semaphore capping ALL pre-
    // admission SQLite writes. `try_best_effort` will attempt
    // to acquire a permit before each `spawn_blocking`, and
    // skip the write when saturated (touch_last_used +
    // anonymous probes are best-effort — the operator prefers
    // a missed row over an unbounded blocking-pool queue).
    // REST/Connect mounts don't inject this and get the
    // unbounded path (their per-mount throughput is bounded
    // by the daemon's overall admission cap).
    let inflight = req
        .extensions()
        .get::<super::mcp::PreAdmissionInflight>()
        .cloned();

    let Some(bearer) = extract_bearer(&req).map(str::to_owned) else {
        // No `Authorization` header at all — no fingerprint to
        // record (the client presented nothing). Still audit as
        // anonymous so the probe volume is visible.
        try_best_effort_probe(
            inflight.as_ref(),
            &state.audit_log,
            &method,
            &http_path,
            401,
            None,
        )
        .await;
        return unauthorized();
    };

    // Round-3/5 P1 on PR #140: the MCP rate-limit layer runs
    // read-only verification upstream and stashes the FULL
    // outcome as `PreVerifiedBearer` (success + denied +
    // internal). Reusing it means the auth path adds ZERO
    // synchronous `SQLite` work on the MCP mount — the
    // read-only SELECT already ran on the blocking pool, and
    // any `last_used_ms` bump on the happy path is offloaded
    // via `spawn_blocking` below (bounded by
    // `PreAdmissionInflight` when injected — round-6 P1).
    let pre_verified = req
        .extensions()
        .get::<super::mcp::PreVerifiedBearer>()
        .is_some();
    let verify_result = match req
        .extensions_mut()
        .remove::<super::mcp::PreVerifiedBearer>()
    {
        Some(super::mcp::PreVerifiedBearer::Verified(rec)) => {
            try_best_effort_touch(inflight.as_ref(), &state.tokens, &rec).await;
            Ok(rec)
        }
        Some(super::mcp::PreVerifiedBearer::Denied) => Err(TokenError::Unknown),
        Some(super::mcp::PreVerifiedBearer::Internal) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
        None => state.tokens.verify(&bearer),
    };

    let (token_id, actor_kind, invocation) = match verify_result {
        Ok(rec) => {
            // Resolving a custom role reads `auth_role`; the MCP mount
            // keeps that off the runtime like its verify.
            let holds_custom = rec
                .roles
                .iter()
                .any(|r| crate::auth::role::builtin(r).is_none());
            let actor = if pre_verified && holds_custom {
                let (tokens, record) = (Arc::clone(&state.tokens), rec.clone());
                // Under the same pre-admission cap as the verify, and
                // refused like it when the cap is reached.
                let permit = match &inflight {
                    Some(gate) => match Arc::clone(&gate.0).try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                [(axum::http::header::RETRY_AFTER, "1")],
                                r#"{"error":"MCP rate limit exceeded; retry shortly"}"#,
                            )
                                .into_response();
                        }
                    },
                    None => None,
                };
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    actor_from_record(&record, &tokens)
                })
                .await
                {
                    Ok(actor) => actor,
                    Err(_) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                            .into_response();
                    }
                }
            } else {
                actor_from_record(&rec, &state.tokens)
            };
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            // H6: one invocation per authenticated request. Handlers
            // that dispatch into plugins hand it to the supervisor so
            // the root principal survives into downstream host calls.
            let invocation = InvocationContext::external(Principal::token(
                actor.kind(),
                &actor,
                state.transport,
            ));
            req.extensions_mut().insert(invocation.clone());
            req.extensions_mut().insert(actor);
            (token_id, actor_kind, invocation)
        }
        Err(
            TokenError::Malformed
            | TokenError::Unknown
            | TokenError::Revoked
            | TokenError::UnknownRole(_),
        ) => {
            // Malformed / unknown / revoked — record the probe with
            // a fingerprint so a forensic sweep can correlate
            // repeats. Never store the raw secret.
            let fp = credential_fingerprint(&bearer);
            try_best_effort_probe(
                inflight.as_ref(),
                &state.audit_log,
                &method,
                &http_path,
                401,
                Some(fp),
            )
            .await;
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
        caused_by: None,
        id: 0,
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
        call_id: Some(invocation.call_id().to_owned()),
        invocation: Some(invocation.audit_json()),
        command_id: None,
        command_outcome: None,

        level: None,
    };
    let audit_id = match record_intent_blocking(&state.audit_log, intent, inflight.as_ref()).await {
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
    // Smuggle the pending row's id to the handler. `GET
    // /api/v1/audit` reads it off the request extension and
    // excludes it from the query result — otherwise the audit
    // query's own pending intent is always the newest row and
    // `?limit=1` on an idle system returns the query, not the
    // preceding event.
    req.extensions_mut().insert(AuditIntentId(audit_id));

    let response = next.run(req).await;
    let denied_action = response
        .extensions()
        .get::<crate::api::authz::DeniedAction>()
        .map(|d| d.0);
    // F4: handlers whose wire response is HTTP 200 but whose
    // *plugin domain outcome* is a failure stamp a `DomainOutcome`
    // response extension. The middleware records that in the
    // audit ledger's separate `execution_outcome` + `domain_error`
    // fields, leaving `status` at the wire status and `decision`
    // at the authorization outcome. See `DomainOutcome`'s
    // docstring for why authorization and execution outcomes are
    // kept independent.
    let domain_outcome = response.extensions().get::<DomainOutcome>().cloned();
    let status = response.status();
    finalize_audit(
        &state.audit_log,
        audit_id,
        &token_id,
        &method,
        &http_path,
        status,
        denied_action,
        domain_outcome,
    )
    .await;
    response
}

/// Record an anonymous-probe audit row for a request that failed
/// authentication. Best-effort — the auth check has already decided
/// the outcome and no handler will run, so a ledger failure here
/// only loses this one row (no unaudited mutation).
/// Best-effort `record_anonymous_probe` gated by the shared
/// pre-admission semaphore when the MCP mount injected one
/// (round-6 P1 on PR #140). Saturated → skip the write and
/// log at debug; the operator prefers a dropped probe row over
/// an unbounded blocking-pool queue during a flood. Non-MCP
/// mounts pass `None` and get the original unbounded path.
async fn try_best_effort_probe(
    inflight: Option<&super::mcp::PreAdmissionInflight>,
    audit_log: &Arc<AuditLog>,
    method: &str,
    path: &str,
    status: u16,
    credential_fp: Option<String>,
) {
    let Some(gate) = inflight else {
        // Non-MCP mount: preserve the original unbounded path
        // — its own error/join logging remains authoritative.
        record_anonymous_probe(audit_log, method, path, status, credential_fp).await;
        return;
    };
    let Ok(permit) = Arc::clone(&gate.0).try_acquire_owned() else {
        tracing::debug!(
            target: "api.audit",
            method,
            path,
            "pre-admission inflight cap reached — skipping anonymous probe",
        );
        return;
    };
    let entry = AuditEntry {
        caused_by: None,
        id: 0,
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
        call_id: None,
        invocation: None,
        command_id: None,
        command_outcome: None,

        level: None,
    };
    let al = Arc::clone(audit_log);
    // Round-7 P2 on PR #140: preserve the original
    // implementation's error / join-failure reporting. Dropping
    // it silently loses forensic rows without any operator
    // signal.
    let owned_method = method.to_owned();
    let owned_path = path.to_owned();
    match tokio::task::spawn_blocking(move || {
        let _guard = permit;
        al.record_completed(&entry)
    })
    .await
    {
        Ok(Ok(_id)) => {}
        Ok(Err(err)) => {
            eprintln!("oxidhome audit_log: record_completed (anonymous probe) failed: {err}");
            tracing::error!(
                target: "api.audit",
                error = %err,
                method = %owned_method,
                path = %owned_path,
                "audit-ledger anonymous-probe write failed",
            );
        }
        Err(join_err) => {
            eprintln!(
                "oxidhome audit_log: record_completed (anonymous probe) join failed: {join_err}",
            );
        }
    }
}

/// Best-effort `touch_last_used` gated by the shared pre-
/// admission semaphore when the MCP mount injected one
/// (round-6 P1 on PR #140). Saturated → skip the timestamp
/// bump. Non-MCP mounts pass `None` and just `spawn_blocking`
/// the write directly.
async fn try_best_effort_touch(
    inflight: Option<&super::mcp::PreAdmissionInflight>,
    tokens: &Arc<crate::state::TokenStore>,
    rec: &crate::state::TokenRecord,
) {
    // M6: a bump the store would coalesce away needs no blocking hop.
    if crate::state::TokenStore::last_used_is_current(rec.last_used_ms) {
        return;
    }
    let token_id = rec.id.as_str();
    if let Some(gate) = inflight {
        let Ok(permit) = Arc::clone(&gate.0).try_acquire_owned() else {
            tracing::debug!(
                target: "auth.token",
                token_id,
                "pre-admission inflight cap reached — skipping last_used_ms bump",
            );
            return;
        };
        let tokens = Arc::clone(tokens);
        let (id, recorded) = (token_id.to_string(), rec.last_used_ms);
        let _ = tokio::task::spawn_blocking(move || {
            let _guard = permit;
            let _ = tokens.touch_last_used_from(&id, recorded);
        })
        .await;
        return;
    }
    let tokens = Arc::clone(tokens);
    let (id, recorded) = (token_id.to_string(), rec.last_used_ms);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = tokens.touch_last_used_from(&id, recorded);
    })
    .await;
}

pub(super) async fn record_anonymous_probe(
    audit_log: &Arc<AuditLog>,
    method: &str,
    path: &str,
    status: u16,
    credential_fp: Option<String>,
) {
    let entry = AuditEntry {
        caused_by: None,
        id: 0,
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
        call_id: None,
        invocation: None,
        command_id: None,
        command_outcome: None,

        level: None,
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
    // C3 follow-up: the `tracing::info!(target: "api.audit", ...)`
    // mirror that used to fire here is gone. Query surface for the
    // ledger is `GET /api/v1/audit` (see `server::query_audit`).
}

/// Blocking-safe wrapper around [`AuditLog::record_intent`]. Runs the
/// insert on the blocking pool so the tokio worker isn't parked on
/// the shared `Db` mutex. Returns a `String` error on either the
/// SQL failure or a `spawn_blocking` join failure — the middleware
/// only needs "something went wrong" to fail-closed with a 500.
///
/// Round-7 P1 on PR #140: when the MCP mount's
/// `PreAdmissionInflight` semaphore is present, the intent
/// task must acquire a permit before submission. Saturated →
/// return an error so the middleware fails closed with a 500
/// instead of enqueueing another blocking task on top of a
/// stalled shared pool. Permit moves into the closure so it
/// survives outer-future cancellation.
async fn record_intent_blocking(
    audit_log: &Arc<AuditLog>,
    entry: AuditEntry,
    inflight: Option<&super::mcp::PreAdmissionInflight>,
) -> Result<u64, String> {
    let al = Arc::clone(audit_log);
    if let Some(gate) = inflight {
        let Ok(permit) = Arc::clone(&gate.0).try_acquire_owned() else {
            return Err("pre-admission inflight cap reached; refusing audit intent".into());
        };
        return match tokio::task::spawn_blocking(move || {
            let _guard = permit;
            al.record_intent(&entry)
        })
        .await
        {
            Ok(Ok(id)) => Ok(id),
            Ok(Err(err)) => Err(err.to_string()),
            Err(join_err) => Err(format!("spawn_blocking join: {join_err}")),
        };
    }
    match tokio::task::spawn_blocking(move || al.record_intent(&entry)).await {
        Ok(Ok(id)) => Ok(id),
        Ok(Err(err)) => Err(err.to_string()),
        Err(join_err) => Err(format!("spawn_blocking join: {join_err}")),
    }
}

/// Phase-2 audit finalize. Wraps [`AuditLog::finalize`] on the
/// blocking pool. Best-effort — the pending row is already
/// committed evidence of intent, so a finalize failure logs an
/// alert but does not fail the request.
///
/// External query surface for the ledger: `GET /api/v1/audit`
/// (gated on `host.audit`). The C3-followup retirement of the
/// `tracing::info!(target = "api.audit", ...)` mirror means this
/// is the sole audit output path — no diagnostic-channel mirror
/// competes for the row's delivery.
///
/// `pub(super)` so the Connect-side middleware calls the same
/// helper — single source of truth for the audit-row contract
/// across both surfaces.
#[allow(clippy::too_many_arguments)]
pub(super) async fn finalize_audit(
    audit_log: &Arc<AuditLog>,
    audit_id: u64,
    token_id: &str,
    method: &str,
    path: &str,
    status: StatusCode,
    required_scope: Option<&'static str>,
    domain_outcome: Option<DomainOutcome>,
) {
    // Authorization outcome. A dispatched device command
    // (`domain_outcome` present) was authorized and reached the
    // plugin's queue: `allow`, whatever status the handler chose for
    // its outcome (H5) — the outcome lives in the separate
    // `execution_outcome` / `domain_error` / `command_outcome` columns
    // (F4). Everything else is classified by the transport status.
    let decision = if domain_outcome.is_some() || status.is_success() {
        "allow"
    } else if status.is_server_error() {
        "error"
    } else {
        "deny"
    };
    // Execution outcome — orthogonal to authorization, `None` for
    // every request that isn't a dispatched device command.
    let (execution_outcome, domain_error, command) = match &domain_outcome {
        Some(o) => (
            o.execution_outcome,
            o.domain_error,
            Some((o.command_id.clone(), o.outcome)),
        ),
        None => (None, None, None),
    };

    let al = Arc::clone(audit_log);
    let required = required_scope.map(str::to_owned);
    let status_u16 = status.as_u16();
    let decision_owned = decision.to_owned();
    let required_for_task = required.clone();
    let execution_for_task = execution_outcome.map(str::to_owned);
    let domain_error_for_task = domain_error.map(str::to_owned);
    let join = tokio::task::spawn_blocking(move || {
        al.finalize_with_command(
            audit_id,
            status_u16,
            &decision_owned,
            required_for_task.as_deref(),
            execution_for_task.as_deref(),
            domain_error_for_task.as_deref(),
            command
                .as_ref()
                .map(|(id, outcome)| (id.as_str(), *outcome)),
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

    // C3 follow-up: the `tracing::info!(target: "api.audit", ...)`
    // mirror is retired. The dedicated ledger (queried at
    // `GET /api/v1/audit`) is now the sole source of truth. Any
    // future stderr / structured-log surface for audit rows lands
    // via the ledger, not via the drop-tolerant `LogStore` channel.
}

/// Build an [`Actor`] from a verified record: its owner flag and the
/// current definitions of its roles, read per request so a role edit
/// applies from the next one. A built-in role needs no read. A missing
/// role grants nothing. A custom role whose definition doesn't parse,
/// or a failed read, leaves the token without its custom roles for
/// this request (fail closed).
///
/// `pub(super)` so the Connect-side auth middleware reuses the
/// same record → actor projection.
pub(super) fn actor_from_record(rec: &TokenRecord, tokens: &TokenStore) -> Actor {
    let mut roles = Vec::with_capacity(rec.roles.len());
    let mut custom = Vec::new();
    for name in &rec.roles {
        match crate::auth::role::builtin(name) {
            Some(role) => roles.push(role),
            None => custom.push(name.clone()),
        }
    }
    if !custom.is_empty() {
        match tokens.roles_by_name(&custom) {
            Ok(rows) => {
                for r in rows {
                    match r.def() {
                        Some(def) => roles.push(Arc::new(def)),
                        None => {
                            tracing::warn!(target: "api.auth", token_id = %rec.id, role = %r.name, "role definition failed to parse; it grants nothing");
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(target: "api.auth", token_id = %rec.id, error = %err, "reading the token's roles failed; they grant nothing for this request");
            }
        }
    }
    Actor::token(rec.id.clone(), rec.owner, roles)
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
pub(crate) fn extract_bearer(req: &Request) -> Option<&str> {
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

    fn test_store() -> TokenStore {
        TokenStore::new(Arc::new(crate::state::Db::open_in_memory().expect("db")))
    }

    /// Built-in roles resolve without a read, custom ones live; a
    /// missing or unparseable custom role grants nothing.
    #[test]
    fn actor_from_record_resolves_roles() {
        let store = test_store();
        store
            .create_role("good", br#"[{"actions":["device.read"]}]"#)
            .unwrap();
        store.create_role("bad", br#"{"deny":[]}"#).unwrap();
        let rec = |roles: &[&str]| TokenRecord {
            id: "tok-r".into(),
            label: "r".into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            created_ms: 0,
            last_used_ms: None,
            revoked_ms: None,
            owner: false,
        };
        let names = |a: &Actor| a.roles().iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        assert_eq!(
            names(&actor_from_record(&rec(&["guest", "good"]), &store)),
            ["guest", "good"]
        );
        assert_eq!(
            names(&actor_from_record(&rec(&["good", "gone", "bad"]), &store)),
            ["good"]
        );
        assert!(!actor_from_record(&rec(&[]), &store).is_owner());
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
