//! Dedicated audit ledger for the external API surface.
//!
//! Architecture-review C3, revised on the PR-#78 review. The auth
//! middleware used to emit audit rows exclusively via
//! `tracing::info!(target = "api.audit", ...)`, which routed them
//! through the same bounded [`LogStore`] channel as diagnostic logs.
//! A saturation-driven drop there was silent. The first cut fixed
//! that by routing every audit to a dedicated `audit_event` `SQLite`
//! table; the review then flagged that "landed" ≠ "unforgeable
//! forensic record" — the row was written *after* the handler
//! returned, so a request cancelled mid-flight (`spawn_blocking`
//! filesystem work continues after the client disconnects and the
//! future is dropped) could commit a mutation with no audit trail.
//!
//! [`AuditLog`] therefore writes in **two phases**:
//!
//! 1. [`AuditLog::record_intent`] at the top of the middleware.
//!    Inserts a `decision = "pending"` row with `status = 0` and
//!    `finalized_ms = NULL`, and returns the freshly-minted row id.
//!    Committing this *before* the handler runs is the entire point
//!    — if the request future is later dropped, the intent row
//!    stays behind as unambiguous evidence of the attempted action.
//!    Fail-closed: the middleware refuses the request with 500 if
//!    this insert errors, rather than execute an unauditable
//!    operation.
//! 2. [`AuditLog::finalize`] after the handler returns. UPDATEs the
//!    row with the outcome (`allow` / `deny` / `error`), the final
//!    HTTP status, and `required_scope` on scope-deny 403s; stamps
//!    `finalized_ms`. Best-effort — if the update errors, the
//!    handler's side effects are already committed, and the pending
//!    row is the operator-visible signal that something went wrong.
//!
//! Single-shot writes ([`AuditLog::record_completed`]) go through
//! for **unauthenticated probes** — the auth check ran and
//! rejected, no handler will execute, so the outcome is known at
//! insert time. That path also captures a [`credential_fingerprint`]
//! — a short SHA-256 prefix of the presented bearer, never the raw
//! secret — so a forensic sweep can correlate repeat probes without
//! giving an attacker something to verify a guess against.
//!
//! ## Blocking discipline
//!
//! Every call path invokes `rusqlite` under the shared [`Db`] mutex,
//! which is a `std::sync::Mutex` — cheap but blocking. Callers on a
//! tokio worker MUST wrap each of the methods below in
//! [`tokio::task::spawn_blocking`] so a slow disk (or contention
//! with the log-store writer, blob store, KV, etc.) can't park the
//! tokio worker thread. The API middleware in `crate::api::auth` /
//! `crate::api::connect_rpc` does exactly that.

use std::sync::Arc;

use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::db::Db;
use super::event_log::now_unix_ms;

/// One row in the `audit_event` table.
///
/// Every field except the `_ms` timestamps is written by the caller
/// (the middleware); the timestamps are always stamped by
/// [`AuditLog`] itself from the host wall clock. A hostile client
/// can't rewrite ledger time by setting `intent_ms` on the input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Host-stamped millisecond Unix timestamp of the intent
    /// (top-of-middleware) write. Assigned by [`AuditLog::record_intent`]
    /// or [`AuditLog::record_completed`]; any value on the input is
    /// ignored.
    pub intent_ms: i64,
    /// Host-stamped millisecond Unix timestamp of the finalize
    /// update, or `None` when the row is still pending / was
    /// abandoned (client disconnected mid-handler). Filled in by
    /// [`AuditLog::finalize`] for the two-phase path, or by
    /// [`AuditLog::record_completed`] at insert time for the
    /// single-shot anonymous-probe path.
    pub finalized_ms: Option<i64>,
    /// Auth-token id (`Actor::id()`), i.e. the token that issued the
    /// request. `"anonymous"` for probe rows that failed
    /// authentication (missing / malformed / unknown / revoked
    /// bearer). Never the raw secret — the ledger only ever sees
    /// the `TokenRecord::id` slug or the sentinel.
    pub token_id: String,
    /// `Actor::kind()` as a stable `snake_case` string
    /// (`"api"` today; `"anonymous"` for probe rows).
    pub actor_kind: String,
    /// HTTP method of the request.
    pub method: String,
    /// Request path — either the JSON REST path (`/api/v1/instances`)
    /// or the Connect RPC path (`/oxidhome.v1.Devices/ListDevices`).
    pub path: String,
    /// Final wire HTTP status the middleware saw. `0` on a pending
    /// row; set by [`AuditLog::finalize`] on completion. On gRPC /
    /// gRPC-Web transports the middleware may synthesize this from
    /// the handler's `HandlerOutcomeSlot` rather than the wire
    /// status. **This is the transport-level status only** — a
    /// domain-level execution failure that rides HTTP 200 leaves
    /// this at 200 and populates [`Self::execution_outcome`] +
    /// [`Self::domain_error`] instead.
    pub status: u16,
    /// **Authorization** outcome — kept independent from execution
    /// outcome (architecture-review F4 follow-up):
    /// - `"pending"` — intent recorded, handler still running (or
    ///   already abandoned).
    /// - `"allow"` — the request passed authorization and the wire
    ///   response was 2xx.
    /// - `"deny"` — the request was rejected at the auth / scope /
    ///   dispatch layer (scope failure, unknown device, bad input,
    ///   …). 4xx wire response.
    /// - `"error"` — server-side failure returning 5xx.
    ///
    /// A plugin returning `CommandResult::Err` on an *authorized*
    /// request records `decision = "allow"` here — the auth check
    /// succeeded — and populates [`Self::execution_outcome`] with
    /// `"failed"` to surface the domain-level failure.
    pub decision: String,
    /// The scope the handler required, populated only on scope-deny
    /// 403s finalized from a `DeniedScope` extension. `None` for
    /// every allow and for non-scope denies.
    pub required_scope: Option<String>,
    /// **Execution** outcome — independent of [`Self::decision`]
    /// (architecture-review F4 follow-up).
    /// - `None` — the request never reached execution (auth deny,
    ///   dispatch `NotFound`, transport error, still pending).
    /// - `Some("success")` — the plugin returned `Ok` /
    ///   `OkWithState`.
    /// - `Some("failed")` — the plugin returned
    ///   `CommandResult::Err`; the specific error kind lives in
    ///   [`Self::domain_error`].
    pub execution_outcome: Option<String>,
    /// WIT error kind when [`Self::execution_outcome`] is
    /// `Some("failed")`. `"not_found"` / `"invalid_argument"` /
    /// `"permission_denied"` / `"unavailable"` / `"internal"`.
    /// `None` otherwise.
    pub domain_error: Option<String>,
    /// Short SHA-256 prefix of the presented bearer, populated on
    /// anonymous-probe rows so a forensic sweep can correlate
    /// repeat probes across requests. `None` when a token was
    /// verified (the `token_id` already identifies the caller) or
    /// when no bearer header was present.
    pub credential_fp: Option<String>,
}

/// Query shape for [`AuditLog::query`]. Every field is optional and
/// AND-combined; `None` everywhere returns the most recent `limit`
/// rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Inclusive lower bound on `intent_ms`.
    pub since_ms: Option<i64>,
    /// Inclusive upper bound on `intent_ms`.
    pub until_ms: Option<i64>,
    /// Filter on `token_id`.
    pub token_id: Option<String>,
    /// Filter on `decision` — including `"pending"` to surface
    /// abandoned intents.
    pub decision: Option<String>,
}

/// Errors returned by [`AuditLog`]. Every insert/update path funnels
/// `rusqlite` errors here; a `NotFound` variant covers the
/// [`AuditLog::finalize`] case where the intent row id has already
/// been trimmed or was never written.
#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    /// The underlying `rusqlite` call returned an error. In the
    /// intent-write path the middleware surfaces this as a 500 (fail-
    /// closed); in the finalize path it's logged and swallowed
    /// because the handler has already returned.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// [`AuditLog::finalize`] was called with a row id that isn't in
    /// the ledger. Shouldn't happen in normal operation — a caller
    /// that just called [`AuditLog::record_intent`] on this same
    /// handle has the id — but it's a distinct diagnostic if a
    /// finalize survives past a `trim_older_than` sweep.
    #[error("audit_event row id {0} not found — trimmed or never inserted")]
    NotFound(u64),
}

/// Per-host audit ledger.
///
/// Held behind `Arc` and cloned into every axum request-handler
/// wrapper that needs to record — cheap because the type is a single
/// `Arc<Db>`.
pub struct AuditLog {
    db: Arc<Db>,
}

impl AuditLog {
    /// Wrap the shared [`Db`]. The `audit_event` table is created by
    /// the migration list in [`super::db`]; no per-instance setup
    /// runs here.
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Phase 1 of the two-phase write. Insert a `decision = "pending"`
    /// row with `status = 0` and `finalized_ms = NULL`, return its
    /// id. The middleware calls this **before** running the handler
    /// so a cancellation-safe intent record exists regardless of
    /// what the handler does.
    ///
    /// Blocks the calling thread on a single-row `SQLite` INSERT.
    /// Callers running under a tokio runtime MUST wrap in
    /// [`tokio::task::spawn_blocking`] so a slow disk can't park a
    /// tokio worker.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error verbatim. The middleware
    /// surfaces those as 500 (fail-closed) — an audit ledger that
    /// can't accept intents must not accept mutations.
    pub fn record_intent(&self, entry: &AuditEntry) -> Result<u64, AuditLogError> {
        let intent_ms = now_unix_ms();
        let id = self
            .db
            .write(|conn| -> Result<i64, AuditLogError> {
                conn.execute(
                    "INSERT INTO audit_event \
                     (intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error) \
                     VALUES (?1, NULL, ?2, ?3, ?4, ?5, 0, 'pending', NULL, ?6, NULL, NULL)",
                    params![
                        intent_ms,
                        &entry.token_id,
                        &entry.actor_kind,
                        &entry.method,
                        &entry.path,
                        &entry.credential_fp,
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(id as u64)
    }

    /// Phase 2 of the two-phase write. UPDATE the pending row with
    /// the handler outcome + stamped `finalized_ms`.
    ///
    /// Blocks the calling thread on a single-row `SQLite` UPDATE.
    /// Callers running under a tokio runtime MUST wrap in
    /// [`tokio::task::spawn_blocking`].
    ///
    /// # Errors
    ///
    /// - [`AuditLogError::Sql`] on any `rusqlite` failure. The
    ///   middleware logs this as ERROR but doesn't fail the request
    ///   — the handler side effects are already committed.
    /// - [`AuditLogError::NotFound`] if the id isn't in the table
    ///   (would mean a retention sweep raced or the caller passed a
    ///   bad id).
    pub fn finalize(
        &self,
        id: u64,
        status: u16,
        decision: &str,
        required_scope: Option<&str>,
        execution_outcome: Option<&str>,
        domain_error: Option<&str>,
    ) -> Result<(), AuditLogError> {
        let finalized_ms = now_unix_ms();
        let rows = self.db.write(|conn| -> Result<usize, AuditLogError> {
            #[allow(clippy::cast_possible_wrap)]
            let id_i = id as i64;
            Ok(conn.execute(
                "UPDATE audit_event \
                 SET finalized_ms = ?1, status = ?2, decision = ?3, required_scope = ?4, \
                     execution_outcome = ?5, domain_error = ?6 \
                 WHERE id = ?7",
                params![
                    finalized_ms,
                    i64::from(status),
                    decision,
                    required_scope,
                    execution_outcome,
                    domain_error,
                    id_i,
                ],
            )?)
        })?;
        if rows == 0 {
            return Err(AuditLogError::NotFound(id));
        }
        Ok(())
    }

    /// Single-shot write for outcomes known at insert time — the
    /// anonymous-probe path (auth failed, no handler will run) and
    /// the plumbing test paths. Sets `intent_ms` and `finalized_ms`
    /// to the same host-stamped timestamp.
    ///
    /// Blocks the calling thread on a single-row `SQLite` INSERT.
    /// Callers running under a tokio runtime MUST wrap in
    /// [`tokio::task::spawn_blocking`].
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error.
    pub fn record_completed(&self, entry: &AuditEntry) -> Result<u64, AuditLogError> {
        let now = now_unix_ms();
        let id = self
            .db
            .write(|conn| -> Result<i64, AuditLogError> {
                conn.execute(
                    "INSERT INTO audit_event \
                     (intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error) \
                     VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        now,
                        &entry.token_id,
                        &entry.actor_kind,
                        &entry.method,
                        &entry.path,
                        i64::from(entry.status),
                        &entry.decision,
                        &entry.required_scope,
                        &entry.credential_fp,
                        &entry.execution_outcome,
                        &entry.domain_error,
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(id as u64)
    }

    /// Read the ledger. Newest-first by `intent_ms`, capped at
    /// `limit`. `decision = "pending"` rows come back too — that's
    /// how a caller finds abandoned intents.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error.
    pub fn query(
        &self,
        filter: &AuditQuery,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, AuditLogError> {
        use std::fmt::Write as _;

        let mut sql = String::from(
            "SELECT intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error \
             FROM audit_event WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();
        let push = |binds: &mut Vec<rusqlite::types::Value>,
                    sql: &mut String,
                    clause: &str,
                    v: rusqlite::types::Value| {
            binds.push(v);
            let _ = write!(sql, " AND {clause} ?{}", binds.len());
        };
        if let Some(t) = filter.since_ms {
            push(&mut binds, &mut sql, "intent_ms >=", t.into());
        }
        if let Some(t) = filter.until_ms {
            push(&mut binds, &mut sql, "intent_ms <=", t.into());
        }
        if let Some(t) = &filter.token_id {
            push(&mut binds, &mut sql, "token_id =", t.clone().into());
        }
        if let Some(d) = &filter.decision {
            push(&mut binds, &mut sql, "decision =", d.clone().into());
        }
        let _ = write!(
            sql,
            " ORDER BY intent_ms DESC, id DESC LIMIT ?{}",
            binds.len() + 1,
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        binds.push(rusqlite::types::Value::Integer(limit as i64));

        self.db.read(|conn| -> Result<_, AuditLogError> {
            let mut stmt = conn.prepare(&sql)?;
            let bind_refs: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let rows = stmt.query_map(bind_refs.as_slice(), |row| {
                let status_i: i64 = row.get(6)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(AuditEntry {
                    intent_ms: row.get(0)?,
                    finalized_ms: row.get(1)?,
                    token_id: row.get(2)?,
                    actor_kind: row.get(3)?,
                    method: row.get(4)?,
                    path: row.get(5)?,
                    status: status_i as u16,
                    decision: row.get(7)?,
                    required_scope: row.get(8)?,
                    credential_fp: row.get(9)?,
                    execution_outcome: row.get(10)?,
                    domain_error: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// Total row count — pending + finalized alike. Useful for smoke
    /// tests and the daemon's status endpoint.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error.
    pub fn count(&self) -> Result<u64, AuditLogError> {
        let n: i64 = self.db.read(|conn| -> Result<_, AuditLogError> {
            Ok(conn.query_row("SELECT COUNT(*) FROM audit_event", (), |row| row.get(0))?)
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(n as u64)
    }
}

/// Short SHA-256 prefix of a presented bearer, for the anonymous-
/// probe audit path. **Never** the raw secret — the ledger stores
/// only 4 bytes of hash so a forensic sweep can correlate repeat
/// probes ("this same token was tried 200 times in the last minute")
/// without giving an attacker a value they can brute-force back to
/// the original credential.
///
/// 4 bytes = 2^32 collision space, plenty of resolution for probe
/// correlation and small enough that the "how much of the secret
/// leaked?" answer is "nothing meaningful."
#[must_use]
pub fn credential_fingerprint(bearer: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bearer.as_bytes());
    let bytes = &hash[..4];
    let mut out = String::with_capacity(8);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AuditLog {
        AuditLog::new(Arc::new(Db::open_in_memory().expect("db open")))
    }

    fn sample_intent(token: &str, path: &str) -> AuditEntry {
        AuditEntry {
            intent_ms: 0,
            finalized_ms: None,
            token_id: token.into(),
            actor_kind: "api".into(),
            method: "GET".into(),
            path: path.into(),
            status: 0,
            decision: "pending".into(),
            required_scope: None,
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
        }
    }

    #[test]
    fn record_intent_returns_pending_row() {
        let log = store();
        let id = log
            .record_intent(&sample_intent("tok", "/api/v1/x"))
            .unwrap();
        assert!(id >= 1);
        let rows = log.query(&AuditQuery::default(), 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "pending");
        assert_eq!(rows[0].status, 0);
        assert!(rows[0].finalized_ms.is_none());
        assert!(rows[0].intent_ms > 0);
    }

    #[test]
    fn finalize_updates_pending_to_outcome() {
        let log = store();
        let id = log
            .record_intent(&sample_intent("tok", "/api/v1/x"))
            .unwrap();
        log.finalize(id, 200, "allow", None, None, None)
            .expect("finalize");
        let rows = log.query(&AuditQuery::default(), 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "allow");
        assert_eq!(rows[0].status, 200);
        assert!(rows[0].finalized_ms.is_some());
        assert!(rows[0].finalized_ms.unwrap() >= rows[0].intent_ms);
    }

    #[test]
    fn finalize_carries_required_scope_on_deny() {
        let log = store();
        let id = log
            .record_intent(&sample_intent("tok", "/api/v1/instances"))
            .unwrap();
        log.finalize(id, 403, "deny", Some("instances:list"), None, None)
            .expect("finalize");
        let rows = log.query(&AuditQuery::default(), 1).unwrap();
        assert_eq!(rows[0].required_scope.as_deref(), Some("instances:list"));
    }

    #[test]
    fn finalize_unknown_id_returns_not_found() {
        let log = store();
        let err = log
            .finalize(999, 200, "allow", None, None, None)
            .unwrap_err();
        assert!(matches!(err, AuditLogError::NotFound(999)));
    }

    #[test]
    fn finalize_records_execution_outcome_independently() {
        // F4 architecture-review pushback — the ledger keeps
        // authorization and execution outcomes as distinct fields.
        // A plugin returning `CommandResult::Err` on an *authorized*
        // request records `decision = "allow"` (auth passed) with
        // `execution_outcome = "failed"` + a domain error kind.
        let log = store();
        let id = log
            .record_intent(&sample_intent("tok", "/api/v1/devices/d-1/command"))
            .unwrap();
        log.finalize(
            id,
            200,
            "allow",
            None,
            Some("failed"),
            Some("invalid_argument"),
        )
        .expect("finalize");
        let rows = log.query(&AuditQuery::default(), 1).unwrap();
        assert_eq!(rows[0].decision, "allow", "auth outcome, not overridden");
        assert_eq!(rows[0].status, 200, "wire status, not synthesized");
        assert_eq!(rows[0].execution_outcome.as_deref(), Some("failed"));
        assert_eq!(rows[0].domain_error.as_deref(), Some("invalid_argument"));
    }

    #[test]
    fn abandoned_intent_stays_visible_as_pending() {
        // Two intents, one finalized, one abandoned — the abandoned
        // one is exactly the shape a mid-handler cancellation would
        // leave behind. Both remain in the ledger.
        let log = store();
        let a = log
            .record_intent(&sample_intent("tok-a", "/api/v1/a"))
            .unwrap();
        let _b = log
            .record_intent(&sample_intent("tok-b", "/api/v1/b"))
            .unwrap();
        log.finalize(a, 200, "allow", None, None, None).unwrap();

        let pending = log
            .query(
                &AuditQuery {
                    decision: Some("pending".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].token_id, "tok-b");
        assert!(pending[0].finalized_ms.is_none());
    }

    #[test]
    fn record_completed_writes_all_columns() {
        let log = store();
        let entry = AuditEntry {
            intent_ms: 0,
            finalized_ms: None,
            token_id: "anonymous".into(),
            actor_kind: "anonymous".into(),
            method: "GET".into(),
            path: "/api/v1/instances".into(),
            status: 401,
            decision: "deny".into(),
            required_scope: None,
            execution_outcome: None,
            domain_error: None,
            credential_fp: Some("deadbeef".into()),
        };
        log.record_completed(&entry).unwrap();
        let rows = log.query(&AuditQuery::default(), 1).unwrap();
        assert_eq!(rows[0].token_id, "anonymous");
        assert_eq!(rows[0].status, 401);
        assert_eq!(rows[0].decision, "deny");
        assert_eq!(rows[0].credential_fp.as_deref(), Some("deadbeef"));
        assert!(rows[0].finalized_ms.is_some());
        assert_eq!(rows[0].intent_ms, rows[0].finalized_ms.unwrap());
    }

    #[test]
    fn query_filters_by_token_id() {
        fn allow_row(token: &str) -> AuditEntry {
            AuditEntry {
                intent_ms: 0,
                finalized_ms: None,
                token_id: token.into(),
                actor_kind: "api".into(),
                method: "GET".into(),
                path: "/x".into(),
                status: 200,
                decision: "allow".into(),
                required_scope: None,
                execution_outcome: None,
                domain_error: None,
                credential_fp: None,
            }
        }
        let log = store();
        log.record_completed(&allow_row("tok-1")).unwrap();
        log.record_completed(&allow_row("tok-2")).unwrap();
        let rows = log
            .query(
                &AuditQuery {
                    token_id: Some("tok-1".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_id, "tok-1");
    }

    #[test]
    fn credential_fingerprint_is_short_and_stable() {
        let a = credential_fingerprint("hunter2");
        let b = credential_fingerprint("hunter2");
        let c = credential_fingerprint("hunter3");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // 8 hex chars — 32 bits of collision space, small enough
        // that no meaningful part of the secret leaks.
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn count_matches_records() {
        let log = store();
        assert_eq!(log.count().unwrap(), 0);
        for i in 0..5 {
            log.record_intent(&sample_intent("tok", &format!("/api/v1/x{i}")))
                .unwrap();
        }
        assert_eq!(log.count().unwrap(), 5);
    }
}
