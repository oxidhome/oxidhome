//! Dedicated audit ledger for the external API surface.
//!
//! Architecture-review C3, revised on the PR-#78 review. The auth
//! middleware used to emit audit rows exclusively via
//! `tracing::info!(target = "api.audit", ...)`, which routed them
//! through the same bounded [`LogStore`](crate::state::LogStore) channel as diagnostic logs.
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
    /// Host-assigned monotonically-increasing row id — the ledger's
    /// primary key. Assigned by the database on
    /// [`AuditLog::record_intent`] / [`AuditLog::record_completed`]
    /// and returned as the method's `u64` result. Reserved as the
    /// tiebreaker for cursor pagination when two rows share the
    /// same `intent_ms`.
    pub id: u64,
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
    /// H6: host-minted invocation id (`call-<32 hex>`). The entry
    /// point's row and every downstream row the invocation caused
    /// (delegated `call-service` hops, `method = "CALL"`) share it.
    /// `None` on probe rows and rows written before migration 17.
    #[serde(default)]
    pub call_id: Option<String>,
    /// H6: JSON summary of the invocation context — root principal
    /// (`kind`, `subject`, `credential_id`, `transport`), the
    /// executing actor (`current`), and the delegation `chain`. See
    /// `crate::auth::InvocationContext::audit_json`.
    #[serde(default)]
    pub invocation: Option<String>,
    /// H5: host-minted device-command id (`cmd-<32 hex>`) on rows for
    /// a device-command dispatch and on the `method = "COMMAND"`
    /// resolution rows that record how an `accepted` (or abandoned)
    /// command finally ended. `None` everywhere else and on rows
    /// written before migration 18.
    #[serde(default)]
    pub command_id: Option<String>,
    /// H5: the explicit command outcome (`accepted`, `completed`,
    /// `rejected`, `timed_out`, `outcome_unknown`) for the row's
    /// `command_id`. Finer-grained than [`Self::execution_outcome`],
    /// which keeps its coarse `success` / `failed` meaning.
    #[serde(default)]
    pub command_outcome: Option<String>,
    /// H6 slice 2: `Some("warn")` on the extra row an allowed sensitive
    /// action writes (lock, opener, alarm commands; camera bytes);
    /// `None` (info) everywhere else.
    #[serde(default)]
    pub level: Option<String>,
}

/// Audit `level` of the row an allowed sensitive action writes.
pub const AUDIT_LEVEL_WARN: &str = "warn";

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
    /// Exact match on the request `path`. The forensic
    /// drill-down for a specific endpoint —
    /// `path = "/api/v1/devices/dev-abc/command"` returns every
    /// command dispatch against that device.
    pub path: Option<String>,
    /// Exact `call_id` match (H6): every row one invocation produced —
    /// the entry point's row plus its delegated `call-service` hops.
    pub call_id: Option<String>,
    /// Exact `level` match (H6 slice 2): `warn` returns the rows of
    /// allowed sensitive actions.
    pub level: Option<String>,
    /// Cursor-based pagination floor: return only rows strictly
    /// *older* than `(before.0, before.1)` in `(intent_ms, id)`
    /// order. The default `ORDER BY intent_ms DESC, id DESC LIMIT
    /// ?` ordering combined with this filter gives lossless
    /// pagination — the next page is the client passing the last
    /// row's `(intent_ms, id)` here. Millisecond timestamps
    /// collide under bursts, so filtering only by `until_ms` would
    /// either drop rows or duplicate them at boundaries.
    pub before: Option<(i64, u64)>,
    /// Exclude a single row id from the result. Used by the
    /// `GET /api/v1/audit` handler to exclude the *self-audit* row
    /// (the query's own pending intent row) — otherwise
    /// `?limit=1` on an idle system always returns that pending
    /// row instead of the preceding event.
    pub exclude_id: Option<u64>,
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

/// M7: free-text audit columns go through redaction on every write:
/// `path` via [`crate::redact::scrub_text`], and `domain_error` /
/// `invocation_json` via [`crate::redact::redact_text`] (structural for
/// JSON, so the invocation stays parseable), so a credential in a request path or an invocation summary
/// never reaches the ledger. The ledger records *who did what*, never
/// command arguments or config values; a future column that does (the
/// UI plan's audited parameter values) must pass them through
/// [`crate::redact::redact_json`] first.
fn scrub(text: &str) -> std::borrow::Cow<'_, str> {
    crate::redact::scrub_text(text)
}

fn scrub_opt(text: Option<&str>) -> Option<std::borrow::Cow<'_, str>> {
    text.map(crate::redact::redact_text)
}

/// Per-host audit ledger.
///
/// Held behind `Arc` and cloned into every axum request-handler
/// wrapper that needs to record — cheap because the type is a single
/// `Arc<Db>`.
pub struct AuditLog {
    db: Arc<Db>,
    /// [`Db::audit_boot_floor`]: a pending row above it was written by
    /// this process and may still be finalized, so retention keeps it.
    boot_floor: i64,
}

impl AuditLog {
    /// Wrap the shared [`Db`]. The `audit_event` table is created by
    /// the migration list in [`super::db`]; no per-instance setup
    /// runs here.
    ///
    /// Reads the database's audit boot floor (the highest row id
    /// before this process wrote any), which retention uses to tell
    /// this process's pending rows from abandoned ones; if that read
    /// fails every pending row is kept.
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        let boot_floor = db.audit_boot_floor();
        Self { db, boot_floor }
    }

    /// Spawn the periodic audit retention task on the current tokio
    /// runtime (see [`crate::state::retention`]). Deletes rows whose
    /// intent is older than `policy.max_age` or that fall beyond the
    /// newest `policy.max_rows`, except rows an unfinished write
    /// still needs:
    ///
    /// - a pending row (`finalized_ms` NULL) written by this process,
    ///   which its request may still finalize. A pending row from an
    ///   earlier process (an abandoned request) goes only by age,
    ///   never by the row limit;
    /// - an `accepted` device-command row (H5) whose `COMMAND`
    ///   resolution row (same `call_id` and `command_id`) hasn't been
    ///   written yet, and a `COMMAND` row while its `accepted` row is
    ///   still there (so the pair goes accepted-first, even when a
    ///   clock rollback made the resolution look older), or while a
    ///   pending row of this process shares its `call_id` (a command
    ///   that resolved before its request was finalized as
    ///   `accepted`).
    ///
    /// Kept rows still count toward `max_rows`: the limit picks the
    /// newest rows by id, and kept rows older than that are kept on
    /// top of it.
    ///
    /// The newest row is never deleted, so ids are not reused. `None`
    /// with no limits.
    #[must_use]
    pub fn spawn_retention(
        self: &Arc<Self>,
        policy: crate::state::RetentionPolicy,
    ) -> Option<crate::state::RetentionTask> {
        crate::state::retention::spawn(Arc::clone(self), policy)
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
        self.insert_intent(entry, false)
    }

    /// [`Self::record_intent`] with the insert committed under
    /// `PRAGMA synchronous = FULL`, so the intent row survives a
    /// power failure. The shared connection otherwise runs WAL +
    /// `synchronous = NORMAL`, where a committed row can be lost.
    /// Used by the host-local admin-token lifecycle (M4), whose
    /// follow-up action is a durable filesystem change (a secret
    /// file removed or promoted) that would otherwise outlive its
    /// own audit evidence. The pragma is restored to `NORMAL`
    /// (a failed restore is logged; the row is committed regardless).
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error.
    pub fn record_intent_durable(&self, entry: &AuditEntry) -> Result<u64, AuditLogError> {
        self.insert_intent(entry, true)
    }

    fn insert_intent(&self, entry: &AuditEntry, durable: bool) -> Result<u64, AuditLogError> {
        let intent_ms = now_unix_ms();
        let id = self.db.write(|conn| -> Result<i64, AuditLogError> {
            if durable {
                conn.pragma_update(None, "synchronous", "FULL")?;
            }
            let result = Self::insert_intent_row(conn, intent_ms, entry);
            // A failed restore leaves the connection at FULL (safe,
            // only slower); the intent row is committed either way,
            // so it's logged rather than turned into an error.
            if durable && let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
                tracing::warn!(
                    error = %err,
                    "failed to restore synchronous = NORMAL after durable audit intent",
                );
            }
            result
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(id as u64)
    }

    fn insert_intent_row(
        conn: &rusqlite::Connection,
        intent_ms: i64,
        entry: &AuditEntry,
    ) -> Result<i64, AuditLogError> {
        conn.execute(
                    "INSERT INTO audit_event \
                     (intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error, call_id, invocation_json, command_id, command_outcome) \
                     VALUES (?1, NULL, ?2, ?3, ?4, ?5, 0, 'pending', NULL, ?6, NULL, NULL, ?7, ?8, ?9, NULL)",
                    params![
                        intent_ms,
                        &entry.token_id,
                        &entry.actor_kind,
                        &entry.method,
                        scrub(&entry.path),
                        &entry.credential_fp,
                        &entry.call_id,
                        scrub_opt(entry.invocation.as_deref()),
                        &entry.command_id,
                    ],
                )?;
        Ok(conn.last_insert_rowid())
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
        self.finalize_with_command(
            id,
            status,
            decision,
            required_scope,
            execution_outcome,
            domain_error,
            None,
        )
    }

    /// [`Self::finalize`] for a device-command row (H5): additionally
    /// stamps `command` = `(command_id, command_outcome)` when `Some`.
    /// `None` leaves both columns as they are.
    ///
    /// # Errors
    ///
    /// As [`Self::finalize`].
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_with_command(
        &self,
        id: u64,
        status: u16,
        decision: &str,
        required_scope: Option<&str>,
        execution_outcome: Option<&str>,
        domain_error: Option<&str>,
        command: Option<(&str, &str)>,
    ) -> Result<(), AuditLogError> {
        let (command_id, command_outcome) = command.unzip();
        let finalized_ms = now_unix_ms();
        let rows = self.db.write(|conn| -> Result<usize, AuditLogError> {
            #[allow(clippy::cast_possible_wrap)]
            let id_i = id as i64;
            Ok(conn.execute(
                "UPDATE audit_event \
                 SET finalized_ms = ?1, status = ?2, decision = ?3, required_scope = ?4, \
                     execution_outcome = ?5, domain_error = ?6, \
                     command_id = COALESCE(?8, command_id), \
                     command_outcome = COALESCE(?9, command_outcome) \
                 WHERE id = ?7",
                params![
                    finalized_ms,
                    i64::from(status),
                    decision,
                    required_scope,
                    execution_outcome,
                    scrub_opt(domain_error),
                    id_i,
                    command_id,
                    command_outcome,
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
        self.insert_completed(entry, false)
    }

    /// [`Self::record_completed`] committed at `synchronous = FULL`:
    /// for a row that must survive power loss once the action it
    /// records has happened (H6 slice 2: a sensitive command's `warn`
    /// row).
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error.
    pub fn record_completed_durable(&self, entry: &AuditEntry) -> Result<u64, AuditLogError> {
        self.insert_completed(entry, true)
    }

    fn insert_completed(&self, entry: &AuditEntry, durable: bool) -> Result<u64, AuditLogError> {
        let now = now_unix_ms();
        let id = self.db.write(|conn| -> Result<i64, AuditLogError> {
            if durable {
                conn.pragma_update(None, "synchronous", "FULL")?;
            }
            let result = Self::insert_completed_row(conn, now, entry);
            if durable && let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
                tracing::warn!(
                    error = %err,
                    "failed to restore synchronous = NORMAL after durable audit row",
                );
            }
            result
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(id as u64)
    }

    /// The INSERT behind [`Self::record_completed`], on a connection
    /// (or transaction) the caller already holds, stamped `now`. The
    /// H5 command journal uses it to commit a resolution row together
    /// with the delete of its persisted pending command.
    pub(crate) fn insert_completed_row(
        conn: &rusqlite::Connection,
        now: i64,
        entry: &AuditEntry,
    ) -> Result<i64, AuditLogError> {
        conn.execute(
            "INSERT INTO audit_event \
             (intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error, call_id, invocation_json, command_id, command_outcome, level) \
             VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                now,
                &entry.token_id,
                &entry.actor_kind,
                &entry.method,
                scrub(&entry.path),
                i64::from(entry.status),
                &entry.decision,
                &entry.required_scope,
                &entry.credential_fp,
                &entry.execution_outcome,
                scrub_opt(entry.domain_error.as_deref()),
                &entry.call_id,
                scrub_opt(entry.invocation.as_deref()),
                &entry.command_id,
                &entry.command_outcome,
                &entry.level,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// The shared database the ledger writes to.
    pub(crate) fn db(&self) -> &Arc<Db> {
        &self.db
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
            "SELECT id, intent_ms, finalized_ms, token_id, actor_kind, method, path, status, decision, required_scope, credential_fp, execution_outcome, domain_error, call_id, invocation_json, command_id, command_outcome, level \
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
        if let Some(p) = &filter.path {
            push(&mut binds, &mut sql, "path =", p.clone().into());
        }
        if let Some(c) = &filter.call_id {
            push(&mut binds, &mut sql, "call_id =", c.clone().into());
        }
        if let Some(l) = &filter.level {
            push(&mut binds, &mut sql, "level =", l.clone().into());
        }
        // Cursor pagination — lexicographic `(intent_ms, id) <
        // (before_ms, before_id)`. SQLite's row-value comparison
        // reads exactly like the tuple: `(a, b) < (?, ?)`. Cheaper
        // than the OR-expanded form and index-friendly (the
        // `audit_intent` index covers `intent_ms` for the primary
        // partition; the `id` PK then breaks ties on rows that
        // share a millisecond).
        if let Some((before_ms, before_id)) = filter.before {
            binds.push(before_ms.into());
            #[allow(clippy::cast_possible_wrap)]
            binds.push((before_id as i64).into());
            let n = binds.len();
            let _ = write!(sql, " AND (intent_ms, id) < (?{}, ?{})", n - 1, n);
        }
        // Self-exclusion for the audit-query endpoint — the
        // middleware records the query's own pending intent
        // *before* the handler runs, so an unfiltered `limit=1`
        // would otherwise return that pending row every time. The
        // handler passes its own row id here.
        if let Some(id) = filter.exclude_id {
            #[allow(clippy::cast_possible_wrap)]
            let id_i = id as i64;
            push(&mut binds, &mut sql, "id !=", id_i.into());
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
                let id_i: i64 = row.get(0)?;
                let status_i: i64 = row.get(7)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(AuditEntry {
                    id: id_i as u64,
                    intent_ms: row.get(1)?,
                    finalized_ms: row.get(2)?,
                    token_id: row.get(3)?,
                    actor_kind: row.get(4)?,
                    method: row.get(5)?,
                    path: row.get(6)?,
                    status: status_i as u16,
                    decision: row.get(8)?,
                    required_scope: row.get(9)?,
                    credential_fp: row.get(10)?,
                    execution_outcome: row.get(11)?,
                    domain_error: row.get(12)?,
                    call_id: row.get(13)?,
                    invocation: row.get(14)?,
                    command_id: row.get(15)?,
                    command_outcome: row.get(16)?,
                    level: row.get(17)?,
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

/// Rows retention may delete (`?1` cutoff, `?2` row bound, `?3` boot
/// floor); see [`AuditLog::spawn_retention`].
const AUDIT_RETENTION_DUE: &str = "\
    ((?1 IS NOT NULL AND intent_ms < ?1) OR (?2 IS NOT NULL AND id <= ?2)) \
    AND NOT (finalized_ms IS NULL AND (id > ?3 OR ?1 IS NULL OR intent_ms >= ?1)) \
    AND NOT (command_outcome IS 'accepted' AND NOT EXISTS ( \
        SELECT 1 FROM audit_event AS r WHERE r.call_id = audit_event.call_id \
        AND r.method = 'COMMAND' AND r.command_id = audit_event.command_id)) \
    AND NOT (method = 'COMMAND' AND EXISTS ( \
        SELECT 1 FROM audit_event AS a WHERE a.call_id = audit_event.call_id \
        AND ((a.command_outcome = 'accepted' AND a.command_id = audit_event.command_id) \
        OR (a.finalized_ms IS NULL AND a.id > ?3))))";

impl crate::state::retention::RetentionTarget for AuditLog {
    type Plan = crate::state::retention::IdWindowPlan;

    const TABLE: &'static str = "audit_event";

    fn db(&self) -> &Arc<Db> {
        &self.db
    }

    fn plan(
        &self,
        cutoff_ms: Option<i64>,
        max_rows: Option<u64>,
    ) -> anyhow::Result<Option<Self::Plan>> {
        Ok(crate::state::retention::plan_id_window(
            &self.db,
            "audit_event",
            "intent_ms",
            cutoff_ms,
            max_rows,
        )?)
    }

    fn step(
        &self,
        plan: &mut Self::Plan,
        stopped: &dyn Fn() -> bool,
    ) -> anyhow::Result<Option<usize>> {
        Ok(crate::state::retention::step_id_window(
            &self.db,
            "audit_event",
            AUDIT_RETENTION_DUE,
            &[&self.boot_floor],
            plan,
            stopped,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AuditLog {
        AuditLog::new(Arc::new(Db::open_in_memory().expect("db open")))
    }

    fn sample_intent(token: &str, path: &str) -> AuditEntry {
        AuditEntry {
            id: 0,
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
            call_id: None,
            invocation: None,
            command_id: None,
            command_outcome: None,

            level: None,
        }
    }

    /// M7: text columns are scrubbed on insert and finalize.
    #[test]
    fn text_columns_are_redacted_on_write() {
        let log = store();
        let mut entry = sample_intent("tok", "/api/v1/x?api_key=abc123");
        entry.invocation = Some(r#"{"subject":"bob","password":"hunter2"}"#.into());
        let id = log.record_intent(&entry).unwrap();
        log.finalize(id, 200, "allow", None, Some("failed"), Some("token=zzz"))
            .unwrap();
        let mut probe = sample_intent("anonymous", "/x?password=p");
        probe.domain_error = Some("Bearer abc".into());
        log.record_completed(&probe).unwrap();

        let rows = log.query(&AuditQuery::default(), 10).unwrap();
        let text = format!("{rows:?}");
        for leaked in ["abc123", "hunter2", "zzz", "password=p", "Bearer abc"] {
            assert!(!text.contains(leaked), "{leaked} leaked: {text}");
        }
        let first = rows.iter().find(|r| r.id == id).unwrap();
        assert_eq!(first.path, "/api/v1/x?api_key=***");
        assert_eq!(first.domain_error.as_deref(), Some("token=***"));
        // Redaction keeps the invocation summary valid JSON, even when a
        // value's text would trip the unquoted-value scanner.
        let mut entry = sample_intent("tok", "/api/v1/y");
        entry.invocation = Some(r#"{"service":"password=abc\"tail"}"#.into());
        let id = log.record_intent(&entry).unwrap();
        let rows = log.query(&AuditQuery::default(), 10).unwrap();
        let row = rows.iter().find(|r| r.id == id).unwrap();
        let invocation: serde_json::Value =
            serde_json::from_str(row.invocation.as_deref().unwrap()).expect("still JSON");
        assert_eq!(invocation["service"], "password=***\"tail");
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
            id: 0,
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
            call_id: None,
            invocation: None,
            command_id: None,
            command_outcome: None,

            level: None,
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
                id: 0,
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
                call_id: None,
                invocation: None,
                command_id: None,
                command_outcome: None,

                level: None,
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

    /// `record_intent_durable` writes the same pending row as
    /// `record_intent` and restores `synchronous = NORMAL`.
    #[test]
    fn record_intent_durable_matches_record_intent() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let log = AuditLog::new(Arc::clone(&db));
        db.write(|c| c.pragma_update(None, "synchronous", "OFF"))
            .unwrap();
        let entry = AuditEntry {
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: "tok".into(),
            actor_kind: "host".into(),
            method: "LOCAL".into(),
            path: "host.auth.bootstrap".into(),
            status: 0,
            decision: "pending".into(),
            required_scope: None,
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
            call_id: None,
            invocation: None,
            command_id: None,
            command_outcome: None,

            level: None,
        };
        let id = log.record_intent_durable(&entry).unwrap();
        let sync: i64 = db
            .read(|c| c.pragma_query_value(None, "synchronous", |r| r.get(0)))
            .unwrap();
        assert_eq!(sync, 1);
        let rows = log.query(&AuditQuery::default(), 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].decision, "pending");
        assert_eq!(rows[0].path, "host.auth.bootstrap");
    }
}
