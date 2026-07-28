//! Dedicated audit ledger for the external API surface.
//!
//! Architecture-review C3 — the auth middleware used to emit audit
//! rows exclusively via `tracing::info!(target = "api.audit", ...)`,
//! which routed them through the same bounded [`LogStore`] channel as
//! diagnostic logs. A saturation-driven drop there is silent, so an
//! attacker who could push the log queue past its capacity could
//! evict the record of their own request. The `LogStore` module note
//! at `log_store.rs:9-19` calls that trade-off out — losing debug
//! events is strictly better than blocking the calling thread —
//! but audit is where "silent drop" stops being acceptable.
//!
//! [`AuditLog`] is the fix: a dedicated `SQLite` table (`audit_event`)
//! and a synchronous, blocking writer. Every authenticated API call
//! records exactly one row in the writing request's own thread
//! before the middleware returns the response. There is no channel,
//! no buffer, and no drop path — the only failure mode is a `SQLite`
//! write error, which the middleware surfaces as an ERROR-level
//! tracing event so an operator sees the alert (that alert itself
//! rides the drop-tolerant `LogStore` — but the audit row it
//! reports on has already committed or already failed by then).
//!
//! ## Why sync?
//!
//! Every audit path today lives inside an axum `async fn` that
//! already `await`s the wrapped handler. Adding one `SQLite` insert
//! on the same async task costs microseconds — small compared with
//! the disk write the handler itself may have done. The blocking
//! call happens under the `Db` mutex, which serializes with the
//! `KvStore` / `BlobStore` / `LogStore` writer — but audit rows are
//! small, indexed, and one-per-request; even a burst of 10k rps
//! against an overloaded disk doesn't rewrite the trade-off, because
//! *the caller is going to feel disk pressure anyway*, and we'd
//! rather feel it as a slowed request than as a lost audit row.
//!
//! ## Contract vs. the tracing target
//!
//! The middleware still emits `tracing::info!(target = "api.audit",
//! ...)` in parallel so operators tailing stderr keep seeing every
//! request in real time (and the existing integration tests that
//! assert via a captured tracing subscriber keep working). The
//! *canonical* forensic ledger is this store; the tracing target is
//! a best-effort mirror. A follow-up will migrate the query API
//! (`/api/v1/logs?target_prefix=api.audit`) and the tests to read
//! from here directly and then retire the tracing side.

use std::sync::Arc;

use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::db::Db;
use super::event_log::now_unix_ms;

/// One row in the `audit_event` table. The middleware constructs this
/// once per authenticated request and hands it to [`AuditLog::record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Millisecond Unix timestamp — assigned by [`AuditLog::record`]
    /// at commit time so the ledger's clock is the host's, not the
    /// caller's. Read back on [`AuditLog::query`].
    pub ts_unix_ms: i64,
    /// Auth-token id (`Actor::id()`), i.e. the token that issued the
    /// request. Never the raw secret — the store only ever sees the
    /// `TokenRecord::id` slug.
    pub token_id: String,
    /// `Actor::kind()` as a stable `snake_case` string (`"api"` today;
    /// `"plugin"` reserved for the plugin-actor path Phase 12 might
    /// route through the audit ledger later).
    pub actor_kind: String,
    /// HTTP method of the request.
    pub method: String,
    /// Request path — either the JSON REST path (`/api/v1/instances`)
    /// or the Connect RPC path (`/oxidhome.v1.Devices/ListDevices`).
    pub path: String,
    /// Final HTTP status the middleware saw. On gRPC / gRPC-Web
    /// transports the middleware may synthesize this from the
    /// handler's `HandlerOutcomeSlot` rather than the wire status;
    /// see [`crate::api::connect_rpc`].
    pub status: u16,
    /// Coarse allow/deny/error classification:
    /// - `"allow"` — 2xx
    /// - `"deny"` — any 4xx returned by the handler
    /// - `"error"` — handler-returned 5xx
    pub decision: String,
    /// The scope the handler required, populated only on scope-deny
    /// 403s. `None` for every allow and for non-scope denies.
    pub required_scope: Option<String>,
}

/// Query shape for [`AuditLog::query`]. Every field is optional and
/// AND-combined; `None` everywhere returns the most recent `limit`
/// rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Inclusive lower bound on `ts_unix_ms`.
    pub since_ms: Option<i64>,
    /// Inclusive upper bound on `ts_unix_ms`.
    pub until_ms: Option<i64>,
    /// Filter on `token_id`.
    pub token_id: Option<String>,
    /// Filter on `decision` (`"allow"` / `"deny"` / `"error"`).
    pub decision: Option<String>,
}

/// Errors returned by [`AuditLog`]. `record` only ever fails with
/// [`AuditLogError::Sql`] — the insert is a single row against an
/// indexed table.
#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    /// The underlying `rusqlite` call returned an error. In the
    /// `record` path the middleware logs an ERROR-level tracing
    /// event so operators see it; the request is not failed because
    /// the alert itself is the useful signal.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
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

    /// Record one audit row. Blocks the caller until the SQL insert
    /// commits or errors — that's the whole point of C3; the row
    /// must land before the request response is emitted.
    ///
    /// The row's timestamp is stamped inside this method from the
    /// host's wall clock (`now_unix_ms`) so a caller with a slow
    /// clock (or a hostile one) can't rewrite history.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` error verbatim. See [`AuditLogError`].
    pub fn record(&self, mut entry: AuditEntry) -> Result<u64, AuditLogError> {
        entry.ts_unix_ms = now_unix_ms();
        let id = self
            .db
            .write(|conn| -> Result<i64, AuditLogError> {
                conn.execute(
                    "INSERT INTO audit_event \
                     (ts_unix_ms, token_id, actor_kind, method, path, status, decision, required_scope) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        entry.ts_unix_ms,
                        entry.token_id,
                        entry.actor_kind,
                        entry.method,
                        entry.path,
                        i64::from(entry.status),
                        entry.decision,
                        entry.required_scope,
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(id as u64)
    }

    /// Read the ledger. Newest-first, capped at `limit`.
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
            "SELECT ts_unix_ms, token_id, actor_kind, method, path, status, decision, required_scope \
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
            push(&mut binds, &mut sql, "ts_unix_ms >=", t.into());
        }
        if let Some(t) = filter.until_ms {
            push(&mut binds, &mut sql, "ts_unix_ms <=", t.into());
        }
        if let Some(t) = &filter.token_id {
            push(&mut binds, &mut sql, "token_id =", t.clone().into());
        }
        if let Some(d) = &filter.decision {
            push(&mut binds, &mut sql, "decision =", d.clone().into());
        }
        // Newest-first + `LIMIT`. `id` in the `ORDER BY` breaks the
        // tie for rows with the same millisecond — otherwise SQLite's
        // ordering there would be undefined.
        let _ = write!(
            sql,
            " ORDER BY ts_unix_ms DESC, id DESC LIMIT ?{}",
            binds.len() + 1
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        binds.push(rusqlite::types::Value::Integer(limit as i64));

        self.db.read(|conn| -> Result<_, AuditLogError> {
            let mut stmt = conn.prepare(&sql)?;
            let bind_refs: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let rows = stmt.query_map(bind_refs.as_slice(), |row| {
                let status_i: i64 = row.get(5)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(AuditEntry {
                    ts_unix_ms: row.get(0)?,
                    token_id: row.get(1)?,
                    actor_kind: row.get(2)?,
                    method: row.get(3)?,
                    path: row.get(4)?,
                    status: status_i as u16,
                    decision: row.get(6)?,
                    required_scope: row.get(7)?,
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
    }

    /// Total row count. Useful for smoke tests and the daemon's
    /// status endpoint.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AuditLog {
        AuditLog::new(Arc::new(Db::open_in_memory().expect("db open")))
    }

    fn sample(token: &str, decision: &str) -> AuditEntry {
        AuditEntry {
            ts_unix_ms: 0,
            token_id: token.into(),
            actor_kind: "api".into(),
            method: "GET".into(),
            path: "/api/v1/instances".into(),
            status: 200,
            decision: decision.into(),
            required_scope: None,
        }
    }

    #[test]
    fn record_then_query_round_trips_shape() {
        let log = store();
        log.record(sample("tok-1", "allow")).expect("record 1");
        log.record(sample("tok-2", "deny")).expect("record 2");

        let rows = log.query(&AuditQuery::default(), 10).expect("query all");
        assert_eq!(rows.len(), 2);
        // Newest-first ordering — the second insert has the same
        // millisecond timestamp as the first in most runs, so the
        // secondary `id DESC` sort settles the tie.
        assert_eq!(rows[0].token_id, "tok-2");
        assert_eq!(rows[1].token_id, "tok-1");
    }

    #[test]
    fn query_filters_by_token_id() {
        let log = store();
        log.record(sample("tok-1", "allow")).unwrap();
        log.record(sample("tok-2", "allow")).unwrap();
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
    fn query_filters_by_decision() {
        let log = store();
        log.record(sample("tok", "allow")).unwrap();
        log.record(sample("tok", "deny")).unwrap();
        log.record(sample("tok", "error")).unwrap();
        let rows = log
            .query(
                &AuditQuery {
                    decision: Some("deny".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "deny");
    }

    #[test]
    fn record_stamps_wall_clock_ms() {
        // The `ts_unix_ms` on the input is ignored — `record` stamps
        // the host clock so a hostile caller can't rewrite time.
        let log = store();
        let mut entry = sample("tok", "allow");
        entry.ts_unix_ms = 0; // sentinel; should be overwritten
        log.record(entry).unwrap();
        let rows = log.query(&AuditQuery::default(), 1).unwrap();
        assert!(
            rows[0].ts_unix_ms > 0,
            "record must stamp a non-zero wall-clock timestamp, got {}",
            rows[0].ts_unix_ms,
        );
    }

    #[test]
    fn count_matches_records() {
        let log = store();
        assert_eq!(log.count().unwrap(), 0);
        for _ in 0..5 {
            log.record(sample("tok", "allow")).unwrap();
        }
        assert_eq!(log.count().unwrap(), 5);
    }

    #[test]
    fn required_scope_round_trips() {
        let log = store();
        let mut entry = sample("tok", "deny");
        entry.required_scope = Some("devices:list".into());
        log.record(entry).unwrap();
        let rows = log.query(&AuditQuery::default(), 1).unwrap();
        assert_eq!(rows[0].required_scope.as_deref(), Some("devices:list"));
    }
}
