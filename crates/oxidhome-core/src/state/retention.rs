//! Periodic retention for the append-only tables (H4 / M6 follow-up).
//!
//! Three tables grow without bound unless something deletes from
//! them: `event_log` (H3 / H4 history), `log_event` (diagnostic logs)
//! and `audit_event` (the C3 ledger). Each gets a background task
//! that runs a pass shortly after start and then on an interval. A
//! pass plans what is due on a pooled reader, then deletes it in
//! bounded chunks, each one low-priority write transaction (M6), so a
//! normal-priority write waits for at most one chunk. What a table
//! may delete, and in which order, is up to the table (`RetentionTarget`):
//! the event log deletes only an id prefix (H4), the audit ledger
//! keeps rows an unfinished two-phase write still needs.
//!
//! Limits come from the environment ([`RetentionEnv`]): a maximum age
//! in days and a maximum row count, `0` disabling either. A value
//! that isn't a non-negative integer fails startup.
//!
//! Shutdown ([`RetentionTask::shutdown`]) stops a task between chunks
//! and cancels a chunk still waiting for the writer
//! ([`super::Db::write_low_priority_unless`]), so a hung write
//! elsewhere doesn't hold shutdown on retention.

use std::sync::Arc;
use std::time::Duration;

use super::Db;

/// Rows per retention `DELETE` transaction (and per scan window), the
/// same chunk the diagnostic log uses, so a normal-priority write
/// waits for at most one bounded chunk.
pub const RETENTION_CHUNK_ROWS: i64 = 2048;

/// How often a retention task runs.
pub const DEFAULT_RETENTION_INTERVAL: Duration = Duration::from_hours(1);

/// Delay before the first pass, so retention doesn't compete with
/// boot (migrations, plugin starts).
pub const DEFAULT_RETENTION_FIRST_DELAY: Duration = Duration::from_secs(60);

/// Where one table's limits come from, and their defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionEnv {
    /// Variable holding the maximum age in days (`0` disables it).
    pub days_var: &'static str,
    /// Variable holding the maximum row count (`0` disables it).
    pub rows_var: &'static str,
    /// Maximum age when the variable is unset.
    pub default_max_age: Option<Duration>,
    /// Maximum row count when the variable is unset.
    pub default_max_rows: Option<u64>,
}

const fn days(n: u64) -> Duration {
    Duration::from_hours(n * 24)
}

/// `event_log`: 30 days, 1,000,000 rows.
pub const EVENT_LOG_RETENTION_ENV: RetentionEnv = RetentionEnv {
    days_var: "OXIDHOME_EVENT_LOG_RETENTION_DAYS",
    rows_var: "OXIDHOME_EVENT_LOG_MAX_ROWS",
    default_max_age: Some(days(30)),
    default_max_rows: Some(1_000_000),
};

/// `log_event` (diagnostic logs): 30 days, 1,000,000 rows.
pub const LOG_RETENTION_ENV: RetentionEnv = RetentionEnv {
    days_var: "OXIDHOME_LOG_RETENTION_DAYS",
    rows_var: "OXIDHOME_LOG_MAX_ROWS",
    default_max_age: Some(days(30)),
    default_max_rows: Some(1_000_000),
};

/// `audit_event` (the audit ledger): 365 days, 1,000,000 rows. Kept
/// longer than the diagnostic tables because it is the security
/// record.
pub const AUDIT_RETENTION_ENV: RetentionEnv = RetentionEnv {
    days_var: "OXIDHOME_AUDIT_RETENTION_DAYS",
    rows_var: "OXIDHOME_AUDIT_MAX_ROWS",
    default_max_age: Some(days(365)),
    default_max_rows: Some(1_000_000),
};

/// What one retention task keeps. `None` disables a limit; with both
/// disabled the task isn't started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Rows older than this are deleted (subject to the table's own
    /// rules, see the table's `spawn_retention`).
    pub max_age: Option<Duration>,
    /// At most this many newest rows are kept (rows a table must keep
    /// don't count against the limit).
    pub max_rows: Option<u64>,
    /// Time between passes.
    pub interval: Duration,
    /// Time before the first pass.
    pub first_delay: Duration,
}

impl RetentionPolicy {
    /// `env`'s defaults, nothing read from the environment.
    #[must_use]
    pub const fn defaults(env: &RetentionEnv) -> Self {
        Self {
            max_age: env.default_max_age,
            max_rows: env.default_max_rows,
            interval: DEFAULT_RETENTION_INTERVAL,
            first_delay: DEFAULT_RETENTION_FIRST_DELAY,
        }
    }

    /// `env`'s defaults overridden by its two variables.
    ///
    /// # Errors
    ///
    /// A variable that is set but isn't a non-negative integer.
    pub fn from_env(env: &RetentionEnv) -> anyhow::Result<Self> {
        // `var_os` + lossy: a non-Unicode value fails the parse below
        // instead of reading as unset and silently applying a default.
        Self::from_lookup(env, |name| {
            std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
        })
    }

    /// [`Self::from_env`] with an injectable lookup, for tests.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_env`].
    pub fn from_lookup(
        env: &RetentionEnv,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let parse = |name: &str| -> anyhow::Result<Option<u64>> {
            lookup(name)
                .map(|raw| {
                    raw.trim().parse::<u64>().map_err(|e| {
                        anyhow::anyhow!("parsing ${name} ({raw:?}) as a non-negative integer: {e}")
                    })
                })
                .transpose()
        };
        let mut policy = Self::defaults(env);
        if let Some(d) = parse(env.days_var)? {
            policy.max_age = (d > 0).then(|| Duration::from_secs(d.saturating_mul(24 * 60 * 60)));
        }
        if let Some(rows) = parse(env.rows_var)? {
            policy.max_rows = (rows > 0).then_some(rows);
        }
        Ok(policy)
    }

    /// Cutoff for the table's timestamp column, or `None` with no age
    /// limit.
    #[must_use]
    pub fn cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        self.max_age
            .map(|age| now_ms.saturating_sub(i64::try_from(age.as_millis()).unwrap_or(i64::MAX)))
    }

    fn is_disabled(&self) -> bool {
        self.max_age.is_none() && self.max_rows.is_none()
    }
}

/// Retention limits for every table, read once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// `event_log`.
    pub event_log: RetentionPolicy,
    /// `log_event`.
    pub logs: RetentionPolicy,
    /// `audit_event`.
    pub audit: RetentionPolicy,
}

impl RetentionConfig {
    /// Every table's limits from the environment.
    ///
    /// # Errors
    ///
    /// Any variable that is set but isn't a non-negative integer.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            event_log: RetentionPolicy::from_env(&EVENT_LOG_RETENTION_ENV)?,
            logs: RetentionPolicy::from_env(&LOG_RETENTION_ENV)?,
            audit: RetentionPolicy::from_env(&AUDIT_RETENTION_ENV)?,
        })
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            event_log: RetentionPolicy::defaults(&EVENT_LOG_RETENTION_ENV),
            logs: RetentionPolicy::defaults(&LOG_RETENTION_ENV),
            audit: RetentionPolicy::defaults(&AUDIT_RETENTION_ENV),
        }
    }
}

/// One table a retention task trims.
pub(crate) trait RetentionTarget: Send + Sync + 'static {
    /// What a pass deletes, computed once at its start.
    type Plan: Send + 'static;

    /// Table name, for the task's log lines.
    const TABLE: &'static str;

    /// The database the table lives in.
    fn db(&self) -> &Arc<Db>;

    /// Work out what is due, on a pooled reader. `None`: nothing.
    fn plan(
        &self,
        cutoff_ms: Option<i64>,
        max_rows: Option<u64>,
    ) -> anyhow::Result<Option<Self::Plan>>;

    /// Delete one bounded chunk in one low-priority transaction,
    /// skipped (`None`) if `stopped` turns true before the writer is
    /// granted. `Some(n)`: `n` rows deleted, call again. `None`: the
    /// pass is over.
    fn step(
        &self,
        plan: &mut Self::Plan,
        stopped: &dyn Fn() -> bool,
    ) -> anyhow::Result<Option<usize>>;
}

/// Run a whole pass synchronously. Returns the rows removed.
#[cfg(test)]
pub(crate) fn run_pass_blocking<T: RetentionTarget>(
    target: &T,
    policy: &RetentionPolicy,
    now_ms: i64,
) -> anyhow::Result<usize> {
    let Some(mut plan) = target.plan(policy.cutoff_ms(now_ms), policy.max_rows)? else {
        return Ok(0);
    };
    let mut total = 0;
    while let Some(n) = target.step(&mut plan, &|| false)? {
        total += n;
    }
    Ok(total)
}

/// Start the periodic task for `target` on the current tokio runtime.
/// Each chunk runs on the blocking pool, one at a time. `None` when
/// both limits are disabled. A zero `interval` is treated as 1 s.
pub(crate) fn spawn<T: RetentionTarget>(
    target: Arc<T>,
    policy: RetentionPolicy,
) -> Option<RetentionTask> {
    if policy.is_disabled() {
        return None;
    }
    let db = Arc::clone(target.db());
    let (stop_tx, mut stop) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(policy.first_delay) => {}
            _ = stop.changed() => return,
        }
        let interval = if policy.interval.is_zero() {
            Duration::from_secs(1)
        } else {
            policy.interval
        };
        let mut ticks = tokio::time::interval(interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticks.tick() => {}
                _ = stop.changed() => return,
            }
            if *stop.borrow() {
                return;
            }
            match run_pass(&target, policy, &stop).await {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!(target: "state.retention", table = T::TABLE, removed, "retention pass trimmed rows");
                }
                Err(error) => {
                    tracing::warn!(target: "state.retention", table = T::TABLE, error = %format!("{error:#}"), "retention pass failed");
                }
            }
        }
    });
    Some(RetentionTask {
        stop: stop_tx,
        db,
        handle,
    })
}

/// One pass of the background task, chunk by chunk on the blocking
/// pool. Checks `stop` before each chunk and while a chunk waits for
/// the writer.
async fn run_pass<T: RetentionTarget>(
    target: &Arc<T>,
    policy: RetentionPolicy,
    stop: &tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<usize> {
    let now_ms = super::event_log::now_unix_ms();
    let plan = {
        let target = Arc::clone(target);
        blocking(move || target.plan(policy.cutoff_ms(now_ms), policy.max_rows)).await?
    };
    let Some(mut plan) = plan else {
        return Ok(0);
    };
    let mut total = 0;
    while !*stop.borrow() {
        let target = Arc::clone(target);
        let stop = stop.clone();
        let (returned, outcome) = blocking(move || {
            let outcome = target.step(&mut plan, &|| *stop.borrow());
            Ok((plan, outcome))
        })
        .await?;
        plan = returned;
        match outcome? {
            Some(n) => total += n,
            None => break,
        }
    }
    Ok(total)
}

/// Run `f` on the blocking pool and wait for it; a panic propagates.
async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> anyhow::Result<R> + Send + 'static,
) -> anyhow::Result<R> {
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join) => std::panic::resume_unwind(join.into_panic()),
    }
}

/// Handle to one task started by [`crate::Engine::spawn_retention`] or
/// [`super::EventLog::spawn_retention`]. Dropping it without
/// [`Self::shutdown`] stops the task the same way, without waiting for
/// it.
#[derive(Debug)]
pub struct RetentionTask {
    stop: tokio::sync::watch::Sender<bool>,
    db: Arc<Db>,
    handle: tokio::task::JoinHandle<()>,
}

impl RetentionTask {
    /// Ask the task to stop: it ends between chunks, and a chunk still
    /// waiting for the writer gives up instead of deleting.
    pub fn request_stop(&self) {
        let _ = self.stop.send(true);
        self.db.wake_low_priority_writers();
    }

    /// [`Self::request_stop`], then wait for the task. A chunk that
    /// already holds the writer finishes first (each chunk is one
    /// bounded transaction).
    pub async fn shutdown(mut self) {
        self.request_stop();
        if let Err(join) = (&mut self.handle).await
            && join.is_panic()
        {
            std::panic::resume_unwind(join.into_panic());
        }
    }
}

impl Drop for RetentionTask {
    fn drop(&mut self) {
        self.request_stop();
    }
}

/// The retention tasks of one daemon process.
#[derive(Debug, Default)]
pub struct RetentionTasks {
    tasks: Vec<RetentionTask>,
}

impl RetentionTasks {
    pub(crate) fn push(&mut self, task: Option<RetentionTask>) {
        self.tasks.extend(task);
    }

    /// Number of running tasks (tables with a limit configured).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// No task is running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Stop every task and wait for them (see
    /// [`RetentionTask::shutdown`]).
    pub async fn shutdown(self) {
        for task in &self.tasks {
            task.request_stop();
        }
        for task in self.tasks {
            task.shutdown().await;
        }
    }
}

/// A scan window over an `INTEGER PRIMARY KEY` table: rows in
/// `(after, last]` are looked at [`RETENTION_CHUNK_ROWS`] ids at a
/// time, oldest first, so every chunk reads a bounded range and a pass
/// reads each candidate row once, even when rows the table must keep
/// sit between deletable ones.
#[derive(Debug, Clone)]
pub(crate) struct IdWindowPlan {
    /// Delete rows stamped before this (`None`: no age limit).
    pub(crate) cutoff_ms: Option<i64>,
    /// Delete rows with an id at or below this (`None`: no row
    /// limit).
    pub(crate) row_bound: Option<i64>,
    /// Highest id a pass looks at.
    pub(crate) last: i64,
    /// Ids up to here have been looked at.
    pub(crate) after: i64,
}

/// Plan a windowed pass over `table` (an `INTEGER PRIMARY KEY` `id`
/// and a millisecond timestamp column `ts`) on a pooled reader. The
/// newest row is never due, so a table trimmed to nothing doesn't hand
/// out its ids again.
pub(crate) fn plan_id_window(
    db: &Db,
    table: &str,
    ts: &str,
    cutoff_ms: Option<i64>,
    max_rows: Option<u64>,
) -> rusqlite::Result<Option<IdWindowPlan>> {
    db.read(|conn| {
        let (lo, hi): (Option<i64>, Option<i64>) = conn.query_row(
            &format!("SELECT (SELECT MIN(id) FROM {table}), (SELECT MAX(id) FROM {table})"),
            (),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (Some(lo), Some(hi)) = (lo, hi) else {
            return Ok(None);
        };
        let by_age: Option<i64> = match cutoff_ms {
            Some(cutoff) => conn.query_row(
                &format!("SELECT MAX(id) FROM {table} WHERE {ts} < ?1"),
                [cutoff],
                |row| row.get(0),
            )?,
            None => None,
        };
        // Ids can be sparse: the span only rules a trim out cheaply,
        // the bound is the actual `max_rows + 1`-th newest id.
        let row_bound: Option<i64> = match max_rows {
            Some(keep) => {
                let keep = i64::try_from(keep).unwrap_or(i64::MAX);
                if hi.saturating_sub(lo) >= keep {
                    conn.query_row(
                        &format!("SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?1"),
                        [keep],
                        |row| row.get(0),
                    )
                    .map(Some)
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        e => Err(e),
                    })?
                } else {
                    None
                }
            }
            None => None,
        };
        let Some(last) = by_age.max(row_bound).map(|l| l.min(hi - 1)) else {
            return Ok(None);
        };
        Ok((last >= lo).then(|| IdWindowPlan {
            cutoff_ms,
            row_bound,
            last,
            after: lo - 1,
        }))
    })
}

/// One windowed chunk: look at the next [`RETENTION_CHUNK_ROWS`] ids of
/// `table` in the plan's range and delete the ones `due` selects
/// (`due` may use `?1` = cutoff and `?2` = row bound, either NULL, and
/// any parameters in `extra` from `?3` on). One low-priority
/// transaction, skipped if `stopped` turns true first.
pub(crate) fn step_id_window(
    db: &Db,
    table: &str,
    due: &str,
    extra: &[&dyn rusqlite::ToSql],
    plan: &mut IdWindowPlan,
    stopped: &dyn Fn() -> bool,
) -> rusqlite::Result<Option<usize>> {
    if plan.after >= plan.last {
        return Ok(None);
    }
    let outcome = db.write_low_priority_unless(stopped, |conn| -> rusqlite::Result<_> {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let end: Option<i64> = tx.query_row(
            &format!(
                "SELECT MAX(id) FROM (SELECT id FROM {table} WHERE id > ?1 AND id <= ?2 \
                 ORDER BY id LIMIT ?3)"
            ),
            rusqlite::params![plan.after, plan.last, RETENTION_CHUNK_ROWS],
            |row| row.get(0),
        )?;
        let Some(end) = end else {
            tx.commit()?;
            return Ok(None);
        };
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&plan.cutoff_ms, &plan.row_bound];
        params.extend_from_slice(extra);
        let lo = plan.after;
        let deleted = tx.execute(
            &format!("DELETE FROM {table} WHERE id > {lo} AND id <= {end} AND ({due})"),
            params.as_slice(),
        )?;
        tx.commit()?;
        Ok(Some((end, deleted)))
    })?;
    match outcome {
        // Cancelled while waiting for the writer, or nothing left.
        None | Some(None) => Ok(None),
        Some(Some((end, deleted))) => {
            plan.after = end;
            Ok(Some(deleted))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuditEntry, AuditLog, LogStore};

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn policy(max_age_ms: Option<u64>, max_rows: Option<u64>) -> RetentionPolicy {
        RetentionPolicy {
            max_age: max_age_ms.map(Duration::from_millis),
            max_rows,
            interval: Duration::from_millis(20),
            first_delay: Duration::ZERO,
        }
    }

    #[test]
    fn every_table_reads_its_own_variables() {
        let config = RetentionConfig::default();
        assert_eq!(config.event_log.max_age, Some(days(30)));
        assert_eq!(config.logs.max_age, Some(days(30)));
        assert_eq!(config.audit.max_age, Some(days(365)));
        for p in [config.event_log, config.logs, config.audit] {
            assert_eq!(p.max_rows, Some(1_000_000));
        }
        let logs = RetentionPolicy::from_lookup(
            &LOG_RETENTION_ENV,
            env(&[
                ("OXIDHOME_LOG_RETENTION_DAYS", "7"),
                ("OXIDHOME_LOG_MAX_ROWS", "0"),
            ]),
        )
        .expect("logs");
        assert_eq!(logs.max_age, Some(days(7)));
        assert_eq!(logs.max_rows, None);
        let audit = RetentionPolicy::from_lookup(
            &AUDIT_RETENTION_ENV,
            env(&[
                ("OXIDHOME_LOG_RETENTION_DAYS", "7"),
                ("OXIDHOME_AUDIT_RETENTION_DAYS", "0"),
            ]),
        )
        .expect("audit");
        assert_eq!(audit.max_age, None, "the audit variable, not the log one");
        assert_eq!(audit.max_rows, Some(1_000_000));
        assert!(
            RetentionPolicy::from_lookup(
                &AUDIT_RETENTION_ENV,
                env(&[("OXIDHOME_AUDIT_MAX_ROWS", "x")])
            )
            .is_err()
        );
    }

    fn log_store() -> (Arc<Db>, Arc<LogStore>) {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        (Arc::clone(&db), Arc::new(LogStore::new(db)))
    }

    fn insert_logs(db: &Db, stamps: impl IntoIterator<Item = i64>) {
        db.write(|c| {
            for ts in stamps {
                c.execute(
                    "INSERT INTO log_event(ts_unix_ms, level, target, message) VALUES (?1, 2, 't', 'm')",
                    [ts],
                )?;
            }
            Ok::<_, rusqlite::Error>(())
        })
        .expect("insert");
    }

    fn ids(db: &Db, table: &str) -> Vec<i64> {
        db.read(|c| {
            let mut stmt = c.prepare(&format!("SELECT id FROM {table} ORDER BY id"))?;
            stmt.query_map([], |r| r.get(0))?.collect()
        })
        .expect("ids")
    }

    /// Logs go by age (any order) or beyond the newest rows, across
    /// several scan windows, and the newest row always stays.
    #[test]
    fn logs_trim_by_age_and_rows_across_windows() {
        let (db, logs) = log_store();
        let n = RETENTION_CHUNK_ROWS * 2 + 7;
        // Old rows with a fresh one in the middle: the fresh one stays.
        insert_logs(&db, (0..n).map(|i| if i == 100 { 50_000 } else { 1_000 }));
        let removed = run_pass_blocking(&*logs, &policy(Some(10_000), None), 20_000).expect("pass");
        assert_eq!(removed, usize::try_from(n - 2).expect("fits"));
        assert_eq!(
            ids(&db, "log_event"),
            [101, n],
            "fresh row and newest row kept"
        );
        // Row limit.
        insert_logs(&db, (0..10).map(|_| 60_000));
        let removed = run_pass_blocking(&*logs, &policy(None, Some(3)), 70_000).expect("pass");
        assert_eq!(removed, 9);
        assert_eq!(ids(&db, "log_event").len(), 3);
        // Everything expired: the newest row stays, so ids aren't
        // handed out again.
        let newest = *ids(&db, "log_event").last().expect("rows");
        run_pass_blocking(&*logs, &policy(Some(1), None), i64::MAX).expect("pass");
        assert_eq!(ids(&db, "log_event"), [newest]);
    }

    fn row(method: &str, call: Option<&str>, command: Option<(&str, &str)>) -> AuditEntry {
        AuditEntry {
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: "t".into(),
            actor_kind: "api".into(),
            method: method.into(),
            path: "/p".into(),
            status: 200,
            decision: "allow".into(),
            required_scope: None,
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
            call_id: call.map(Into::into),
            invocation: None,
            command_id: command.map(|(id, _)| id.into()),
            command_outcome: command.map(|(_, o)| o.into()),
        }
    }

    /// Audit retention keeps what an unfinished write still needs: this
    /// process's pending rows, and an accepted command until its
    /// resolution row lands. Earlier processes' pending rows go by age
    /// only.
    #[test]
    #[expect(clippy::too_many_lines, reason = "one scenario, step by step")]
    fn audit_keeps_rows_unfinished_writes_need() {
        let dir = std::env::temp_dir().join(format!(
            "oxidhome-audit-retention-{}-{}",
            std::process::id(),
            super::super::event_log::now_unix_ms()
        ));
        // Written by an "earlier process": abandoned pending rows.
        let (old_pending, old_pending_2) = {
            let db = Arc::new(Db::open_file(&dir).expect("db"));
            let log0 = AuditLog::new(Arc::clone(&db));
            (
                log0.record_intent(&row("GET", None, None)).expect("intent"),
                log0.record_intent(&row("GET", None, None)).expect("intent"),
            )
        };
        // This process: a second handle on its database shares the
        // floor.
        let db = Arc::new(Db::open_file(&dir).expect("db"));
        let first = AuditLog::new(Arc::clone(&db));
        let log = Arc::new(AuditLog::new(Arc::clone(&db)));
        let done = log.record_completed(&row("GET", None, None)).expect("row");
        let pending = log.record_intent(&row("GET", None, None)).expect("intent");
        let accepted = log
            .record_completed(&row("POST", Some("call-a"), Some(("cmd-a", "accepted"))))
            .expect("row");
        let accepted_resolved = log
            .record_completed(&row("POST", Some("call-b"), Some(("cmd-b", "accepted"))))
            .expect("row");
        let _resolution = log
            .record_completed(&row(
                "COMMAND",
                Some("call-b"),
                Some(("cmd-b", "completed")),
            ))
            .expect("row");
        let newest = log.record_completed(&row("GET", None, None)).expect("row");
        // Everything is old except `old_pending_2`.
        db.write(|c| c.execute("UPDATE audit_event SET intent_ms = 1000", []))
            .expect("age");
        db.write(|c| {
            c.execute(
                "UPDATE audit_event SET intent_ms = 90000 WHERE id = ?1",
                [i64::try_from(old_pending_2).expect("id")],
            )
        })
        .expect("fresh");
        // Row limit of one: pending rows never go by count.
        run_pass_blocking(&*log, &policy(None, Some(1)), 100_000).expect("pass");
        let kept = ids(&db, "audit_event");
        let as_i64 = |id: u64| i64::try_from(id).expect("id");
        assert!(kept.contains(&as_i64(old_pending)), "{kept:?}");
        assert!(kept.contains(&as_i64(old_pending_2)), "{kept:?}");
        assert!(kept.contains(&as_i64(pending)), "{kept:?}");
        assert!(kept.contains(&as_i64(accepted)), "{kept:?}");
        assert!(!kept.contains(&as_i64(done)), "{kept:?}");
        assert!(!kept.contains(&as_i64(accepted_resolved)), "{kept:?}");
        // `resolution` waits for its accepted row, gone this pass.
        assert!(kept.contains(&as_i64(newest)), "{kept:?}");
        // By age: the earlier process's old pending row goes, the
        // fresh one and this process's pending row stay.
        run_pass_blocking(&*log, &policy(Some(10_000), None), 100_000).expect("pass");
        assert_eq!(
            ids(&db, "audit_event"),
            [
                as_i64(old_pending_2),
                as_i64(pending),
                as_i64(accepted),
                as_i64(newest)
            ]
        );
        // A resolution that looks older than its accepted row (clock
        // rollback) waits for it, so the accepted row never loses its
        // resolution.
        let late = log
            .record_completed(&row("POST", Some("call-c"), Some(("cmd-c", "accepted"))))
            .expect("row");
        let early_resolution = log
            .record_completed(&row(
                "COMMAND",
                Some("call-c"),
                Some(("cmd-c", "completed")),
            ))
            .expect("row");
        log.record_completed(&row("GET", None, None)).expect("row");
        db.write(|c| {
            c.execute(
                "UPDATE audit_event SET intent_ms = 90000 WHERE id = ?1",
                [as_i64(late)],
            )?;
            c.execute(
                "UPDATE audit_event SET intent_ms = 1000 WHERE id = ?1",
                [as_i64(early_resolution)],
            )
        })
        .expect("rollback");
        run_pass_blocking(&*log, &policy(Some(10_000), None), 100_000).expect("pass");
        let kept = ids(&db, "audit_event");
        assert!(kept.contains(&as_i64(early_resolution)), "{kept:?}");
        // A command that resolved before its request was finalized:
        // the resolution waits while the request is still pending.
        log.record_intent(&row("POST", Some("call-d"), None))
            .expect("intent");
        let fast = log
            .record_completed(&row(
                "COMMAND",
                Some("call-d"),
                Some(("cmd-d", "completed")),
            ))
            .expect("row");
        log.record_completed(&row("GET", None, None)).expect("row");
        db.write(|c| {
            c.execute(
                "UPDATE audit_event SET intent_ms = 1000 WHERE id = ?1",
                [as_i64(fast)],
            )
        })
        .expect("age");
        run_pass_blocking(&*log, &policy(Some(10_000), Some(1)), 100_000).expect("pass");
        assert!(ids(&db, "audit_event").contains(&as_i64(fast)));
        // Once the accepted command is resolved, its row can go, and
        // then its resolution.
        log.record_completed(&row(
            "COMMAND",
            Some("call-a"),
            Some(("cmd-a", "outcome_unknown")),
        ))
        .expect("row");
        run_pass_blocking(&*log, &policy(Some(10_000), None), 100_000).expect("pass");
        assert!(!ids(&db, "audit_event").contains(&as_i64(accepted)));
        drop((log, first, db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stop request cancels a chunk queued behind a hung writer, so
    /// shutdown returns promptly and nothing is deleted afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cancels_a_chunk_waiting_for_the_writer() {
        // File-backed, so the pass plans on a pooled reader instead of
        // the held writer.
        let dir = std::env::temp_dir().join(format!(
            "oxidhome-retention-{}-{}",
            std::process::id(),
            super::super::event_log::now_unix_ms()
        ));
        let db = Arc::new(Db::open_file(&dir).expect("db"));
        let logs = Arc::new(LogStore::new(Arc::clone(&db)));
        insert_logs(&db, 0..10);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.write(|_| {
                    held_tx.send(()).expect("held");
                    release_rx.recv().expect("release");
                    Ok::<_, rusqlite::Error>(())
                })
                .expect("hold");
            })
        };
        held_rx.recv().expect("writer held");
        let task = logs
            .spawn_retention(policy(None, Some(1)))
            .expect("spawned");
        // Let the first pass plan and queue its chunk.
        tokio::time::sleep(Duration::from_millis(300)).await;
        tokio::time::timeout(Duration::from_secs(5), task.shutdown())
            .await
            .expect("shutdown is not held by the hung writer");
        release_tx.send(()).expect("release");
        holder.join().expect("holder");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            ids(&db, "log_event").len(),
            10,
            "the cancelled chunk never ran"
        );
        drop((logs, db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The engine starts one task per table with a limit.
    #[tokio::test(flavor = "current_thread")]
    async fn engine_starts_a_task_per_limited_table() {
        let engine = crate::Engine::new().expect("engine");
        let config = RetentionConfig {
            logs: policy(None, None),
            ..RetentionConfig::default()
        };
        let tasks = engine.spawn_retention(config);
        assert_eq!(tasks.len(), 2);
        tasks.shutdown().await;
    }
}
