//! The H5 command journal (ADR-0003 implementation notes): one bounded
//! writer thread for everything the host records about a device
//! command after its request row.
//!
//! It does two jobs, in the order they were queued:
//!
//! - **Persist** an externally-rooted `accepted` command into the
//!   `pending_command` table (migration 20), so a daemon restart can't
//!   drop it without a final outcome.
//! - **Resolve** a command: append its `COMMAND` resolution row to the
//!   audit ledger and, when the command was persisted, delete its
//!   `pending_command` row in the same transaction. A command is
//!   therefore either still in the table (and the next boot resolves
//!   it) or has its resolution row, never both and never neither.
//!
//! Both are queued from the command path with an in-memory push; the
//! disk write happens on the writer thread, at normal priority through
//! the M6 writer, in batches of up to [`MAX_JOURNAL_BATCH`] jobs per
//! transaction. Jobs are applied in queue order, so a command that
//! resolves before its persist is written can't come back: the delete
//! lands after the insert (and a persist followed by its resolve in one
//! batch skips the insert).
//!
//! The queue is bounded by [`MAX_JOURNAL_QUEUE`]. Past it a persist is
//! skipped (the command stays in memory and still gets its resolution
//! row; only a crash before it resolves loses it), and a resolution of
//! a command that was never persisted is dropped and counted. The
//! resolution of a persisted command is always queued, so its row can't
//! outlive its outcome; such resolutions can only exceed the bound by
//! the persists admitted under it, so the queue stays below about twice
//! the bound.
//!
//! At boot, `reconcile` resolves every surviving row to
//! `outcome_unknown` (`domain_error` = `daemon_restart`, or `expired`
//! when its expiry had already passed) before any plugin runs.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rusqlite::params;

use crate::state::db::Db;
use crate::state::event_log::now_unix_ms;
use crate::state::{AuditEntry, AuditLog, AuditLogError};

use super::command::{COMMAND_RESOLUTION_AUDIT_METHOD, resolution_path};

/// Jobs the journal holds before it starts refusing optional work (see
/// the module docs).
pub const MAX_JOURNAL_QUEUE: usize = 4096;

/// Jobs written per transaction.
pub const MAX_JOURNAL_BATCH: usize = 256;

/// Pause before a failed batch is retried.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// `domain_error` of a command resolved at boot because the daemon
/// stopped while it was pending.
pub const REASON_DAEMON_RESTART: &str = "daemon_restart";

/// `domain_error` of a command whose pending entry expired.
pub const REASON_EXPIRED: &str = "expired";

/// One persisted `accepted` command: what the boot reconciliation
/// needs to write its final row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRow {
    pub(crate) command_id: String,
    pub(crate) call_id: String,
    pub(crate) owner_instance: String,
    pub(crate) device_id: String,
    pub(crate) capability: String,
    pub(crate) created_ms: i64,
    pub(crate) expires_ms: i64,
    pub(crate) token_id: String,
    pub(crate) actor_kind: String,
    pub(crate) invocation_json: String,
}

enum Job {
    Persist(PendingRow),
    Resolve {
        entry: AuditEntry,
        /// The persisted row to delete with it.
        forget: Option<String>,
    },
}

/// How long a batch that fails while closing is retried.
#[derive(Clone, Copy, Default)]
enum Retry {
    /// Not closing, or closed by `Drop`: no retries while closing.
    #[default]
    Never,
    /// Until this instant.
    Until(Instant),
    /// The close budget doesn't fit an `Instant`: no bound.
    Unbounded,
}

#[derive(Default)]
struct Queue {
    jobs: VecDeque<Job>,
    /// No more jobs are taken; the worker drains and exits.
    closed: bool,
    /// Set by [`CommandJournal::close`]: how long a failing batch is
    /// retried, so a transient error doesn't cost a final row.
    retry: Retry,
    /// The worker is writing a batch it took off `jobs`.
    busy: bool,
    /// Jobs refused since the worker last reported.
    dropped: u64,
    /// Admitted jobs whose batch was given up on (a write failure
    /// while closing). [`CommandJournal::flush`] reports `false` once
    /// any job is lost.
    lost: u64,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    /// Signals the worker: jobs queued, or closed.
    work: Condvar,
    /// Signals waiters: the queue drained.
    idle: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Handle to the journal's writer thread. Dropping it closes the
/// journal: the thread writes what is queued and exits.
pub(crate) struct CommandJournal {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for CommandJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandJournal").finish_non_exhaustive()
    }
}

impl CommandJournal {
    /// Start the writer thread on `db`.
    ///
    /// # Errors
    ///
    /// The thread could not be spawned.
    pub(crate) fn start(db: Arc<Db>) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let worker = Arc::clone(&shared);
        // A std thread, not a blocking task: tokio waits for blocking
        // tasks at runtime teardown, and a write stuck on the disk must
        // not hold that up. Shutdown drains it with a bound instead.
        std::thread::Builder::new()
            .name("command-journal".into())
            .spawn(move || run(&worker, &db))?;
        Ok(Self { shared })
    }

    /// Queue `row` for the `pending_command` table. `false` when the
    /// queue is full or closed: the command is then tracked in memory
    /// only.
    pub(crate) fn persist(&self, row: PendingRow) -> bool {
        let mut q = self.shared.lock();
        if q.closed || q.jobs.len() >= MAX_JOURNAL_QUEUE {
            q.dropped += 1;
            return false;
        }
        q.jobs.push_back(Job::Persist(row));
        drop(q);
        self.shared.work.notify_one();
        true
    }

    /// Queue a resolution row; `forget` names the persisted row it
    /// replaces. A resolution with nothing to forget is dropped (and
    /// counted) when the queue is full.
    pub(crate) fn resolve(&self, entry: AuditEntry, forget: Option<String>) {
        let mut q = self.shared.lock();
        if q.closed || (forget.is_none() && q.jobs.len() >= MAX_JOURNAL_QUEUE) {
            q.dropped += 1;
            if q.closed {
                tracing::warn!(
                    target: "host.audit",
                    command_id = entry.command_id.as_deref().unwrap_or_default(),
                    "command resolution after the journal closed; not recorded",
                );
            }
            return;
        }
        q.jobs.push_back(Job::Resolve { entry, forget });
        drop(q);
        self.shared.work.notify_one();
    }

    /// Wait up to `timeout` for every queued job to be written. `true`
    /// when the queue drained and no admitted job was ever lost.
    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        // An unrepresentable deadline waits without bound.
        let deadline = Instant::now().checked_add(timeout);
        let mut q = self.shared.lock();
        while !q.jobs.is_empty() || q.busy {
            q = match deadline {
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        return false;
                    };
                    self.shared
                        .idle
                        .wait_timeout(q, left)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0
                }
                None => self
                    .shared
                    .idle
                    .wait(q)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            };
        }
        q.lost == 0
    }

    /// Stop taking jobs and wait up to `timeout` for the queued ones to
    /// be written. `true` when everything queued was written.
    pub(crate) fn close(&self, timeout: Duration) -> bool {
        {
            let mut q = self.shared.lock();
            q.closed = true;
            q.retry = Instant::now()
                .checked_add(timeout)
                .map_or(Retry::Unbounded, Retry::Until);
        }
        self.shared.work.notify_one();
        self.flush(timeout)
    }
}

impl Drop for CommandJournal {
    fn drop(&mut self) {
        {
            let mut q = self.shared.lock();
            q.closed = true;
            // Nobody waits on an unbounded close any more: don't let
            // the worker retry forever.
            if matches!(q.retry, Retry::Unbounded) {
                q.retry = Retry::Never;
            }
        }
        self.shared.work.notify_one();
    }
}

fn run(shared: &Shared, db: &Db) {
    // Commands whose persist was in a batch given up on: a zero-row
    // delete for one of them is not a sign of reconciliation.
    let mut unwritten: HashSet<String> = HashSet::new();
    loop {
        let (batch, lost) = {
            let mut q = shared.lock();
            while q.jobs.is_empty() && !q.closed {
                q = shared
                    .work
                    .wait(q)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if q.jobs.is_empty() {
                shared.idle.notify_all();
                return;
            }
            q.busy = true;
            let n = q.jobs.len().min(MAX_JOURNAL_BATCH);
            let batch: Vec<Job> = q.jobs.drain(..n).collect();
            (batch, std::mem::take(&mut q.dropped))
        };
        if lost > 0 {
            tracing::warn!(target: "host.audit", lost, "command journal full: jobs dropped");
        }
        loop {
            let Err(err) = write_batch(db, &batch, &unwritten) else {
                break;
            };
            if !shared.lock().closed {
                tracing::error!(
                    target: "host.audit",
                    error = %err,
                    jobs = batch.len(),
                    "command journal batch failed; retrying",
                );
                wait_retry_unless_closed(shared);
                continue;
            }
            // Closing: retry within the close budget, then give up.
            if retry_while_closing(shared) {
                continue;
            }
            tracing::error!(
                target: "host.audit",
                error = %err,
                jobs = batch.len(),
                "command journal batch failed while closing; dropped",
            );
            shared.lock().lost += batch.len() as u64;
            unwritten.extend(batch.iter().filter_map(|job| match job {
                Job::Persist(row) => Some(row.command_id.clone()),
                Job::Resolve { .. } => None,
            }));
            break;
        }
        let mut q = shared.lock();
        q.busy = false;
        if q.jobs.is_empty() {
            shared.idle.notify_all();
        }
    }
}

/// Wait [`RETRY_DELAY`] before retrying a failed batch, cut short by
/// a close so the retry moves onto the close budget at once.
fn wait_retry_unless_closed(shared: &Shared) {
    let until = Instant::now() + RETRY_DELAY;
    let mut q = shared.lock();
    while !q.closed {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            return;
        };
        q = shared
            .work
            .wait_timeout(q, left)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
}

/// Whether a batch that failed while closing gets another attempt:
/// sleeps briefly and answers `true` while the close budget lasts.
fn retry_while_closing(shared: &Shared) -> bool {
    let delay = match shared.lock().retry {
        Retry::Never => return false,
        Retry::Until(until) => {
            let Some(delay) = closing_retry_delay(until.checked_duration_since(Instant::now()))
            else {
                return false;
            };
            delay
        }
        Retry::Unbounded => CLOSING_RETRY_DELAY,
    };
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    true
}

/// Retry spacing while closing, until the budget gets short.
const CLOSING_RETRY_DELAY: Duration = Duration::from_millis(50);

/// The wait before retrying a failed batch with `left` of the close
/// budget remaining; `None` once it is spent. Near the end, half of
/// what is left (so an attempt still lands inside the budget), and at
/// once below 2 ms.
fn closing_retry_delay(left: Option<Duration>) -> Option<Duration> {
    match left {
        Some(left) if left.is_zero() => None,
        Some(left) if left < Duration::from_millis(2) => Some(Duration::ZERO),
        Some(left) => Some((left / 2).min(CLOSING_RETRY_DELAY)),
        None => None,
    }
}

fn write_batch(db: &Db, batch: &[Job], unwritten: &HashSet<String>) -> Result<(), AuditLogError> {
    // A persist whose command resolves later in the same batch has
    // nothing to keep.
    let resolved: HashSet<&str> = batch
        .iter()
        .filter_map(|job| match job {
            Job::Resolve {
                forget: Some(id), ..
            } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    // Commands persisted and resolved within this batch: their insert
    // is skipped, so their delete finds no row.
    let persisted_here: HashSet<&str> = batch
        .iter()
        .filter_map(|job| match job {
            Job::Persist(row) if resolved.contains(row.command_id.as_str()) => {
                Some(row.command_id.as_str())
            }
            _ => None,
        })
        .collect();
    db.write(|conn| -> Result<(), AuditLogError> {
        let tx = conn.transaction()?;
        let now = now_unix_ms();
        for job in batch {
            match job {
                Job::Persist(row) if !resolved.contains(row.command_id.as_str()) => {
                    insert_row(&tx, row)?;
                }
                Job::Persist(_) => {}
                Job::Resolve { entry, forget } => {
                    // A persisted command whose row is gone was already
                    // resolved by a boot reconciliation (another
                    // process took over the state dir): one final row
                    // per command, so write none. Its persist is always
                    // queued, and so written, before this.
                    if let Some(id) = forget {
                        let deleted = tx.execute(
                            "DELETE FROM pending_command WHERE command_id = ?1",
                            params![id],
                        )?;
                        if deleted == 0
                            && !persisted_here.contains(id.as_str())
                            && !unwritten.contains(id)
                        {
                            tracing::warn!(
                                target: "host.audit",
                                command_id = %id,
                                "pending command already reconciled; resolution row skipped",
                            );
                            continue;
                        }
                    }
                    AuditLog::insert_completed_row(&tx, now, entry)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    })
}

fn insert_row(conn: &rusqlite::Connection, row: &PendingRow) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT OR REPLACE INTO pending_command \
         (command_id, call_id, owner_instance, device_id, capability, created_ms, expires_ms, \
          token_id, actor_kind, invocation_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.command_id,
            row.call_id,
            row.owner_instance,
            row.device_id,
            row.capability,
            row.created_ms,
            row.expires_ms,
            row.token_id,
            row.actor_kind,
            row.invocation_json,
        ],
    )
}

/// The `pending_command` rows, oldest first.
#[cfg(test)]
pub(crate) fn load_rows(db: &Db) -> rusqlite::Result<Vec<PendingRow>> {
    db.read(select_rows)
}

fn select_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<PendingRow>> {
    let mut stmt = conn.prepare(
        "SELECT command_id, call_id, owner_instance, device_id, capability, created_ms, \
                expires_ms, token_id, actor_kind, invocation_json \
         FROM pending_command ORDER BY created_ms, command_id",
    )?;
    stmt.query_map([], |r| {
        Ok(PendingRow {
            command_id: r.get(0)?,
            call_id: r.get(1)?,
            owner_instance: r.get(2)?,
            device_id: r.get(3)?,
            capability: r.get(4)?,
            created_ms: r.get(5)?,
            expires_ms: r.get(6)?,
            token_id: r.get(7)?,
            actor_kind: r.get(8)?,
            invocation_json: r.get(9)?,
        })
    })?
    .collect()
}

/// Boot reconciliation: resolve every `pending_command` row a previous
/// process left behind to `outcome_unknown` and delete it, in one
/// transaction. Runs before any plugin starts, so nothing can complete
/// one of these commands any more. Returns how many were resolved.
///
/// # Errors
///
/// Forwards `SQLite` errors; the rows then stay for the next boot.
pub(crate) fn reconcile(db: &Db) -> Result<usize, AuditLogError> {
    let now = now_unix_ms();
    db.write(|conn| -> Result<usize, AuditLogError> {
        let tx = conn.transaction()?;
        // Read and claim under the writer, so a row resolved by a
        // writer that got in first is never resolved twice.
        let rows = select_rows(&tx)?;
        let mut resolved = 0;
        for row in &rows {
            let claimed = tx.execute(
                "DELETE FROM pending_command WHERE command_id = ?1",
                params![row.command_id],
            )?;
            if claimed == 0 {
                continue;
            }
            let reason = if now >= row.expires_ms {
                REASON_EXPIRED
            } else {
                REASON_DAEMON_RESTART
            };
            tracing::warn!(
                target: "host.command",
                command_id = %row.command_id,
                call_id = %row.call_id,
                device_id = %row.device_id,
                instance_id = %row.owner_instance,
                reason,
                "accepted command still pending at startup; outcome unknown",
            );
            AuditLog::insert_completed_row(&tx, now, &reconciled_entry(row, reason))?;
            resolved += 1;
        }
        tx.commit()?;
        Ok(resolved)
    })
}

fn reconciled_entry(row: &PendingRow, reason: &str) -> AuditEntry {
    AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: row.token_id.clone(),
        actor_kind: row.actor_kind.clone(),
        method: COMMAND_RESOLUTION_AUDIT_METHOD.to_owned(),
        path: resolution_path(&row.device_id),
        status: 200,
        decision: "allow".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: Some(reason.to_owned()),
        credential_fp: None,
        call_id: Some(row.call_id.clone()),
        invocation: Some(row.invocation_json.clone()),
        command_id: Some(row.command_id.clone()),
        command_outcome: Some("outcome_unknown".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AuditQuery;

    fn row(id: &str, expires_ms: i64) -> PendingRow {
        PendingRow {
            command_id: id.to_owned(),
            call_id: "call-1".into(),
            owner_instance: "inst-a".into(),
            device_id: "dev-1".into(),
            capability: "switch".into(),
            created_ms: 1,
            expires_ms,
            token_id: "tok-1".into(),
            actor_kind: "api".into(),
            invocation_json: "{}".into(),
        }
    }

    fn entry(id: &str) -> AuditEntry {
        let mut e = reconciled_entry(&row(id, 0), "x");
        e.domain_error = None;
        e.command_outcome = Some("completed".into());
        e
    }

    fn db() -> Arc<Db> {
        Arc::new(Db::open_in_memory().expect("db"))
    }

    fn resolution_rows(db: &Arc<Db>) -> Vec<AuditEntry> {
        AuditLog::new(Arc::clone(db))
            .query(&AuditQuery::default(), 100)
            .expect("query")
            .into_iter()
            .filter(|r| r.method == COMMAND_RESOLUTION_AUDIT_METHOD)
            .collect()
    }

    #[test]
    fn persisted_rows_are_deleted_with_their_resolution() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.persist(row("cmd-a", i64::MAX)));
        assert!(journal.persist(row("cmd-b", i64::MAX)));
        assert!(journal.flush(Duration::from_secs(5)));
        assert_eq!(load_rows(&db).unwrap().len(), 2);

        journal.resolve(entry("cmd-a"), Some("cmd-a".into()));
        assert!(journal.close(Duration::from_secs(5)));
        let left = load_rows(&db).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].command_id, "cmd-b");
        let rows = resolution_rows(&db);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].command_outcome.as_deref(), Some("completed"));
    }

    #[test]
    fn a_command_resolved_before_its_flush_does_not_resurrect() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        // Queued under one lock, so both jobs land in one batch.
        {
            let mut q = journal.shared.lock();
            q.jobs.push_back(Job::Persist(row("cmd-a", i64::MAX)));
            q.jobs.push_back(Job::Resolve {
                entry: entry("cmd-a"),
                forget: Some("cmd-a".into()),
            });
        }
        journal.shared.work.notify_one();
        assert!(journal.flush(Duration::from_secs(5)));
        assert_eq!(
            load_rows(&db).unwrap(),
            Vec::<PendingRow>::new(),
            "the row resurrected"
        );
        // And across batches: persist written, then resolved.
        assert!(journal.persist(row("cmd-b", i64::MAX)));
        assert!(journal.flush(Duration::from_secs(5)));
        journal.resolve(entry("cmd-b"), Some("cmd-b".into()));
        assert!(journal.flush(Duration::from_secs(5)));
        assert_eq!(load_rows(&db).unwrap(), Vec::<PendingRow>::new());
        assert_eq!(resolution_rows(&db).len(), 2);
    }

    #[test]
    fn reconcile_resolves_survivors_by_restart_or_expiry() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.persist(row("cmd-live", i64::MAX)));
        assert!(journal.persist(row("cmd-old", 1)));
        assert!(journal.close(Duration::from_secs(5)));

        assert_eq!(reconcile(&db).unwrap(), 2);
        assert_eq!(load_rows(&db).unwrap(), Vec::<PendingRow>::new());
        let rows = resolution_rows(&db);
        let reason_of = |id: &str| {
            rows.iter()
                .find(|r| r.command_id.as_deref() == Some(id))
                .and_then(|r| r.domain_error.clone())
        };
        assert_eq!(
            reason_of("cmd-live").as_deref(),
            Some(REASON_DAEMON_RESTART)
        );
        assert_eq!(reason_of("cmd-old").as_deref(), Some(REASON_EXPIRED));
        for r in &rows {
            assert_eq!(r.command_outcome.as_deref(), Some("outcome_unknown"));
            assert_eq!(r.call_id.as_deref(), Some("call-1"));
            assert_eq!(r.token_id, "tok-1");
            assert_eq!(r.path, "device.command/dev-1");
        }
        // Idempotent: nothing left to resolve.
        assert_eq!(reconcile(&db).unwrap(), 0);
    }

    #[test]
    fn a_resolution_after_reconciliation_writes_no_second_row() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.persist(row("cmd-a", i64::MAX)));
        assert!(journal.flush(Duration::from_secs(5)));
        // Another boot took over and resolved it.
        assert_eq!(reconcile(&db).unwrap(), 1);
        journal.resolve(entry("cmd-a"), Some("cmd-a".into()));
        assert!(journal.close(Duration::from_secs(5)));
        let rows = resolution_rows(&db);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].domain_error.as_deref(), Some(REASON_DAEMON_RESTART));
    }

    #[test]
    fn a_transient_failure_while_closing_is_retried_within_the_budget() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        // The batch's delete fails until the table comes back.
        db.write(|c| c.execute_batch("DROP TABLE pending_command"))
            .unwrap();
        {
            let mut q = journal.shared.lock();
            q.jobs.push_back(Job::Persist(row("cmd-a", i64::MAX)));
            q.jobs.push_back(Job::Resolve {
                entry: entry("cmd-a"),
                forget: Some("cmd-a".into()),
            });
        }
        let restore = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                db.write(|c| {
                    c.execute_batch(
                        "CREATE TABLE pending_command (
                            command_id TEXT PRIMARY KEY NOT NULL, call_id TEXT NOT NULL,
                            owner_instance TEXT NOT NULL, device_id TEXT NOT NULL,
                            capability TEXT NOT NULL, created_ms INTEGER NOT NULL,
                            expires_ms INTEGER NOT NULL, token_id TEXT NOT NULL,
                            actor_kind TEXT NOT NULL, invocation_json TEXT NOT NULL
                        ) WITHOUT ROWID",
                    )
                })
                .unwrap();
            })
        };
        assert!(journal.close(Duration::from_secs(5)), "the retry wrote it");
        restore.join().unwrap();
        assert_eq!(resolution_rows(&db).len(), 1);
    }

    #[test]
    fn a_close_cuts_short_the_retry_wait_of_a_batch_failing_before_it() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        db.write(|c| c.execute_batch("ALTER TABLE pending_command RENAME TO pc_away"))
            .unwrap();
        assert!(journal.persist(row("cmd-a", i64::MAX)));
        // The first attempt fails; the worker is now in its 1 s retry
        // wait.
        std::thread::sleep(Duration::from_millis(100));
        let restore = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                db.write(|c| c.execute_batch("ALTER TABLE pc_away RENAME TO pending_command"))
                    .unwrap();
            })
        };
        // Well under the 1 s wait: only a close that wakes the worker
        // gets the retry in.
        assert!(
            journal.close(Duration::from_millis(500)),
            "the retry wrote it"
        );
        restore.join().unwrap();
        assert_eq!(load_rows(&db).unwrap().len(), 1);
    }

    #[test]
    fn a_failed_reconcile_rolls_back_every_delete() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.persist(row("cmd-a", i64::MAX)));
        assert!(journal.persist(row("cmd-b", i64::MAX)));
        assert!(journal.close(Duration::from_secs(5)));
        // The second resolution row fails, after the first row's delete
        // and audit insert went through.
        db.write(|c| {
            c.execute_batch(&format!(
                "CREATE TRIGGER fail_second BEFORE INSERT ON audit_event
                 WHEN NEW.method = '{COMMAND_RESOLUTION_AUDIT_METHOD}'
                  AND (SELECT COUNT(*) FROM audit_event
                       WHERE method = '{COMMAND_RESOLUTION_AUDIT_METHOD}') >= 1
                 BEGIN SELECT RAISE(ABORT, 'second insert fails'); END",
            ))
        })
        .unwrap();
        assert!(reconcile(&db).is_err());
        assert_eq!(load_rows(&db).unwrap().len(), 2, "both rows kept");
        assert_eq!(resolution_rows(&db), Vec::<AuditEntry>::new());
    }

    #[test]
    fn closing_retries_use_the_budget_to_its_end() {
        let ms = Duration::from_millis;
        assert_eq!(
            closing_retry_delay(Some(ms(500))),
            Some(CLOSING_RETRY_DELAY)
        );
        assert_eq!(closing_retry_delay(Some(ms(30))), Some(ms(15)));
        assert_eq!(
            closing_retry_delay(Some(Duration::from_micros(1500))),
            Some(Duration::ZERO)
        );
        assert_eq!(closing_retry_delay(Some(Duration::ZERO)), None);
        assert_eq!(closing_retry_delay(None), None);
    }

    #[test]
    fn a_full_queue_refuses_optional_jobs_only() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.persist(row("cmd-z", i64::MAX)));
        assert!(journal.flush(Duration::from_secs(5)));
        // Hold the database writer so the worker can take at most one
        // batch off the queue while the test runs.
        db.write(|_| -> Result<(), rusqlite::Error> {
            {
                let mut q = journal.shared.lock();
                for i in 0..=MAX_JOURNAL_QUEUE + MAX_JOURNAL_BATCH {
                    q.jobs.push_back(Job::Resolve {
                        entry: entry(&format!("cmd-fill-{i}")),
                        forget: None,
                    });
                }
            }
            journal.shared.work.notify_one();
            assert!(!journal.persist(row("cmd-x", i64::MAX)), "persist refused");
            journal.resolve(entry("cmd-y"), None);
            journal.resolve(entry("cmd-z"), Some("cmd-z".into()));
            let q = journal.shared.lock();
            assert!(
                matches!(q.jobs.back(), Some(Job::Resolve { forget: Some(id), .. }) if id == "cmd-z"),
                "a persisted command's resolution is always queued",
            );
            Ok(())
        })
        .unwrap();
        assert!(journal.close(Duration::from_secs(30)));
        let rows = resolution_rows(&db);
        assert!(
            rows.iter()
                .any(|r| r.command_id.as_deref() == Some("cmd-z"))
        );
        assert!(
            !rows
                .iter()
                .any(|r| r.command_id.as_deref() == Some("cmd-y"))
        );
    }

    #[test]
    fn a_closed_journal_refuses_new_jobs() {
        let db = db();
        let journal = CommandJournal::start(Arc::clone(&db)).expect("journal");
        assert!(journal.close(Duration::from_secs(5)));
        assert!(!journal.persist(row("cmd-a", i64::MAX)));
        journal.resolve(entry("cmd-a"), None);
        assert!(journal.flush(Duration::from_secs(1)));
        assert_eq!(resolution_rows(&db), Vec::<AuditEntry>::new());
    }
}
