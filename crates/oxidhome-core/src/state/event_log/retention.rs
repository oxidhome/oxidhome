//! Event-log retention (H4 / M6 follow-up).
//!
//! A periodic task trims `event_log` by age and by row count. Every
//! trim removes an **id prefix** (H4): the pass picks one boundary id
//! and deletes the rows below it, oldest first, in chunks of
//! [`TRIM_CHUNK_ROWS`]. Each chunk is one low-priority transaction
//! (M6) that deletes the lowest remaining ids, so every committed
//! state — and every reader snapshot — still has pruned exactly
//! `1..=k`, and `cursor_expired` (checking the row right after a
//! cursor) stays exact. New rows only get higher ids, so a boundary
//! computed at the start of a pass stays a valid prefix bound for
//! the whole pass.

use std::sync::Arc;
use std::time::Duration;

use rusqlite::{OptionalExtension, params};

use super::{EventLog, EventLogError};

/// Rows per retention `DELETE` transaction. Same as the diagnostic
/// log's chunk, so a normal-priority write waits for at most one
/// bounded chunk.
pub(super) const TRIM_CHUNK_ROWS: i64 = 2048;

/// Default maximum event age: 30 days.
pub const DEFAULT_EVENT_LOG_MAX_AGE: Duration = Duration::from_hours(30 * 24);

/// Default maximum row count kept in `event_log`.
pub const DEFAULT_EVENT_LOG_MAX_ROWS: u64 = 1_000_000;

/// How often the retention task runs.
pub const DEFAULT_EVENT_LOG_RETENTION_INTERVAL: Duration = Duration::from_hours(1);

/// Delay before the first pass, so retention doesn't compete with
/// boot (migrations, plugin starts).
pub const DEFAULT_EVENT_LOG_RETENTION_FIRST_DELAY: Duration = Duration::from_secs(60);

/// Environment variable for the maximum age, in days (`0` disables
/// the age limit).
pub const ENV_EVENT_LOG_RETENTION_DAYS: &str = "OXIDHOME_EVENT_LOG_RETENTION_DAYS";

/// Environment variable for the maximum row count (`0` disables the
/// row limit).
pub const ENV_EVENT_LOG_MAX_ROWS: &str = "OXIDHOME_EVENT_LOG_MAX_ROWS";

/// What the retention task keeps. `None` disables a limit; with both
/// disabled the task never deletes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogRetention {
    /// Rows received longer ago than this are deleted (subject to
    /// the id-prefix rule).
    pub max_age: Option<Duration>,
    /// At most this many newest rows are kept.
    pub max_rows: Option<u64>,
    /// Time between passes.
    pub interval: Duration,
    /// Time before the first pass.
    pub first_delay: Duration,
}

impl Default for EventLogRetention {
    fn default() -> Self {
        Self {
            max_age: Some(DEFAULT_EVENT_LOG_MAX_AGE),
            max_rows: Some(DEFAULT_EVENT_LOG_MAX_ROWS),
            interval: DEFAULT_EVENT_LOG_RETENTION_INTERVAL,
            first_delay: DEFAULT_EVENT_LOG_RETENTION_FIRST_DELAY,
        }
    }
}

impl EventLogRetention {
    /// Defaults overridden by [`ENV_EVENT_LOG_RETENTION_DAYS`] and
    /// [`ENV_EVENT_LOG_MAX_ROWS`].
    ///
    /// # Errors
    ///
    /// A variable that is set but isn't a non-negative integer.
    pub fn from_env() -> anyhow::Result<Self> {
        // `var_os` + lossy: a non-Unicode value fails the parse below
        // instead of reading as unset and silently applying a default.
        Self::from_lookup(|name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()))
    }

    /// [`Self::from_env`] with an injectable lookup, for tests.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_env`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let parse = |name: &str| -> anyhow::Result<Option<u64>> {
            lookup(name)
                .map(|raw| {
                    raw.trim().parse::<u64>().map_err(|e| {
                        anyhow::anyhow!("parsing ${name} ({raw:?}) as a non-negative integer: {e}")
                    })
                })
                .transpose()
        };
        let mut policy = Self::default();
        if let Some(days) = parse(ENV_EVENT_LOG_RETENTION_DAYS)? {
            policy.max_age = match days {
                0 => None,
                d => Some(Duration::from_secs(d.saturating_mul(24 * 60 * 60))),
            };
        }
        if let Some(rows) = parse(ENV_EVENT_LOG_MAX_ROWS)? {
            policy.max_rows = (rows > 0).then_some(rows);
        }
        Ok(policy)
    }

    /// Cutoff for `received_ms`, or `None` with no age limit.
    fn cutoff_ms(&self, now_ms: i64) -> Option<i64> {
        self.max_age
            .map(|age| now_ms.saturating_sub(i64::try_from(age.as_millis()).unwrap_or(i64::MAX)))
    }
}

impl EventLog {
    /// The last id (inclusive) `policy` would delete, or `None` when
    /// nothing is due. Runs on a pooled reader: retention only
    /// deletes id prefixes and new rows only get higher ids, so a
    /// bound computed from any recent snapshot is still a prefix
    /// bound.
    pub(super) fn retention_bound(
        &self,
        cutoff_ms: Option<i64>,
        max_rows: Option<u64>,
    ) -> Result<Option<i64>, EventLogError> {
        self.db.read(|conn| -> Result<_, EventLogError> {
            // Age: every row below the first row (by id) received at
            // or after the cutoff — under a clock rollback an
            // old-stamped row above that point waits for the rows
            // before it (H4). No such row: everything is due.
            let by_age: Option<i64> = match cutoff_ms {
                Some(cutoff) => conn.query_row(
                    "SELECT COALESCE( \
                     (SELECT MIN(id) FROM event_log WHERE received_ms >= ?1) - 1, \
                     (SELECT MAX(id) FROM event_log))",
                    params![cutoff],
                    |row| row.get(0),
                )?,
                None => None,
            };
            // Rows: keep the `max_rows` highest ids. Ids can be sparse
            // (databases from before migration 16 keep their ids), so
            // the id span only rules a trim out cheaply; when the span
            // exceeds the limit the bound is the actual
            // `max_rows + 1`-th newest id.
            let by_rows: Option<i64> = match max_rows {
                Some(keep) => {
                    let keep = i64::try_from(keep).unwrap_or(i64::MAX);
                    // Separate scalar subqueries, so each is a seek to
                    // one end of the primary key, not an index scan.
                    let (lo, hi): (Option<i64>, Option<i64>) = conn.query_row(
                        "SELECT (SELECT MIN(id) FROM event_log), (SELECT MAX(id) FROM event_log)",
                        (),
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    match (lo, hi) {
                        (Some(lo), Some(hi)) if hi.saturating_sub(lo) >= keep => conn
                            .query_row(
                                "SELECT id FROM event_log ORDER BY id DESC LIMIT 1 OFFSET ?1",
                                params![keep],
                                |row| row.get::<_, i64>(0),
                            )
                            .optional()?,
                        _ => None,
                    }
                }
                None => None,
            };
            Ok(by_age.max(by_rows))
        })
    }

    /// Delete one chunk of the id prefix up to `last` (inclusive):
    /// the [`TRIM_CHUNK_ROWS`] lowest ids at most. One low-priority
    /// transaction (M6). `proceed` is checked once the writer is
    /// held, so a stop requested while this waited for the writer
    /// skips the delete. Returns the rows removed; `0` means the
    /// prefix is gone (or the chunk was skipped).
    fn trim_chunk_through(
        &self,
        last: i64,
        proceed: impl FnOnce() -> bool,
    ) -> Result<usize, EventLogError> {
        self.db
            .write_low_priority(|conn| -> Result<_, EventLogError> {
                if !proceed() {
                    return Ok(0);
                }
                // `MIN(id) + chunk - 1` may exceed `i64::MAX`; SQLite
                // then compares against a REAL, which is still exact
                // enough to bound the chunk.
                Ok(conn.execute(
                    "DELETE FROM event_log WHERE id <= \
                     MIN(?1, (SELECT MIN(id) FROM event_log) + (?2 - 1))",
                    params![last, TRIM_CHUNK_ROWS],
                )?)
            })
    }

    /// Delete the whole id prefix up to `last`, chunk by chunk.
    pub(super) fn trim_through(&self, last: i64) -> Result<usize, EventLogError> {
        let mut total = 0;
        loop {
            match self.trim_chunk_through(last, || true)? {
                0 => return Ok(total),
                n => total += n,
            }
        }
    }

    /// Run one retention pass synchronously: compute the boundary,
    /// then delete the prefix below it in bounded low-priority
    /// chunks. Returns the rows removed.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error; rows deleted by earlier chunks stay
    /// deleted.
    pub fn apply_retention(
        &self,
        policy: &EventLogRetention,
        now_ms: i64,
    ) -> Result<usize, EventLogError> {
        match self.retention_bound(policy.cutoff_ms(now_ms), policy.max_rows)? {
            Some(last) => self.trim_through(last),
            None => Ok(0),
        }
    }

    /// Spawn the periodic retention task on the current tokio
    /// runtime. Each chunk runs on the blocking pool, one at a time.
    /// [`RetentionTask::shutdown`] stops the task between chunks and
    /// waits for an in-flight chunk, so the caller can release the
    /// state-dir lock knowing no retention write is still running.
    /// A failed pass logs a warning and the next one runs on
    /// schedule. With no limits configured the task isn't spawned
    /// and `None` is returned. A zero `interval` is treated as 1 s.
    #[must_use]
    pub fn spawn_retention(self: &Arc<Self>, policy: EventLogRetention) -> Option<RetentionTask> {
        if policy.max_age.is_none() && policy.max_rows.is_none() {
            return None;
        }
        let log = Arc::clone(self);
        let (stop_tx, mut stop) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            let stopped = |stop: &tokio::sync::watch::Receiver<bool>| *stop.borrow();
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
                if stopped(&stop) {
                    return;
                }
                match run_pass(&log, policy, &stop).await {
                    Ok(0) => {}
                    Ok(removed) => {
                        tracing::info!(target: "event_log.retention", removed, "event log trimmed");
                    }
                    Err(error) => {
                        tracing::warn!(target: "event_log.retention", %error, "event log retention pass failed");
                    }
                }
            }
        });
        Some(RetentionTask {
            stop: stop_tx,
            handle,
        })
    }
}

/// Handle to the task started by [`EventLog::spawn_retention`].
/// Dropping it without [`Self::shutdown`] stops the task after its
/// current pass, without waiting for it.
#[derive(Debug)]
pub struct RetentionTask {
    stop: tokio::sync::watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RetentionTask {
    /// Stop the task and wait for it: a pass in progress ends after
    /// its current chunk commits (each chunk is one bounded
    /// transaction).
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        if let Err(join) = self.handle.await
            && join.is_panic()
        {
            std::panic::resume_unwind(join.into_panic());
        }
    }
}

/// One pass of the background task, chunk by chunk on the blocking
/// pool. Checks `stop` before each chunk.
async fn run_pass(
    log: &Arc<EventLog>,
    policy: EventLogRetention,
    stop: &tokio::sync::watch::Receiver<bool>,
) -> Result<usize, EventLogError> {
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX);
    let bound = {
        let log = Arc::clone(log);
        blocking(move || log.retention_bound(policy.cutoff_ms(now_ms), policy.max_rows)).await?
    };
    let Some(last) = bound else {
        return Ok(0);
    };
    let mut total = 0;
    while !*stop.borrow() {
        let log = Arc::clone(log);
        let stop = stop.clone();
        match blocking(move || log.trim_chunk_through(last, || !*stop.borrow())).await? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// Run `f` on the blocking pool and wait for it; a panic propagates.
async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> Result<R, EventLogError> + Send + 'static,
) -> Result<R, EventLogError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join) => std::panic::resume_unwind(join.into_panic()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, Event, EventPayload};
    use crate::state::db::Db;

    fn log() -> Arc<EventLog> {
        Arc::new(EventLog::new(Arc::new(Db::open_in_memory().expect("db"))))
    }

    fn record(log: &EventLog, received_ms: i64) -> u64 {
        let ev = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: "t.x".into(),
                payload: "{}".into(),
            }),
        };
        log.record(received_ms, &ev, "alpha", "example.alpha")
            .expect("record")
    }

    fn oldest(log: &EventLog) -> Option<i64> {
        log.db
            .read(|c| c.query_row("SELECT MIN(id) FROM event_log", (), |r| r.get(0)))
            .expect("min")
    }

    fn policy(max_age_ms: Option<u64>, max_rows: Option<u64>) -> EventLogRetention {
        EventLogRetention {
            max_age: max_age_ms.map(Duration::from_millis),
            max_rows,
            ..EventLogRetention::default()
        }
    }

    /// Each chunk deletes at most `TRIM_CHUNK_ROWS` of the lowest ids,
    /// so after every committed chunk the pruned range is `1..=k`.
    #[test]
    fn chunks_delete_the_lowest_ids_first() {
        let log = log();
        let rows = TRIM_CHUNK_ROWS * 2 + 10;
        for t in 0..rows {
            record(&log, t);
        }
        let last = rows;
        assert_eq!(
            log.trim_chunk_through(last, || true).expect("chunk"),
            usize::try_from(TRIM_CHUNK_ROWS).expect("fits")
        );
        assert_eq!(oldest(&log), Some(TRIM_CHUNK_ROWS + 1));
        assert_eq!(
            log.trim_chunk_through(last, || true).expect("chunk"),
            usize::try_from(TRIM_CHUNK_ROWS).expect("fits")
        );
        assert_eq!(oldest(&log), Some(TRIM_CHUNK_ROWS * 2 + 1));
        assert_eq!(log.trim_chunk_through(last, || true).expect("chunk"), 10);
        assert_eq!(log.trim_chunk_through(last, || true).expect("chunk"), 0);
        assert_eq!(log.count().expect("count"), 0);
    }

    /// A chunk whose stop flag flipped while it waited for the writer
    /// deletes nothing.
    #[test]
    fn stopped_chunk_skips_the_delete() {
        let log = log();
        for t in 0..5 {
            record(&log, t);
        }
        assert_eq!(log.trim_chunk_through(5, || false).expect("chunk"), 0);
        assert_eq!(log.count().expect("count"), 5);
    }

    /// Databases from before migration 16 keep sparse ids: the row
    /// limit counts rows, not the id span.
    #[test]
    fn row_limit_counts_rows_when_ids_are_sparse() {
        let log = log();
        for t in 0..10 {
            record(&log, t);
        }
        log.db
            .write(|c| c.execute("DELETE FROM event_log WHERE id NOT IN (5, 9)", ()))
            .expect("make sparse");
        assert_eq!(
            log.apply_retention(&policy(None, Some(2)), 100)
                .expect("retention"),
            0,
            "two rows under a two-row limit"
        );
        assert_eq!(
            log.apply_retention(&policy(None, Some(1)), 100)
                .expect("retention"),
            1
        );
        assert_eq!(oldest(&log), Some(9));
    }

    /// An expired row at the largest row id is still deleted (the
    /// bound is inclusive, so it never needs `MAX(id) + 1`).
    #[test]
    fn age_limit_handles_the_largest_row_id() {
        let log = log();
        record(&log, 0);
        log.db
            .write(|c| c.execute("UPDATE event_log SET id = ?1", params![i64::MAX]))
            .expect("max id");
        assert_eq!(
            log.apply_retention(&policy(Some(10), None), 1_000)
                .expect("retention"),
            1
        );
        assert_eq!(log.count().expect("count"), 0);
    }

    #[test]
    fn age_limit_trims_an_id_prefix_across_chunks() {
        let log = log();
        let old = TRIM_CHUNK_ROWS + 5;
        for _ in 0..old {
            record(&log, 1_000);
        }
        // Fresh row, then a clock-rollback row above it: H4 keeps the
        // rollback row until the rows before it age out.
        let fresh = record(&log, 90_000);
        record(&log, 1_000);
        let removed = log
            .apply_retention(&policy(Some(50_000), None), 100_000)
            .expect("retention");
        assert_eq!(removed, usize::try_from(old).expect("fits"));
        assert_eq!(oldest(&log), i64::try_from(fresh).ok());
        assert_eq!(log.count().expect("count"), 2);
    }

    #[test]
    fn row_limit_keeps_the_newest_rows() {
        let log = log();
        for t in 0..20 {
            record(&log, t);
        }
        assert_eq!(
            log.apply_retention(&policy(None, Some(5)), 100)
                .expect("retention"),
            15
        );
        assert_eq!(oldest(&log), Some(16));
        assert_eq!(log.count().expect("count"), 5);
        // Under the limit: nothing to do.
        assert_eq!(
            log.apply_retention(&policy(None, Some(5)), 100)
                .expect("retention"),
            0
        );
    }

    /// With both limits, a row goes when either says so.
    #[test]
    fn the_stricter_limit_wins() {
        let log = log();
        for t in 0..10 {
            record(&log, t * 1_000);
        }
        // Age keeps ids 6..=10 (received >= 5_000); rows keep 8..=10.
        assert_eq!(
            log.apply_retention(&policy(Some(5_000), Some(3)), 10_000)
                .expect("retention"),
            7
        );
        assert_eq!(oldest(&log), Some(8));
        // Age stricter than rows.
        assert_eq!(
            log.apply_retention(&policy(Some(1_500), Some(100)), 10_000)
                .expect("retention"),
            2
        );
        assert_eq!(log.count().expect("count"), 1);
    }

    #[test]
    fn no_limits_and_empty_tables_delete_nothing() {
        let log = log();
        assert_eq!(
            log.apply_retention(&policy(Some(1), Some(1)), 100)
                .expect("empty"),
            0
        );
        record(&log, 0);
        assert_eq!(
            log.apply_retention(&policy(None, None), i64::MAX)
                .expect("none"),
            0
        );
        assert!(log.spawn_retention(policy(None, None)).is_none());
    }

    #[test]
    fn env_overrides_defaults() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            EventLogRetention::from_lookup(env(&[])).expect("defaults"),
            EventLogRetention::default()
        );
        let p = EventLogRetention::from_lookup(env(&[
            (ENV_EVENT_LOG_RETENTION_DAYS, "7"),
            (ENV_EVENT_LOG_MAX_ROWS, " 0 "),
        ]))
        .expect("parse");
        assert_eq!(p.max_age, Some(Duration::from_hours(7 * 24)));
        assert_eq!(p.max_rows, None);
        let p = EventLogRetention::from_lookup(env(&[(ENV_EVENT_LOG_RETENTION_DAYS, "0")]))
            .expect("parse");
        assert_eq!(p.max_age, None);
        assert_eq!(p.max_rows, Some(DEFAULT_EVENT_LOG_MAX_ROWS));
        assert!(EventLogRetention::from_lookup(env(&[(ENV_EVENT_LOG_MAX_ROWS, "-1")])).is_err());
        assert!(
            EventLogRetention::from_lookup(env(&[(ENV_EVENT_LOG_RETENTION_DAYS, "week")])).is_err()
        );
    }

    /// The spawned task runs passes on its interval.
    #[tokio::test(flavor = "current_thread")]
    async fn spawned_task_trims_periodically() {
        let log = log();
        for t in 0..10 {
            record(&log, t);
        }
        let task = log
            .spawn_retention(EventLogRetention {
                max_age: None,
                max_rows: Some(4),
                interval: Duration::from_millis(20),
                first_delay: Duration::ZERO,
            })
            .expect("spawned");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while log.count().expect("count") != 4 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "first pass never ran"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // A later pass picks up new rows.
        for t in 10..13 {
            record(&log, t);
        }
        while log.count().expect("count") != 4 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "later pass never ran"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(oldest(&log), Some(10));
        task.shutdown().await;
        // Stopped: new rows are no longer trimmed.
        for t in 13..20 {
            record(&log, t);
        }
        // Several configured intervals: a surviving task would trim.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(log.count().expect("count"), 11);
    }
}
