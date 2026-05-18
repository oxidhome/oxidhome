//! `SQLite`-backed log/trace store — Phase 5c.
//!
//! Captures every `tracing` event the host emits — Phase-4 capability
//! denials, Phase-5d `publish_event` writes, plugin-side log lines
//! forwarded through the `logging` import, plus host-internal spans —
//! into the `log_event` table. The CLI/API (Phase 12) reads back
//! filtered/aggregated views; plugins don't get to read the store.
//!
//! ## Trade-off: dropping vs. blocking
//!
//! Phase 5d's event history blocks the publisher on disk because
//! losing audit history isn't acceptable. Logs are *diagnostic* —
//! losing the last 0.01% of debug events during a disk hiccup is
//! strictly better than blocking the calling thread on `SQLite`. So
//! this store uses the bounded-channel + writer-thread shape Phase
//! 5d's docs originally sketched: the Layer's `on_event` does a
//! `try_send` that's constant-time, the writer thread drains the
//! channel into `SQLite`, and saturation bumps a drop counter rather
//! than back-pressuring tracing.
//!
//! ## Why a `std::thread`, not `tokio::spawn`?
//!
//! `tracing::Subscriber::on_event` fires synchronously from
//! *wherever* the originating `info!` / `warn!` etc. lives —
//! possibly off a tokio worker, possibly off a plain
//! `std::thread::spawn`'d background task. We can't assume a tokio
//! runtime is in scope, so the writer is a plain `std::thread` and
//! the channel is `std::sync::mpsc::sync_channel`. Same `SQLite` handle
//! the Phase-5a KV and Phase-5d event log share — the rusqlite
//! `Connection` is mutex-guarded inside `Db`, so concurrent use from
//! tokio + this thread is safe.
//!
//! ## Span-carried context
//!
//! The Layer walks the span chain **root → leaf** for each event;
//! the innermost span's `instance_id` / `plugin_id` / `device_id`
//! field wins because it's recorded last. Event-level fields on
//! the `info!` / `warn!` / etc. call itself override the inherited
//! span value. Plugin authors and host callers don't have to type
//! the field at every callsite — Phase 4B's `plugin.load` span
//! adds `instance_id` (and records `plugin_id` once the manifest
//! parses); the device/event/storage host impls add `plugin_id` /
//! `device_id` as they apply. The `span_path` column is the
//! slash-joined span name chain in root→leaf order — useful for
//! "everything that happened inside `plugin.execute_command`."

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use rusqlite::params;
use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::db::Db;

/// Channel capacity for the in-memory log-event queue. Sized to
/// absorb short bursts (a few hundred events in 50 ms) without
/// blocking the writer; sustained overflow trips the drop counter
/// instead of back-pressuring tracing.
const DEFAULT_CAPACITY: usize = 1024;

/// Errors returned by [`LogStore`]. Layer-side `try_send` never
/// returns these (it can only fail by dropping into the counter);
/// this enum is for the host-side query / retention / count API.
#[derive(Debug, thiserror::Error)]
pub enum LogStoreError {
    /// ``SQLite`` returned an error during the operation.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// A stored row's `fields_blob` couldn't be decoded — would mean
    /// the table was hand-edited or a future migration didn't keep
    /// the JSON shape.
    #[error("decoding fields_blob for log id {id}: {source}")]
    Decode {
        id: u64,
        #[source]
        source: serde_json::Error,
    },
}

/// Log levels mapped to integers for the `log_event.level` column.
/// TRACE=0 through ERROR=4 — bigger numbers are *louder*, so the
/// natural "show me INFO and above" filter is `level >= 2`. Matches
/// `tracing::Level`'s own ordering and lets `min_level` queries do
/// a single index range scan.
const LEVEL_TRACE: i64 = 0;
const LEVEL_DEBUG: i64 = 1;
const LEVEL_INFO: i64 = 2;
const LEVEL_WARN: i64 = 3;
const LEVEL_ERROR: i64 = 4;

fn level_to_int(level: Level) -> i64 {
    match level {
        Level::TRACE => LEVEL_TRACE,
        Level::DEBUG => LEVEL_DEBUG,
        Level::INFO => LEVEL_INFO,
        Level::WARN => LEVEL_WARN,
        Level::ERROR => LEVEL_ERROR,
    }
}

fn int_to_level(level: i64) -> Option<LogLevel> {
    match level {
        LEVEL_TRACE => Some(LogLevel::Trace),
        LEVEL_DEBUG => Some(LogLevel::Debug),
        LEVEL_INFO => Some(LogLevel::Info),
        LEVEL_WARN => Some(LogLevel::Warn),
        LEVEL_ERROR => Some(LogLevel::Error),
        _ => None,
    }
}

/// Owned mirror of [`tracing::Level`] for the query API. Avoids
/// having callers depend on `tracing` types directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// One row from `log_event`, decoded back into typed Rust.
#[derive(Debug, Clone)]
pub struct HistoricalLogEvent {
    pub id: u64,
    pub ts_unix_ms: i64,
    pub level: LogLevel,
    pub instance_id: Option<String>,
    pub plugin_id: Option<String>,
    pub device_id: Option<String>,
    pub target: String,
    pub span_path: Option<String>,
    pub message: String,
    pub fields: Vec<(String, LogValue)>,
}

/// JSON-friendly value type for structured fields. Mirrors the
/// concrete shapes `tracing`'s `Visit` exposes; `Debug` is the
/// catchall for fields that don't fit a typed variant (custom
/// `impl Debug` types, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum LogValue {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    /// Captured from the `?` formatter — what `tracing` calls
    /// `record_debug` — plus non-finite floats that
    /// [`Visit::record_f64`](tracing::field::Visit::record_f64)
    /// can't otherwise round-trip through JSON. The field visitor
    /// trims a single pair of surrounding `"` quotes when the
    /// `Debug` output is a quoted string literal so
    /// `device_id = %"d-1"` and `device_id = "d-1"` look the same
    /// to the store; everything else lands verbatim as the
    /// Debug-formatted form.
    Debug(String),
}

/// Query shape for [`LogStore::query`]. Every field is optional and
/// AND-combined; `None` everywhere returns the most recent `limit`
/// rows. Time bounds (`since_ms` / `until_ms`) are inclusive on both
/// ends. `min_level` is inclusive: `Info` matches info/warn/error.
///
/// Prefix filters (`target_prefix`, `span_path_prefix`) use the
/// same `substr(col, 1, length(?)) = ?` shape `kv::list_keys` and
/// `event_log` settled on — correct on TEXT, no `LIKE` escaping
/// hazards. The `log_target_ts` / `log_span_ts` partial indexes
/// help **range** queries (`target = ?` / `span_path = ?`), not
/// these prefix predicates — `substr(...)` doesn't seek a B-tree.
/// Phase-5c workloads are small (per-host log volume measured in
/// thousands of events / hour), so the planner-chosen `(target, ts)`
/// index keeps the post-filter cheap. A range-rewrite with
/// codepoint-correct upper bounds (`target >= ? AND target < ?`)
/// lands when there's a workload that pushes past that envelope.
///
/// Message-substring search, structured-field equality, and a live
/// tail are deferred to the Phase 12 query API; the on-disk shape
/// (`fields_blob` as tagged JSON, message as TEXT) is forward-
/// compatible with both.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub min_level: Option<LogLevel>,
    pub instance_id: Option<String>,
    pub plugin_id: Option<String>,
    pub device_id: Option<String>,
    /// Exact target match. Use [`target_prefix`] for module-tree
    /// scans (e.g. `oxidhome_core::runtime`).
    ///
    /// [`target_prefix`]: Self::target_prefix
    pub target: Option<String>,
    /// Match every event whose `target` starts with this prefix —
    /// e.g. `oxidhome_core::runtime` catches both
    /// `oxidhome_core::runtime::state` and
    /// `oxidhome_core::runtime::instance`.
    pub target_prefix: Option<String>,
    /// Match every event whose `span_path` starts with this prefix —
    /// e.g. `plugin.` catches `plugin.init`, `plugin.shutdown`,
    /// `plugin.execute_command`, etc.
    pub span_path_prefix: Option<String>,
}

// ── Internal channel record ─────────────────────────────────────────
//
// The Layer constructs a `LogRecord` on the calling thread and ships
// it through the channel; the writer thread reads, formats, and
// inserts. Keeping this struct private and the field representation
// stable lets us swap the encoding later (postcard, etc.) without
// touching the public surface.

struct LogRecord {
    ts_unix_ms: i64,
    level: i64,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    target: String,
    span_path: Option<String>,
    message: String,
    fields_blob: Vec<u8>,
}

// ── Shared state ────────────────────────────────────────────────────
//
// One `Inner` per LogStore. The Layer holds a `SyncSender<LogRecord>`
// + `Arc<Counters>` (for try_send drop accounting). The writer
// thread holds the `Receiver` + `Arc<Counters>` (bumps `written`
// after each successful insert). Tests reach into `counters` to
// wait until `written == sent`.

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    dropped: AtomicU64,
    written: AtomicU64,
    write_errors: AtomicU64,
    /// `true` iff the most recent `flush()` call hit its budget
    /// without draining. Used by `LogStore::drop` to avoid a
    /// second 5-second wait when an explicit shutdown flush has
    /// already given up — re-waiting won't catch up a writer
    /// that's stuck.
    last_flush_timed_out: std::sync::atomic::AtomicBool,
}

/// Per-host log/trace store.
///
/// `LogStore` itself is *not* `Clone` — share it as `Arc<LogStore>`
/// (which is what `Engine::log_store()` hands out). The bits inside
/// (`SyncSender`, `Arc<Counters>`, `Arc<Db>`) are all individually
/// cheap to clone; the type doesn't derive `Clone` because the
/// `JoinHandle` slot for the writer thread is single-owner — we
/// keep it on `LogStore` so future shutdown paths can join the
/// writer (today it's stored and never joined — see below).
///
/// Drop semantics: dropping the `LogStore` doesn't kill the writer
/// thread, because [`LogStore::layer`] clones hand out fresh
/// senders. When every sender (`LogStore` + every `SqliteLayer`
/// clone the subscriber holds) drops, the receiver in the writer
/// thread sees `Err`, exits the loop, and the thread returns. The
/// `JoinHandle` is held in `_writer` but **not joined** — the
/// `Drop` impl below explicitly detaches it. Detaching is the
/// right shape: `LogStore` dropping mid-program (because the host
/// is restarting an engine) shouldn't block on a writer that's
/// still serving Layer clones held by the global subscriber, and
/// at process exit the OS reaps the thread regardless.
///
/// What does run at `LogStore::drop` is a bounded `flush(5s)` so
/// rows already in the channel land before the store goes away.
pub struct LogStore {
    tx: SyncSender<LogRecord>,
    counters: Arc<Counters>,
    db: Arc<Db>,
    /// Held but never joined — see the type-level doc. The slot
    /// stays so a future explicit `LogStore::shutdown(self)` can
    /// drop the sender, then join the writer, when there's a
    /// caller pattern that wants that. Today's callers all live in
    /// `Arc<LogStore>` so a `&mut self`-taking shutdown would need
    /// interior mutability that doesn't pull its weight yet.
    _writer: Option<JoinHandle<()>>,
}

impl LogStore {
    /// Construct a log store backed by `db`. Spawns the writer
    /// thread.
    /// # Panics
    /// Panics if the OS refuses to spawn the writer thread (e.g.
    /// resource exhaustion). Treated as catastrophic — the host
    /// can't usefully run without the log store reachable, so we
    /// surface it loudly instead of silently degrading.
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self::new_with_capacity(db, DEFAULT_CAPACITY)
    }

    /// # Panics
    /// See [`Self::new`].
    #[must_use]
    pub fn new_with_capacity(db: Arc<Db>, capacity: usize) -> Self {
        let (tx, rx) = sync_channel::<LogRecord>(capacity);
        let counters = Arc::new(Counters::default());
        let writer_db = Arc::clone(&db);
        let writer_counters = Arc::clone(&counters);
        let writer = std::thread::Builder::new()
            .name("oxidhome-log-writer".into())
            .spawn(move || writer_loop(writer_db, rx, writer_counters))
            .expect("spawn log writer");
        Self {
            tx,
            counters,
            db,
            _writer: Some(writer),
        }
    }

    /// Returns a `tracing_subscriber::Layer` that pushes each event
    /// into this store. Clone-friendly — the underlying channel
    /// sender is a `SyncSender`, which is cloneable. The returned
    /// layer composes into any `Subscriber` that satisfies
    /// `for<'a> LookupSpan<'a>` (e.g. `tracing_subscriber::Registry`).
    #[must_use]
    pub fn layer(&self) -> SqliteLayer {
        SqliteLayer {
            tx: self.tx.clone(),
            counters: Arc::clone(&self.counters),
        }
    }

    /// Total number of events the Layer observed — every call to
    /// `on_event`, whether the row eventually committed, errored,
    /// or was dropped. Monotonic; never decremented. The flush
    /// invariant `written + write_errors + dropped >= sent` holds
    /// because every increment here matches exactly one increment
    /// in those terminal counters.
    #[must_use]
    pub fn sent(&self) -> u64 {
        self.counters.sent.load(Ordering::Relaxed)
    }

    /// Number of events dropped because the channel was full *or*
    /// the writer thread was gone (every `TrySendError`). Bumped by
    /// the Layer; the writer thread emits no `tracing::warn!`
    /// itself (would loop). The host's periodic status endpoint
    /// (Phase 12) surfaces this counter.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Number of events the writer thread has successfully committed
    /// to `SQLite` storage. Tests use this to know when a flush has landed.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.counters.written.load(Ordering::Relaxed)
    }

    /// Number of writer-side `SQLite` errors. Used as a smoke check —
    /// in normal operation this stays at zero. The writer keeps
    /// running on failure so a single bad row doesn't kill the
    /// store.
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.counters.write_errors.load(Ordering::Relaxed)
    }

    /// Wait until the writer thread has processed every event the
    /// Layer has successfully enqueued so far (committed *or*
    /// failed-with-Sql-error), with a bound on how long we'll spin.
    ///
    /// Returns `true` if the queue drained inside `budget`, `false`
    /// if the timeout elapsed first. Callers that want the
    /// "definitely drained, no time limit" shape should pass
    /// `Duration::MAX` (or [`Self::wait_drained_for_test`], which
    /// is the same thing under the hood and exists so tests read
    /// intent-clearly).
    ///
    /// The condition is `written + write_errors + dropped >= sent_snapshot`.
    /// `sent` is monotonic ("every event the Layer observed") and
    /// every observation deposits in exactly one terminal counter,
    /// so the sum is monotonically non-decreasing and self-correcting.
    /// (Earlier revisions decremented `sent` on `TrySendError`; the
    /// fix dropped the decrement so a flush snapshot taken between
    /// the layer's `fetch_add` and a subsequent `fetch_sub` can't
    /// outrun what the writer can ever process.)
    ///
    /// Concurrency note: snapshots `sent` once up front. Concurrent
    /// producers can keep emitting after the snapshot — those events
    /// land on the *next* flush. For program shutdown, ensure no
    /// plugin is still firing events when you call this (the natural
    /// shape after `instance.shutdown()`).
    #[must_use]
    pub fn flush(&self, budget: std::time::Duration) -> bool {
        let target = self.sent();
        let deadline = std::time::Instant::now().checked_add(budget);
        // Naive `yield_now` polling. A disk-stalled writer makes this
        // pin one CPU until the budget expires. The actual fix —
        // a condvar bumped by the writer thread after each commit /
        // failure, or an ack-channel — is filed for Phase 12's
        // shutdown-coordination work since it's only operationally
        // expensive (not incorrect) and `flush` is rare on the hot
        // path (called once per process exit, once per LogStore drop).
        loop {
            // Every `sent` deposits in exactly one of the three:
            // `written` (writer committed), `write_errors` (writer
            // failed), `dropped` (try_send Full / Disconnected, never
            // reached the writer). Sum is monotonically non-decreasing
            // and catches up to any prior `sent` snapshot.
            let processed = self.written() + self.write_errors() + self.dropped();
            if processed >= target {
                self.counters
                    .last_flush_timed_out
                    .store(false, Ordering::Relaxed);
                return true;
            }
            if let Some(deadline) = deadline
                && std::time::Instant::now() >= deadline
            {
                self.counters
                    .last_flush_timed_out
                    .store(true, Ordering::Relaxed);
                return false;
            }
            std::thread::yield_now();
        }
    }

    /// Convenience wrapper around [`Self::flush`] for tests: spin
    /// without a timeout. Don't use from production code — a slow or
    /// hung writer would hang the caller forever.
    pub fn wait_drained_for_test(&self) {
        let _ = self.flush(std::time::Duration::MAX);
    }

    /// Query the store. Returns at most `limit` rows newest-first.
    ///
    /// # Errors
    ///
    /// - [`LogStoreError::Sql`] for any underlying `SQLite` error.
    /// - [`LogStoreError::Decode`] if a stored row's `fields_blob`
    ///   doesn't parse as the expected tagged-JSON map.
    // SQL builder + row decode is naturally linear and reads top-to-
    // bottom; splitting for the `too_many_lines` lint would shuffle
    // the parameterized-WHERE logic across helpers without making
    // anything clearer.
    #[allow(clippy::too_many_lines)]
    pub fn query(
        &self,
        filter: &LogQuery,
        limit: usize,
    ) -> Result<Vec<HistoricalLogEvent>, LogStoreError> {
        use std::fmt::Write as _;

        let mut sql = String::from(
            "SELECT id, ts_unix_ms, level, instance_id, plugin_id, device_id, target, span_path, message, fields_blob \
             FROM log_event WHERE 1=1",
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
        if let Some(lv) = filter.min_level {
            push(&mut binds, &mut sql, "level >=", level_int(lv).into());
        }
        if let Some(i) = &filter.instance_id {
            push(&mut binds, &mut sql, "instance_id =", i.clone().into());
        }
        if let Some(p) = &filter.plugin_id {
            push(&mut binds, &mut sql, "plugin_id =", p.clone().into());
        }
        if let Some(d) = &filter.device_id {
            push(&mut binds, &mut sql, "device_id =", d.clone().into());
        }
        if let Some(t) = &filter.target {
            push(&mut binds, &mut sql, "target =", t.clone().into());
        }
        // Prefix filters: `substr(col, 1, length(?)) = ?` matches the
        // shape kv::list_keys / event_log topic prefix use — correct
        // on TEXT, no `LIKE` wildcard hazards.
        if let Some(t) = &filter.target_prefix {
            binds.push(rusqlite::types::Value::Text(t.clone()));
            let n_left = binds.len();
            binds.push(rusqlite::types::Value::Text(t.clone()));
            let n_right = binds.len();
            let _ = write!(
                sql,
                " AND substr(target, 1, length(?{n_left})) = ?{n_right}"
            );
        }
        if let Some(s) = &filter.span_path_prefix {
            binds.push(rusqlite::types::Value::Text(s.clone()));
            let n_left = binds.len();
            binds.push(rusqlite::types::Value::Text(s.clone()));
            let n_right = binds.len();
            let _ = write!(
                sql,
                " AND span_path IS NOT NULL AND substr(span_path, 1, length(?{n_left})) = ?{n_right}"
            );
        }

        binds.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));
        let _ = write!(
            sql,
            " ORDER BY ts_unix_ms DESC, id DESC LIMIT ?{}",
            binds.len()
        );

        self.db.read(|conn| -> Result<_, LogStoreError> {
            let mut stmt = conn.prepare(&sql)?;
            let binds: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let mut rows = stmt.query(binds.as_slice())?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                #[allow(clippy::cast_sign_loss)]
                let id_u = id as u64;
                let ts_unix_ms: i64 = row.get(1)?;
                let level_int: i64 = row.get(2)?;
                let level = int_to_level(level_int).ok_or_else(|| {
                    LogStoreError::Sql(rusqlite::Error::IntegralValueOutOfRange(2, level_int))
                })?;
                let instance_id: Option<String> = row.get(3)?;
                let plugin_id: Option<String> = row.get(4)?;
                let device_id: Option<String> = row.get(5)?;
                let target: String = row.get(6)?;
                let span_path: Option<String> = row.get(7)?;
                let message: String = row.get(8)?;
                let fields_blob: Option<Vec<u8>> = row.get(9)?;
                let fields: Vec<(String, LogValue)> = match fields_blob {
                    Some(b) if !b.is_empty() => serde_json::from_slice(&b)
                        .map_err(|source| LogStoreError::Decode { id: id_u, source })?,
                    _ => Vec::new(),
                };
                out.push(HistoricalLogEvent {
                    id: id_u,
                    ts_unix_ms,
                    level,
                    instance_id,
                    plugin_id,
                    device_id,
                    target,
                    span_path,
                    message,
                    fields,
                });
            }
            Ok(out)
        })
    }

    /// Delete every event with `ts_unix_ms < cutoff_ms`. Returns the
    /// number of rows removed. Used by the future retention
    /// scheduler.
    ///
    /// Flushes the writer thread first (5 s budget) so any rows in
    /// the channel with `ts_unix_ms < cutoff_ms` actually commit
    /// before the `DELETE` runs — otherwise the retention contract
    /// is violated by writer-side races: a row already in the
    /// channel keeps its original timestamp, the trim DELETE
    /// doesn't see it, and the writer inserts it *after* the
    /// trim, leaving a row older than `cutoff_ms` behind. If the
    /// flush budget exceeds, a `tracing::warn!` fires and the trim
    /// proceeds — better to under-trim than to block the retention
    /// scheduler on a wedged writer.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn trim_older_than(&self, cutoff_ms: i64) -> Result<usize, LogStoreError> {
        if !self.flush(std::time::Duration::from_secs(5)) {
            // No `tracing::error!` here — would loop into the layer
            // we're trying to drain. Stderr is the same backstop the
            // writer-side error path uses.
            eprintln!(
                "oxidhome log_store: trim_older_than: flush budget exceeded; \
                 retention may miss in-flight rows on this pass",
            );
        }
        self.db.write(|conn| -> Result<_, LogStoreError> {
            Ok(conn.execute(
                "DELETE FROM log_event WHERE ts_unix_ms < ?1",
                params![cutoff_ms],
            )?)
        })
    }

    /// Total row count.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn count(&self) -> Result<u64, LogStoreError> {
        let n: i64 = self.db.read(|conn| -> Result<_, LogStoreError> {
            Ok(conn.query_row("SELECT COUNT(*) FROM log_event", (), |row| row.get(0))?)
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(n as u64)
    }
}

impl Drop for LogStore {
    /// Best-effort drain on drop. Bounded at 5 s so unexpected
    /// teardown (panic unwind, error path bailing early) doesn't
    /// hang the caller. The explicit `flush(...)` call in
    /// `oxidhome` main covers the happy path with a tunable budget;
    /// this is the fall-back for everything else (tests that drop
    /// the engine instead of cleanly shutting down, library
    /// embedders that don't call flush themselves).
    ///
    /// If the most recent `flush()` call **already timed out**, skip
    /// the re-flush. The writer is stuck (disk hiccup, sqlite hang,
    /// etc.); another 5-second wait won't catch it up, and would
    /// double the worst-case shutdown latency to 10 s. Callers
    /// observe that case via `flush()` returning `false`; the
    /// flag is internal so Drop can avoid the duplicate wait
    /// without an extra API.
    ///
    /// If everything's already drained — common: an explicit
    /// `flush()` succeeded just before drop and no new events were
    /// emitted — the inner flush loop returns immediately because
    /// `processed >= sent` holds on entry, so this Drop is cheap.
    ///
    /// **The writer thread isn't joined**, only flushed. Cloned
    /// `SqliteLayer` handles can outlive the `LogStore` (they live
    /// inside whichever subscriber holds them); the writer keeps
    /// serving those until every sender — including each Layer
    /// clone — drops. That's what we want: a `LogStore` dropping
    /// mid-program shouldn't abort tracing capture, and at process
    /// exit the OS reaps the detached thread regardless.
    fn drop(&mut self) {
        if self.counters.last_flush_timed_out.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.flush(std::time::Duration::from_secs(5));
    }
}

fn level_int(level: LogLevel) -> i64 {
    match level {
        LogLevel::Trace => LEVEL_TRACE,
        LogLevel::Debug => LEVEL_DEBUG,
        LogLevel::Info => LEVEL_INFO,
        LogLevel::Warn => LEVEL_WARN,
        LogLevel::Error => LEVEL_ERROR,
    }
}

// ── Layer ───────────────────────────────────────────────────────────

/// The `tracing_subscriber::Layer` half of [`LogStore`]. Returned by
/// [`LogStore::layer`]; compose it into a `Registry` next to your
/// `fmt::layer()`, `EnvFilter`, etc.
#[derive(Clone)]
pub struct SqliteLayer {
    tx: SyncSender<LogRecord>,
    counters: Arc<Counters>,
}

impl<S> Layer<S> for SqliteLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = SpanFields::default();
        attrs.record(&mut fields);
        span.extensions_mut().insert(fields);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut exts = span.extensions_mut();
        if let Some(fields) = exts.get_mut::<SpanFields>() {
            values.record(fields);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut event_fields = EventFields::default();
        event.record(&mut event_fields);

        // Walk the span chain root → leaf. Innermost wins for
        // attribution fields (a `device_id` recorded on a child span
        // overrides one set by a parent).
        let mut instance_id = None;
        let mut plugin_id = None;
        let mut device_id = None;
        let mut span_names = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                span_names.push(span.name().to_owned());
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    if let Some(v) = &fields.instance_id {
                        instance_id = Some(v.clone());
                    }
                    if let Some(v) = &fields.plugin_id {
                        plugin_id = Some(v.clone());
                    }
                    if let Some(v) = &fields.device_id {
                        device_id = Some(v.clone());
                    }
                }
            }
        }
        // Event-level fields with these names override the inherited
        // span values — useful for a one-off `tracing::info!(device_id
        // = "d-99", "...")` that doesn't want the surrounding span's
        // device.
        if let Some(v) = &event_fields.instance_id {
            instance_id = Some(v.clone());
        }
        if let Some(v) = &event_fields.plugin_id {
            plugin_id = Some(v.clone());
        }
        if let Some(v) = &event_fields.device_id {
            device_id = Some(v.clone());
        }

        let span_path = if span_names.is_empty() {
            None
        } else {
            Some(span_names.join("/"))
        };

        let meta = event.metadata();
        let fields_blob = if event_fields.extra.is_empty() {
            Vec::new()
        } else {
            serde_json::to_vec(&event_fields.extra).unwrap_or_default()
        };

        let record = LogRecord {
            ts_unix_ms: now_unix_ms(),
            level: level_to_int(*meta.level()),
            instance_id,
            plugin_id,
            device_id,
            target: meta.target().to_owned(),
            span_path,
            message: event_fields.message.unwrap_or_default(),
            fields_blob,
        };

        // Bump `sent` **before** `try_send`, and never decrement.
        // `sent` counts every event the Layer observed — equivalent
        // to "Layer invocations." Each invocation deposits the row
        // in exactly one of three terminal counters:
        //
        // - `try_send` Ok → writer eventually bumps `written` or
        //   `write_errors`.
        // - `try_send` Full → bump `dropped` here.
        // - `try_send` Disconnected → bump `dropped` here too. The
        //   row is lost (writer thread gone), but from flush's
        //   perspective it's "done" — count it as dropped so the
        //   invariant `written + write_errors + dropped == sent`
        //   holds eventually.
        //
        // Pre-bumping closes the original race (a concurrent flush
        // snapshot between channel insert and counter bump would
        // miss the row); never decrementing closes the *second*
        // race (a flush snapshot caught the over-counted state,
        // and a later fetch_sub on `Full` would let the target
        // outrun what the writer can ever process). With
        // sent-monotonic, every snapshot has a matching invariant:
        // `written + write_errors + dropped` is monotonically
        // non-decreasing and will catch up to any prior `sent`
        // snapshot.
        self.counters.sent.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(record) {
            Ok(()) => {}
            // `Full`: channel saturated.
            // `Disconnected`: writer thread gone (very rare — only
            // happens if LogStore drops while a Layer clone is still
            // emitting, or in pathological subscriber teardown).
            // Both lose the row from the writer's perspective, so
            // bucket both as `dropped` from flush's perspective.
            // (A separate `disconnected` counter would only help
            // diagnostics; Phase-12's status endpoint can split if
            // useful.)
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ── Field visitors ──────────────────────────────────────────────────
//
// `SpanFields` watches a span's recorded fields for the three
// attribution columns (`instance_id` / `plugin_id` / `device_id`) and
// stores them in dedicated slots. Everything *else* on a span is
// **discarded** — the store doesn't persist arbitrary span fields
// because no current query consumer reads them and the cost of
// encoding+writing them would scale with span depth. (If a future
// caller needs them, add an `extra: Vec<(String, LogValue)>` slot
// here and merge into `fields_blob` at `on_event` time.) `EventFields`
// is the parallel shape for *event*-level fields: same three
// attribution slots, plus a `message` slot for the `tracing` macro's
// format string, plus an `extra` vec for everything else (which
// **is** persisted in `fields_blob`).

// The `*_id` postfix is intentional — these mirror the SQLite
// columns of the same name. Lint relaxed for that reason.
#[allow(clippy::struct_field_names)]
#[derive(Default)]
struct SpanFields {
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
}

impl SpanFields {
    fn record_attribution(&mut self, field: &Field, value: String) {
        match field.name() {
            "instance_id" => self.instance_id = Some(value),
            "plugin_id" => self.plugin_id = Some(value),
            "device_id" => self.device_id = Some(value),
            _ => {}
        }
    }
}

impl Visit for SpanFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_attribution(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `%`-formatted strings + bare string fields land here as
        // `Debug` because the wrapper type implements `Debug`. Strip
        // surrounding quotes that `Debug` adds for `&str` so
        // `device_id = %dev_id` and `device_id = dev_id` look the
        // same to the store.
        let mut formatted = format!("{value:?}");
        if formatted.starts_with('"') && formatted.ends_with('"') && formatted.len() >= 2 {
            // Drop the leading + trailing `"` in place — saves the
            // extra allocation `formatted = formatted[…].to_owned()`
            // would do.
            formatted.pop();
            formatted.remove(0);
        }
        self.record_attribution(field, formatted);
    }
}

#[derive(Default)]
struct EventFields {
    message: Option<String>,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    /// Non-attribution, non-`message` fields, encoded as the on-disk
    /// JSON map. `Vec<(String, LogValue)>` keeps deterministic
    /// ordering (insertion-order) so the query consumer sees fields
    /// in the order the call-site wrote them.
    extra: Vec<(String, LogValue)>,
}

impl EventFields {
    fn record(&mut self, field: &Field, value: LogValue) {
        match field.name() {
            // The magic name `tracing::info!("hello, world")` stores
            // its format string under.
            "message" => {
                if let LogValue::String(s) | LogValue::Debug(s) = value {
                    self.message = Some(s);
                } else {
                    // Numeric / bool `message` field is unusual but
                    // legal. Render through Display via the Debug-
                    // string fall-through.
                    self.extra.push(("message".into(), value));
                }
            }
            "instance_id" => {
                if let LogValue::String(s) | LogValue::Debug(s) = value {
                    self.instance_id = Some(s);
                } else {
                    self.extra.push((field.name().to_owned(), value));
                }
            }
            "plugin_id" => {
                if let LogValue::String(s) | LogValue::Debug(s) = value {
                    self.plugin_id = Some(s);
                } else {
                    self.extra.push((field.name().to_owned(), value));
                }
            }
            "device_id" => {
                if let LogValue::String(s) | LogValue::Debug(s) = value {
                    self.device_id = Some(s);
                } else {
                    self.extra.push((field.name().to_owned(), value));
                }
            }
            _ => {
                self.extra.push((field.name().to_owned(), value));
            }
        }
    }
}

impl Visit for EventFields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field, LogValue::Bool(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, LogValue::Int(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, LogValue::UInt(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        // `serde_json` serializes non-finite floats (NaN, ±inf) as
        // `null`. A round-trip through `from_slice` back into
        // `LogValue::Float(f64)` would then fail with
        // `LogStoreError::Decode`, taking the whole row's
        // `fields_blob` with it. Stash non-finite values as
        // `Debug(String)` so they round-trip losslessly and don't
        // poison the row. (Same trade-off `kv.rs`/`event_log.rs`
        // make for floats; the host's tracing macros use this path
        // when an operator emits, say, `tracing::warn!(ratio = f, …)`
        // with `f = f64::NAN` from a failed calculation.)
        let v = if value.is_finite() {
            LogValue::Float(value)
        } else {
            LogValue::Debug(format!("{value}"))
        };
        self.record(field, v);
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, LogValue::String(value.to_owned()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut formatted = format!("{value:?}");
        if formatted.starts_with('"') && formatted.ends_with('"') && formatted.len() >= 2 {
            // Drop the leading + trailing `"` in place — saves the
            // extra allocation `formatted = formatted[…].to_owned()`
            // would do.
            formatted.pop();
            formatted.remove(0);
        }
        self.record(field, LogValue::Debug(formatted));
    }
}

// ── Writer thread ───────────────────────────────────────────────────

// All three args are owned for the thread's lifetime — that's the
// shape `std::thread::spawn(move || writer_loop(...))` wants. Clippy
// sees the body never explicitly `.clone()`s and recommends `&Arc<_>`,
// which would force the spawner to extend their lifetimes by hand.
// The owning-by-value version is right.
#[allow(clippy::needless_pass_by_value)]
fn writer_loop(db: Arc<Db>, rx: Receiver<LogRecord>, counters: Arc<Counters>) {
    while let Ok(record) = rx.recv() {
        let written = match db.write(|conn| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO log_event(ts_unix_ms, level, instance_id, plugin_id, device_id, target, span_path, message, fields_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.ts_unix_ms,
                    record.level,
                    record.instance_id,
                    record.plugin_id,
                    record.device_id,
                    record.target,
                    record.span_path,
                    record.message,
                    if record.fields_blob.is_empty() {
                        None
                    } else {
                        Some(record.fields_blob.as_slice())
                    },
                ],
            )?;
            Ok(())
        }) {
            Ok(()) => true,
            Err(e) => {
                // No `tracing::error!` here — would loop. Stderr is
                // fine for a host-side smoke channel; Phase 12's
                // status endpoint reads `write_errors`.
                eprintln!("oxidhome log_store: write failed: {e}");
                false
            }
        };
        if written {
            counters.written.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    // Sender side fully dropped — exit cleanly.
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry;

    fn store() -> LogStore {
        LogStore::new(Arc::new(Db::open_in_memory().expect("db")))
    }

    /// Drive a closure with a subscriber that only contains the
    /// store's layer. Uses `with_default` so the global subscriber
    /// stays untouched between tests.
    fn with_log_subscriber<F: FnOnce()>(store: &LogStore, f: F) {
        let layer: SqliteLayer = store.layer();
        let subscriber = registry().with(layer);
        with_default(subscriber, f);
    }

    #[test]
    fn info_event_lands_in_table() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", "hello world");
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.level, LogLevel::Info);
        assert_eq!(row.target, "test");
        assert_eq!(row.message, "hello world");
        assert!(row.instance_id.is_none());
    }

    /// `tracing::info!(instance_id = "alpha", ...)` lands the field
    /// in the dedicated column, not in `extra`.
    #[test]
    fn instance_id_field_lands_in_dedicated_column() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", instance_id = "alpha", "x");
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].instance_id.as_deref(), Some("alpha"));
        assert!(rows[0].fields.is_empty(), "no extras expected");
    }

    /// Phase 5c-review follow-up: `plugin.load`'s span declares
    /// `plugin_id = tracing::field::Empty` and records the manifest's
    /// id once parsed. The Layer's `on_record` handler must pick up
    /// that deferred value so events fired afterwards attribute to
    /// the plugin.
    #[test]
    fn span_record_attributes_subsequent_events() {
        let store = store();
        with_log_subscriber(&store, || {
            let span = tracing::info_span!(
                "plugin.load",
                instance_id = "alpha",
                plugin_id = tracing::field::Empty,
            );
            let _enter = span.enter();
            // Pre-record event lands without plugin_id — honest about
            // not knowing yet.
            tracing::info!(target: "test", "pre-record");
            span.record("plugin_id", "example.alpha");
            // Post-record event picks up the field via on_record.
            tracing::info!(target: "test", "post-record");
        });
        store.wait_drained_for_test();

        let rows = store
            .query(
                &LogQuery {
                    instance_id: Some("alpha".into()),
                    ..LogQuery::default()
                },
                16,
            )
            .expect("query");
        let pre = rows
            .iter()
            .find(|r| r.message == "pre-record")
            .expect("pre-record row");
        let post = rows
            .iter()
            .find(|r| r.message == "post-record")
            .expect("post-record row");
        assert!(
            pre.plugin_id.is_none(),
            "pre-record event should have no plugin_id; got {:?}",
            pre.plugin_id,
        );
        assert_eq!(post.plugin_id.as_deref(), Some("example.alpha"));
    }

    /// A span carrying `instance_id` attributes child events without
    /// each callsite repeating the field. Mirrors how Phase 4B's
    /// `plugin.load` span flows through.
    #[test]
    fn span_instance_id_attributes_child_events() {
        let store = store();
        with_log_subscriber(&store, || {
            let span = tracing::info_span!("plugin.load", instance_id = "alpha");
            let _enter = span.enter();
            tracing::info!(target: "test", "ready");
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].instance_id.as_deref(), Some("alpha"));
        assert_eq!(rows[0].span_path.as_deref(), Some("plugin.load"));
    }

    /// Event-level fields override inherited span fields — useful for
    /// a one-off `device_id` that points at a different device than
    /// the surrounding span.
    #[test]
    fn event_field_overrides_span_field() {
        let store = store();
        with_log_subscriber(&store, || {
            let span = tracing::info_span!("plugin.execute_command", device_id = "d-1");
            let _enter = span.enter();
            tracing::info!(target: "test", device_id = "d-99", "redirected");
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id.as_deref(), Some("d-99"));
    }

    /// Structured non-attribution fields land in `fields` as
    /// typed `LogValue`s.
    #[test]
    fn structured_fields_round_trip_by_type() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(
                target: "test",
                count = 42_i64,
                ratio = 0.5_f64,
                ok = true,
                "structured",
            );
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        let fields = &rows[0].fields;
        let by_name: std::collections::HashMap<&str, &LogValue> =
            fields.iter().map(|(k, v)| (k.as_str(), v)).collect();
        assert!(matches!(by_name["count"], LogValue::Int(42)));
        assert!(
            matches!(by_name["ratio"], LogValue::Float(f) if (f - 0.5).abs() < f64::EPSILON),
            "ratio should round-trip as Float(0.5)",
        );
        assert!(matches!(by_name["ok"], LogValue::Bool(true)));
    }

    /// Non-finite floats (`NaN`, `±inf`) round-trip as
    /// `LogValue::Debug(String)` rather than `LogValue::Float`,
    /// because `serde_json` serializes non-finite floats as `null`
    /// and the decode would fail. The row stays readable; the
    /// payload survives as the float's Display string.
    #[test]
    fn non_finite_floats_survive_round_trip() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(
                target: "test",
                ratio_nan = f64::NAN,
                ratio_pos_inf = f64::INFINITY,
                ratio_neg_inf = f64::NEG_INFINITY,
                "non-finite floats",
            );
        });
        store.wait_drained_for_test();

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1, "row should be present, not failed-decode");
        let fields = &rows[0].fields;
        let by_name: std::collections::HashMap<&str, &LogValue> =
            fields.iter().map(|(k, v)| (k.as_str(), v)).collect();
        // Each non-finite value lands as a Debug string whose body
        // is the float's Display form.
        for (key, expected) in &[
            ("ratio_nan", "NaN"),
            ("ratio_pos_inf", "inf"),
            ("ratio_neg_inf", "-inf"),
        ] {
            let v = by_name
                .get(*key)
                .unwrap_or_else(|| panic!("field {key} missing in {fields:?}"));
            match v {
                LogValue::Debug(s) => assert_eq!(s, expected, "field {key}"),
                other => panic!("expected Debug for non-finite {key}, got {other:?}"),
            }
        }
    }

    /// `min_level = Warn` narrows to warn+error rows.
    #[test]
    fn min_level_filter_narrows() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", "i");
            tracing::warn!(target: "test", "w");
            tracing::error!(target: "test", "e");
        });
        store.wait_drained_for_test();

        let rows = store
            .query(
                &LogQuery {
                    min_level: Some(LogLevel::Warn),
                    ..LogQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| matches!(r.level, LogLevel::Warn | LogLevel::Error))
        );
    }

    /// Per-target filter narrows to one target only.
    #[test]
    fn target_filter_narrows() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "alpha", "a");
            tracing::info!(target: "beta", "b");
        });
        store.wait_drained_for_test();

        let rows = store
            .query(
                &LogQuery {
                    target: Some("alpha".into()),
                    ..LogQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "alpha");
    }

    /// `target_prefix` narrows to every event whose target starts
    /// with the given module path — catches a whole module tree
    /// without enumerating each leaf.
    #[test]
    fn target_prefix_filter_narrows() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "oxidhome_core::runtime::state", "rt-state");
            tracing::info!(target: "oxidhome_core::runtime::instance", "rt-instance");
            tracing::info!(target: "oxidhome_sdk::plugin", "sdk-plugin");
        });
        store.wait_drained_for_test();

        let rows = store
            .query(
                &LogQuery {
                    target_prefix: Some("oxidhome_core::runtime".into()),
                    ..LogQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| r.target.starts_with("oxidhome_core::runtime"))
        );
    }

    /// `span_path_prefix` narrows to every event under a span subtree
    /// (e.g. `plugin.` catches `plugin.init`, `plugin.execute_command`,
    /// `plugin.shutdown` without naming each).
    #[test]
    fn span_path_prefix_filter_narrows() {
        let store = store();
        with_log_subscriber(&store, || {
            let init = tracing::info_span!("plugin.init", instance_id = "alpha");
            init.in_scope(|| tracing::info!(target: "t", "in-init"));
            let cmd = tracing::info_span!("plugin.execute_command", instance_id = "alpha");
            cmd.in_scope(|| tracing::info!(target: "t", "in-cmd"));
            let unrelated = tracing::info_span!("other.span");
            unrelated.in_scope(|| tracing::info!(target: "t", "in-other"));
            // Top-level (no span).
            tracing::info!(target: "t", "no-span");
        });
        store.wait_drained_for_test();

        let rows = store
            .query(
                &LogQuery {
                    span_path_prefix: Some("plugin.".into()),
                    ..LogQuery::default()
                },
                16,
            )
            .expect("query");
        // Two events live under `plugin.*` spans.
        assert_eq!(rows.len(), 2, "got {rows:?}");
        assert!(
            rows.iter().all(|r| r
                .span_path
                .as_deref()
                .is_some_and(|s| s.starts_with("plugin."))),
            "every row should have a plugin.* span_path",
        );
    }

    /// `flush(timeout)` returns `false` when the writer hasn't
    /// drained within the budget. We can't reliably create that
    /// state without racing the writer thread, so the test confirms
    /// the *opposite*: `flush(MAX)` always drains and returns `true`
    /// once events are committed.
    #[test]
    fn flush_returns_true_when_drained() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "t", "flush-target");
        });
        assert!(
            store.flush(std::time::Duration::from_secs(5)),
            "flush should drain within 5 s for a single in-memory write",
        );
        assert_eq!(store.written(), 1);
    }

    /// Regression for the earlier `written + dropped >= sent` formula:
    /// a burst that dropped many rows while a small number of
    /// enqueued rows are still pending would have let `flush`
    /// trivially return `true` because `dropped` already exceeded
    /// `sent`. The corrected `written + write_errors >= sent` waits
    /// for the actually-enqueued rows to commit regardless of how
    /// many were dropped in transit.
    #[test]
    fn flush_waits_for_enqueued_rows_after_drops() {
        let store = LogStore::new_with_capacity(Arc::new(Db::open_in_memory().expect("db")), 1);
        // Capacity 1 + 32 emits → most drop, a handful (≥1) enqueue.
        // After the burst returns we expect `sent >= 1`, `dropped` may
        // be very large, and `written` may still be 0.
        with_log_subscriber(&store, || {
            for i in 0..32 {
                tracing::info!(target: "t", i, "burst");
            }
        });
        // Don't sleep here — go straight to flush. The pre-fix
        // formula `written + dropped >= sent` (where `sent` was
        // decremented on drop) would have returned `true`
        // immediately because `dropped >> sent`. The current
        // formula treats `sent` as monotonic and sums all three
        // terminal counters, so flush has to wait for every
        // observed event to land in one bucket.
        assert!(
            store.flush(std::time::Duration::from_secs(5)),
            "flush should still drain within budget",
        );
        // Invariant after flush returns true: every event the
        // Layer observed has been processed (committed, errored,
        // or dropped).
        assert!(
            store.written() + store.write_errors() + store.dropped() >= store.sent(),
            "post-flush invariant: written + write_errors + dropped >= sent (\
             written={}, write_errors={}, sent={}, dropped={})",
            store.written(),
            store.write_errors(),
            store.sent(),
            store.dropped(),
        );
    }

    /// `trim_older_than(cutoff)` removes rows strictly older than the
    /// cutoff. The bytes_used-style refund here is the row count.
    #[test]
    fn trim_older_than_drops_old_rows() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", "first");
        });
        store.wait_drained_for_test();
        // Use the first row's stored `ts_unix_ms` + 1 as the cutoff
        // instead of `now_unix_ms() + 1` plus a sleep. The
        // `SystemTime::now()` call inside the layer might land on
        // the same millisecond as our outside call; the safe move
        // is to read what actually landed and bump by 1.
        let first_ts = store
            .query(&LogQuery::default(), 1)
            .expect("query first")
            .first()
            .expect("first row")
            .ts_unix_ms;
        let cutoff = first_ts + 1;
        // Spin until `SystemTime::now()` is strictly past `cutoff`
        // before emitting the second event. Coarse-clock platforms
        // (Windows historically, some CI VMs) would otherwise stamp
        // the second event with the same millisecond as the first
        // and trim it too. Bounded so the loop can't run away on a
        // broken clock.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while now_unix_ms() <= cutoff {
            assert!(
                std::time::Instant::now() < deadline,
                "clock never advanced past cutoff = {cutoff}",
            );
            std::thread::yield_now();
        }
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", "second");
        });
        store.wait_drained_for_test();

        let dropped = store.trim_older_than(cutoff).expect("trim");
        assert_eq!(dropped, 1, "first row should be trimmed, got {dropped}");

        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "second");
    }

    /// A bounded channel + a high-rate burst trips the drop counter.
    /// Capacity 0 (`sync_channel(0)` = rendezvous) deterministically
    /// drops everything `try_send` can't hand off synchronously to
    /// the writer thread.
    ///
    /// Previously this test used capacity 1 + a 2 ms sleep, betting
    /// the writer was slow enough to leave most emits dropped. On a
    /// fast or quietly-scheduled CI worker the writer can drain
    /// between sends and leave `dropped == 0`, making the test
    /// flaky. With a rendezvous channel + no sleep, every emit that
    /// arrives while the writer is busy committing a `SQLite` hit takes the
    /// drop path — and out of 64 back-to-back tries, at least one
    /// is going to find the writer busy.
    #[test]
    fn channel_overflow_increments_dropped_counter() {
        let store = LogStore::new_with_capacity(Arc::new(Db::open_in_memory().expect("db")), 0);
        with_log_subscriber(&store, || {
            for i in 0..64 {
                tracing::info!(target: "test", i, "burst");
            }
        });
        let sent = store.sent();
        let dropped = store.dropped();
        let written = store.written();
        // `sent` is bumped on every Layer invocation and never
        // decremented, so we know the Layer saw all 64 emits — a
        // tighter check than the old `sent + dropped >= 1`. Would
        // also catch a filter / EnvFilter regression that swallowed
        // events before the Layer ran.
        assert_eq!(
            sent, 64,
            "Layer should have observed every emit: sent={sent} dropped={dropped} written={written}",
        );
        // Capacity-0 + 64 rapid emits → every try_send that
        // doesn't catch the writer mid-recv drops. The writer
        // committing a single SQLite insert takes long enough that
        // at least a few of 64 emits will arrive while it's busy.
        assert!(
            dropped > 0,
            "drop counter should fire under capacity=0 burst, got sent={sent} dropped={dropped} written={written}",
        );
        // Drain so the writer thread exits cleanly on test teardown.
        store.wait_drained_for_test();
    }

    /// Restart-survival: write some events, drop the store, reopen
    /// against the same file-backed Db, query.
    #[test]
    fn rows_survive_db_reopen() {
        let dir = tempdir_for_test();
        let path = dir.path.clone();
        {
            let db = Arc::new(Db::open_file(&path).expect("open"));
            let store = LogStore::new(db);
            with_log_subscriber(&store, || {
                tracing::info!(target: "test", "persistent");
            });
            store.wait_drained_for_test();
        }
        let db = Arc::new(Db::open_file(&path).expect("reopen"));
        let store = LogStore::new(db);
        let rows = store.query(&LogQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "persistent");
    }

    // Tiny tempdir helper — same shape as the one used by db/kv/event_log.
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn tempdir_for_test() -> TempDir {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "oxidhome-logstore-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&path).expect("mk tempdir");
        TempDir { path }
    }
}
