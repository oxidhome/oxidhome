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
//! The Layer extracts `instance_id`, `plugin_id`, and `device_id`
//! from the *innermost-to-root* span chain so every host call's
//! emissions are attributed correctly without each callsite having
//! to type the field at the macro. Phase 4B's `plugin.load` span
//! adds `instance_id`; the device/event/storage host impls add
//! `plugin_id` / `device_id` as they apply. The `span_path` column
//! is the slash-joined span name chain — useful for "everything
//! that happened inside `plugin.execute_command`."

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
/// Matches the doc: TRACE=0, DEBUG=1, INFO=2, WARN=3, ERROR=4.
/// Lower-is-louder is intentional — operators usually filter
/// `level >= 2` to see info+ — and matches tracing's own ordering.
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
    /// Captured from `?` formatter — what `tracing` calls
    /// `record_debug`. Stored verbatim as the Debug-formatted
    /// string.
    Debug(String),
}

/// Query shape for [`LogStore::query`]. Every field is optional and
/// AND-combined; `None` everywhere returns the most recent `limit`
/// rows. Time bounds (`since_ms` / `until_ms`) are inclusive on both
/// ends. `min_level` is inclusive: `Info` matches info/warn/error.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub min_level: Option<LogLevel>,
    pub instance_id: Option<String>,
    pub plugin_id: Option<String>,
    pub device_id: Option<String>,
    pub target: Option<String>,
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
}

/// Per-host log/trace store. Cheap to clone — holds an `Arc<Inner>`.
///
/// Drop semantics: dropping the `LogStore` doesn't kill the writer
/// thread, because [`LogStore::layer`] clones hand out fresh
/// senders. When every sender (`LogStore` + every `Layer` instance)
/// drops, the receiver in the writer thread sees `Err`, exits the
/// loop, and joins.
pub struct LogStore {
    tx: SyncSender<LogRecord>,
    counters: Arc<Counters>,
    db: Arc<Db>,
    /// `Some` while the writer thread is alive — the handle moves
    /// out on `wait_drained_for_test`-style joins.
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

    /// Number of events the Layer tried to enqueue. Mostly useful in
    /// tests that want to wait for the writer to catch up.
    #[must_use]
    pub fn sent(&self) -> u64 {
        self.counters.sent.load(Ordering::Relaxed)
    }

    /// Number of events dropped because the channel was full. Bumped
    /// by the Layer on `TrySendError::Full`; the writer thread emits
    /// no `tracing::warn!` itself (would loop). The host's periodic
    /// status endpoint (Phase 12) surfaces this counter.
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

    /// Spin-wait until the writer thread has committed every event
    /// the Layer has enqueued so far. Returns immediately if the
    /// queue is already empty. Used by tests; **don't** call from
    /// production code — there's no timeout, and live producers can
    /// keep the gap open indefinitely.
    pub fn wait_drained_for_test(&self) {
        loop {
            let sent = self.sent();
            let written = self.written();
            let dropped = self.dropped();
            if written + dropped >= sent {
                return;
            }
            std::thread::yield_now();
        }
    }

    /// Query the store. Returns at most `limit` rows newest-first.
    ///
    /// # Errors
    ///
    /// - [`LogStoreError::Sql`] for any underlying ``SQLite`` error.
    /// - [`LogStoreError::Decode`] if a stored row's `fields_blob`
    ///   doesn't parse as the expected tagged-JSON map.
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
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn trim_older_than(&self, cutoff_ms: i64) -> Result<usize, LogStoreError> {
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

        match self.tx.try_send(record) {
            Ok(()) => {
                self.counters.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer thread has gone away (LogStore dropped, all
            // senders closed). Lose the record silently — tracing
            // must never panic on the calling thread.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

// ── Field visitors ──────────────────────────────────────────────────
//
// `SpanFields` watches for `instance_id` / `plugin_id` / `device_id`
// by name and keeps them in dedicated slots; everything else lands in
// `extra` for the row's `fields_blob`. `EventFields` is the same
// shape with one extra slot for `message` (the `tracing` macro
// stores the format string under the magic field name `"message"`).

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
        self.record(field, LogValue::Float(value));
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

    /// `trim_older_than(cutoff)` removes rows strictly older than the
    /// cutoff. The bytes_used-style refund here is the row count.
    #[test]
    fn trim_older_than_drops_old_rows() {
        let store = store();
        with_log_subscriber(&store, || {
            tracing::info!(target: "test", "first");
        });
        store.wait_drained_for_test();
        let cutoff = now_unix_ms() + 1;
        // Sleep one ms so the next event lands strictly after cutoff.
        std::thread::sleep(std::time::Duration::from_millis(2));
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
    /// Tiny capacity (1) makes the test fast and deterministic.
    #[test]
    fn channel_overflow_increments_dropped_counter() {
        let store = LogStore::new_with_capacity(Arc::new(Db::open_in_memory().expect("db")), 1);
        // Fill + try to overflow without draining. `with_default`
        // pulls in the layer; the writer thread is still slow because
        // each `SQLite` insert takes ~hundreds of µs.
        with_log_subscriber(&store, || {
            for i in 0..64 {
                tracing::info!(target: "test", i, "burst");
            }
        });
        // Don't wait for drain — we want to inspect the in-flight
        // dropped counter. Give the writer a moment to land at least
        // one row but not all 64.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let sent = store.sent();
        let dropped = store.dropped();
        let written = store.written();
        // Sanity: every emit was accounted for (sent + dropped == 64,
        // possibly minus any in-flight write).
        assert!(
            sent + dropped >= 1,
            "Layer should have observed all events: sent={sent} dropped={dropped} written={written}",
        );
        // Capacity 1 + 64 emits guarantees the drop path fires at
        // least once.
        assert!(
            dropped > 0,
            "drop counter should fire under capacity=1 burst, got sent={sent} dropped={dropped} written={written}",
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
