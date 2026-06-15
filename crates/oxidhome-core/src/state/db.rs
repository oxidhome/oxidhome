//! Host-owned `SQLite` handle.
//!
//! One database file (or one in-memory database, for tests) backs
//! every persistent host store: Phase-5a's KV here, and the
//! blob-index / log/trace / event-history stores that Phase 5b/5c/5d
//! add. They share the same file so a single `BEGIN IMMEDIATE` covers
//! cross-store atomicity when we need it (e.g. blob-index + blob-bytes
//! commit must be transactional with the KV usage counter, per
//! `03_core.md` §5).
//!
//! [`Db`] holds a [`rusqlite::Connection`] behind a mutex and exposes
//! synchronous `read` / `write` helpers. Callers from the async host
//! side wrap them in [`tokio::task::spawn_blocking`] — the `SQLite` call
//! itself stays sync, which keeps the rusqlite API straightforward and
//! avoids the cost of an async wrapper crate for a workload measured
//! in single-thousand inserts per day.
//!
//! Two construction paths:
//!
//! - [`Db::open_in_memory`] — `":memory:"`. Used by every existing
//!   integration test and the no-arg [`Engine::new`] entry point so
//!   the "engine without a state dir" shape still works.
//! - [`Db::open_file`] — `<state_dir>/oxidhome.db` with WAL mode +
//!   `synchronous = NORMAL`. The combination chosen by Phase 5's
//!   storage-backend decision (Appendix A in `00_OVERVIEW.md`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;
use rusqlite::Connection;

/// Schema migrations applied at open time. Append-only; `user_version`
/// in the database file picks up where the last run left off.
///
/// Each entry is the *body* of one migration — the loop in
/// [`Db::apply_migrations`] wraps it in a `BEGIN; ... ; PRAGMA
/// user_version = N; COMMIT;`. Keep migrations idempotent on top of
/// `IF NOT EXISTS` only when re-running a migration would be safe;
/// otherwise rely on `user_version` to skip already-applied ones.
const MIGRATIONS: &[&str] = &[
    // 1 — Phase 5a: KV store + usage tracking.
    //
    // `kv` holds the actual values, scoped per instance. `kv_usage`
    // tracks bytes-used and bytes-quota so a write can be refused
    // transactionally instead of after-the-fact. Triggers keep
    // `kv_usage.bytes_used` in sync with the rows in `kv`:
    //
    // - INSERT: charges `length(key) + length(value)` against the
    //   inserting instance's `bytes_used`.
    // - DELETE: refunds the same amount.
    // - UPDATE on `value`: charges the delta
    //   (`length(new.value) - length(old.value)`).
    //
    // Quota enforcement happens in the writing transaction in
    // `kv::set` — see that file for the BEGIN IMMEDIATE / check / write
    // shape. The triggers only update accounting; they don't refuse.
    "
    CREATE TABLE kv (
        instance_id  TEXT NOT NULL,
        key          TEXT NOT NULL,
        value        BLOB NOT NULL,
        updated_ms   INTEGER NOT NULL,
        PRIMARY KEY (instance_id, key)
    ) WITHOUT ROWID;

    CREATE TABLE kv_usage (
        instance_id  TEXT PRIMARY KEY,
        bytes_used   INTEGER NOT NULL DEFAULT 0,
        bytes_quota  INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TRIGGER kv_usage_insert AFTER INSERT ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(NEW.key) + length(NEW.value)
         WHERE instance_id = NEW.instance_id;
    END;

    CREATE TRIGGER kv_usage_delete AFTER DELETE ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used - length(OLD.key) - length(OLD.value)
         WHERE instance_id = OLD.instance_id;
    END;

    CREATE TRIGGER kv_usage_update AFTER UPDATE OF value ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(NEW.value) - length(OLD.value)
         WHERE instance_id = NEW.instance_id;
    END;
    ",
    // 2 — Phase 5a follow-up: count key length in **bytes**, not
    // characters. SQLite's `length()` on TEXT returns the character
    // count; on BLOB it returns the byte count. Migration 1 used the
    // bare `length(key)` so a non-ASCII key was undercounted against
    // the byte quota the Rust side projects in `state::kv::set`.
    // Drop the triggers and recreate with `length(CAST(... AS BLOB))`,
    // then re-baseline `kv_usage.bytes_used` for any rows that already
    // drifted under migration 1's accounting.
    //
    // `value` is already declared `BLOB NOT NULL` so `length(value)`
    // is byte-correct without a cast.
    "
    DROP TRIGGER kv_usage_insert;
    DROP TRIGGER kv_usage_delete;
    DROP TRIGGER kv_usage_update;

    CREATE TRIGGER kv_usage_insert AFTER INSERT ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(CAST(NEW.key AS BLOB)) + length(NEW.value)
         WHERE instance_id = NEW.instance_id;
    END;

    CREATE TRIGGER kv_usage_delete AFTER DELETE ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used - length(CAST(OLD.key AS BLOB)) - length(OLD.value)
         WHERE instance_id = OLD.instance_id;
    END;

    CREATE TRIGGER kv_usage_update AFTER UPDATE OF value ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(NEW.value) - length(OLD.value)
         WHERE instance_id = NEW.instance_id;
    END;

    -- Re-baseline existing rows so already-drifted instances start
    -- from the correct byte total. Sum over each instance's `kv` rows;
    -- COALESCE handles instances with a `kv_usage` row but no `kv`
    -- rows yet (registered + never wrote).
    UPDATE kv_usage SET bytes_used = COALESCE((
        SELECT SUM(length(CAST(key AS BLOB)) + length(value))
          FROM kv
         WHERE kv.instance_id = kv_usage.instance_id
    ), 0);
    ",
    // 3 — Phase 5d: event history store.
    //
    // Durable mirror of the live `EventBus` (`state/events.rs`). The
    // host writes every plugin-published event here, the CLI/API
    // reads back history. Trust separation on timestamps: `received_ms`
    // is the host's wall-clock at receive time (used for ordering,
    // retention, query bounds); `payload_ms` is the plugin's
    // self-reported `events::event.timestamp` (informational only, so
    // a buggy plugin can't backdate history).
    //
    // `actor_kind` / `actor_id` columns from the per-crate plan are
    // **not** here — Phase 4B only constructs `Actor::plugin(instance_id)`
    // so they'd always echo `(plugin, instance_id)` and add no info.
    // Phase 12 (external API) adds them as a follow-up migration when
    // non-plugin actors become real callers.
    //
    // `payload_blob` is the WIT event-payload variant encoded as
    // tagged JSON via `serde_json`. Postcard (smaller wire) is an
    // optimization for later; the store reads opaque BLOBs so a
    // future migration can re-encode in place.
    "
    CREATE TABLE event_log (
        id            INTEGER PRIMARY KEY,
        received_ms   INTEGER NOT NULL,
        payload_ms    INTEGER NOT NULL,
        device_id     TEXT,
        instance_id   TEXT NOT NULL,
        plugin_id     TEXT NOT NULL,
        topic         TEXT NOT NULL,
        payload_blob  BLOB NOT NULL
    );

    CREATE INDEX evt_received      ON event_log(received_ms);
    CREATE INDEX evt_device        ON event_log(device_id, received_ms) WHERE device_id IS NOT NULL;
    CREATE INDEX evt_topic         ON event_log(topic, received_ms);
    CREATE INDEX evt_instance      ON event_log(instance_id, received_ms);
    CREATE INDEX evt_plugin        ON event_log(plugin_id, received_ms);
    ",
    // 4 — Phase 5c: log/trace store.
    //
    // Host-owned diagnostic stream. Every `tracing::{trace,debug,info,
    // warn,error}!` macro the host emits — including Phase-4 capability
    // denials, Phase-5d publish_event writes, plugin-side log lines
    // forwarded through the `logging` import — captures into this
    // table via a `tracing_subscriber::Layer` (`state::log_store`).
    // CLI / API query is Phase 12.
    //
    // Schema mirrors `03_core.md` §5c with one shape decision: the
    // structured-field map is encoded as tagged JSON (same format as
    // `event_log.payload_blob`) rather than postcard. JSON keeps the
    // store self-debuggable via `sqlite3 oxidhome.db` and matches the
    // pattern the rest of Phase 5 settled on; postcard is a possible
    // smaller-on-disk follow-up.
    //
    // Indexes match the CLI's expected query shapes: time-range scans
    // (`log_ts`), level-filter (`log_level_ts`), per-instance /
    // per-plugin / per-device drill-down, and per-target filtering.
    // Partial indexes (`WHERE … IS NOT NULL`) skip rows that don't
    // carry that column — host-only events without an `instance_id`
    // shouldn't bloat the per-instance index.
    "
    CREATE TABLE log_event (
        id            INTEGER PRIMARY KEY,
        ts_unix_ms    INTEGER NOT NULL,
        level         INTEGER NOT NULL,
        instance_id   TEXT,
        plugin_id     TEXT,
        device_id     TEXT,
        target        TEXT NOT NULL,
        span_path     TEXT,
        message       TEXT NOT NULL,
        fields_blob   BLOB
    );

    CREATE INDEX log_ts          ON log_event(ts_unix_ms);
    CREATE INDEX log_level_ts    ON log_event(level, ts_unix_ms);
    CREATE INDEX log_instance_ts ON log_event(instance_id, ts_unix_ms) WHERE instance_id IS NOT NULL;
    CREATE INDEX log_plugin_ts   ON log_event(plugin_id, ts_unix_ms)   WHERE plugin_id   IS NOT NULL;
    CREATE INDEX log_device_ts   ON log_event(device_id, ts_unix_ms)   WHERE device_id   IS NOT NULL;
    CREATE INDEX log_target_ts   ON log_event(target, ts_unix_ms);
    ",
    // 5 — Phase 5c follow-up: add the `log_span_ts` index that the
    // per-crate plan listed but migration 4 forgot. Note this index
    // helps `span_path = ?` (and `span_path` time-range scans on
    // events that carry one); it does **not** seek the
    // `LogQuery::span_path_prefix` predicate, which uses
    // `substr(span_path, 1, length(?)) = ?` — SQLite can't seek a
    // B-tree with `substr(...)`. The partial-index `WHERE span_path
    // IS NOT NULL` still narrows the scan because the planner can
    // restrict to non-null span_path rows. A codepoint-range
    // rewrite (`span_path >= ? AND span_path < ?`) would let
    // prefix queries seek the index; Phase 12 picks that up when
    // there's a workload that wants it.
    "
    CREATE INDEX log_span_ts ON log_event(span_path, ts_unix_ms) WHERE span_path IS NOT NULL;
    ",
    // 6 — Phase 5b: blob store index + usage tracking.
    //
    // Blob *bytes* live on the filesystem (`<state_dir>/blobs/<instance_id>/<id>`);
    // these tables are the index + quota accounting. `blob` maps the
    // plugin-chosen `name` to the host-minted id + metadata; `blob_usage`
    // tracks `bytes_used` per instance for the manifest-declared
    // `blob_quota_mb` cap. Triggers maintain `bytes_used` from
    // `size_bytes` deltas so the quota check on write is a single
    // transactional `SELECT bytes_used + new_size > bytes_quota` rather
    // than a `SUM` over the table. Quota enforcement happens in the
    // writing transaction in `state::blobs::write` — the triggers only
    // update accounting; they don't refuse.
    "
    CREATE TABLE blob (
        instance_id  TEXT NOT NULL,
        name         TEXT NOT NULL,
        id           TEXT NOT NULL,
        size_bytes   INTEGER NOT NULL,
        created_ms   INTEGER NOT NULL,
        mime         TEXT,
        PRIMARY KEY (instance_id, name)
    ) WITHOUT ROWID;

    CREATE INDEX blob_by_id ON blob(id);

    CREATE TABLE blob_usage (
        instance_id  TEXT PRIMARY KEY,
        bytes_used   INTEGER NOT NULL DEFAULT 0,
        bytes_quota  INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TRIGGER blob_usage_insert AFTER INSERT ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used + NEW.size_bytes
         WHERE instance_id = NEW.instance_id;
    END;

    CREATE TRIGGER blob_usage_delete AFTER DELETE ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used - OLD.size_bytes
         WHERE instance_id = OLD.instance_id;
    END;

    -- `blob_usage_update` fires on `UPDATE OF size_bytes` only — today
    -- `state::blobs::write` does DELETE+INSERT for replacements, so
    -- this trigger never runs in the shipped write path. Kept for any
    -- future path that mutates `size_bytes` in place (e.g. a streaming
    -- resource-handle resize) so the accounting stays consistent
    -- without a Phase-N code change.
    CREATE TRIGGER blob_usage_update AFTER UPDATE OF size_bytes ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used + NEW.size_bytes - OLD.size_bytes
         WHERE instance_id = NEW.instance_id;
    END;
    ",
    // 7 — Phase 5b follow-up: tighten blob id uniqueness.
    //
    // Migration 6's `blob_by_id` index was non-unique. `mint_id` is
    // per-`BlobStore` (per-process) — two processes opening the same
    // DB and minting an id in the same millisecond + counter slot
    // would silently collide, producing two `blob` rows with the
    // same `id` and overwriting each other's FS file. Replacing the
    // index with a UNIQUE one on `(instance_id, id)` makes a
    // collision fail the writing transaction loudly instead.
    //
    // Cross-instance collisions are fine (the id namespace is
    // per-instance — `read(id)` already filters by `instance_id`),
    // so the constraint is `(instance_id, id)` rather than `id`.
    //
    // Defensive: collapse any duplicate `(instance_id, id)` rows
    // before the UNIQUE index goes on. Two host processes that briefly
    // shared a DB between #19 (5b ship) and #20 (this index) could
    // have written colliding ids; without the dedupe, the index
    // creation would fail and brick the upgrade. `blob` is `WITHOUT
    // ROWID` (PK is `(instance_id, name)`) so we partition by
    // `(instance_id, id)`, keep the most-recently-created row, and
    // tiebreak by `name` for determinism. The dropped row's FS bytes
    // become an orphan that the Phase-12 sweep will reclaim.
    "
    DELETE FROM blob WHERE (instance_id, name) IN (
      SELECT instance_id, name FROM (
        SELECT instance_id, name,
               ROW_NUMBER() OVER (
                 PARTITION BY instance_id, id
                 ORDER BY created_ms DESC, name DESC
               ) AS rn
        FROM blob
      ) WHERE rn > 1
    );
    DROP INDEX blob_by_id;
    CREATE UNIQUE INDEX blob_by_id ON blob(instance_id, id);
    ",
    // Migration 8 — Phase 12 external API token store.
    //
    // High-entropy random tokens (256 bits from a CSPRNG) hashed at
    // rest with plain SHA-256. Argon2/bcrypt would be overengineering
    // — those KDFs are tuned to slow down brute-force on
    // low-entropy passwords; against a uniformly random 256-bit
    // secret, brute force is infeasible regardless of hash speed.
    // SHA-256 is constant-time on the relevant inputs and keeps the
    // verify path cheap.
    //
    // `scope_json` is the scope policy blob the API consults before
    // dispatch (shape lives in `state::auth_token`; the API enforces
    // it). `last_used_ms` is bumped on every successful verify so
    // operators can tell a token is in use. `revoked_ms` is the
    // tombstone — non-null means the token is dead; rows aren't
    // deleted so audit trails stay intact.
    "
    CREATE TABLE auth_token (
      id            TEXT PRIMARY KEY,
      label         TEXT NOT NULL,
      hash          BLOB NOT NULL,
      scope_json    BLOB NOT NULL,
      created_ms    INTEGER NOT NULL,
      last_used_ms  INTEGER,
      revoked_ms    INTEGER
    ) STRICT;
    CREATE UNIQUE INDEX auth_token_hash ON auth_token(hash);
    ",
];

/// Wrapper around the host's `rusqlite::Connection`.
///
/// The connection is mutex-guarded — `SQLite` in WAL mode supports many
/// concurrent readers and one writer, but `rusqlite::Connection` itself
/// is `!Sync`, so a single host-side connection routes every operation
/// through one mutex. For Phase-5 workloads (per-instance KV, low
/// thousands of log events / day) that's plenty; a real `r2d2`-style
/// pool can drop in when contention shows up in profiling.
pub struct Db {
    /// `None` for `:memory:` databases (the "file path" we report in
    /// error messages); `Some(path)` for file-backed instances.
    path: Option<PathBuf>,
    conn: Mutex<Connection>,
}

impl Db {
    /// Open an in-memory database. Each call returns its own database
    /// — no shared state. Used by [`crate::Engine::new`] for the
    /// no-state-dir default and by tests that don't care about
    /// persistence across loads.
    ///
    /// # Errors
    ///
    /// Forwards any rusqlite open / migration error verbatim.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory `SQLite` database")?;
        Self::initialize(None, conn)
    }

    /// Open the persistent database at `<state_dir>/oxidhome.db`.
    /// Creates `state_dir` if it doesn't already exist; enables WAL
    /// mode and `synchronous = NORMAL` (the durability sweet spot per
    /// Phase 5's appendix-A choice).
    ///
    /// # Errors
    ///
    /// Returns the first failure across directory creation, file
    /// open, pragma application, or migration.
    pub fn open_file(state_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        let path = state_dir.join("oxidhome.db");
        let conn = Connection::open(&path)
            .with_context(|| format!("opening database at {}", path.display()))?;
        // WAL: many concurrent readers + one writer, plus crash safety
        // without the cost of full `synchronous = FULL`. `query_row`
        // because PRAGMA journal_mode returns the new mode.
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", (), |row| row.get(0))
            .context("setting WAL mode")?;
        anyhow::ensure!(
            mode.eq_ignore_ascii_case("wal"),
            "expected WAL journal mode, `SQLite` reported `{mode}`",
        );
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("setting synchronous = NORMAL")?;
        // `foreign_keys = ON` is off by default per `SQLite` docs — turn
        // it on so future cross-table constraints (`blob_usage`,
        // future Phase-5b additions) are enforced.
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign_keys")?;
        Self::initialize(Some(path), conn)
    }

    fn initialize(path: Option<PathBuf>, conn: Connection) -> anyhow::Result<Self> {
        let db = Self {
            path,
            conn: Mutex::new(conn),
        };
        db.apply_migrations()?;
        Ok(db)
    }

    fn apply_migrations(&self) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let current: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("reading user_version")?;
        let mut next = usize::try_from(current).context("user_version is negative")?;
        while next < MIGRATIONS.len() {
            let body = MIGRATIONS[next];
            let new_version = next + 1;
            let tx = conn
                .transaction()
                .context("starting migration transaction")?;
            tx.execute_batch(body)
                .with_context(|| format!("running migration {new_version}"))?;
            // `PRAGMA user_version = ?` doesn't bind via parameters in
            // rusqlite (it's a PRAGMA, not a SQL statement) — splice
            // the validated integer in.
            tx.execute_batch(&format!("PRAGMA user_version = {new_version}"))
                .with_context(|| format!("bumping user_version to {new_version}"))?;
            tx.commit()
                .with_context(|| format!("committing migration {new_version}"))?;
            next = new_version;
        }
        Ok(())
    }

    /// Run a closure with a `&Connection`. Cheap read-only operations
    /// (queries that don't write) go through here; the closure borrows
    /// the connection, runs synchronously, and the mutex releases as
    /// soon as it returns. Caller is responsible for hopping out to
    /// `spawn_blocking` if it's calling from an async context.
    ///
    /// Error-generic so a caller's domain error (e.g.
    /// `state::kv::KvError`) can be returned directly via `?` from
    /// inside the closure — anything with a `From<rusqlite::Error>`
    /// impl works.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    ///
    /// # Panics
    ///
    /// Panics only if another thread holding the connection mutex
    /// panicked while it was locked. Recoverable poisoning isn't a
    /// useful state for a database handle, so the panic is the
    /// intentional shape.
    pub fn read<R, E>(&self, f: impl FnOnce(&Connection) -> Result<R, E>) -> Result<R, E>
    where
        R: Send,
    {
        let conn = self.conn.lock().expect("db mutex poisoned");
        f(&conn)
    }

    /// Same shape as [`Self::read`], but takes a `&mut Connection` so
    /// the closure can start a transaction. `BEGIN IMMEDIATE` /
    /// `COMMIT` lives inside `f` — this method just unlocks the mutex
    /// and hands the connection over.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    ///
    /// # Panics
    ///
    /// Same as [`Self::read`] — only on poisoning of the connection
    /// mutex.
    pub fn write<R, E>(&self, f: impl FnOnce(&mut Connection) -> Result<R, E>) -> Result<R, E>
    where
        R: Send,
    {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        f(&mut conn)
    }

    /// Path the database is backed by, or `None` for `:memory:`. Used
    /// in error messages so the operator can see *which* database the
    /// failure came from when several plugin hosts run side by side.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.path)
            .field("conn", &"<rusqlite::Connection>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_applies_migrations() {
        let db = Db::open_in_memory().expect("open");
        db.read(|c| -> rusqlite::Result<()> {
            // `kv` and `kv_usage` should exist with the expected
            // columns. The integer-truthiness check here just confirms
            // sqlite_master has matching rows.
            let kv: i64 = c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='kv'",
                (),
                |row| row.get(0),
            )?;
            let usage: i64 = c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='kv_usage'",
                (),
                |row| row.get(0),
            )?;
            assert_eq!(kv, 1);
            assert_eq!(usage, 1);
            Ok(())
        })
        .expect("read");
    }

    #[test]
    fn user_version_advances_to_migrations_len() {
        let db = Db::open_in_memory().expect("open");
        let version: i64 = db
            .read(|c| c.pragma_query_value(None, "user_version", |row| row.get(0)))
            .expect("user_version");
        let expected = i64::try_from(MIGRATIONS.len()).expect("migrations.len fits in i64");
        assert_eq!(version, expected);
    }

    #[test]
    fn reopening_file_db_is_idempotent() {
        let dir = tempdir_for_test();
        let _db1 = Db::open_file(dir.path()).expect("open 1");
        // Second open must not re-run migrations (it'd error on
        // CREATE TABLE without IF NOT EXISTS) — proves user_version
        // gating works.
        let _db2 = Db::open_file(dir.path()).expect("open 2");
    }

    /// Migration 2 has to fix up `kv_usage.bytes_used` for any
    /// instances that already accumulated character-counted totals
    /// under migration 1. Simulate that by:
    ///
    /// 1. Open a fresh file DB (runs both migrations on empty tables
    ///    — nothing to re-baseline).
    /// 2. Hand-craft a drifted row: insert a non-ASCII key and
    ///    manually overwrite `bytes_used` with the character count
    ///    migration 1's triggers would have produced.
    /// 3. Run the migration-2 body again as a one-shot UPDATE and
    ///    confirm `bytes_used` jumps to the byte total.
    ///
    /// Step 3 is the same SQL the actual migration runs; this gives
    /// us a deterministic check without needing to roll back
    /// `user_version` and replay the upgrade.
    #[test]
    fn migration_2_rebaseline_corrects_drifted_bytes_used() {
        let dir = tempdir_for_test();
        let db = Db::open_file(dir.path()).expect("open");
        db.write(|conn| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO kv_usage(instance_id, bytes_used, bytes_quota) VALUES (?1, 0, ?2)",
                rusqlite::params!["alpha", 4096_i64],
            )?;
            // The triggers (now migration-2-shape) account this
            // correctly on insert, so explicitly set `bytes_used` to
            // the character total a migration-1 trigger would have
            // produced: "αβγ" = 3 chars, value JSON = ~10 bytes.
            conn.execute(
                "INSERT INTO kv(instance_id, key, value, updated_ms) VALUES (?1, ?2, ?3, 0)",
                rusqlite::params!["alpha", "αβγ", &b"{\"t\":\"Int\",\"v\":0}"[..]],
            )?;
            // Force the drift: pretend the row was inserted under
            // migration 1's character-counting triggers. 3 (chars) +
            // 17 (payload bytes) = 20, where the byte-correct total
            // is 6 + 17 = 23.
            conn.execute(
                "UPDATE kv_usage SET bytes_used = 20 WHERE instance_id = 'alpha'",
                (),
            )?;
            Ok(())
        })
        .expect("seed drift");

        // Re-run migration 2's rebaseline body. Same SQL as in
        // `MIGRATIONS[1]`.
        db.write(|conn| -> rusqlite::Result<()> {
            conn.execute_batch(
                "UPDATE kv_usage SET bytes_used = COALESCE((
                    SELECT SUM(length(CAST(key AS BLOB)) + length(value))
                      FROM kv
                     WHERE kv.instance_id = kv_usage.instance_id
                ), 0);",
            )?;
            Ok(())
        })
        .expect("rebaseline");

        let used: i64 = db
            .read(|conn| {
                conn.query_row(
                    "SELECT bytes_used FROM kv_usage WHERE instance_id = 'alpha'",
                    (),
                    |row| row.get(0),
                )
            })
            .expect("read");
        assert_eq!(
            used, 23,
            "rebaseline should produce 6 byte key + 17 byte value = 23",
        );
    }

    /// Tiny tempdir helper — same shape as the one in the
    /// manifest-loader integration tests, kept local so this lib
    /// test doesn't pick up an external dep.
    fn tempdir_for_test() -> TempDir {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "oxidhome-db-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&path).expect("mk tempdir");
        TempDir { path }
    }
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
