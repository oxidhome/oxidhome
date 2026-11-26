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
//! [`Db`] owns one writer connection behind a mutex, a small pool of
//! read-only connections, and a passive-checkpoint thread (M6; see
//! the type docs for the model and the busy / checkpoint policy). It
//! exposes synchronous `read` / `write` helpers. Callers from the
//! async host side wrap them in [`tokio::task::spawn_blocking`] — the
//! `SQLite` call itself stays sync, which keeps the rusqlite API
//! straightforward and avoids the cost of an async wrapper crate.
//!
//! Two construction paths:
//!
//! - [`Db::open_in_memory`] — `":memory:"`. Used by every existing
//!   integration test and the no-arg [`Engine::new`](crate::Engine::new) entry point so
//!   the "engine without a state dir" shape still works. A private
//!   in-memory database has exactly one connection, so reads share
//!   the writer.
//! - [`Db::open_file`] — `<state_dir>/oxidhome.db` with WAL mode +
//!   `synchronous = NORMAL`. The combination chosen by Phase 5's
//!   storage-backend decision (Appendix A in `00_OVERVIEW.md`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::{Connection, OpenFlags};

/// Schema migrations applied at open time. Append-only; `user_version`
/// in the database file picks up where the last run left off.
///
/// Each entry is the *body* of one migration — the loop in
/// [`Db::apply_migrations`] wraps it in a transaction and sets
/// `PRAGMA user_version` to its 1-based position. Migration 1 is the
/// whole initial schema; a schema change appends migration 2, 3, …
/// and never edits an applied entry.
const MIGRATIONS: &[&str] = &[INITIAL_SCHEMA];

/// Migration 1: every table, index and trigger of the host database.
///
/// Per-instance plugin state (`kv`, `blob` and their usage rows) is
/// keyed on `(installation_uuid, instance_id)`, so a reinstall starts
/// from an empty keyspace and uninstall purges by installation.
const INITIAL_SCHEMA: &str = "
    -- KV store (`state::kv`). `kv_usage` tracks bytes used against the
    -- quota so `kv::set` refuses a write inside its transaction; the
    -- triggers only keep `bytes_used` in sync (key length counted in
    -- bytes, hence the cast) and never refuse.
    CREATE TABLE kv (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        key               TEXT NOT NULL,
        value             BLOB NOT NULL,
        updated_ms        INTEGER NOT NULL,
        PRIMARY KEY (installation_uuid, instance_id, key)
    ) WITHOUT ROWID;

    CREATE TABLE kv_usage (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        bytes_used        INTEGER NOT NULL DEFAULT 0,
        bytes_quota       INTEGER NOT NULL,
        PRIMARY KEY (installation_uuid, instance_id)
    ) WITHOUT ROWID;

    CREATE TRIGGER kv_usage_insert AFTER INSERT ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(CAST(NEW.key AS BLOB)) + length(NEW.value)
         WHERE installation_uuid = NEW.installation_uuid
           AND instance_id       = NEW.instance_id;
    END;

    CREATE TRIGGER kv_usage_delete AFTER DELETE ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used - length(CAST(OLD.key AS BLOB)) - length(OLD.value)
         WHERE installation_uuid = OLD.installation_uuid
           AND instance_id       = OLD.instance_id;
    END;

    CREATE TRIGGER kv_usage_update AFTER UPDATE OF value ON kv
    BEGIN
        UPDATE kv_usage
           SET bytes_used = bytes_used + length(NEW.value) - length(OLD.value)
         WHERE installation_uuid = NEW.installation_uuid
           AND instance_id       = NEW.instance_id;
    END;

    -- Event history (`state::event_log`), the durable mirror of the
    -- live bus. `received_ms` is host time (retention, query bounds;
    -- order is by id); `payload_ms` is the plugin's self-reported timestamp.
    -- `AUTOINCREMENT` so an id is never reused after retention deletes
    -- the current max: clients page and resume on id cursors. The
    -- filter indexes are keyed `(col, id)` so a cursor query seeks and
    -- streams in id order without a sort. `call_id` is the call id of
    -- the external request the publishing invocation traces back to
    -- (through any chain of `on-event` reactions), NULL when it traces
    -- back to none.
    CREATE TABLE event_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        received_ms   INTEGER NOT NULL,
        payload_ms    INTEGER NOT NULL,
        device_id     TEXT,
        instance_id   TEXT NOT NULL,
        plugin_id     TEXT NOT NULL,
        topic         TEXT NOT NULL,
        payload_blob  BLOB NOT NULL,
        call_id       TEXT
    );

    CREATE INDEX evt_received ON event_log(received_ms);
    CREATE INDEX evt_device   ON event_log(device_id, id) WHERE device_id IS NOT NULL;
    CREATE INDEX evt_topic    ON event_log(topic, id);
    CREATE INDEX evt_instance ON event_log(instance_id, id);
    CREATE INDEX evt_plugin   ON event_log(plugin_id, id);
    CREATE INDEX event_log_call_id ON event_log(call_id) WHERE call_id IS NOT NULL;

    -- Diagnostic log/trace store (`state::log_store`), fed by a
    -- `tracing` layer. Drop-tolerant; the audit ledger is separate.
    -- `log_span_ts` serves `span_path = ?`; prefix queries use
    -- `substr` and only get the partial-index narrowing.
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
    CREATE INDEX log_span_ts     ON log_event(span_path, ts_unix_ms)   WHERE span_path   IS NOT NULL;

    -- Blob index (`state::blobs`); the bytes live under
    -- `<state_dir>/blobs/`. `blob` maps a plugin-chosen name to the
    -- host-minted id; the UNIQUE `blob_by_id` makes an id collision
    -- fail the write. `blob_usage` mirrors `kv_usage`: the quota check
    -- is in `blobs::write`, the triggers only keep the count.
    -- `blob_usage_update` covers in-place `size_bytes` changes; the
    -- write path replaces rows with DELETE + INSERT today. The `mime`
    -- CHECK is `blobs::MAX_BLOB_MIME_BYTES` (checked first in
    -- `blobs::write` for a clean error); `octet_length` counts bytes.
    CREATE TABLE blob (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        name              TEXT NOT NULL,
        id                TEXT NOT NULL,
        size_bytes        INTEGER NOT NULL,
        created_ms        INTEGER NOT NULL,
        mime              TEXT CHECK (mime IS NULL OR octet_length(mime) <= 256),
        PRIMARY KEY (installation_uuid, instance_id, name)
    ) WITHOUT ROWID;

    CREATE UNIQUE INDEX blob_by_id
        ON blob(installation_uuid, instance_id, id);

    CREATE TABLE blob_usage (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        bytes_used        INTEGER NOT NULL DEFAULT 0,
        bytes_quota       INTEGER NOT NULL,
        PRIMARY KEY (installation_uuid, instance_id)
    ) WITHOUT ROWID;

    CREATE TRIGGER blob_usage_insert AFTER INSERT ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used + NEW.size_bytes
         WHERE installation_uuid = NEW.installation_uuid
           AND instance_id       = NEW.instance_id;
    END;

    CREATE TRIGGER blob_usage_delete AFTER DELETE ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used - OLD.size_bytes
         WHERE installation_uuid = OLD.installation_uuid
           AND instance_id       = OLD.instance_id;
    END;

    CREATE TRIGGER blob_usage_update AFTER UPDATE OF size_bytes ON blob
    BEGIN
        UPDATE blob_usage
           SET bytes_used = bytes_used + NEW.size_bytes - OLD.size_bytes
         WHERE installation_uuid = NEW.installation_uuid
           AND instance_id       = NEW.instance_id;
    END;

    -- API tokens (`state::auth_token`): 256-bit random secrets stored
    -- as plain SHA-256 hashes. `roles` is a JSON array of the names of
    -- the roles the token holds.
    -- `revoked_ms` is a tombstone; rows are kept for the audit trail.
    -- `owner` marks the owner token (first-run bootstrap or
    -- `recover-admin-token`); the partial unique index keeps one live
    -- owner.
    CREATE TABLE auth_token (
      id            TEXT PRIMARY KEY,
      label         TEXT NOT NULL,
      hash          BLOB NOT NULL,
      roles         TEXT NOT NULL,
      created_ms    INTEGER NOT NULL,
      last_used_ms  INTEGER,
      revoked_ms    INTEGER,
      owner         INTEGER NOT NULL DEFAULT 0
    ) STRICT;
    CREATE UNIQUE INDEX auth_token_hash ON auth_token(hash);
    CREATE UNIQUE INDEX auth_token_one_owner ON auth_token(owner)
     WHERE owner = 1 AND revoked_ms IS NULL;

    -- Audit ledger (`state::audit_log`), separate from `log_event` so
    -- diagnostic bursts can't evict it. Request rows are written in two
    -- phases (a `pending` intent before the handler runs, finalized
    -- after) so a cancelled request still leaves evidence; rows whose
    -- outcome is known up front (unauthenticated probes, command
    -- resolutions) are inserted finalized. `decision` is the
    -- authorization outcome and `status` the wire status;
    -- `execution_outcome` / `domain_error` record what the plugin did.
    -- `call_id` / `invocation_json` carry the invocation context
    -- (shared by an entry point and its delegated hops),
    -- `command_id` / `command_outcome` the explicit device-command
    -- outcome, and `level` is `warn` on sensitive-action rows. On a
    -- reaction's rows `caused_by` is the call id of the event it
    -- reacts to.
    CREATE TABLE audit_event (
      id                INTEGER PRIMARY KEY,
      intent_ms         INTEGER NOT NULL,
      finalized_ms      INTEGER,
      token_id          TEXT NOT NULL,
      actor_kind        TEXT NOT NULL,
      method            TEXT NOT NULL,
      path              TEXT NOT NULL,
      status            INTEGER NOT NULL,
      decision          TEXT NOT NULL,
      required_scope    TEXT,
      credential_fp     TEXT,
      execution_outcome TEXT,
      domain_error      TEXT,
      call_id           TEXT,
      invocation_json   TEXT,
      command_id        TEXT,
      command_outcome   TEXT,
      level             TEXT,
      caused_by         TEXT
    ) STRICT;
    CREATE INDEX audit_intent   ON audit_event(intent_ms);
    CREATE INDEX audit_token_ts ON audit_event(token_id, intent_ms);
    CREATE INDEX audit_call     ON audit_event(call_id) WHERE call_id IS NOT NULL;
    CREATE INDEX audit_caused_by ON audit_event(caused_by) WHERE caused_by IS NOT NULL;

    -- Plugin installations (`state::installed_plugins`). Every install
    -- mints a fresh `installation_uuid`, which feeds device ids and
    -- keys per-instance state; uninstall sets `uninstalled_ms` (a
    -- tombstone), and only one live row per `plugin_id` may exist.
    -- `granted_capabilities_json` is what the host approved, separate
    -- from what the manifest requests; `content_digest` binds that
    -- grant to the installed package's bytes.
    CREATE TABLE plugin_installation (
      installation_uuid         TEXT PRIMARY KEY,
      plugin_id                 TEXT NOT NULL,
      version                   TEXT NOT NULL,
      installed_ms              INTEGER NOT NULL,
      uninstalled_ms            INTEGER,
      granted_capabilities_json TEXT,
      content_digest            TEXT
    ) STRICT;
    CREATE UNIQUE INDEX plugin_installation_live
      ON plugin_installation(plugin_id)
      WHERE uninstalled_ms IS NULL;

    -- Dashboards (`state::dashboards`). `layout_json` is opaque to the
    -- host; `schema_version` versions its shape for the shell.
    CREATE TABLE dashboard (
        id             INTEGER PRIMARY KEY,
        name           TEXT NOT NULL,
        owner_user_id  TEXT NOT NULL,
        layout_json    BLOB NOT NULL,
        schema_version INTEGER NOT NULL DEFAULT 1,
        created_ms     INTEGER NOT NULL,
        updated_ms     INTEGER NOT NULL
    );
    CREATE INDEX dashboard_by_owner ON dashboard(owner_user_id);

    -- Durable device-state projection (`state::device_state`): one row
    -- per `(device_id, capability)` slot, written by the coalescing
    -- flusher. `device_state_meta` is a single row: store epoch, the
    -- revision the rows were flushed at, the eviction watermark and the
    -- revision ranges earlier boots skipped.
    CREATE TABLE device_state (
        device_id         TEXT NOT NULL,
        capability        TEXT NOT NULL,
        owner_instance    TEXT NOT NULL,
        owner_plugin      TEXT NOT NULL,
        owner_install     TEXT NOT NULL,
        fields_blob       BLOB NOT NULL,
        global_revision   INTEGER NOT NULL,
        received_ms       INTEGER NOT NULL,
        observed_ms       INTEGER NOT NULL,
        source_generation INTEGER NOT NULL,
        quality           TEXT NOT NULL,
        PRIMARY KEY (device_id, capability)
    ) WITHOUT ROWID;

    CREATE TABLE device_state_meta (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        epoch             TEXT NOT NULL,
        revision          INTEGER NOT NULL,
        evicted_through   INTEGER NOT NULL,
        holes_json        TEXT NOT NULL,
        writer            TEXT NOT NULL
    );

    -- Externally-rooted device commands a plugin answered `accepted`
    -- (`runtime::command_journal`). Deleted with the command's
    -- `COMMAND` resolution row; rows left at boot resolve to
    -- `outcome_unknown`.
    CREATE TABLE pending_command (
        command_id       TEXT PRIMARY KEY NOT NULL,
        call_id          TEXT NOT NULL,
        owner_instance   TEXT NOT NULL,
        device_id        TEXT NOT NULL,
        capability       TEXT NOT NULL,
        created_ms       INTEGER NOT NULL,
        expires_ms       INTEGER NOT NULL,
        token_id         TEXT NOT NULL,
        actor_kind       TEXT NOT NULL,
        invocation_json  TEXT NOT NULL
    ) WITHOUT ROWID;

    -- Per device (`state::device_meta`): the sensitive categories the
    -- host has ever derived (a floor a plugin can't lower), the
    -- operator's category raise, and the registering instance.
    CREATE TABLE device_meta (
        device_id          TEXT PRIMARY KEY NOT NULL,
        owner_instance     TEXT,
        sensitive_floor    TEXT NOT NULL,
        category_override  TEXT,
        updated_ms         INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    -- A removed script sandbox's storage purge (ADR-0001), announced
    -- before it starts and deleted once it succeeded. While a row
    -- exists the sandbox id can't be reused; an unfinished purge runs
    -- again at the next boot.
    CREATE TABLE sandbox_removal (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        created_ms        INTEGER NOT NULL,
        PRIMARY KEY (installation_uuid, instance_id)
    ) WITHOUT ROWID;

    -- Custom roles (`state::auth_role`). Tokens hold a role by name,
    -- so an edit of its definition applies to every holder.
    CREATE TABLE auth_role (
        name        TEXT PRIMARY KEY,
        definition  BLOB NOT NULL,
        created_ms  INTEGER NOT NULL,
        updated_ms  INTEGER NOT NULL
    ) WITHOUT ROWID;

    -- Certificates streaming instances trusted on first use for LAN
    -- devices (`state::tls_pins`), keyed by instance, the request's
    -- host and port, and plugin installation. Reset by the operator;
    -- deleted with the plugin's uninstall.
    CREATE TABLE network_tls_pin (
        instance_id       TEXT NOT NULL,
        host              TEXT NOT NULL,
        port              INTEGER NOT NULL,
        sha256            TEXT NOT NULL,
        pinned_ms         INTEGER NOT NULL,
        installation_uuid TEXT NOT NULL,
        PRIMARY KEY (instance_id, host, port, installation_uuid)
    ) WITHOUT ROWID;
";

/// File name of the host database inside the state dir.
pub const DB_FILE_NAME: &str = "oxidhome.db";

/// Schema version this binary migrates to (`PRAGMA user_version`
/// after every migration has applied).
#[must_use]
pub fn schema_version() -> i64 {
    i64::try_from(MIGRATIONS.len()).expect("migration count fits in i64")
}

/// How long any connection waits on a `SQLite` lock before it
/// reports `SQLITE_BUSY`. Inside one process the writer mutex
/// already serializes writes, so this mostly covers other
/// processes on the same file (an online `oxidhome backup`, an
/// operator's `sqlite3` shell) and WAL-index recovery, so a stuck
/// lock surfaces as an error instead of a hang. It is longer than
/// the H3 mirror's 2 s write deadline: a publish past that deadline
/// is delivered in degraded mode while its blocking write keeps
/// waiting here.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on read-only connections a file-backed [`Db`]
/// opens. Connections open lazily on first contended use, so an
/// idle host holds one or two.
pub const READ_POOL_SIZE: usize = 4;

/// Backstop `wal_autocheckpoint` on the writer, in pages
/// (64 MiB at the default 4 KiB page). The routine checkpoint runs
/// off the commit path on the checkpointer thread
/// ([`CHECKPOINT_INTERVAL`]); this only fires if that thread falls
/// far behind, so a committing writer (an event publish holding
/// the bus gate) almost never pays for a checkpoint. If a long read
/// pins an old snapshot past this size, each commit attempts a
/// passive checkpoint until the WAL can reset.
pub const WAL_AUTOCHECKPOINT_PAGES: i64 = 16_384;

/// Size the WAL file is truncated back to after a checkpoint lets
/// it reset, so a burst doesn't leave a large `-wal` on disk.
pub const JOURNAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

/// How often the checkpointer thread runs
/// `PRAGMA wal_checkpoint(PASSIVE)`. Passive checkpoints never take
/// the writer lock and never wait on readers; they copy whatever
/// frames no open read snapshot still needs.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(10);

/// Longest a [`Db::write_low_priority`] caller defers to waiting
/// normal-priority writers before it takes its turn anyway. Bounds
/// diagnostic-log latency under a sustained control-write storm
/// (the log channel absorbs the backlog and drops past capacity).
pub const LOW_PRIORITY_MAX_DEFER: Duration = Duration::from_millis(250);

/// Connection-model knobs. [`Db::open_file`] uses the defaults
/// above; tests shrink the intervals to observe the policy without
/// waiting on wall-clock time, and swap in a longer migration list to
/// exercise the upgrade path.
#[derive(Clone, Copy)]
pub(crate) struct ConnectionPolicy {
    pub(crate) read_pool_size: usize,
    pub(crate) checkpoint_interval: Duration,
    pub(crate) low_priority_max_defer: Duration,
    pub(crate) migrations: &'static [&'static str],
}

impl std::fmt::Debug for ConnectionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPolicy")
            .field("read_pool_size", &self.read_pool_size)
            .field("checkpoint_interval", &self.checkpoint_interval)
            .field("low_priority_max_defer", &self.low_priority_max_defer)
            .field("migrations", &self.migrations.len())
            .finish()
    }
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            read_pool_size: READ_POOL_SIZE,
            checkpoint_interval: CHECKPOINT_INTERVAL,
            low_priority_max_defer: LOW_PRIORITY_MAX_DEFER,
            migrations: MIGRATIONS,
        }
    }
}

/// The host's `SQLite` handle: one writer, a small read pool, and a
/// checkpointer (M6).
///
/// - **Writer.** One `rusqlite::Connection` behind a mutex. Every
///   write goes through it, so `BEGIN IMMEDIATE` never races
///   another in-process writer and commit order is mutex order.
///   [`Self::write`] is normal priority (events, KV, audit, tokens,
///   registry, dashboards); [`Self::write_low_priority`] (diagnostic
///   log batches, log and event-log retention) yields to any normal-priority
///   writer already waiting, for at most
///   [`LOW_PRIORITY_MAX_DEFER`].
/// - **Readers.** File-backed databases open up to
///   [`READ_POOL_SIZE`] extra connections with `query_only = ON`.
///   [`Self::read`] runs its closure on one of them inside a
///   deferred read transaction, so a query sees one consistent
///   snapshot (the same isolation the old single mutex gave) and
///   never waits on the writer: WAL lets readers proceed while a
///   write transaction is open. `:memory:` databases are private
///   to one connection, so they have no pool and `read` uses the
///   writer.
/// - **Checkpointer.** A background thread with its own connection
///   runs a passive WAL checkpoint every [`CHECKPOINT_INTERVAL`].
///
/// `rusqlite::Connection` is `!Sync`, which is why every
/// connection sits behind a mutex or a pool lease.
pub struct Db {
    /// `None` for `:memory:` databases (the "file path" we report in
    /// error messages); `Some(path)` for file-backed instances.
    path: Option<PathBuf>,
    conn: Mutex<Connection>,
    /// Decides who owns `conn` next (normal before low priority).
    write_gate: WriteGate,
    /// `None` for `:memory:`.
    readers: Option<ReadPool>,
    /// `None` for `:memory:`. Dropped (stopped + joined) with the
    /// `Db`, so no connection outlives it.
    checkpointer: Option<Checkpointer>,
    policy: ConnectionPolicy,
    /// Highest `audit_event` id when the first audit handle of this
    /// process opened (see [`Self::audit_boot_floor`]).
    audit_boot_floor: std::sync::OnceLock<i64>,
}

/// The full pathname `SQLite` resolved for the `main` database of
/// `conn`, read as raw bytes from `PRAGMA database_list`.
/// `Connection::path()` returns `None` for a non-UTF-8 path, and
/// re-resolving the name ourselves would race a symlink retargeted
/// after the open, so the bytes are taken as they are (Unix paths
/// are arbitrary bytes). Elsewhere a path must be UTF-8.
fn opened_main_path(conn: &Connection) -> anyhow::Result<PathBuf> {
    // The `PRAGMA` statement, not the `pragma_database_list` table
    // function: a schema object with that name would shadow it.
    let mut stmt = conn
        .prepare("PRAGMA database_list")
        .context("reading the main database path")?;
    let mut rows = stmt.query(()).context("reading the main database path")?;
    let mut bytes = Vec::new();
    while let Some(row) = rows.next().context("reading the main database path")? {
        if row.get_ref(1)?.as_str().ok() == Some("main") {
            if let rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) =
                row.get_ref(2)?
            {
                bytes = b.to_vec();
            }
            break;
        }
    }
    anyhow::ensure!(
        !bytes.is_empty(),
        "SQLite reported no file path for the main database"
    );
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        let s = String::from_utf8(bytes).context("database path is not valid UTF-8")?;
        Ok(PathBuf::from(s))
    }
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
        Self::initialize(None, None, conn, ConnectionPolicy::default())
    }

    /// Open the persistent database at `<state_dir>/oxidhome.db`.
    /// Creates `state_dir` if it doesn't already exist; enables WAL
    /// mode and `synchronous = NORMAL` (the durability sweet spot per
    /// Phase 5's appendix-A choice), sets [`BUSY_TIMEOUT`] and the
    /// checkpoint policy, and starts the read pool and checkpointer
    /// once migrations have applied.
    ///
    /// M3: refuses a state dir with an interrupted restore, and runs
    /// the migration preflight
    /// ([`crate::backup::snapshot_before_migration`]) before applying
    /// pending migrations to an existing database.
    ///
    /// # Errors
    ///
    /// Returns the first failure across directory creation, file
    /// open, pragma application, preflight, or migration.
    pub fn open_file(state_dir: &Path) -> anyhow::Result<Self> {
        Self::open_file_with_policy(state_dir, ConnectionPolicy::default())
    }

    pub(crate) fn open_file_with_policy(
        state_dir: &Path,
        policy: ConnectionPolicy,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        crate::backup::ensure_no_interrupted_restore(state_dir)?;
        // Canonical (absolute, symlinks resolved) before the writer
        // opens, so readers and the checkpointer, which open later,
        // reach the same file even after a working-directory change
        // or a symlinked state dir being retargeted.
        let state_dir = std::fs::canonicalize(state_dir)
            .with_context(|| format!("resolving state dir {}", state_dir.display()))?;
        let path = state_dir.join(DB_FILE_NAME);
        let conn = Connection::open(&path)
            .with_context(|| format!("opening database at {}", path.display()))?;
        // Pin every later connection to the file the writer actually
        // opened: `SQLite` reports the full pathname it resolved
        // (symlinks included), so a link retargeted during or after
        // startup can't split readers from the writer.
        let path = opened_main_path(&conn)?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .context("setting busy_timeout")?;
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
        // NORMAL is the baseline; the durable paths (M4 token writes,
        // `AuditLog::record_intent_durable`) raise it to FULL on this
        // connection for one write and restore it afterwards.
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("setting synchronous = NORMAL")?;
        // `foreign_keys = ON` is off by default per `SQLite` docs — turn
        // it on so future cross-table constraints (`blob_usage`,
        // future Phase-5b additions) are enforced.
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign_keys")?;
        apply_checkpoint_pragmas(&conn)?;
        let mut db = Self::initialize(Some(path.clone()), Some(&state_dir), conn, policy)?;
        // Readers and the checkpointer start only after migrations,
        // so none of them ever caches a pre-migration schema.
        db.checkpointer = Some(Checkpointer::start(&path, policy.checkpoint_interval)?);
        db.readers = Some(ReadPool::new(path, policy.read_pool_size));
        Ok(db)
    }

    fn initialize(
        path: Option<PathBuf>,
        state_dir: Option<&Path>,
        conn: Connection,
        policy: ConnectionPolicy,
    ) -> anyhow::Result<Self> {
        let pre_open_user_version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("reading user_version pre-migration")?;
        let target = i64::try_from(policy.migrations.len()).expect("migration count fits in i64");
        // M3: no silent downgrade. Running against a newer schema
        // would skip migrations this binary doesn't know about and
        // read / write tables in a shape it wasn't built for.
        anyhow::ensure!(
            pre_open_user_version <= target,
            "database schema v{pre_open_user_version} is newer than this binary supports \
             (v{target}) — run a newer oxidhome, or restore a backup taken with this version",
        );
        // M3 migration preflight: an existing file-backed database
        // with pending migrations gets an integrity check + snapshot
        // first. A fresh database (v0) has nothing to protect.
        if let Some(state_dir) = state_dir
            && pre_open_user_version > 0
            && pre_open_user_version < target
        {
            let snapshot = crate::backup::snapshot_before_migration(
                &conn,
                state_dir,
                pre_open_user_version,
                target,
            )?;
            tracing::warn!(
                from = pre_open_user_version,
                to = target,
                snapshot = %snapshot.display(),
                "applying schema migrations; pre-migration snapshot written",
            );
        }
        let db = Self {
            path,
            conn: Mutex::new(conn),
            write_gate: WriteGate::default(),
            readers: None,
            checkpointer: None,
            policy,
            audit_boot_floor: std::sync::OnceLock::new(),
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
        let migrations = self.policy.migrations;
        while next < migrations.len() {
            let body = migrations[next];
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

    /// Run a read-only closure against the database.
    ///
    /// On a file-backed database the closure runs on a pooled
    /// `query_only` connection inside one deferred read transaction:
    /// it sees a single committed snapshot, never waits on the
    /// writer, and fails with `SQLITE_READONLY` if it tries to write.
    /// On `:memory:` it runs on the writer connection. Either way the
    /// call is synchronous; async callers hop to `spawn_blocking`.
    ///
    /// Error-generic so a caller's domain error (e.g.
    /// `state::kv::KvError`) can be returned directly via `?` from
    /// inside the closure — anything with a `From<rusqlite::Error>`
    /// impl works.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns, or a `rusqlite` error opening a pooled
    /// connection or its read transaction.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the
    /// writer or pool mutex. Recoverable poisoning isn't a useful
    /// state for a database handle, so the panic is the intentional
    /// shape.
    pub fn read<R, E>(&self, f: impl FnOnce(&Connection) -> Result<R, E>) -> Result<R, E>
    where
        R: Send,
        E: From<rusqlite::Error>,
    {
        let Some(pool) = &self.readers else {
            let conn = self.lock_writer();
            return f(&conn);
        };
        let mut lease = pool.checkout()?;
        lease.run(f)
    }

    /// Run a closure with the writer connection at normal priority.
    /// `BEGIN IMMEDIATE` / `COMMIT` lives inside `f` — this method
    /// just takes the writer mutex and hands the connection over. A
    /// normal-priority caller waiting here makes
    /// [`Self::write_low_priority`] callers stand aside.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    ///
    /// # Panics
    ///
    /// Same as [`Self::read`] — only on poisoning of the writer
    /// mutex.
    pub fn write<R, E>(&self, f: impl FnOnce(&mut Connection) -> Result<R, E>) -> Result<R, E>
    where
        R: Send,
    {
        let mut conn = self.lock_writer();
        f(&mut conn)
    }

    /// [`Self::write`] for work nobody waits on (diagnostic log
    /// batches, log retention). The writer goes to a queued
    /// normal-priority caller first; this call takes it only when
    /// no normal-priority caller is waiting, or once it has deferred
    /// for [`LOW_PRIORITY_MAX_DEFER`]. A normal-priority caller that
    /// arrives while `f` runs waits for `f` to finish, so `f` should
    /// be one bounded transaction.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    ///
    /// # Panics
    ///
    /// Same as [`Self::write`].
    pub fn write_low_priority<R, E>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, E>,
    ) -> Result<R, E>
    where
        R: Send,
    {
        let ticket = self
            .write_gate
            .acquire_low(self.policy.low_priority_max_defer, &|| false)
            .expect("an uncancellable wait is always admitted");
        let mut conn = WriterGuard {
            conn: self.conn.lock().expect("db mutex poisoned"),
            _ticket: ticket,
        };
        f(&mut conn)
    }

    /// [`Self::write_low_priority`] with a cancellable wait for the
    /// writer: `cancelled` is checked before every wait, and after
    /// every wakeup, including the ones
    /// [`Self::wake_low_priority_writers`] forces. Once it returns
    /// `true` the call gives up its place and returns `Ok(None)`
    /// without running `f`; once the writer is granted `f` runs to
    /// completion. Retention uses this so a stop request at shutdown
    /// doesn't leave a chunk queued behind a hung write, to run after
    /// the caller moved on.
    ///
    /// `cancelled` runs under the admission mutex, so it must be
    /// cheap and must not take the writer.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    ///
    /// # Panics
    ///
    /// Same as [`Self::write`].
    pub fn write_low_priority_unless<R, E>(
        &self,
        cancelled: &dyn Fn() -> bool,
        f: impl FnOnce(&mut Connection) -> Result<R, E>,
    ) -> Result<Option<R>, E>
    where
        R: Send,
    {
        let Some(ticket) = self
            .write_gate
            .acquire_low(self.policy.low_priority_max_defer, cancelled)
        else {
            return Ok(None);
        };
        let mut conn = WriterGuard {
            conn: self.conn.lock().expect("db mutex poisoned"),
            _ticket: ticket,
        };
        f(&mut conn).map(Some)
    }

    /// The highest `audit_event` id before this process wrote any audit
    /// row, read once per `Db` (so per process) by the first caller:
    /// a pending row above it belongs to this process and may still be
    /// finalized. `0` if the read fails, which keeps every pending
    /// row.
    pub(crate) fn audit_boot_floor(&self) -> i64 {
        *self.audit_boot_floor.get_or_init(|| {
            self.read(|c| {
                c.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_event", [], |r| {
                    r.get(0)
                })
            })
            .unwrap_or(0)
        })
    }

    /// Wake every caller waiting in
    /// [`Self::write_low_priority_unless`] so it re-checks its
    /// cancellation. Call it after setting whatever `cancelled`
    /// reads.
    pub fn wake_low_priority_writers(&self) {
        let _state = self.write_gate.lock_state();
        self.write_gate.changed.notify_all();
    }

    /// The writer at normal priority.
    fn lock_writer(&self) -> WriterGuard<'_> {
        let ticket = self.write_gate.acquire_normal();
        WriterGuard {
            conn: self.conn.lock().expect("db mutex poisoned"),
            _ticket: ticket,
        }
    }

    /// Normal-priority callers currently queued for the writer.
    #[cfg(test)]
    fn waiting_writers(&self) -> usize {
        self.write_gate.lock_state().normal_waiting
    }

    /// Low-priority callers currently queued for the writer.
    #[cfg(test)]
    fn waiting_low_priority_writers(&self) -> usize {
        self.write_gate.lock_state().low_waiting
    }

    /// Path the database is backed by, or `None` for `:memory:`. Used
    /// in error messages so the operator can see *which* database the
    /// failure came from when several plugin hosts run side by side.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Cheap connectivity check. Takes the writer mutex and runs
    /// `SELECT 1` — sub-millisecond on a healthy `SQLite` handle, and
    /// any of the failure modes worth surfacing to an orchestrator
    /// (mutex poisoned, connection closed, disk I/O error, a writer
    /// stuck in a transaction) show up as an error or a wait here.
    ///
    /// Used by the JSON `GET /api/v1/readyz` readiness probe. Every
    /// persistent store writes through this connection, so a working
    /// ping stands in for all of them.
    ///
    /// # Errors
    ///
    /// Forwards any `rusqlite` failure verbatim.
    pub fn ping(&self) -> Result<(), rusqlite::Error> {
        let conn = self.lock_writer();
        conn.query_row("SELECT 1", [], |_| Ok(()))
    }

    /// Passive WAL checkpoints the checkpointer thread has completed.
    #[cfg(test)]
    fn checkpoints_run(&self) -> u64 {
        self.checkpointer
            .as_ref()
            .map_or(0, |c| c.shared.runs.load(Ordering::Relaxed))
    }
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.path)
            .field("conn", &"<rusqlite::Connection>")
            .field("read_pool", &self.readers.as_ref().map(|p| p.max))
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Checkpoint pragmas shared by the writer and the checkpointer.
fn apply_checkpoint_pragmas(conn: &Connection) -> anyhow::Result<()> {
    conn.pragma_update(None, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES)
        .context("setting wal_autocheckpoint")?;
    // `journal_size_limit` returns the new value, so read it back
    // through `query_row` rather than `pragma_update`.
    let _: i64 = conn
        .query_row(
            &format!("PRAGMA journal_size_limit = {JOURNAL_SIZE_LIMIT_BYTES}"),
            (),
            |row| row.get(0),
        )
        .context("setting journal_size_limit")?;
    Ok(())
}

/// Admission to the writer (M6). Ownership is decided here, under
/// one mutex, so a low-priority caller can't slip into the writer
/// mutex's queue ahead of a normal-priority caller that is already
/// waiting. Rules, evaluated whenever the writer is free:
///
/// - A queued normal-priority caller goes before a low-priority one,
///   even if the low-priority caller queued earlier.
/// - A low-priority caller that has deferred for its full bound is
///   *overdue*: it gets the next turn after a normal-priority
///   transaction, so a stream of normal writes can't starve it.
/// - After a low-priority transaction, a queued normal-priority
///   caller goes next, so several overdue low-priority callers
///   alternate with normal ones rather than running back to back.
#[derive(Default)]
struct WriteGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    /// Some caller owns the writer.
    held: bool,
    normal_waiting: usize,
    low_waiting: usize,
    /// Low-priority waiters whose deferral bound has run out.
    overdue: usize,
    /// The last owner was low priority.
    last_was_low: bool,
}

impl GateState {
    /// An overdue low-priority caller is owed the next turn.
    fn low_owed_turn(&self) -> bool {
        self.overdue > 0 && !self.last_was_low
    }
}

impl WriteGate {
    /// The gate's state is plain counters that are never left
    /// half-updated, so poisoning (a panic elsewhere while it was
    /// held) is ignored rather than propagated.
    fn lock_state(&self) -> MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn acquire_normal(&self) -> GateTicket<'_> {
        let mut state = self.lock_state();
        if state.held || state.low_owed_turn() {
            state.normal_waiting += 1;
            state = self
                .changed
                .wait_while(state, |s| s.held || s.low_owed_turn())
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.normal_waiting -= 1;
        }
        state.held = true;
        state.last_was_low = false;
        GateTicket { gate: self }
    }

    /// `None` when `cancelled` turned true before the writer was
    /// granted; the caller has then left the queue.
    fn acquire_low(
        &self,
        max_defer: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Option<GateTicket<'_>> {
        let deadline = Instant::now().checked_add(max_defer);
        let mut state = self.lock_state();
        state.low_waiting += 1;
        let mut overdue = false;
        loop {
            if cancelled() {
                state.low_waiting -= 1;
                if overdue {
                    state.overdue -= 1;
                }
                // Normal waiters may have been standing aside for this
                // caller's owed turn.
                self.changed.notify_all();
                return None;
            }
            let now = Instant::now();
            if !overdue && deadline.is_some_and(|d| now >= d) {
                overdue = true;
                state.overdue += 1;
                // Normal waiters re-check: this caller may now be
                // owed the next turn.
                self.changed.notify_all();
            }
            let eligible = state.normal_waiting == 0 || (overdue && !state.last_was_low);
            if !state.held && eligible {
                break;
            }
            state = match deadline {
                // Deferring with a deadline still ahead: wake on the
                // next change or when the deferral runs out.
                Some(d) if !overdue => {
                    self.changed
                        .wait_timeout(state, d - now)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0
                }
                _ => self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            };
        }
        state.low_waiting -= 1;
        if overdue {
            state.overdue -= 1;
        }
        state.held = true;
        state.last_was_low = true;
        Some(GateTicket { gate: self })
    }
}

/// Ownership of the writer; released on drop, including on unwind.
struct GateTicket<'a> {
    gate: &'a WriteGate,
}

impl Drop for GateTicket<'_> {
    fn drop(&mut self) {
        self.gate.lock_state().held = false;
        self.gate.changed.notify_all();
    }
}

/// The writer connection plus its admission ticket. Field order
/// matters: the connection mutex unlocks before the ticket frees
/// the gate, so the next owner never blocks on the mutex.
struct WriterGuard<'a> {
    conn: MutexGuard<'a, Connection>,
    _ticket: GateTicket<'a>,
}

impl std::ops::Deref for WriterGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl std::ops::DerefMut for WriterGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Lazily-filled pool of `query_only` connections to one file.
struct ReadPool {
    path: PathBuf,
    max: usize,
    state: Mutex<PoolState>,
    returned: Condvar,
}

struct PoolState {
    idle: Vec<Connection>,
    /// Connections that exist right now (idle + leased).
    open: usize,
}

impl ReadPool {
    fn new(path: PathBuf, max: usize) -> Self {
        Self {
            path,
            max: max.max(1),
            state: Mutex::new(PoolState {
                idle: Vec::new(),
                open: 0,
            }),
            returned: Condvar::new(),
        }
    }

    fn checkout(&self) -> Result<ReadLease<'_>, rusqlite::Error> {
        let mut state = self.state.lock().expect("read pool poisoned");
        loop {
            if let Some(conn) = state.idle.pop() {
                return Ok(ReadLease {
                    pool: self,
                    conn: Some(conn),
                });
            }
            if state.open < self.max {
                state.open += 1;
                drop(state);
                return match open_reader(&self.path) {
                    Ok(conn) => Ok(ReadLease {
                        pool: self,
                        conn: Some(conn),
                    }),
                    Err(err) => {
                        self.forget_one();
                        Err(err)
                    }
                };
            }
            state = self.returned.wait(state).expect("read pool poisoned");
        }
    }

    /// A slot was given up (open failed, or a connection was
    /// discarded): let a waiter open a fresh one.
    fn forget_one(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.open -= 1;
        drop(state);
        self.returned.notify_one();
    }
}

fn open_reader(path: &Path) -> Result<Connection, rusqlite::Error> {
    // No `SQLITE_OPEN_CREATE`: the writer created the file and set
    // WAL (a persistent property of the file) before any reader opens.
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // Read-write open + `query_only` rather than a read-only open: a
    // read-only WAL connection needs the `-shm` to already exist and
    // be writable, which is not guaranteed across a writer restart.
    conn.pragma_update(None, "query_only", true)?;
    Ok(conn)
}

/// A pooled reader on loan. Returns the connection on drop, or
/// discards it if its transaction state is unknown.
struct ReadLease<'a> {
    pool: &'a ReadPool,
    conn: Option<Connection>,
}

impl ReadLease<'_> {
    fn run<R, E>(&mut self, f: impl FnOnce(&Connection) -> Result<R, E>) -> Result<R, E>
    where
        E: From<rusqlite::Error>,
    {
        let conn = self.conn.as_mut().expect("lease holds a connection");
        // Deferred: the snapshot starts at the first read, and a
        // read-only transaction never takes a write lock.
        let tx = conn.transaction()?;
        let out = f(&tx);
        if tx.rollback().is_err() {
            // Unknown transaction state: don't hand this connection
            // to the next caller. The read result is still valid.
            self.discard();
        }
        out
    }

    fn discard(&mut self) {
        if self.conn.take().is_some() {
            self.pool.forget_one();
        }
    }
}

impl Drop for ReadLease<'_> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        if std::thread::panicking() || !conn.is_autocommit() {
            // A panic mid-closure or a transaction left open: close
            // the connection instead of recycling it.
            drop(conn);
            self.pool.forget_one();
            return;
        }
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.idle.push(conn);
        drop(state);
        self.pool.returned.notify_one();
    }
}

/// Background passive-checkpoint thread. Stopped and joined on drop.
struct Checkpointer {
    shared: Arc<CheckpointShared>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct CheckpointShared {
    stop: Mutex<bool>,
    wake: Condvar,
    runs: AtomicU64,
}

impl Checkpointer {
    fn start(path: &Path, interval: Duration) -> anyhow::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening checkpoint connection to {}", path.display()))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .context("setting checkpointer busy_timeout")?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("setting checkpointer synchronous")?;
        apply_checkpoint_pragmas(&conn)?;
        let shared = Arc::new(CheckpointShared::default());
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("oxidhome-db-checkpoint".into())
            .spawn(move || checkpoint_loop(&conn, &thread_shared, interval))
            .context("spawning checkpointer thread")?;
        Ok(Self {
            shared,
            handle: Some(handle),
        })
    }
}

impl Drop for Checkpointer {
    fn drop(&mut self) {
        *self
            .shared
            .stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.shared.wake.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn checkpoint_loop(conn: &Connection, shared: &CheckpointShared, interval: Duration) {
    let mut stop = shared
        .stop
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        stop = shared
            .wake
            .wait_timeout_while(stop, interval, |stopped| !*stopped)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
        if *stop {
            return;
        }
        drop(stop);
        // (busy, wal frames, frames checkpointed). PASSIVE returns
        // busy = 1 only if another checkpoint was running.
        match conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", (), |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(busy) => {
                if busy == 0 {
                    shared.runs.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(err) => {
                tracing::warn!(
                    target: "state.db",
                    error = %err,
                    "passive WAL checkpoint failed; the writer's autocheckpoint backstop still applies",
                );
            }
        }
        stop = shared
            .stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// Lookups by request call id use the
    /// partial indexes on `event_log.call_id` and
    /// `audit_event.caused_by`.
    #[test]
    fn attribution_lookups_are_indexed() {
        let db = Db::open_in_memory().expect("open");
        db.read(|c| -> rusqlite::Result<()> {
            for (sql, index) in [
                (
                    "SELECT id FROM event_log WHERE call_id = 'call-x'",
                    "event_log_call_id",
                ),
                (
                    "SELECT id FROM audit_event WHERE caused_by = 'call-x'",
                    "audit_caused_by",
                ),
            ] {
                let plan: String =
                    c.query_row(&format!("EXPLAIN QUERY PLAN {sql}"), (), |row| row.get(3))?;
                assert!(plan.contains(index), "{sql}: {plan}");
            }
            Ok(())
        })
        .expect("read");
    }

    #[test]
    fn ping_ok_on_healthy_connection() {
        // The readiness probe (`GET /api/v1/readyz`) leans on this
        // as its single dependency check. A fresh in-memory DB
        // always passes; the operational failure modes (mutex
        // poisoning, disk I/O errors) are hard to synthesize
        // without deeper plumbing, so this test just pins the
        // happy path.
        let db = Db::open_in_memory().expect("open");
        db.ping().expect("healthy connection must ping");
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

    /// Round-8 P2 on PR #157: the `event_log` filter indexes
    /// are keyed `(col, id)` so an id-cursor query seeks
    /// straight to the cursor and streams in `ORDER BY id`
    /// order — no full scan of the filtered set, no temp
    /// B-tree sort.
    #[test]
    fn event_log_filter_indexes_serve_id_cursor_queries() {
        let db = Db::open_in_memory().expect("open");
        for col in ["device_id", "instance_id", "plugin_id", "topic"] {
            for order in ["ASC", "DESC"] {
                let sql = format!(
                    "EXPLAIN QUERY PLAN SELECT id FROM event_log \
                     WHERE {col} = 'x' AND id > 5 ORDER BY id {order} LIMIT 100"
                );
                let plan: Vec<String> = db
                    .read(|c| -> rusqlite::Result<_> {
                        let mut stmt = c.prepare(&sql)?;
                        let rows = stmt.query_map((), |r| r.get::<_, String>(3))?;
                        rows.collect()
                    })
                    .expect("explain");
                let plan = plan.join(" | ");
                assert!(
                    plan.contains(&format!("{col}=? AND id>?")),
                    "{col} {order}: expected (col, id) index seek, got `{plan}`",
                );
                assert!(
                    !plan.contains("TEMP B-TREE"),
                    "{col} {order}: unexpected sort, got `{plan}`",
                );
            }
        }
    }

    /// The shipped migrations plus one more, so the upgrade path
    /// (preflight snapshot, then the pending migration) has something
    /// to apply.
    const UPGRADE_MIGRATIONS: &[&str] =
        &[INITIAL_SCHEMA, "CREATE TABLE upgrade_probe (x INTEGER);"];

    fn upgrade_policy() -> ConnectionPolicy {
        ConnectionPolicy {
            migrations: UPGRADE_MIGRATIONS,
            ..ConnectionPolicy::default()
        }
    }

    /// Build `<dir>/oxidhome.db` at schema `version` by applying the
    /// first `version` of `migrations` directly (no preflight).
    fn seed_db_at(dir: &Path, migrations: &[&str], version: usize) {
        let conn = Connection::open(dir.join(DB_FILE_NAME)).expect("open seed db");
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", (), |r| r.get(0))
            .expect("wal");
        for body in &migrations[..version] {
            conn.execute_batch(body).expect("seed migration");
        }
        conn.execute_batch(&format!("PRAGMA user_version = {version}"))
            .expect("seed user_version");
    }

    fn pre_migration_snapshots(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir.join(crate::backup::PRE_MIGRATION_DIR)) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        out.sort();
        out
    }

    /// M3: pending migrations on an existing file get a snapshot of
    /// the pre-migration database first — self-contained (rollback
    /// journal) and still at the old version.
    #[test]
    fn migration_preflight_snapshots_the_pre_migration_database() {
        let dir = tempdir_for_test();
        let from = 1;
        let to = UPGRADE_MIGRATIONS.len();
        seed_db_at(dir.path(), UPGRADE_MIGRATIONS, from);
        let db = Db::open_file_with_policy(dir.path(), upgrade_policy()).expect("open + migrate");
        let version: i64 = db
            .read(|c| c.pragma_query_value(None, "user_version", |r| r.get(0)))
            .unwrap();
        assert_eq!(version, i64::try_from(to).unwrap());
        let has_probe = |c: &Connection| -> bool {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'upgrade_probe')",
                (),
                |r| r.get(0),
            )
            .unwrap()
        };
        assert!(db.read(|c| Ok::<_, rusqlite::Error>(has_probe(c))).unwrap());

        let snapshots = pre_migration_snapshots(dir.path());
        assert_eq!(snapshots.len(), 1, "{snapshots:?}");
        let name = snapshots[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.ends_with(&format!("-v{from}-to-v{to}.db")), "{name}");
        let snap =
            Connection::open_with_flags(&snapshots[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let snap_version: i64 = snap
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(snap_version, i64::try_from(from).unwrap());
        assert!(
            !has_probe(&snap),
            "the snapshot predates the pending migration"
        );
        let mode: String = snap
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
    }

    #[test]
    fn fresh_and_current_databases_skip_the_preflight() {
        let dir = tempdir_for_test();
        drop(Db::open_file(dir.path()).expect("fresh"));
        drop(Db::open_file(dir.path()).expect("current"));
        assert_eq!(pre_migration_snapshots(dir.path()), Vec::<PathBuf>::new());
    }

    /// No snapshot, no migration: the database stays at its old
    /// version.
    #[test]
    fn failed_preflight_refuses_to_migrate() {
        let dir = tempdir_for_test();
        let from = 1;
        seed_db_at(dir.path(), UPGRADE_MIGRATIONS, from);
        // A file where the snapshot directory should go.
        std::fs::write(dir.path().join(crate::backup::PRE_MIGRATION_DIR), b"x").unwrap();
        let err = Db::open_file_with_policy(dir.path(), upgrade_policy()).unwrap_err();
        assert!(
            format!("{err:#}").contains("pre-migration snapshot"),
            "{err:#}"
        );
        let conn = Connection::open(dir.path().join(DB_FILE_NAME)).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, i64::try_from(from).unwrap());
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = tempdir_for_test();
        seed_db_at(dir.path(), MIGRATIONS, MIGRATIONS.len());
        {
            let conn = Connection::open(dir.path().join(DB_FILE_NAME)).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {}", MIGRATIONS.len() + 1))
                .unwrap();
        }
        let err = Db::open_file(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("newer than this binary"),
            "{err:#}"
        );
    }

    #[test]
    fn pre_migration_snapshots_are_pruned_to_the_newest() {
        let dir = tempdir_for_test();
        seed_db_at(dir.path(), MIGRATIONS, MIGRATIONS.len());
        let conn = Connection::open(dir.path().join(DB_FILE_NAME)).unwrap();
        let mut written = Vec::new();
        for _ in 0..crate::backup::PRE_MIGRATION_KEEP + 2 {
            written
                .push(crate::backup::snapshot_before_migration(&conn, dir.path(), 1, 2).unwrap());
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        let kept = pre_migration_snapshots(dir.path());
        assert_eq!(
            kept,
            written[written.len() - crate::backup::PRE_MIGRATION_KEEP..]
        );
    }

    /// A wall-clock rollback makes the new snapshot sort oldest; it
    /// must still survive pruning.
    #[test]
    fn pruning_never_drops_the_snapshot_just_written() {
        let dir = tempdir_for_test();
        seed_db_at(dir.path(), MIGRATIONS, MIGRATIONS.len());
        let snap_dir = dir.path().join(crate::backup::PRE_MIGRATION_DIR);
        std::fs::create_dir_all(&snap_dir).unwrap();
        for i in 0..crate::backup::PRE_MIGRATION_KEEP {
            std::fs::write(
                snap_dir.join(format!("9999999999999-v{i}-to-v{}.db", i + 1)),
                b"",
            )
            .unwrap();
        }
        let conn = Connection::open(dir.path().join(DB_FILE_NAME)).unwrap();
        let fresh = crate::backup::snapshot_before_migration(&conn, dir.path(), 1, 2).unwrap();
        assert!(fresh.is_file());
        assert_eq!(
            pre_migration_snapshots(dir.path()).len(),
            crate::backup::PRE_MIGRATION_KEEP
        );
    }

    // ── M6: connection model ───────────────────────────────────────

    /// Generous bound for "this must happen eventually" waits. The
    /// tests below assert ordering and progress, never latency, so
    /// the bound only turns a deadlock into a failure.
    const PROGRESS_BOUND: Duration = Duration::from_secs(60);

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !cond() {
            assert!(
                start.elapsed() < PROGRESS_BOUND,
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn test_policy() -> ConnectionPolicy {
        ConnectionPolicy {
            // Long enough that a loaded machine can't turn the
            // priority-ordering test into a timeout race.
            low_priority_max_defer: PROGRESS_BOUND,
            ..ConnectionPolicy::default()
        }
    }

    fn custom_event(topic: &str) -> crate::host_impl::plugin::oxidhome::plugin::events::Event {
        use crate::host_impl::plugin::oxidhome::plugin::events::{
            CustomEvent, Event, EventPayload,
        };
        Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id: None,
            call_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: "{}".into(),
            }),
        }
    }

    fn insert_log_rows(conn: &Connection, n: usize) -> rusqlite::Result<()> {
        let mut stmt = conn.prepare(
            "INSERT INTO log_event(ts_unix_ms, level, target, message) VALUES (?1, 2, 't', 'burst')",
        )?;
        for i in 0..n {
            stmt.execute([i64::try_from(i).unwrap_or(i64::MAX)])?;
        }
        Ok(())
    }

    /// Every connection of a file-backed `Db` carries the busy and
    /// checkpoint policy; durable paths still start from NORMAL.
    #[test]
    fn file_db_applies_busy_and_checkpoint_policy() {
        let dir = tempdir_for_test();
        let db = Db::open_file(dir.path()).expect("open");
        let (busy, autockpt, limit, sync, query_only): (i64, i64, i64, i64, i64) = db
            .write(|c| -> rusqlite::Result<_> {
                Ok((
                    c.pragma_query_value(None, "busy_timeout", |r| r.get(0))?,
                    c.pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))?,
                    c.pragma_query_value(None, "journal_size_limit", |r| r.get(0))?,
                    c.pragma_query_value(None, "synchronous", |r| r.get(0))?,
                    c.pragma_query_value(None, "query_only", |r| r.get(0))?,
                ))
            })
            .expect("writer pragmas");
        let expected_busy = i64::try_from(BUSY_TIMEOUT.as_millis()).expect("fits");
        assert_eq!(busy, expected_busy);
        assert_eq!(autockpt, WAL_AUTOCHECKPOINT_PAGES);
        assert_eq!(limit, JOURNAL_SIZE_LIMIT_BYTES);
        assert_eq!(sync, 1, "writer baseline is synchronous = NORMAL");
        assert_eq!(query_only, 0);

        let (reader_busy, reader_query_only): (i64, i64) = db
            .read(|c| -> rusqlite::Result<_> {
                Ok((
                    c.pragma_query_value(None, "busy_timeout", |r| r.get(0))?,
                    c.pragma_query_value(None, "query_only", |r| r.get(0))?,
                ))
            })
            .expect("reader pragmas");
        assert_eq!(reader_busy, expected_busy);
        assert_eq!(reader_query_only, 1);
    }

    /// `read` really is read-only on a file-backed `Db`: a write
    /// attempted through it fails instead of bypassing the writer.
    #[test]
    fn pooled_reads_refuse_writes() {
        let dir = tempdir_for_test();
        let db = Db::open_file(dir.path()).expect("open");
        let err = db
            .read(|c| insert_log_rows(c, 1))
            .expect_err("query_only reader must refuse INSERT");
        assert!(
            err.to_string().contains("readonly") || err.to_string().contains("read-only"),
            "unexpected error: {err}",
        );
        let n: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(n, 0);
        // The failed lease was recycled or replaced; reads keep working.
        for _ in 0..(READ_POOL_SIZE * 2) {
            db.ping().expect("ping");
            let _: i64 = db
                .read(|c| c.query_row("SELECT 1", [], |r| r.get(0)))
                .expect("read after refused write");
        }
    }

    /// M6 evidence: while a large diagnostic-log batch holds the
    /// writer mid-transaction, (1) a KV read and an event-history
    /// query complete, seeing the pre-batch snapshot, and (2) an
    /// event-log append that queues behind the batch commits before
    /// the next log batch, even though that batch queued first.
    /// Before M6 both reads waited for the batch, and the next batch
    /// could win the mutex.
    ///
    /// No timing assertions: the batch is held open until the
    /// reads report back, and commit order is observed in the
    /// database itself.
    #[test]
    fn log_batch_blocks_neither_reads_nor_event_append() {
        use std::sync::mpsc;

        use crate::host_impl::plugin::oxidhome::plugin::types::Value as WitValue;
        use crate::state::{EventLog, EventQuery, KvStore};

        let dir = tempdir_for_test();
        let db = Arc::new(Db::open_file_with_policy(dir.path(), test_policy()).expect("open"));
        let kv = Arc::new(KvStore::new(Arc::clone(&db)));
        let events = Arc::new(EventLog::new(Arc::clone(&db)));
        kv.register_instance("inst-1", "alpha", 1024)
            .expect("register");
        kv.set(
            "inst-1",
            "alpha",
            "mode",
            WitValue::StringVal("away".into()),
        )
        .expect("kv set");
        events
            .record(1, &custom_event("before"), "alpha", "acme.test")
            .expect("seed event");

        // (1) A low-priority "log batch" takes the writer, inserts a
        // large batch, and holds the transaction open until told.
        let (holding_tx, holding_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let batch = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.write_low_priority(|c| -> rusqlite::Result<()> {
                    let tx =
                        c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    insert_log_rows(&tx, 5_000)?;
                    holding_tx.send(()).expect("signal holding");
                    release_rx.recv().expect("release");
                    tx.commit()
                })
            })
        };
        holding_rx
            .recv_timeout(PROGRESS_BOUND)
            .expect("batch holds the writer");

        let (read_tx, read_rx) = mpsc::channel();
        {
            let kv = Arc::clone(&kv);
            let events = Arc::clone(&events);
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                let value = kv.get("inst-1", "alpha", "mode").expect("kv get");
                let history = events.query(&EventQuery::default(), 10).expect("history");
                let logs: i64 = db
                    .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
                    .expect("log count");
                read_tx.send((value, history.len(), logs)).expect("report");
            });
        }
        let (value, history, logs) = read_rx
            .recv_timeout(PROGRESS_BOUND)
            .expect("reads must complete while the log batch holds the writer");
        assert!(matches!(value, Some(WitValue::StringVal(ref s)) if s == "away"));
        assert_eq!(history, 1);
        assert_eq!(logs, 0, "the uncommitted batch is invisible to readers");

        // (2) Priority: the next log batch queues first, then an
        // event append. The append still commits first: the batch,
        // once it runs, already sees the appended row.
        let next_batch = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.write_low_priority(|c| -> rusqlite::Result<i64> {
                    insert_log_rows(c, 1)?;
                    c.query_row(
                        "SELECT COUNT(*) FROM event_log WHERE topic = 'control'",
                        [],
                        |r| r.get(0),
                    )
                })
                .expect("next batch")
            })
        };
        wait_until("the next log batch to queue on the writer", || {
            db.waiting_low_priority_writers() == 1
        });
        let append = {
            let events = Arc::clone(&events);
            std::thread::spawn(move || {
                events
                    .record(2, &custom_event("control"), "alpha", "acme.test")
                    .expect("append")
            })
        };
        wait_until("the event append to queue on the writer", || {
            db.waiting_writers() == 1
        });
        release_tx.send(()).expect("release batch");
        batch.join().expect("batch thread").expect("batch commit");
        let append_id = append.join().expect("append thread");
        let control_rows_seen_by_batch = next_batch.join().expect("next batch thread");
        assert!(append_id > 0);
        assert_eq!(
            control_rows_seen_by_batch, 1,
            "the queued event append must commit before the queued log batch",
        );
        let logs: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("log count");
        assert_eq!(logs, 5_001);
    }

    /// A low-priority caller queued behind a hung writer leaves the
    /// queue once cancelled and woken, without running its closure,
    /// and the gate's counters are back to idle.
    #[test]
    fn cancelled_low_priority_wait_gives_up_its_place() {
        use std::sync::atomic::AtomicBool;
        let db = Arc::new(Db::open_in_memory().expect("db"));
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
        let cancel = Arc::new(AtomicBool::new(false));
        let waiter = {
            let db = Arc::clone(&db);
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                db.write_low_priority_unless(&|| cancel.load(Ordering::SeqCst), |_| {
                    Ok::<_, rusqlite::Error>("ran")
                })
            })
        };
        wait_until("low-priority caller queued", || {
            db.waiting_low_priority_writers() == 1
        });
        cancel.store(true, Ordering::SeqCst);
        db.wake_low_priority_writers();
        assert_eq!(waiter.join().expect("waiter").expect("no error"), None);
        assert_eq!(db.waiting_low_priority_writers(), 0);
        assert_eq!(db.write_gate.lock_state().overdue, 0);
        release_tx.send(()).expect("release");
        holder.join().expect("holder");
        // Not cancelled: runs as usual.
        assert_eq!(
            db.write_low_priority_unless(&|| false, |_| Ok::<_, rusqlite::Error>(1))
                .expect("write"),
            Some(1)
        );
    }

    /// Run `who` on a thread that takes the gate and appends its
    /// label to `order` while it owns the writer.
    fn gate_contender(
        gate: &Arc<WriteGate>,
        order: &Arc<Mutex<Vec<&'static str>>>,
        who: &'static str,
        low_defer: Option<Duration>,
    ) -> std::thread::JoinHandle<()> {
        let gate = Arc::clone(gate);
        let order = Arc::clone(order);
        std::thread::spawn(move || {
            let _ticket = match low_defer {
                Some(defer) => gate.acquire_low(defer, &|| false).expect("admitted"),
                None => gate.acquire_normal(),
            };
            order.lock().unwrap().push(who);
        })
    }

    /// An overdue low-priority caller gets the next turn ahead of a
    /// queued normal-priority caller (no starvation), and two
    /// overdue low-priority callers alternate with normal ones
    /// instead of running back to back.
    #[test]
    fn overdue_low_priority_gets_a_turn_but_not_two_in_a_row() {
        let gate = Arc::new(WriteGate::default());
        let order = Arc::new(Mutex::new(Vec::new()));
        let held = gate.acquire_normal();
        let low_a = gate_contender(&gate, &order, "low-a", Some(Duration::ZERO));
        wait_until("low-a overdue", || gate.lock_state().overdue == 1);
        let low_b = gate_contender(&gate, &order, "low-b", Some(Duration::ZERO));
        wait_until("low-b overdue", || gate.lock_state().overdue == 2);
        let normal = gate_contender(&gate, &order, "normal", None);
        wait_until("normal queued", || gate.lock_state().normal_waiting == 1);
        drop(held);
        for t in [low_a, low_b, normal] {
            t.join().expect("contender");
        }
        let order = order.lock().unwrap().clone();
        assert_eq!(order.len(), 3);
        assert!(
            order[0].starts_with("low"),
            "overdue low goes first: {order:?}"
        );
        assert_eq!(order[1], "normal", "then the queued normal: {order:?}");
        assert!(order[2].starts_with("low"), "{order:?}");
    }

    /// A read closure sees one snapshot even if a write commits
    /// between its statements (the isolation the single mutex used
    /// to give).
    #[test]
    fn pooled_read_sees_one_snapshot() {
        use std::sync::mpsc;
        let dir = tempdir_for_test();
        let db = Arc::new(Db::open_file(dir.path()).expect("open"));
        let (first_tx, first_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let reader = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.read(|c| -> rusqlite::Result<(i64, i64)> {
                    let a: i64 = c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0))?;
                    first_tx.send(()).expect("signal");
                    // Bounded, so a regression where reads hold the
                    // writer fails instead of deadlocking.
                    go_rx.recv_timeout(PROGRESS_BOUND).expect("go");
                    let b: i64 = c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0))?;
                    Ok((a, b))
                })
            })
        };
        first_rx.recv_timeout(PROGRESS_BOUND).expect("first read");
        db.write(|c| insert_log_rows(c, 3))
            .expect("commit between reads");
        go_tx.send(()).expect("go");
        let (a, b) = reader.join().expect("reader").expect("read");
        assert_eq!((a, b), (0, 0));
        let now: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(now, 3);
    }

    /// The checkpointer thread runs passive checkpoints on its own
    /// connection and stops when the `Db` drops.
    #[test]
    fn checkpointer_runs_and_stops_with_db() {
        let dir = tempdir_for_test();
        let policy = ConnectionPolicy {
            checkpoint_interval: Duration::from_millis(5),
            ..ConnectionPolicy::default()
        };
        let db = Db::open_file_with_policy(dir.path(), policy).expect("open");
        db.write(|c| insert_log_rows(c, 100)).expect("insert");
        // The rows reach the main database file (not just the WAL)
        // while the `Db` is alive and idle: a copy of the main file
        // alone, opened without its WAL, already holds them.
        let main_file = dir.path().join(DB_FILE_NAME);
        let snap_dir = tempdir_for_test();
        let snap = snap_dir.path().join("snap.db");
        wait_until("a checkpoint of the seeded rows", || {
            if db.checkpoints_run() == 0 {
                return false;
            }
            if std::fs::copy(&main_file, &snap).is_err() {
                return false;
            }
            let count = Connection::open(&snap).and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get::<_, i64>(0))
            });
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(snap_dir.path().join(format!("snap.db{suffix}")));
            }
            matches!(count, Ok(100))
        });
        let worker = Arc::downgrade(
            &db.checkpointer
                .as_ref()
                .expect("file db has a checkpointer")
                .shared,
        );
        drop(db);
        assert!(
            worker.upgrade().is_none(),
            "the checkpointer thread must have exited before Db::drop returned",
        );
        // Reopen proves no connection or lock leaked from the drop.
        let db = Db::open_file(dir.path()).expect("reopen");
        let n: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(n, 100);
    }

    /// A dangling `oxidhome.db` symlink: the writer creates its
    /// target, and later reader opens follow the writer even after
    /// the link is retargeted.
    #[cfg(unix)]
    #[test]
    fn readers_follow_the_file_the_writer_opened() {
        let dir = tempdir_for_test();
        let targets = tempdir_for_test();
        let first = targets.path().join("first.db");
        let link = dir.path().join(DB_FILE_NAME);
        std::os::unix::fs::symlink(&first, &link).expect("dangling link");
        let db = Db::open_file(dir.path()).expect("open");
        db.write(|c| insert_log_rows(c, 2)).expect("insert");
        // Retarget the link at a different, valid database.
        let other = Db::open_file(targets.path()).expect("other db");
        drop(other);
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(targets.path().join(DB_FILE_NAME), &link).expect("relink");
        let n: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(
            n, 2,
            "the reader must open the writer's file, not the new link target"
        );
    }

    /// The writer's path comes from `PRAGMA database_list`, so it
    /// matches what `rusqlite` reports for a UTF-8 path.
    #[test]
    fn opened_main_path_matches_connection_path() {
        let dir = tempdir_for_test();
        let file = std::fs::canonicalize(dir.path())
            .expect("canonical")
            .join(DB_FILE_NAME);
        let conn = Connection::open(&file).expect("open");
        let opened = opened_main_path(&conn).expect("path");
        assert_eq!(opened.to_str(), conn.path());
        assert_eq!(opened, file);
        let mem = Connection::open_in_memory().expect("memory");
        assert!(opened_main_path(&mem).is_err(), "`:memory:` has no file");
    }

    /// M6 follow-up: when the file the writer resolves has a
    /// non-UTF-8 path (`Connection::path()` is `None`), readers are
    /// still pinned to it: the bytes come from `PRAGMA
    /// database_list` instead of a re-resolve that a retargeted
    /// symlink could redirect. Skipped where the filesystem refuses
    /// non-UTF-8 names (APFS).
    #[cfg(unix)]
    #[test]
    fn readers_follow_a_non_utf8_writer_path() {
        use std::os::unix::ffi::OsStrExt as _;
        let base = tempdir_for_test();
        let odd = base
            .path()
            .join(std::ffi::OsStr::from_bytes(b"target-\xff\xfe"));
        if std::fs::create_dir(&odd).is_err() {
            return;
        }
        let odd = std::fs::canonicalize(&odd).expect("canonical");
        let dir = tempdir_for_test();
        let targets = tempdir_for_test();
        let link = dir.path().join(DB_FILE_NAME);
        let first = odd.join("first.db");
        std::os::unix::fs::symlink(&first, &link).expect("dangling link");

        let probe = Connection::open(&link).expect("probe open");
        assert_eq!(probe.path(), None, "rusqlite can't report a non-UTF-8 path");
        assert_eq!(opened_main_path(&probe).expect("raw path"), first);
        drop(probe);

        let db = Db::open_file(dir.path()).expect("open");
        db.write(|c| insert_log_rows(c, 3)).expect("insert");
        drop(Db::open_file(targets.path()).expect("other db"));
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(targets.path().join(DB_FILE_NAME), &link).expect("relink");
        let n: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM log_event", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(
            n, 3,
            "the reader must open the writer's file, not the new link target"
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
