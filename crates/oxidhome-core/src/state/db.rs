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
    // Migration 9 — architecture-review C3 dedicated audit ledger.
    //
    // Every API request lands here, synchronously from the middleware
    // before the handler executes. Separate from `log_event` (which
    // is the drop-tolerant diagnostic stream) so audit rows can't be
    // evicted by a burst of debug logs — the whole point of C3.
    //
    // The row is written in **two phases**:
    //
    // 1. `record_intent` at the top of the middleware. Inserts with
    //    `decision = "pending"`, `status = 0`, `finalized_ms = NULL`.
    //    Committing this row *before* the handler runs is what makes
    //    the ledger cancellation-safe: if the client disconnects
    //    mid-handler (a common exploit path — `spawn_blocking`
    //    handler tasks continue after the request future is dropped),
    //    the intent row stays behind as evidence of the attempted
    //    action, unambiguously flagged as unfinished. Fail-closed —
    //    if the insert errors, the middleware refuses the request
    //    with 500 rather than executing an unauditable operation.
    // 2. `finalize` after the handler returns. UPDATEs the pending
    //    row with the outcome (`allow` / `deny` / `error`), the
    //    final HTTP status, `required_scope` (populated only on
    //    scope-deny 403s), and stamps `finalized_ms`. Best-effort:
    //    a finalize failure logs an ERROR but doesn't undo the
    //    handler's already-committed side effects — the operator
    //    still sees the pending row and knows something is wrong.
    //
    // Single-shot writes (`record_completed`) are used for
    // unauthenticated probes — no handler runs, so the outcome is
    // known at insert time. That path fills `finalized_ms` immediately
    // and records `token_id = "anonymous"` + a `credential_fp` short
    // SHA-256 prefix (never the raw presented secret) so a
    // forensic sweep can correlate probes without giving an
    // attacker anything to verify a guess against.
    //
    // See `state::audit_log` for the write path.
    //
    // Indexes:
    // - `audit_intent`   for time-range scans on `intent_ms`
    //                    (retention sweep + generic time-window
    //                    queries + "abandoned intents" —
    //                    `finalized_ms IS NULL AND intent_ms < ?`).
    // - `audit_token_ts` so forensic drill-down on a specific token
    //                    seeks the B-tree without a full scan.
    "
    CREATE TABLE audit_event (
      id             INTEGER PRIMARY KEY,
      intent_ms      INTEGER NOT NULL,
      finalized_ms   INTEGER,
      token_id       TEXT NOT NULL,
      actor_kind     TEXT NOT NULL,
      method         TEXT NOT NULL,
      path           TEXT NOT NULL,
      status         INTEGER NOT NULL,
      decision       TEXT NOT NULL,
      required_scope TEXT,
      credential_fp  TEXT
    ) STRICT;
    CREATE INDEX audit_intent   ON audit_event(intent_ms);
    CREATE INDEX audit_token_ts ON audit_event(token_id, intent_ms);
    ",
    // Migration 10 — architecture-review F4: split execution outcome
    // from authorization outcome on the audit ledger.
    //
    // Before this migration `decision` and `status` served two
    // purposes at once: they carried the *authorization* result
    // (allow / deny / error / pending) *and* the transport
    // classification, and — after PR #79's first cut of F4 — a
    // domain-execution failure was folded into the same fields via
    // a synthesized status. That conflation broke forensic queries:
    // a plugin returning `CommandResult::Err(InvalidArgument)` on
    // an authorized request would show up in `WHERE decision =
    // 'deny'` searches next to real authorization denials, and the
    // real wire status (HTTP 200) was overwritten.
    //
    // Two new nullable columns capture the execution outcome
    // separately:
    //
    // - `execution_outcome`: NULL when the request never reached
    //   the plugin (auth deny, dispatch NotFound, transport error),
    //   `"success"` when the plugin returned Ok / OkWithState, and
    //   `"failed"` when the plugin returned `CommandResult::Err`.
    // - `domain_error`: the WIT error kind
    //   (`"not_found"` / `"invalid_argument"` / `"permission_denied"`
    //   / `"unavailable"` / `"internal"`) on `execution_outcome =
    //   "failed"`, NULL otherwise.
    //
    // `status` returns to being the wire HTTP status, and `decision`
    // returns to being the pure authorization outcome. Every
    // pre-existing row is backfilled with NULLs for the new
    // columns (they'd been rolled up into `decision` / `status`
    // under the old semantics — leaving the values there preserves
    // the historical record without pretending to know which entries
    // were execution-failures vs. real denials).
    "
    ALTER TABLE audit_event ADD COLUMN execution_outcome TEXT;
    ALTER TABLE audit_event ADD COLUMN domain_error TEXT;
    ",
    // Migration 11 — architecture-review C1b: persistent
    // installation identity.
    //
    // C1 gave devices deterministic ids derived from
    // `(plugin_id, instance_id, local_id)` so restarts stopped
    // renumbering them. The reviewer flagged that a reusable
    // `plugin_id` string means uninstall + reinstall (or a
    // replacement plugin sharing the id) inherits every audit /
    // API / history reference from the previous installation.
    // C1b closes that hole by minting a fresh **installation
    // UUID** on every install and threading it through the
    // device-id derivation instead of the raw `plugin_id`.
    //
    // Row shape:
    // - `installation_uuid`: 32 random hex chars, prefix
    //   `inst-`. Minted on install; opaque to plugin authors.
    //   Feeds `stable_device_id` so a fresh install of the same
    //   `plugin_id` produces different device ids.
    // - `plugin_id`: the manifest id — human-facing name. Not
    //   unique across the table (multiple installs over time
    //   share the id but not the uuid). Uniqueness is enforced
    //   only for **live** rows via the partial index below, so
    //   `install` refuses "already installed" while `uninstall`
    //   sets `uninstalled_ms` (tombstone) and a subsequent
    //   `install` inserts a fresh row.
    // - `version`: manifest version at install time.
    // - `installed_ms` / `uninstalled_ms`: host wall-clock at
    //   the transition. `uninstalled_ms IS NULL` means the row
    //   is live; not-null is a tombstone.
    "
    CREATE TABLE plugin_installation (
      installation_uuid TEXT PRIMARY KEY,
      plugin_id         TEXT NOT NULL,
      version           TEXT NOT NULL,
      installed_ms      INTEGER NOT NULL,
      uninstalled_ms    INTEGER
    ) STRICT;
    CREATE UNIQUE INDEX plugin_installation_live
      ON plugin_installation(plugin_id)
      WHERE uninstalled_ms IS NULL;
    ",
    // Migration 12 — architecture-review C5: split requested
    // capabilities (what the plugin declared in its manifest)
    // from granted capabilities (what the host approved for this
    // install). Runtime gates consult the grant, not the manifest
    // — so an operator can, in a future PR, narrow the grant
    // (or fail the install altogether) without editing the
    // plugin's manifest.
    //
    // v1: `granted_capabilities_json` is set at install time to
    // a verbatim JSON serialization of the manifest's
    // `[capabilities]` block. That preserves current behavior
    // while establishing the split so a follow-up can add an
    // operator override endpoint without a schema change or a
    // second migration wave. `NULL` (backfilled pre-C5 rows or
    // deserialization failure) means "fall back to the
    // manifest's requested capabilities" — see
    // `InstalledPluginRegistry::install` and `scan`.
    "
    ALTER TABLE plugin_installation ADD COLUMN granted_capabilities_json TEXT;
    ",
    // Migration 13 — architecture-review C5 review F3:
    // content-bound grants.
    //
    // Persist a SHA-256 digest over the installed plugin's
    // manifest + wasm + assets at install time. Load-time
    // verification compares the stored digest against a fresh
    // recompute so an in-place `plugin.wasm` swap runs under a
    // NULL grant (dev fallback) rather than the previously-issued
    // one. Combined with C5's grant column and the C5 review F1
    // quarantine, that means every production load either matches
    // an issued grant against an unchanged package or refuses to
    // apply the grant at all. NULL for pre-C5 rows — those are
    // quarantined by scan alongside NULL-grant rows, so an
    // operator's reinstall re-issues both fields together.
    "
    ALTER TABLE plugin_installation ADD COLUMN content_digest TEXT;
    ",
    // Migration 14 — architecture-review H2: rekey per-instance state
    // on the host-minted installation identity.
    //
    // Before this migration `kv`, `kv_usage`, `blob`, and `blob_usage`
    // all keyed on the caller-supplied `instance_id` alone. That
    // string is a plugin-author-chosen identifier — an uninstall
    // followed by a fresh `install` of the same (or a colliding)
    // `plugin_id` inherited every stored value from the previous
    // installation, sidestepping the fresh grant that C1b / C5 mint
    // at install time. H2 closes the hole by qualifying every row
    // with the host-minted `installation_uuid`.
    //
    // Uninstall now calls `purge_installation` on each store, which
    // deletes every row (KV + blob index + FS bytes) that carries
    // the tombstoned installation's uuid — so a subsequent reinstall
    // starts with an empty per-instance keyspace and no orphan blob
    // files.
    //
    // Legacy rows written under migrations 1–7 don't carry an
    // installation_uuid we could truthfully backfill. Pre-1.0 the
    // acceptable path is to DROP those rows so the invariant
    // ("every state row is tied to a live install") holds from this
    // migration onward. Operators upgrading with existing plugin
    // KV/blob data will need to reinstall to repopulate; the audit
    // trail (`audit_event`, `event_log`, `log_event`) is untouched.
    //
    // Table shape:
    // - `kv (installation_uuid, instance_id, key)` composite PK.
    // - `kv_usage (installation_uuid, instance_id)` composite PK.
    // - `blob (installation_uuid, instance_id, name)` composite PK,
    //   UNIQUE index on `(installation_uuid, instance_id, id)`.
    // - `blob_usage (installation_uuid, instance_id)` composite PK.
    //
    // Triggers are rewritten to match the composite key on both
    // sides of the `UPDATE ... WHERE` so accounting stays per-tuple.
    "
    DROP TRIGGER kv_usage_insert;
    DROP TRIGGER kv_usage_delete;
    DROP TRIGGER kv_usage_update;
    DROP TRIGGER blob_usage_insert;
    DROP TRIGGER blob_usage_delete;
    DROP TRIGGER blob_usage_update;

    -- Pre-H2 rows can't be truthfully attributed to any installation_uuid,
    -- so drop them and recreate the tables with the new key shape. See
    -- the migration header for the rationale.
    DROP TABLE kv;
    DROP TABLE kv_usage;
    DROP INDEX blob_by_id;
    DROP TABLE blob;
    DROP TABLE blob_usage;

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

    CREATE TABLE blob (
        installation_uuid TEXT NOT NULL,
        instance_id       TEXT NOT NULL,
        name              TEXT NOT NULL,
        id                TEXT NOT NULL,
        size_bytes        INTEGER NOT NULL,
        created_ms        INTEGER NOT NULL,
        mime              TEXT,
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
    ",
    // Migration 15 — Phase 13 slice 3: dashboard storage.
    //
    // User-composed dashboards (rows of widgets, per the UI
    // architecture design note). Persisted centrally so the
    // shell can show the same dashboard on any browser the
    // operator logs in from, and so a host restart doesn't
    // lose the layout.
    //
    // `layout_json` is the tree the shell serializes — the
    // host treats it as opaque bytes; the *shape* is the
    // shell's contract with itself, versioned by
    // `schema_version` so a widget catalog change (widget
    // renamed / removed / config-shape migrated) can drive
    // a declarative shell-side transform on load.
    //
    // `owner_user_id` is v1's row-level ownership key. Every
    // row carries the stable literal `"admin"` (see
    // `DASHBOARD_ADMIN_OWNER` in `oxidhome-core::api::server`
    // and the Phase 13 round-2 F2 doc trail on
    // `state::dashboards`). It is deliberately NOT the
    // Phase 12 `Actor::id()` — that returns a per-token id
    // that rotates when the operator mints a new token,
    // which would silo dashboards per-token and strand rows
    // on rotation. The multi-user follow-up will require a
    // one-line migration to map the placeholder onto the
    // real session identity:
    // `UPDATE dashboard SET owner_user_id = <real id> WHERE owner_user_id = 'admin'`.
    // `created_ms` / `updated_ms` are host wall-clock — the
    // shell shows relative timestamps off them.
    //
    // `by_owner` index is what the list-dashboards endpoint
    // scans; primary-key ordering happens to match creation
    // order which is fine for the common case.
    "
    CREATE TABLE dashboard (
        id            INTEGER PRIMARY KEY,
        name          TEXT NOT NULL,
        owner_user_id TEXT NOT NULL,
        layout_json   BLOB NOT NULL,
        schema_version INTEGER NOT NULL DEFAULT 1,
        created_ms    INTEGER NOT NULL,
        updated_ms    INTEGER NOT NULL
    );
    CREATE INDEX dashboard_by_owner ON dashboard(owner_user_id);
    ",
    // 16 — Phase 14.3 follow-up (round-3 P1 on PR #157):
    // switch `event_log.id` from plain `INTEGER PRIMARY KEY`
    // to `INTEGER PRIMARY KEY AUTOINCREMENT`.
    //
    // Without `AUTOINCREMENT`, `INTEGER PRIMARY KEY` is a
    // ROWID alias — SQLite reuses ids after a DELETE removes
    // the current max. Retention (`DELETE FROM event_log
    // WHERE received_ms < ?1`) normally deletes the oldest
    // rows (lowest ids) so reuse can't fire, BUT under a
    // wall-clock rollback a *fresh* insert lands with a
    // lower `received_ms` and a higher id — retention then
    // deletes that fresh row (matches the cutoff) and the
    // next insert reuses its id. A durable MCP-subscribe
    // cursor at `after_id = <reused id>` would then see the
    // NEW row as an already-seen event and miss it.
    //
    // `AUTOINCREMENT` binds ids to a monotonic counter in
    // `sqlite_sequence` so a reused id is never issued. The
    // migration rebuilds `event_log` in place — SQLite has
    // no `ALTER TABLE` for this — preserving every row's
    // existing id (and recreating every index, the filter
    // ones rekeyed to `(col, id)` — see below) so any client
    // that already saved an `after_id` cursor keeps working.
    // Copying the rows with their explicit ids makes SQLite
    // seed the `sqlite_sequence` counter at the max existing
    // id, so post-migration inserts continue from there.
    "
    CREATE TABLE event_log_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        received_ms   INTEGER NOT NULL,
        payload_ms    INTEGER NOT NULL,
        device_id     TEXT,
        instance_id   TEXT NOT NULL,
        plugin_id     TEXT NOT NULL,
        topic         TEXT NOT NULL,
        payload_blob  BLOB NOT NULL
    );

    INSERT INTO event_log_new
        (id, received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob)
    SELECT id, received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob
      FROM event_log;

    DROP TABLE event_log;
    ALTER TABLE event_log_new RENAME TO event_log;

    -- No explicit `sqlite_sequence` seed. `AUTOINCREMENT`
    -- tables track their high-water mark automatically: an
    -- INSERT with an explicit id ≥ the current seq raises
    -- the seq to that id (see SQLite `AUTOINCREMENT` docs).
    -- The bulk copy above already advanced the sequence to
    -- `MAX(id)`; a manual `INSERT OR REPLACE INTO
    -- sqlite_sequence(name, seq)` would create a *duplicate*
    -- row because the table has no unique constraint on
    -- `name`, and AUTOINCREMENT might then read either row.
    -- Round-4 P1 on PR #157.

    -- Filter indexes are keyed `(col, id)`, not `(col,
    -- received_ms)`: `EventLog::query` now orders by `id`
    -- and pages on `id` cursors, so `(col, id)` lets SQLite
    -- seek `col = ? AND id > ?` and stream rows in ORDER BY
    -- order. The old time-keyed shape forced a scan of every
    -- matching row plus a temp B-tree sort per query (round-8
    -- P2). `evt_received` stays for retention + `since`.
    CREATE INDEX evt_received ON event_log(received_ms);
    CREATE INDEX evt_device   ON event_log(device_id, id) WHERE device_id IS NOT NULL;
    CREATE INDEX evt_topic    ON event_log(topic, id);
    CREATE INDEX evt_instance ON event_log(instance_id, id);
    CREATE INDEX evt_plugin   ON event_log(plugin_id, id);
    ",
    // 17 — architecture-review H6: invocation context on the audit
    // ledger. Every authenticated request now runs under a
    // host-minted `call_id`; the entry point's row and every
    // downstream row it causes (delegated `call-service` hops,
    // `method = 'CALL'`) carry the same id plus a JSON summary of
    // the root principal and delegation chain. Both nullable:
    // pre-17 rows and anonymous probes have no invocation. The
    // partial index serves `GET /api/v1/audit?call_id=…`.
    "
    ALTER TABLE audit_event ADD COLUMN call_id TEXT;
    ALTER TABLE audit_event ADD COLUMN invocation_json TEXT;
    CREATE INDEX audit_call ON audit_event(call_id) WHERE call_id IS NOT NULL;
    ",
    // 18 — architecture-review H5 / ADR-0003: explicit device-command
    // outcomes. A device-command row carries the host-minted
    // `command_id` and its outcome (`accepted` / `completed` /
    // `rejected` / `timed_out` / `outcome_unknown`); the
    // `method = 'COMMAND'` resolution rows written when an accepted
    // command completes or expires carry the same id. Both nullable:
    // every other row leaves them NULL.
    "
    ALTER TABLE audit_event ADD COLUMN command_id TEXT;
    ALTER TABLE audit_event ADD COLUMN command_outcome TEXT;
    ",
    // 19 — architecture-review H2: durable device-state projection.
    // One row per `(device_id, capability)` slot of the in-memory
    // `DeviceStateStore`, written off the publish path by its
    // coalescing flusher. `device_state_meta` is a single row: the
    // store epoch, the revision the rows were flushed at, the stale
    // eviction watermark and the JSON list of revision ranges that
    // earlier boots skipped (cursors inside one must resync).
    "
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
    ",
    // 20 — architecture-review H5 / ADR-0003 follow-up: pending
    // `accepted` device commands survive a daemon restart. One row per
    // externally-rooted command a plugin answered with `accepted`,
    // written behind the command path by the engine's command-journal
    // writer and deleted in the same transaction as the command's
    // `COMMAND` resolution row. Rows still present at boot are
    // resolved to `outcome_unknown` (daemon restart, or expiry when
    // `expires_ms` already passed). The audit linkage columns copy the
    // request's `audit_event` attribution.
    "
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
    ",
    // 21 — H6 slice 2: sensitive device categories.
    //
    // - `auth_token.owner` marks the owner token: the one the host
    //   minted at first-run bootstrap or with `recover-admin-token`.
    //   The owner holds every sensitive category; every other
    //   wildcard token loses them. The flag is backfilled from the
    //   host's own audit rows for those two actions (`method = LOCAL`,
    //   which no API, Connect or MCP request can produce) on tokens
    //   that still hold exactly the minted `["*"]` scope, and set at
    //   insert by those two code paths from now on. It is a column
    //   rather than a lookup because audit retention prunes the rows.
    // - `audit_event.level`: `warn` on the extra row every allowed
    //   sensitive action writes; NULL (info) otherwise.
    // - `device_meta`: per device id, the sensitive categories the host
    //   has ever derived (a floor a plugin can't lower), the operator's
    //   category raise, and the registering instance. See
    //   `state::device_meta`. Backfilled with a `camera` floor for
    //   every device whose `video-stream` state is persisted, so the
    //   state restored before plugins load (and the instance's blobs)
    //   is camera data from the first read after upgrade. The other
    //   sensitive capabilities are new in this version.
    "
    ALTER TABLE auth_token ADD COLUMN owner INTEGER NOT NULL DEFAULT 0;
    UPDATE auth_token SET owner = 1
     WHERE CAST(scope_json AS TEXT) = '[\"*\"]'
       AND id IN (
         SELECT token_id FROM audit_event
          WHERE method = 'LOCAL'
            AND ((actor_kind = 'host' AND path = 'host.auth.bootstrap')
              OR (actor_kind = 'cli' AND path = 'cli.auth.recover')));
    ALTER TABLE audit_event ADD COLUMN level TEXT;
    CREATE TABLE device_meta (
        device_id          TEXT PRIMARY KEY NOT NULL,
        owner_instance     TEXT,
        sensitive_floor    TEXT NOT NULL,
        category_override  TEXT,
        updated_ms         INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    INSERT INTO device_meta(device_id, owner_instance, sensitive_floor, category_override, updated_ms)
    SELECT device_id, owner_instance, 'camera', NULL, 0
      FROM device_state WHERE capability = 'video-stream';
    ",
];

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
/// waiting on wall-clock time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectionPolicy {
    pub(crate) read_pool_size: usize,
    pub(crate) checkpoint_interval: Duration,
    pub(crate) low_priority_max_defer: Duration,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            read_pool_size: READ_POOL_SIZE,
            checkpoint_interval: CHECKPOINT_INTERVAL,
            low_priority_max_defer: LOW_PRIORITY_MAX_DEFER,
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
    /// `user_version` observed *before* this process open ran any
    /// migrations. Callers use this to detect "did migration N just
    /// run this boot" — the H2 round-2 F3 one-shot blob-root sweep
    /// checks `pre_open_user_version < 14` to decide whether to
    /// reclaim legacy pre-migration-14 blob trees. `0` for a fresh
    /// (empty) database.
    pre_open_user_version: i64,
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
        // Read the on-file `user_version` before touching the
        // schema, so callers can distinguish "we just applied
        // migration N this open" from "N had already been applied
        // in a prior process." The H2 round-2 F3 blob-root sweep
        // uses this to run its one-shot cleanup exactly once, on
        // the first boot after the migration-14 upgrade.
        let pre_open_user_version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("reading user_version pre-migration")?;
        let target = schema_version();
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
            pre_open_user_version,
            audit_boot_floor: std::sync::OnceLock::new(),
        };
        db.apply_migrations()?;
        Ok(db)
    }

    /// H2 round-2 F3: the `user_version` this process observed
    /// *before* running any migrations. Zero for a fresh DB.
    /// Called by [`crate::Engine::with_state_dir`] to decide
    /// whether the one-shot blob-root sweep should run (only
    /// when `pre_open_user_version < 14` — i.e., migration 14
    /// just applied this boot).
    #[must_use]
    pub fn pre_open_user_version(&self) -> i64 {
        self.pre_open_user_version
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
            .field("pre_open_user_version", &self.pre_open_user_version)
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

    /// Round-5 P2 on PR #157: exercise the ACTUAL v15→v16
    /// migration path, not just the post-migration
    /// behaviour. Simulates a persisted v15 database
    /// (`event_log` without `AUTOINCREMENT`) by:
    ///
    /// 1. Opening a Db (runs every migration, through 16), then
    ///    reverting to v15 shape: DROP the post-16
    ///    `event_log`, recreate it under the pre-16
    ///    `INTEGER PRIMARY KEY` schema, INSERT rows with
    ///    known ids, PRAGMA `user_version` = 15.
    /// 2. Reopening the same file — `apply_migrations`
    ///    sees `user_version = 15 < 16` and runs migration
    ///    16 exactly.
    ///
    /// Then asserts: `user_version = 16`, existing rows
    /// preserved verbatim (id + payload), no duplicate
    /// `sqlite_sequence` rows, AUTOINCREMENT high-water
    /// tracked correctly (next insert gets `max_existing +
    /// 1`, and reissuing after deleting that new max still
    /// bumps rather than reuses).
    // Two-phase reopen + full post-migration invariant sweep
    // — splitting into per-assertion helpers would obscure
    // the "same file, closed and reopened, migration ran"
    // narrative the test depends on.
    #[test]
    fn migration_21_backfills_the_owner_from_bootstrap_audit_rows() {
        let dir = tempdir_for_test();
        {
            let db = Db::open_file(dir.path()).expect("open");
            db.write(|conn| -> rusqlite::Result<()> {
                conn.execute_batch(
                    "
                    DROP TABLE device_meta;
                    ALTER TABLE audit_event DROP COLUMN level;
                    ALTER TABLE auth_token DROP COLUMN owner;
                    INSERT INTO auth_token(id, label, hash, scope_json, created_ms)
                    VALUES ('boot', 'admin', X'01', CAST('[\"*\"]' AS BLOB), 1),
                           ('recovered', 'admin', X'02', CAST('[\"*\"]' AS BLOB), 2),
                           ('minted', 'admin', X'03', CAST('[\"*\"]' AS BLOB), 3),
                           ('spoof', 'x', X'04', CAST('[\"*\"]' AS BLOB), 4),
                           ('narrowed', 'x', X'05', CAST('[\"devices:list\"]' AS BLOB), 5);
                    INSERT INTO audit_event(intent_ms, token_id, actor_kind, method, path, status, decision)
                    VALUES (1, 'boot', 'host', 'LOCAL', 'host.auth.bootstrap', 200, 'allow'),
                           (2, 'recovered', 'cli', 'LOCAL', 'cli.auth.recover', 200, 'allow'),
                           -- Wrong actor or method: an API request can't
                           -- forge the owner by its path.
                           (3, 'spoof', 'api', 'POST', 'host.auth.bootstrap', 200, 'allow'),
                           (4, 'spoof', 'api', 'LOCAL', 'host.auth.bootstrap', 200, 'allow'),
                           (5, 'narrowed', 'host', 'LOCAL', 'host.auth.bootstrap', 200, 'allow');
                    INSERT INTO device_state(device_id, capability, owner_instance, owner_plugin,
                        owner_install, fields_blob, global_revision, received_ms, observed_ms,
                        source_generation, quality)
                    VALUES ('dev-00000000000000aa', 'video-stream', 'cam', 'p', 'u', X'00', 1, 1, 1, 1, 'ok'),
                           ('dev-00000000000000bb', 'on-off', 'cam', 'p', 'u', X'00', 2, 1, 1, 1, 'ok');
                    PRAGMA user_version = 20;
                    ",
                )
            })
            .expect("rewind to v20");
        }
        let db = Db::open_file(dir.path()).expect("reopen");
        let owners: Vec<String> = db
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT id FROM auth_token WHERE owner = 1 ORDER BY id")?;
                stmt.query_map([], |r| r.get(0))?.collect()
            })
            .expect("owners");
        assert_eq!(owners, vec!["boot".to_string(), "recovered".to_string()]);
        let floors: Vec<(String, String, String)> = db
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT device_id, owner_instance, sensitive_floor FROM device_meta",
                )?;
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect()
            })
            .expect("floors");
        assert_eq!(
            floors,
            vec![(
                "dev-00000000000000aa".to_string(),
                "cam".to_string(),
                "camera".to_string()
            )]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn migration_16_from_v15_preserves_ids_and_enables_autoincrement() {
        let dir = tempdir_for_test();

        // Phase 1: open, drop the post-16 event_log, seed a
        // pre-16 event_log with fixed ids, roll user_version
        // back to 15.
        {
            let db = Db::open_file(dir.path()).expect("open");
            db.write(|conn| -> rusqlite::Result<()> {
                conn.execute_batch(
                    "
                    -- Undo every migration after 16 so the file is a
                    -- genuine v15 state; reopening re-applies them.
                    -- 21 (H6 slice 2): owner flag, audit level,
                    -- device categories.
                    DROP TABLE device_meta;
                    ALTER TABLE audit_event DROP COLUMN level;
                    ALTER TABLE auth_token DROP COLUMN owner;
                    -- 20 (H5): pending commands.
                    DROP TABLE pending_command;
                    -- 19 (H2): device-state tables.
                    DROP TABLE device_state;
                    DROP TABLE device_state_meta;
                    -- 18 (H5): audit_event command columns.
                    ALTER TABLE audit_event DROP COLUMN command_outcome;
                    ALTER TABLE audit_event DROP COLUMN command_id;
                    -- 17 (H6): audit_event invocation columns.
                    DROP INDEX audit_call;
                    ALTER TABLE audit_event DROP COLUMN invocation_json;
                    ALTER TABLE audit_event DROP COLUMN call_id;
                    DROP TABLE IF EXISTS event_log;
                    -- Pre-migration-16 schema: `INTEGER PRIMARY
                    -- KEY` without `AUTOINCREMENT` (ROWID
                    -- semantics).
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
                    -- Two rows with explicit ids so we can
                    -- assert preservation across the rebuild.
                    INSERT INTO event_log(id, received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob)
                    VALUES (5, 100, 100, NULL, 'alpha', 'example.alpha', 't', X'00');
                    INSERT INTO event_log(id, received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob)
                    VALUES (9, 200, 200, NULL, 'alpha', 'example.alpha', 't', X'01');
                    ",
                )?;
                // No `sqlite_sequence` cleanup needed: SQLite
                // deletes an AUTOINCREMENT table's sequence row
                // when the table is dropped, so the DROP above
                // already leaves the clean pre-16 state.
                Ok(())
            })
            .expect("seed pre-migration state");
            db.write(|conn| -> rusqlite::Result<()> {
                conn.execute_batch("PRAGMA user_version = 15")?;
                Ok(())
            })
            .expect("roll user_version back");
        }

        // Phase 2: reopen — `apply_migrations` sees v15 and
        // applies migration 16 onward.
        let db = Db::open_file(dir.path()).expect("reopen");

        let version: i64 = db
            .read(|c| c.pragma_query_value(None, "user_version", |row| row.get(0)))
            .expect("user_version");
        assert_eq!(
            version,
            i64::try_from(MIGRATIONS.len()).unwrap(),
            "migration 16 onward must have applied",
        );

        // Existing rows preserved verbatim.
        let (id_5_ms, id_9_ms): (i64, i64) = db
            .read(|c| -> rusqlite::Result<_> {
                let a: i64 =
                    c.query_row("SELECT received_ms FROM event_log WHERE id = 5", (), |r| {
                        r.get(0)
                    })?;
                let b: i64 =
                    c.query_row("SELECT received_ms FROM event_log WHERE id = 9", (), |r| {
                        r.get(0)
                    })?;
                Ok((a, b))
            })
            .expect("read preserved rows");
        assert_eq!((id_5_ms, id_9_ms), (100, 200));

        // No duplicate `sqlite_sequence` rows for
        // `event_log` (round-4 P1: the removed manual seed
        // used to append a duplicate row here).
        let seq_rows: i64 = db
            .read(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM sqlite_sequence WHERE name = 'event_log'",
                    (),
                    |r| r.get(0),
                )
            })
            .expect("count sqlite_sequence");
        assert_eq!(seq_rows, 1, "exactly one sqlite_sequence row expected");

        // High-water: seq = max existing id (9). Next
        // insert with implicit id must be 10, not 1.
        let next_id: i64 = db
            .write(|conn| -> rusqlite::Result<i64> {
                conn.execute(
                    "INSERT INTO event_log(received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob) \
                     VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
                    rusqlite::params![300_i64, 300_i64, "alpha", "example.alpha", "t", &b"\x02"[..]],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .expect("insert after migration");
        assert_eq!(
            next_id, 10,
            "post-migration insert must bump past MAX(id), not reuse",
        );

        // Round-4 P1: even after deleting that max, next
        // insert must NOT reuse id=10.
        db.write(|conn| -> rusqlite::Result<()> {
            conn.execute("DELETE FROM event_log WHERE id = 10", ())?;
            Ok(())
        })
        .expect("delete max");
        let after_delete: i64 = db
            .write(|conn| -> rusqlite::Result<i64> {
                conn.execute(
                    "INSERT INTO event_log(received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob) \
                     VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
                    rusqlite::params![400_i64, 400_i64, "alpha", "example.alpha", "t", &b"\x03"[..]],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .expect("insert after delete-max");
        assert_eq!(
            after_delete, 11,
            "AUTOINCREMENT must not reuse the deleted max id",
        );
    }

    /// Migration 2 has to fix up `kv_usage.bytes_used` for any
    /// instances that already accumulated character-counted totals
    /// under migration 1. Simulate that (on top of the current
    /// migration-14 schema — H2 rekeyed the `kv` / `kv_usage`
    /// tables to `(installation_uuid, instance_id)`) by:
    ///
    /// 1. Open a fresh file DB (runs every migration on empty
    ///    tables — nothing to re-baseline).
    /// 2. Hand-craft a drifted row: insert a non-ASCII key and
    ///    manually overwrite `bytes_used` with the character count
    ///    migration 1's triggers would have produced.
    /// 3. Run the migration-2 rebaseline body, rewritten against
    ///    the migration-14 shape (composite PK), and confirm
    ///    `bytes_used` jumps to the byte total.
    ///
    /// The invariant under test — "`bytes_used = SUM(length_of_key_in_bytes + length_of_value)`" —
    /// is the load-bearing bit of migration 2, and it still holds
    /// post-14. The column list changed but the math is the same.
    #[test]
    fn migration_2_rebaseline_corrects_drifted_bytes_used() {
        let dir = tempdir_for_test();
        let db = Db::open_file(dir.path()).expect("open");
        db.write(|conn| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO kv_usage(installation_uuid, instance_id, bytes_used, bytes_quota) \
                 VALUES (?1, ?2, 0, ?3)",
                rusqlite::params!["inst-test-0", "alpha", 4096_i64],
            )?;
            // The triggers (now migration-14-shape) account this
            // correctly on insert, so explicitly set `bytes_used` to
            // the character total a migration-1 trigger would have
            // produced: "αβγ" = 3 chars, value JSON = ~10 bytes.
            conn.execute(
                "INSERT INTO kv(installation_uuid, instance_id, key, value, updated_ms) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                rusqlite::params![
                    "inst-test-0",
                    "alpha",
                    "αβγ",
                    &b"{\"t\":\"Int\",\"v\":0}"[..]
                ],
            )?;
            // Force the drift: pretend the row was inserted under
            // migration 1's character-counting triggers. 3 (chars) +
            // 17 (payload bytes) = 20, where the byte-correct total
            // is 6 + 17 = 23.
            conn.execute(
                "UPDATE kv_usage SET bytes_used = 20 \
                 WHERE installation_uuid = 'inst-test-0' AND instance_id = 'alpha'",
                (),
            )?;
            Ok(())
        })
        .expect("seed drift");

        // Migration 2's rebaseline body, rewritten against the
        // composite `(installation_uuid, instance_id)` PK migration
        // 14 established for the `kv` / `kv_usage` tables.
        db.write(|conn| -> rusqlite::Result<()> {
            conn.execute_batch(
                "UPDATE kv_usage SET bytes_used = COALESCE((
                    SELECT SUM(length(CAST(key AS BLOB)) + length(value))
                      FROM kv
                     WHERE kv.installation_uuid = kv_usage.installation_uuid
                       AND kv.instance_id       = kv_usage.instance_id
                ), 0);",
            )?;
            Ok(())
        })
        .expect("rebaseline");

        let used: i64 = db
            .read(|conn| {
                conn.query_row(
                    "SELECT bytes_used FROM kv_usage \
                     WHERE installation_uuid = 'inst-test-0' AND instance_id = 'alpha'",
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

    /// Build `<dir>/oxidhome.db` at schema `version` by applying the
    /// first `version` migrations directly (no preflight).
    fn seed_db_at(dir: &Path, version: usize) {
        let conn = Connection::open(dir.join(DB_FILE_NAME)).expect("open seed db");
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", (), |r| r.get(0))
            .expect("wal");
        for body in &MIGRATIONS[..version] {
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
        let from = MIGRATIONS.len() - 1;
        seed_db_at(dir.path(), from);
        let db = Db::open_file(dir.path()).expect("open + migrate");
        let version: i64 = db
            .read(|c| c.pragma_query_value(None, "user_version", |r| r.get(0)))
            .unwrap();
        assert_eq!(version, schema_version());

        let snapshots = pre_migration_snapshots(dir.path());
        assert_eq!(snapshots.len(), 1, "{snapshots:?}");
        let name = snapshots[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            name.ends_with(&format!("-v{from}-to-v{}.db", schema_version())),
            "{name}"
        );
        let snap =
            Connection::open_with_flags(&snapshots[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let snap_version: i64 = snap
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(snap_version, i64::try_from(from).unwrap());
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
        let from = MIGRATIONS.len() - 1;
        seed_db_at(dir.path(), from);
        // A file where the snapshot directory should go.
        std::fs::write(dir.path().join(crate::backup::PRE_MIGRATION_DIR), b"x").unwrap();
        let err = Db::open_file(dir.path()).unwrap_err();
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
        seed_db_at(dir.path(), MIGRATIONS.len());
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
        seed_db_at(dir.path(), MIGRATIONS.len());
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
        seed_db_at(dir.path(), MIGRATIONS.len());
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
