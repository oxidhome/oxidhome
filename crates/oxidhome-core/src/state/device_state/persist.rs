//! H2: durable backing for the [`DeviceStateStore`].
//!
//! The in-memory store stays the source of truth while the daemon
//! runs; this module makes it survive a restart.
//!
//! - **Write path.** Every mutation marks its `(device, capability)`
//!   key dirty under the store lock (a set insert plus a condvar
//!   signal, no I/O). A flusher thread waits [`COALESCE`] after the
//!   first signal, takes the dirty set and the current values under
//!   one lock (so the batch is the store's state at one revision), and
//!   writes them in one normal-priority transaction. Publishing never
//!   waits on the disk: the H3 bus gate covers only the in-memory
//!   update. A failed flush puts the keys back and retries after
//!   [`RETRY_BACKOFF`]; the dirty set is bounded by
//!   [`MAX_DIRTY_KEYS`], past which the next flush rewrites the
//!   whole table.
//! - **Restore.** At boot the rows are loaded before any plugin runs,
//!   so reads are correct immediately. Every restored entry that was
//!   `fresh` is flipped to `stale` (with a new revision): a restored
//!   value is the last thing the owner reported, not a confirmation,
//!   and it stays `stale` until the owner republishes it
//!   (`register-device` initial state, a `state-changed` event or a
//!   command's `ok-with-state`). Supervisor generations continue from
//!   the highest restored one.
//! - **Revisions across a restart.** The store epoch is persisted, so
//!   it changes only when the projection itself is discarded (a new
//!   state directory). The flushed revision `R` is a consistent
//!   snapshot point, but the previous process may have issued
//!   revisions above `R` that were never flushed (a crash, a disk
//!   error). The restored store therefore continues from
//!   `R + REVISION_GAP` and records the skipped range `(R, R + GAP]` as
//!   a *hole*: a `/state/changes` cursor at or below `R` stays valid,
//!   a cursor inside a hole gets `reset_required`. The hole and the
//!   new base revision are written before the store serves anything,
//!   so a crash later in this life can't reuse those revisions. The
//!   newest [`MAX_HOLES`] holes are kept; older ones fold into the
//!   eviction watermark (cursors below it also reset).
//! - **What is lost.** Changes made after the last successful flush
//!   (at most [`COALESCE`] in steady state, longer while the disk is
//!   failing). Their cursors land in the hole and resync.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{DeviceState, DeviceStateStore, StateQuality, StoreInner};
use crate::host_impl::plugin::oxidhome::plugin::types::DeviceId;
use crate::state::Db;

type Key = (DeviceId, String);

/// How long the flusher waits after the first change before it writes,
/// so a burst of publishes costs one transaction.
pub(super) const COALESCE: Duration = Duration::from_millis(250);

/// Wait after a failed flush before the next attempt.
pub(super) const RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Revision distance a restored store skips past the last flushed
/// revision. Any revision the previous process issued without flushing
/// lands inside the skipped range unless it issued more than this many
/// unflushed changes. 2^32 per boot keeps revisions below 2^53 (the
/// JSON-number precision limit) for about two million restarts.
pub const REVISION_GAP: u64 = 1 << 32;

/// Skipped ranges kept for cursor checks.
pub(super) const MAX_HOLES: usize = 16;

/// Dirty keys tracked individually; past this the next flush rewrites
/// the table.
pub(super) const MAX_DIRTY_KEYS: usize = 16_384;

/// Wakes the flusher thread.
#[derive(Debug, Default)]
pub(super) struct FlushSignal {
    state: Mutex<SignalState>,
    cv: Condvar,
}

#[derive(Debug, Default)]
struct SignalState {
    pending: bool,
    closed: bool,
}

impl FlushSignal {
    fn lock(&self) -> std::sync::MutexGuard<'_, SignalState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self) {
        let mut st = self.lock();
        if !st.pending {
            st.pending = true;
            self.cv.notify_one();
        }
    }

    fn close(&self) {
        self.lock().closed = true;
        self.cv.notify_all();
    }

    /// Block until a flush is requested. `false` once closed.
    fn wait_pending(&self) -> bool {
        let mut st = self.lock();
        while !st.pending && !st.closed {
            st = self.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        }
        if st.closed {
            return false;
        }
        st.pending = false;
        true
    }

    /// Sleep for `d` unless closed first. Returns whether it closed.
    fn sleep(&self, d: Duration) -> bool {
        let st = self.lock();
        let (st, _) = self
            .cv
            .wait_timeout_while(st, d, |s| !s.closed)
            .unwrap_or_else(PoisonError::into_inner);
        st.closed
    }
}

/// Keys changed since the last flush.
#[derive(Debug)]
pub(super) struct Dirty {
    keys: BTreeSet<Key>,
    /// Too many keys to track: rewrite every row on the next flush.
    rewrite_all: bool,
    signal: Arc<FlushSignal>,
}

impl Dirty {
    pub(super) fn touch(&mut self, key: &Key) {
        if !self.rewrite_all {
            if self.keys.len() >= MAX_DIRTY_KEYS {
                self.rewrite_all = true;
                self.keys.clear();
            } else {
                self.keys.insert(key.clone());
            }
        }
        self.signal.notify();
    }

    fn is_empty(&self) -> bool {
        !self.rewrite_all && self.keys.is_empty()
    }
}

/// The database side of a persistent store.
#[derive(Debug)]
pub(super) struct Backing {
    db: Arc<Db>,
    signal: Arc<FlushSignal>,
    /// Serializes flushes (the flusher thread and an explicit
    /// [`DeviceStateStore::flush`]), so batches commit in the order
    /// they were taken.
    flush_lock: Mutex<()>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// A flush failed; the batch was re-queued.
#[derive(Debug, thiserror::Error)]
#[error("device-state flush failed: {0}")]
pub struct FlushError(String);

/// One consistent write: the store's state at `revision`.
struct FlushBatch {
    epoch: String,
    revision: u64,
    evicted_through: u64,
    holes: Vec<(u64, u64)>,
    upserts: Vec<Arc<DeviceState>>,
    deletes: Vec<Key>,
    rewrite_all: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredHole(u64, u64);

struct Meta {
    epoch: String,
    revision: u64,
    evicted_through: u64,
    holes: Vec<(u64, u64)>,
}

impl DeviceStateStore {
    /// H2: open the store backed by `db`: restore every persisted slot
    /// (see the module docs for the freshness and revision rules),
    /// persist the new revision base, and start the flusher thread.
    ///
    /// # Errors
    ///
    /// Reading the table, or writing the restored base, failed.
    pub fn open_persistent(db: Arc<Db>) -> anyhow::Result<Arc<Self>> {
        let (meta, rows) = load(&db)?;
        let signal = Arc::new(FlushSignal::default());
        let mut inner = StoreInner {
            dirty: Some(Dirty {
                keys: BTreeSet::new(),
                rewrite_all: false,
                signal: Arc::clone(&signal),
            }),
            ..StoreInner::default()
        };
        let restored = rows.len();
        let max_row_revision = rows.iter().map(|r| r.global_revision).max().unwrap_or(0);
        for row in rows {
            let generation = inner
                .generations
                .entry(row.owner_instance.clone())
                .or_insert(0);
            *generation = (*generation).max(row.source_generation);
            if !row.owner_plugin.is_empty() {
                inner
                    .owner_plugins
                    .insert(row.owner_instance.clone(), row.owner_plugin.clone());
            }
            inner.entries.insert(
                (row.device_id.clone(), row.capability.clone()),
                Arc::new(row),
            );
        }
        if let Some(meta) = meta {
            let flushed = meta.revision.max(max_row_revision);
            let base = flushed.saturating_add(REVISION_GAP);
            inner.epoch = meta.epoch;
            inner.evicted_through_revision = meta.evicted_through;
            inner.holes = meta.holes;
            inner.holes.push((flushed, base));
            if inner.holes.len() > MAX_HOLES {
                let excess = inner.holes.len() - MAX_HOLES;
                for (_, hi) in inner.holes.drain(..excess) {
                    inner.evicted_through_revision = inner.evicted_through_revision.max(hi);
                }
            }
            inner.global_revision = base;
        } else {
            inner.global_revision = max_row_revision;
        }
        // Restored values are unconfirmed until the owner republishes.
        let now = crate::state::event_log::now_unix_ms();
        let flipped =
            Self::stale_where_locked(&mut inner, now, |_, e| e.quality == StateQuality::Fresh);
        // A first boot (no meta row) still writes the meta row now, so
        // the epoch is durable before any client sees it.
        inner.dirty.as_mut().expect("set above").signal.notify();
        let store = Arc::new(Self {
            inner: std::sync::RwLock::new(inner),
            backing: Some(Backing {
                db,
                signal: Arc::clone(&signal),
                flush_lock: Mutex::new(()),
                thread: Mutex::new(None),
            }),
        });
        // Persist the base revision and hole before serving anything.
        store.flush_inner(true).map_err(|e| anyhow::anyhow!(e))?;
        tracing::info!(
            target: "device_state.persist",
            restored,
            marked_stale = flipped,
            revision = store.current_revision(),
            "device-state projection restored",
        );
        let handle = spawn_flusher(Arc::downgrade(&store), signal)?;
        *store
            .backing
            .as_ref()
            .expect("set above")
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(handle);
        Ok(store)
    }

    /// H2: write every pending change now. `Ok(false)` for a store
    /// without a backing database.
    ///
    /// # Errors
    ///
    /// The write failed; the changes stay queued for the next flush.
    pub fn flush(&self) -> Result<bool, FlushError> {
        self.flush_inner(false)
    }

    /// H2: final flush at shutdown, then stop the flusher thread.
    /// Returns whether everything was written.
    pub fn close_persistence(&self) -> bool {
        let Some(backing) = &self.backing else {
            return true;
        };
        let ok = match self.flush() {
            Ok(_) => true,
            Err(err) => {
                tracing::error!(
                    target: "device_state.persist",
                    error = %err,
                    "final device-state flush failed; changes since the last flush are lost",
                );
                false
            }
        };
        backing.signal.close();
        let handle = backing
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
        ok
    }

    fn flush_inner(&self, force_meta: bool) -> Result<bool, FlushError> {
        let Some(backing) = &self.backing else {
            return Ok(false);
        };
        let _serial = backing
            .flush_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(batch) = self.take_batch(force_meta) else {
            return Ok(true);
        };
        let result = backing.db.write(|conn| write_batch(conn, &batch));
        match result {
            Ok(()) => Ok(true),
            Err(err) => {
                self.requeue(batch);
                Err(FlushError(err.to_string()))
            }
        }
    }

    fn take_batch(&self, force_meta: bool) -> Option<FlushBatch> {
        let mut inner = self.inner_write();
        let dirty = inner.dirty.as_mut()?;
        if dirty.is_empty() && !force_meta {
            return None;
        }
        let rewrite_all = std::mem::take(&mut dirty.rewrite_all);
        let keys = std::mem::take(&mut dirty.keys);
        let (upserts, deletes) = if rewrite_all {
            (inner.entries.values().cloned().collect(), Vec::new())
        } else {
            let mut upserts = Vec::new();
            let mut deletes = Vec::new();
            for key in keys {
                match inner.entries.get(&key) {
                    Some(entry) => upserts.push(Arc::clone(entry)),
                    None => deletes.push(key),
                }
            }
            (upserts, deletes)
        };
        Some(FlushBatch {
            epoch: inner.epoch.clone(),
            revision: inner.global_revision,
            evicted_through: inner.evicted_through_revision,
            holes: inner.holes.clone(),
            upserts,
            deletes,
            rewrite_all,
        })
    }

    fn requeue(&self, batch: FlushBatch) {
        let mut inner = self.inner_write();
        let Some(dirty) = inner.dirty.as_mut() else {
            return;
        };
        if batch.rewrite_all {
            dirty.rewrite_all = true;
            dirty.keys.clear();
            return;
        }
        for entry in &batch.upserts {
            dirty.touch(&(entry.device_id.clone(), entry.capability.clone()));
        }
        for key in &batch.deletes {
            dirty.touch(key);
        }
    }
}

impl Drop for DeviceStateStore {
    fn drop(&mut self) {
        // Let the flusher thread exit. It holds only a `Weak`, so it
        // can't be what keeps the store alive; no join here, because
        // the last `Arc` may be the flusher's own upgrade.
        if let Some(backing) = &self.backing {
            backing.signal.close();
        }
    }
}

fn spawn_flusher(
    store: Weak<DeviceStateStore>,
    signal: Arc<FlushSignal>,
) -> anyhow::Result<JoinHandle<()>> {
    let handle = std::thread::Builder::new()
        .name("oxidhome-device-state-flush".into())
        .spawn(move || {
            let mut failing = false;
            while signal.wait_pending() {
                if signal.sleep(COALESCE) {
                    return;
                }
                let Some(store) = store.upgrade() else {
                    return;
                };
                let outcome = store.flush();
                drop(store);
                match outcome {
                    Ok(_) => {
                        if failing {
                            tracing::warn!(
                                target: "device_state.persist",
                                "device-state flush recovered",
                            );
                        }
                        failing = false;
                    }
                    Err(err) => {
                        if failing {
                            tracing::warn!(target: "device_state.persist", error = %err, "device-state flush still failing");
                        } else {
                            tracing::error!(
                                target: "device_state.persist",
                                error = %err,
                                "device-state flush failed; live state is unaffected, \
                                 retrying with backoff",
                            );
                        }
                        failing = true;
                        if signal.sleep(RETRY_BACKOFF) {
                            return;
                        }
                        signal.notify();
                    }
                }
            }
        })?;
    Ok(handle)
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn write_batch(conn: &mut rusqlite::Connection, batch: &FlushBatch) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if batch.rewrite_all {
        tx.execute("DELETE FROM device_state", [])?;
    }
    {
        let mut upsert = tx.prepare(
            "INSERT INTO device_state(device_id, capability, owner_instance, owner_plugin, \
             fields_blob, global_revision, received_ms, observed_ms, source_generation, quality) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(device_id, capability) DO UPDATE SET \
             owner_instance = excluded.owner_instance, owner_plugin = excluded.owner_plugin, \
             fields_blob = excluded.fields_blob, global_revision = excluded.global_revision, \
             received_ms = excluded.received_ms, observed_ms = excluded.observed_ms, \
             source_generation = excluded.source_generation, quality = excluded.quality",
        )?;
        for e in &batch.upserts {
            let blob = crate::state::event_log::encode_fields(&e.fields)
                .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
            upsert.execute(params![
                e.device_id,
                e.capability,
                e.owner_instance,
                e.owner_plugin,
                blob,
                to_i64(e.global_revision),
                e.received_ms,
                to_i64(e.observed_ms),
                to_i64(e.source_generation),
                quality_str(e.quality),
            ])?;
        }
        let mut delete =
            tx.prepare("DELETE FROM device_state WHERE device_id = ?1 AND capability = ?2")?;
        for (device, capability) in &batch.deletes {
            delete.execute(params![device, capability])?;
        }
    }
    let holes: Vec<StoredHole> = batch
        .holes
        .iter()
        .map(|&(lo, hi)| StoredHole(lo, hi))
        .collect();
    let holes_json = serde_json::to_string(&holes)
        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    tx.execute(
        "INSERT INTO device_state_meta(id, epoch, revision, evicted_through, holes_json) \
         VALUES (1, ?1, ?2, ?3, ?4) \
         ON CONFLICT(id) DO UPDATE SET epoch = excluded.epoch, revision = excluded.revision, \
         evicted_through = excluded.evicted_through, holes_json = excluded.holes_json",
        params![
            batch.epoch,
            to_i64(batch.revision),
            to_i64(batch.evicted_through),
            holes_json,
        ],
    )?;
    tx.commit()
}

fn quality_str(q: StateQuality) -> &'static str {
    match q {
        StateQuality::Fresh => "fresh",
        StateQuality::Stale => "stale",
    }
}

fn load(db: &Db) -> anyhow::Result<(Option<Meta>, Vec<DeviceState>)> {
    db.read(|conn| -> anyhow::Result<_> {
        let meta = conn
            .query_row(
                "SELECT epoch, revision, evicted_through, holes_json FROM device_state_meta \
                 WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(epoch, revision, evicted, holes_json)| {
                let holes = serde_json::from_str::<Vec<StoredHole>>(&holes_json)
                    .unwrap_or_else(|err| {
                        tracing::warn!(
                            target: "device_state.persist",
                            error = %err,
                            "unreadable device-state hole list; cursors below the restored \
                             revision will resync",
                        );
                        Vec::new()
                    })
                    .into_iter()
                    .map(|StoredHole(lo, hi)| (lo, hi))
                    .collect();
                Meta {
                    epoch,
                    revision: to_u64(revision),
                    evicted_through: to_u64(evicted),
                    holes,
                }
            });
        let mut stmt = conn.prepare(
            "SELECT device_id, capability, owner_instance, owner_plugin, fields_blob, \
             global_revision, received_ms, observed_ms, source_generation, quality \
             FROM device_state",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        let mut skipped = 0usize;
        while let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(4)?;
            let Ok(fields) = crate::state::event_log::decode_fields(&blob) else {
                skipped += 1;
                continue;
            };
            let quality: String = row.get(9)?;
            out.push(DeviceState {
                device_id: row.get(0)?,
                capability: row.get(1)?,
                owner_instance: row.get(2)?,
                owner_plugin: row.get(3)?,
                fields,
                global_revision: to_u64(row.get(5)?),
                received_ms: row.get(6)?,
                observed_ms: to_u64(row.get(7)?),
                source_generation: to_u64(row.get(8)?),
                quality: if quality == "fresh" {
                    StateQuality::Fresh
                } else {
                    StateQuality::Stale
                },
            });
        }
        if skipped > 0 {
            tracing::warn!(
                target: "device_state.persist",
                skipped,
                "skipped undecodable device-state rows",
            );
        }
        Ok((meta, out))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};
    use crate::state::CursorError;

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oxidhome-device-state-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        TempDir(path)
    }

    fn open(dir: &TempDir) -> Arc<DeviceStateStore> {
        let db = Arc::new(Db::open_file(&dir.0).expect("db"));
        DeviceStateStore::open_persistent(db).expect("open store")
    }

    fn on(v: bool) -> Vec<KeyValue> {
        vec![KeyValue {
            key: "on".into(),
            value: Value::BoolVal(v),
        }]
    }

    fn fmt(fields: &[KeyValue]) -> String {
        format!("{fields:?}")
    }

    fn put(store: &DeviceStateStore, device: &str, v: bool) {
        store.apply_delta(device.into(), "inst".into(), "switch".into(), on(v), 1, 2);
    }

    #[test]
    fn restart_restores_values_as_stale_and_keeps_epoch_and_old_cursors() {
        let dir = tempdir();
        let store = open(&dir);
        store.bind_owner_plugin("inst", "example.switch");
        store.bump_generation("inst");
        put(&store, "dev-a", true);
        put(&store, "dev-b", false);
        let epoch = store.epoch();
        let flushed = store.current_revision();
        assert!(store.close_persistence());
        drop(store);

        let store = open(&dir);
        assert_eq!(store.epoch(), epoch, "epoch survives a restart");
        let rev = store.current_revision();
        assert!(rev > flushed + REVISION_GAP, "restored store skips the gap");
        let a = store
            .snapshot_capability("dev-a", "switch")
            .expect("restored");
        assert_eq!(a.quality, StateQuality::Stale);
        assert_eq!(fmt(&a.fields), fmt(&on(true)));
        assert_eq!(a.owner_plugin, "example.switch");
        // A cursor at the flushed revision is still valid and sees
        // the stale flips.
        let page = store.deltas_since_with_revision(flushed, 100);
        assert!(!page.reset_required);
        assert_eq!(page.entries.len(), 2);
        // The owner's generation continues past the restored one.
        assert_eq!(store.bump_generation("inst"), 2);
        // A republish makes the slot fresh again.
        put(&store, "dev-a", false);
        let a = store.snapshot_capability("dev-a", "switch").expect("slot");
        assert_eq!(a.quality, StateQuality::Fresh);
        assert_eq!(fmt(&a.fields), fmt(&on(false)));
        assert!(store.close_persistence());
    }

    #[test]
    fn unflushed_changes_are_lost_and_their_cursors_reset() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        store.flush().expect("flush");
        let flushed = store.current_revision();
        // Not flushed: dropped like a crash (the flusher coalesces for
        // 250 ms first, and it holds only a weak reference).
        put(&store, "dev-a", false);
        put(&store, "dev-new", true);
        let lost_cursor = store.current_revision();
        assert!(lost_cursor > flushed);
        drop(store);

        let store = open(&dir);
        assert_eq!(
            fmt(&store
                .snapshot_capability("dev-a", "switch")
                .expect("slot")
                .fields),
            fmt(&on(true)),
            "the last flushed value is restored",
        );
        assert!(store.snapshot_capability("dev-new", "switch").is_none());
        assert!(
            store
                .deltas_since_with_revision(lost_cursor, 10)
                .reset_required,
            "a cursor from the lost window must resync",
        );
        assert!(!store.deltas_since_with_revision(flushed, 10).reset_required);
        // Even once revisions pass the lost cursor, it stays in the hole.
        for _ in 0..4 {
            put(&store, "dev-a", true);
        }
        assert!(
            store
                .deltas_since_with_revision(lost_cursor, 10)
                .reset_required
        );
        assert!(store.close_persistence());
        drop(store);

        // The hole survives a further restart.
        let store = open(&dir);
        assert!(
            store
                .deltas_since_with_revision(lost_cursor, 10)
                .reset_required
        );
        assert!(store.close_persistence());
    }

    #[test]
    fn evicted_entries_are_deleted_from_the_table() {
        let dir = tempdir();
        let store = open(&dir);
        for i in 0..=crate::state::MAX_STALE_ENTRIES {
            put(&store, &format!("dev-{i:05}"), true);
            store.mark_device_stale(&format!("dev-{i:05}"));
        }
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        let rows: i64 = db
            .read(|c| c.query_row("SELECT COUNT(*) FROM device_state", [], |r| r.get(0)))
            .expect("count");
        assert_eq!(
            usize::try_from(rows).expect("count"),
            crate::state::MAX_STALE_ENTRIES
        );
        assert!(store.snapshot_capability("dev-00000", "switch").is_none());
    }

    #[test]
    fn background_flusher_writes_without_an_explicit_flush() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let rows: i64 = db
                .read(|c| c.query_row("SELECT COUNT(*) FROM device_state", [], |r| r.get(0)))
                .expect("count");
            if rows == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "flusher never wrote");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(store.close_persistence());
    }

    #[test]
    fn pagination_cursor_from_an_earlier_process_is_a_restart() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        let cursor = store.issue_cursor(store.current_revision(), "dev-a");
        assert!(store.verify_cursor(&cursor).is_ok());
        assert!(store.close_persistence());
        drop(store);
        let store = open(&dir);
        assert_eq!(store.verify_cursor(&cursor), Err(CursorError::EpochChanged));
        assert!(store.close_persistence());
    }
}
