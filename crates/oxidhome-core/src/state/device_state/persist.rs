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
//!   `R + REVISION_GAP` and records the skipped range `(R, R + GAP)` as
//!   a *hole*: a `/state/changes` cursor at or below `R` stays valid,
//!   a cursor inside a hole gets `reset_required`. The base `R + GAP`
//!   itself is a valid cursor (a snapshot taken before the first new
//!   write reports it). The hole and the new base revision are written
//!   at `synchronous = FULL` before the store serves anything, so
//!   neither a crash nor a power loss later in this life can reuse
//!   those revisions. The
//!   newest [`MAX_HOLES`] holes are kept; older ones fold into the
//!   eviction watermark (cursors below it also reset).
//! - **What is lost.** Changes made after the last successful flush
//!   (at most [`COALESCE`] in steady state, longer while the disk is
//!   failing). Their cursors land in the hole and resync.
//! - **Damage and restores.** A row or hole list that can't be decoded
//!   is dropped and the epoch is rotated with every cursor expired,
//!   since no earlier cursor describes what was dropped. A backup
//!   restore does the same ([`invalidate_cursors_after_restore`]): the
//!   restored database is an older history.
//! - **Consistency marker.** Each flush stores, next to the hole list
//!   in `holes_json`, the table's row count and a checksum over the
//!   meta row (epoch, revision, watermark, holes, writer, row count).
//!   A boot whose meta row or row count doesn't match its marker
//!   treats the meta as damage and starts a new history, so a
//!   revision inflated by damage can't keep cursors valid that the
//!   lost writes made invalid. A meta row from before the marker has
//!   none and is accepted once; the boot flush adds it.
//! - **Encoding.** Fields use their own tagged JSON shape: floats by
//!   bit pattern (NaN and infinities round-trip), bytes as hex, and
//!   `u64` timestamps by bit pattern in `SQLite`'s signed integers.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{DeviceState, DeviceStateStore, StateQuality, StoreInner};
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, KeyValue, Value};
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

/// Highest flushed revision a restore continues from. Above it the
/// persisted numbers are treated as damage (a new history starts): a
/// real store never gets near it, and it leaves room for the gap and
/// the renumbering of every restored slot.
const MAX_RESTORABLE_REVISION: u64 = 1 << 62;

/// Longest persisted device id or capability accepted at restore:
/// host-minted ids are 20 bytes, and a longer one wouldn't fit a
/// pagination cursor.
const MAX_RESTORED_ID_LEN: usize = 256;

/// Largest encoded field blob read at restore. A valid slot is at most
/// 16 KiB of field data; hex, JSON escaping and per-field framing stay
/// well under this.
const MAX_RESTORED_BLOB_BYTES: usize = 1024 * 1024;

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
        if !self.rewrite_all && !self.keys.contains(key) {
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
    /// Outcome of the flushes so far, for [`DeviceStateHealth`].
    health: Mutex<FlushStatus>,
}

#[derive(Debug, Default)]
struct FlushStatus {
    /// The current run of failed flushes started here.
    failing_since_ms: Option<i64>,
    last_error: Option<String>,
    last_flush_ms: Option<i64>,
    failed_total: u64,
}

/// H2: flush health of the durable device-state projection, reported
/// by `GET /api/v1/readyz` and Connect `HealthService.Check`
/// (`device_state: ok | degraded`) and in full on the MCP
/// `oxidhome://status` resource.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DeviceStateHealth {
    /// The store flushes to a database (`false` for an in-memory
    /// store, which is never degraded).
    pub persistent: bool,
    /// The last flush failed: changes are queued in memory and
    /// retried, and a crash now would lose them. Live state and
    /// control are unaffected.
    pub degraded: bool,
    /// Host time of the first failed flush in the current run.
    pub degraded_since_ms: Option<i64>,
    /// Error of the last failed flush, while degraded.
    pub last_error: Option<String>,
    /// Host time of the last successful flush.
    pub last_flush_ms: Option<i64>,
    /// Failed flushes since the daemon started.
    pub failed_flushes_total: u64,
    /// Slots waiting for the next flush.
    pub pending_keys: usize,
}

/// A flush failed; the batch was re-queued.
#[derive(Debug, thiserror::Error)]
#[error("device-state flush failed: {0}")]
pub struct FlushError(String);

/// One consistent write: the store's state at `revision`.
struct FlushBatch {
    /// Boot nonce of the store that took the batch. The boot flush
    /// claims the table for it; any other flush is refused once a
    /// newer store has claimed it, so a batch still in flight from a
    /// dropped store can't overwrite the new one's reservation.
    writer: String,
    claim: bool,
    epoch: String,
    revision: u64,
    evicted_through: u64,
    holes: Vec<(u64, u64)>,
    upserts: Vec<Arc<DeviceState>>,
    deletes: Vec<Key>,
    rewrite_all: bool,
    /// Rows in the table once this batch commits: the store's entry
    /// count at the batch's revision (every flush writes every key
    /// changed since the last one, so the table mirrors the store).
    rows: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredHole(u64, u64);

/// `holes_json` as stored: the hole list with its consistency marker,
/// or the bare list written before the marker existed.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum StoredRanges {
    Marked {
        holes: Vec<StoredHole>,
        rows: u64,
        check: String,
    },
    Legacy(Vec<StoredHole>),
}

struct Meta {
    epoch: String,
    revision: u64,
    evicted_through: u64,
    holes: Vec<(u64, u64)>,
    /// The stored marker matched (or there was none).
    consistent: bool,
}

/// Checksum over everything one flush writes to the meta row, plus the
/// table's row count. Not a MAC: it detects damage, not tampering.
fn meta_check(
    epoch: &str,
    revision: u64,
    evicted_through: u64,
    holes: &[(u64, u64)],
    writer: &str,
    rows: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"oxidhome.device_state_meta.v1\0");
    h.update(epoch.as_bytes());
    h.update([0]);
    h.update(revision.to_be_bytes());
    h.update(evicted_through.to_be_bytes());
    h.update(u64::try_from(holes.len()).unwrap_or(u64::MAX).to_be_bytes());
    for &(lo, hi) in holes {
        h.update(lo.to_be_bytes());
        h.update(hi.to_be_bytes());
    }
    h.update(writer.as_bytes());
    h.update([0]);
    h.update(rows.to_be_bytes());
    super::hex_lower(&h.finalize()[..16])
}

/// `holes_json` for a meta row: the holes with their marker.
fn encode_ranges(
    epoch: &str,
    revision: u64,
    evicted_through: u64,
    holes: &[(u64, u64)],
    writer: &str,
    rows: u64,
) -> serde_json::Result<String> {
    serde_json::to_string(&StoredRanges::Marked {
        holes: holes.iter().map(|&(lo, hi)| StoredHole(lo, hi)).collect(),
        rows,
        check: meta_check(epoch, revision, evicted_through, holes, writer, rows),
    })
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
        let (meta, rows, damaged) = load(&db)?;
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
            inner.entries.insert(
                (row.device_id.clone(), row.capability.clone()),
                Arc::new(row),
            );
        }
        let min_row_revision = inner.entries.values().map(|e| e.global_revision).min();
        restore_revisions(
            &mut inner,
            meta,
            max_row_revision,
            min_row_revision,
            damaged,
        );
        // Every restored slot gets a revision above the base, so a
        // client polling from any surviving cursor is sent the whole
        // restored projection again. Otherwise a slot whose newer
        // write was lost in the crash, and which the client skipped
        // (e.g. a continuation page left it out as newer than its
        // pin), would come back at its old revision, below the cursor.
        // Stale slots keep their `received_ms`; fresh ones are
        // renumbered by the stale flip below.
        // In persisted revision order, so stale eviction (oldest
        // revision first) keeps its order across the restart.
        let mut stale_keys: Vec<(u64, Key)> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.quality == StateQuality::Stale)
            .map(|(k, e)| (e.global_revision, k.clone()))
            .collect();
        stale_keys.sort_unstable();
        let stale_keys: Vec<Key> = stale_keys.into_iter().map(|(_, k)| k).collect();
        for key in &stale_keys {
            let global_revision = inner.next_revision();
            if let Some(entry) = inner.entries.get_mut(key) {
                Arc::make_mut(entry).global_revision = global_revision;
            }
            inner.touch(key);
        }
        // Restored values are unconfirmed until the owner republishes.
        let now = crate::state::event_log::now_unix_ms();
        // Flipped here rather than through `stale_where_locked`: that
        // enforces the runtime stale cap, which would evict (and the
        // boot flush delete) persisted slots on a big install. The cap
        // applies again from the next runtime stale transition.
        let fresh_keys: Vec<Key> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.quality == StateQuality::Fresh)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &fresh_keys {
            let global_revision = inner.next_revision();
            if let Some(entry) = inner.entries.get_mut(key) {
                let e = Arc::make_mut(entry);
                e.global_revision = global_revision;
                e.received_ms = now;
                e.quality = StateQuality::Stale;
            }
            inner.touch(key);
        }
        let flipped = fresh_keys.len();
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
                health: Mutex::new(FlushStatus::default()),
            }),
        });
        // Persist the base revision and hole before serving anything,
        // at `synchronous = FULL`: a power loss must not roll the
        // reservation back after clients saw revisions above it.
        store
            .flush_inner(true, true)
            .map_err(|e| anyhow::anyhow!(e))?;
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
        self.flush_inner(false, false)
    }

    /// H2: current flush health (see [`DeviceStateHealth`]).
    #[must_use]
    pub fn flush_health(&self) -> DeviceStateHealth {
        let Some(backing) = &self.backing else {
            return DeviceStateHealth::default();
        };
        let pending_keys = {
            let inner = self.inner_read();
            inner.dirty.as_ref().map_or(0, |d| {
                if d.rewrite_all {
                    inner.entries.len()
                } else {
                    d.keys.len()
                }
            })
        };
        let st = backing
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        DeviceStateHealth {
            // An in-memory database is not persistence.
            persistent: backing.db.path().is_some(),
            degraded: st.failing_since_ms.is_some(),
            degraded_since_ms: st.failing_since_ms,
            last_error: st.failing_since_ms.and(st.last_error.clone()),
            last_flush_ms: st.last_flush_ms,
            failed_flushes_total: st.failed_total,
            pending_keys,
        }
    }

    /// Test hook: report a failed flush, so API tests can observe the
    /// degraded signal.
    #[cfg(test)]
    pub(crate) fn degrade_for_test(&self, reason: &str) {
        if let Some(backing) = &self.backing {
            let mut st = backing
                .health
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            st.failing_since_ms.get_or_insert(0);
            st.last_error = Some(reason.to_owned());
            st.failed_total += 1;
        }
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

    fn flush_inner(&self, force_meta: bool, durable: bool) -> Result<bool, FlushError> {
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
        let result = backing.db.write(|conn| {
            if durable {
                conn.pragma_update(None, "synchronous", "FULL")?;
            }
            let result = write_batch(conn, &batch);
            if durable && let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
                tracing::warn!(
                    target: "device_state.persist",
                    error = %err,
                    "failed to restore synchronous = NORMAL after the boot flush",
                );
            }
            result
        });
        let now = crate::state::event_log::now_unix_ms();
        let mut st = backing
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(()) => {
                st.failing_since_ms = None;
                st.last_error = None;
                st.last_flush_ms = Some(now);
                Ok(true)
            }
            Err(err) => {
                st.failing_since_ms.get_or_insert(now);
                st.last_error = Some(err.to_string());
                st.failed_total += 1;
                drop(st);
                self.requeue(&batch);
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
            writer: inner.boot.clone(),
            claim: force_meta,
            epoch: inner.epoch.clone(),
            revision: inner.global_revision,
            evicted_through: inner.evicted_through_revision,
            holes: inner.holes.clone(),
            upserts,
            deletes,
            rewrite_all,
            rows: u64::try_from(inner.entries.len()).unwrap_or(u64::MAX),
        })
    }

    fn requeue(&self, batch: &FlushBatch) {
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

/// H2: set the restored store's epoch, revision, watermark and holes
/// (see the module docs).
fn restore_revisions(
    inner: &mut StoreInner,
    meta: Option<Meta>,
    max_row_revision: u64,
    min_row_revision: Option<u64>,
    damaged: bool,
) {
    // A revision too close to the top of `u64` (a damaged row or
    // meta) can't fit the gap and the renumbering below: start a
    // new history instead.
    let flushed = meta
        .as_ref()
        .map_or(max_row_revision, |m| m.revision.max(max_row_revision));
    // Holes must lie at or below the flushed revision and the
    // watermark at or below the new base (a backup restore raises it
    // to exactly that); anything else is damage, since a watermark
    // above the base would reset every future cursor.
    // A row newer than the meta revision can't come from a consistent
    // flush (both are written in one transaction), and an epoch the
    // cursor format can't carry would break pagination: damage too.
    let usable = flushed <= MAX_RESTORABLE_REVISION
        && meta.as_ref().is_none_or(|m| {
            m.consistent
                && m.revision >= max_row_revision
                && super::is_valid_epoch(&m.epoch)
                && m.evicted_through <= flushed.saturating_add(REVISION_GAP)
                // Every boot records exactly `(R, R + GAP)`, in order.
                && m.holes.iter().all(|&(lo, hi)| lo.checked_add(REVISION_GAP) == Some(hi) && hi <= flushed)
                && m.holes.windows(2).all(|w| w[0].1 <= w[1].0)
                // Every slot is renumbered above the newest range at
                // boot, so a row at or below it means the range moved.
                && m.holes
                    .last()
                    .zip(min_row_revision)
                    .is_none_or(|(&(_, hi), min)| min > hi)
        });
    if let Some(meta) = meta.filter(|_| usable) {
        let base = flushed + REVISION_GAP;
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
        if damaged {
            // Part of the persisted state couldn't be read back: no
            // earlier cursor can be trusted to describe what was
            // dropped. Rotate the epoch and expire every cursor.
            tracing::warn!(
                target: "device_state.persist",
                "persisted device state was partly unreadable; every client cursor resyncs",
            );
            inner.epoch = super::mint_epoch();
            inner.evicted_through_revision = base;
            // Rewrite the table from what decoded, so the dropped
            // rows don't trip this again on the next boot.
            if let Some(dirty) = inner.dirty.as_mut() {
                dirty.rewrite_all = true;
            }
        }
    } else if usable && !damaged {
        // First boot with persistence: no cursor can predate it.
        inner.global_revision = max_row_revision;
    } else {
        tracing::warn!(
            target: "device_state.persist",
            "persisted device-state metadata unusable; starting a new revision history",
        );
        inner.epoch = super::mint_epoch();
        // Above every revision the damaged history claims, with the
        // watermark there, so a cursor from it resets even for a
        // client that doesn't compare epochs. A revision with no room
        // left starts over from zero; the new epoch is then the only
        // signal.
        let base = if flushed <= MAX_RESTORABLE_REVISION {
            flushed + REVISION_GAP
        } else {
            0
        };
        inner.global_revision = base;
        inner.evicted_through_revision = base;
        inner.holes.clear();
        if let Some(dirty) = inner.dirty.as_mut() {
            dirty.rewrite_all = true;
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

/// `SQLite` integers are signed; store `u64` by bit pattern so values
/// above `i64::MAX` (a plugin's `observed-ms`) round-trip.
fn to_i64(v: u64) -> i64 {
    v.cast_signed()
}

fn to_u64(v: i64) -> u64 {
    v.cast_unsigned()
}

fn write_batch(conn: &mut rusqlite::Connection, batch: &FlushBatch) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !batch.claim {
        let owner: Option<String> = tx
            .query_row(
                "SELECT writer FROM device_state_meta WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if owner.is_some_and(|w| w != batch.writer) {
            return Err(rusqlite::Error::ToSqlConversionFailure(
                "device-state table was claimed by a newer store".into(),
            ));
        }
    }
    if batch.rewrite_all {
        tx.execute("DELETE FROM device_state", [])?;
    }
    {
        let mut upsert = tx.prepare(
            "INSERT INTO device_state(device_id, capability, owner_instance, owner_plugin, \
             fields_blob, global_revision, received_ms, observed_ms, source_generation, quality, \
             owner_install) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT(device_id, capability) DO UPDATE SET \
             owner_instance = excluded.owner_instance, owner_plugin = excluded.owner_plugin, \
             owner_install = excluded.owner_install, \
             fields_blob = excluded.fields_blob, global_revision = excluded.global_revision, \
             received_ms = excluded.received_ms, observed_ms = excluded.observed_ms, \
             source_generation = excluded.source_generation, quality = excluded.quality",
        )?;
        for e in &batch.upserts {
            let blob = encode_fields(&e.fields)
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
                e.owner_install,
            ])?;
        }
        let mut delete =
            tx.prepare("DELETE FROM device_state WHERE device_id = ?1 AND capability = ?2")?;
        for (device, capability) in &batch.deletes {
            delete.execute(params![device, capability])?;
        }
    }
    let holes_json = encode_ranges(
        &batch.epoch,
        batch.revision,
        batch.evicted_through,
        &batch.holes,
        &batch.writer,
        batch.rows,
    )
    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    tx.execute(
        "INSERT INTO device_state_meta(id, epoch, revision, evicted_through, holes_json, writer) \
         VALUES (1, ?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(id) DO UPDATE SET epoch = excluded.epoch, revision = excluded.revision, \
         evicted_through = excluded.evicted_through, holes_json = excluded.holes_json, \
         writer = excluded.writer",
        params![
            batch.epoch,
            to_i64(batch.revision),
            to_i64(batch.evicted_through),
            holes_json,
            batch.writer,
        ],
    )?;
    tx.commit()
}

/// On-disk shape of one field value. Floats are stored by bit pattern
/// (JSON has no NaN or infinity) and bytes as hex.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "v")]
enum PersistedValue {
    Bool(bool),
    Int(i64),
    FloatBits(u64),
    String(String),
    BytesHex(String),
    Json(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedField {
    k: String,
    v: PersistedValue,
}

fn encode_fields(fields: &[KeyValue]) -> Result<Vec<u8>, serde_json::Error> {
    let out: Vec<PersistedField> = fields
        .iter()
        .map(|kv| PersistedField {
            k: kv.key.clone(),
            v: match &kv.value {
                Value::BoolVal(b) => PersistedValue::Bool(*b),
                Value::IntVal(i) => PersistedValue::Int(*i),
                Value::FloatVal(f) => PersistedValue::FloatBits(f.to_bits()),
                Value::StringVal(s) => PersistedValue::String(s.clone()),
                Value::BytesVal(b) => PersistedValue::BytesHex(super::hex_lower(b)),
                Value::JsonVal(j) => PersistedValue::Json(j.clone()),
            },
        })
        .collect();
    serde_json::to_vec(&out)
}

fn decode_fields(blob: &[u8]) -> Result<Vec<KeyValue>, String> {
    let stored: Vec<PersistedField> = serde_json::from_slice(blob).map_err(|e| e.to_string())?;
    stored
        .into_iter()
        .map(|f| {
            let value = match f.v {
                PersistedValue::Bool(b) => Value::BoolVal(b),
                PersistedValue::Int(i) => Value::IntVal(i),
                PersistedValue::FloatBits(bits) => Value::FloatVal(f64::from_bits(bits)),
                PersistedValue::String(s) => Value::StringVal(s),
                PersistedValue::BytesHex(h) => {
                    Value::BytesVal(super::hex_bytes(&h).ok_or("invalid hex")?)
                }
                PersistedValue::Json(j) => Value::JsonVal(j),
            };
            Ok(KeyValue { key: f.k, value })
        })
        .collect()
}

/// H2: make every `/state/changes` cursor and the epoch from before a
/// backup restore invalid. A restored database is an older history:
/// a client of the live daemon may hold a revision the restored store
/// will reissue for different state, and the skipped range at the
/// next boot only covers what the backup itself issued. Rotating the
/// epoch tells epoch-checking clients; raising the eviction watermark
/// past the next boot's base makes every older cursor reset.
///
/// Runs on the restored database before migrations; a database older
/// than the device-state tables has no cursors to invalidate.
///
/// # Errors
///
/// The update failed.
pub fn invalidate_cursors_after_restore(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' \
         AND name = 'device_state_meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        return Ok(());
    }
    // One row even when the meta row is missing (the rows' watermark
    // must still move past the backup's history).
    let (revision, row_max, rows, writer) = conn.query_row(
        "SELECT m.revision, \
             COALESCE((SELECT MAX(global_revision) FROM device_state), 0), \
             (SELECT COUNT(*) FROM device_state), m.holes_json, m.writer \
             FROM (SELECT 1) LEFT JOIN device_state_meta AS m ON m.id = 1",
        [],
        // Damaged columns (a BLOB hole list, a TEXT revision) pass
        // the integrity check and the boot recovers from them, so
        // the restore must not fail on them either.
        |row| {
            use rusqlite::types::ValueRef;
            let int = |i: usize| -> rusqlite::Result<Option<i64>> {
                Ok(match row.get_ref(i)? {
                    ValueRef::Integer(n) => Some(n),
                    _ => None,
                })
            };
            // Invalid UTF-8 counts as undecodable, not as an error.
            let text = |i: usize| -> rusqlite::Result<Option<String>> {
                Ok(match row.get_ref(i)? {
                    ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_owned),
                    _ => None,
                })
            };
            Ok((
                int(0)?,
                int(1)?.unwrap_or(0),
                int(2)?.unwrap_or(0),
                text(4)?,
            ))
        },
    )?;
    let epoch = super::mint_epoch();
    // A damaged revision falls back to the rows' highest.
    let revision = revision.unwrap_or(row_max).max(0);
    // Past everything the restored database issued, including the
    // skipped range its next boot records.
    let evicted = revision.max(row_max).saturating_add(to_i64(REVISION_GAP));
    // Rewrite the whole meta row with a fresh marker, so the next boot
    // accepts the new epoch and watermark even if the backup's row was
    // damaged. Holes are dropped: every revision they cover is below
    // the new watermark, where every cursor resets anyway.
    let writer = writer.unwrap_or_default();
    let holes_json = encode_ranges(
        &epoch,
        to_u64(revision),
        to_u64(evicted),
        &[],
        &writer,
        u64::try_from(rows).unwrap_or(0),
    )
    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    conn.execute(
        "INSERT INTO device_state_meta(id, epoch, revision, evicted_through, holes_json, writer) \
         VALUES (1, ?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET epoch = excluded.epoch, \
         revision = excluded.revision, evicted_through = excluded.evicted_through, \
         holes_json = excluded.holes_json, writer = excluded.writer",
        params![epoch, revision, evicted, holes_json, writer],
    )?;
    Ok(())
}

fn quality_str(q: StateQuality) -> &'static str {
    match q {
        StateQuality::Fresh => "fresh",
        StateQuality::Stale => "stale",
    }
}

/// Persisted rows plus whether anything had to be dropped.
type Loaded = (Option<Meta>, Vec<DeviceState>, bool);

fn load(db: &Db) -> anyhow::Result<Loaded> {
    db.read(|conn| -> anyhow::Result<_> {
        let mut damaged = false;
        let mut marker: Option<(u64, String, String)> = None;
        let mut meta = conn
            .query_row(
                "SELECT epoch, revision, evicted_through, holes_json, writer \
                 FROM device_state_meta WHERE id = 1",
                [],
                // Conversion failures are damage, not a failed boot.
                |row| {
                    Ok((|| -> rusqlite::Result<_> {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })()
                    .ok())
                },
            )
            .optional()?
            .and_then(|decoded| {
                if decoded.is_none() {
                    tracing::warn!(target: "device_state.persist", "unreadable device-state meta row");
                    damaged = true;
                }
                decoded
            })
            .map(|(epoch, revision, evicted, holes_json, writer)| {
                let holes = match serde_json::from_str::<StoredRanges>(&holes_json) {
                    Ok(StoredRanges::Legacy(holes)) => holes,
                    Ok(StoredRanges::Marked { holes, rows, check }) => {
                        marker = Some((rows, check, writer));
                        holes
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "device_state.persist",
                            error = %err,
                            "unreadable device-state hole list",
                        );
                        damaged = true;
                        Vec::new()
                    }
                }
                .into_iter()
                .map(|StoredHole(lo, hi)| (lo, hi))
                .collect();
                Meta {
                    epoch,
                    revision: to_u64(revision),
                    evicted_through: to_u64(evicted),
                    holes,
                    consistent: true,
                }
            });
        let mut stmt = conn.prepare(
            "SELECT device_id, capability, owner_instance, owner_plugin, fields_blob, \
             global_revision, received_ms, observed_ms, source_generation, quality, \
             owner_install FROM device_state",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        let mut skipped = 0usize;
        while let Some(row) = rows.next()? {
            // A row whose columns don't convert (wrong SQL type, bad
            // field encoding) is skipped like any other damage; only
            // the cursor's own I/O errors abort the boot.
            match decode_row(row) {
                Some(entry) => out.push(entry),
                None => skipped += 1,
            }
        }
        if skipped > 0 {
            damaged = true;
            tracing::warn!(
                target: "device_state.persist",
                skipped,
                "skipped undecodable device-state rows",
            );
        }
        if meta.is_none() && out.len() + skipped > 0 {
            // Rows without their meta row: the revision and watermark
            // are lost, so recover as from damage (gap + watermark)
            // instead of taking the first-boot path.
            damaged = true;
            tracing::warn!(
                target: "device_state.persist",
                rows = out.len() + skipped,
                "device-state rows without a meta row",
            );
        }
        if let (Some(m), Some(marker)) = (meta.as_mut(), marker) {
            let total = u64::try_from(out.len() + skipped).unwrap_or(u64::MAX);
            m.consistent = marker_matches(m, &marker, total);
        }
        Ok((meta, out, damaged))
    })
}

/// Whether `meta` and the `total` rows found match the marker stored
/// with them (`rows`, `check`, `writer`). The marker covers every row
/// in the table, decodable or not: undecodable rows take the damage
/// path, a missing or extra row or a changed meta field fails here.
fn marker_matches(meta: &Meta, (rows, check, writer): &(u64, String, String), total: u64) -> bool {
    let expected = meta_check(
        &meta.epoch,
        meta.revision,
        meta.evicted_through,
        &meta.holes,
        writer,
        *rows,
    );
    if *rows == total && *check == expected {
        return true;
    }
    tracing::warn!(
        target: "device_state.persist",
        rows_marked = rows,
        rows_found = total,
        "device-state metadata fails its consistency marker",
    );
    false
}

fn decode_row(row: &rusqlite::Row<'_>) -> Option<DeviceState> {
    // Bound the encoded size before copying or decoding it: a damaged
    // row must not exhaust memory before the damage path runs.
    let blob = row.get_ref(4).ok()?.as_blob().ok()?;
    if blob.len() > MAX_RESTORED_BLOB_BYTES {
        return None;
    }
    let fields = decode_fields(blob).ok()?;
    if fields.len() > super::MAX_FIELDS_PER_SLOT
        || super::fields_byte_estimate(&fields) > super::MAX_BYTES_PER_SLOT
    {
        return None;
    }
    let quality: String = row.get(9).ok()?;
    let device_id: String = row.get(0).ok()?;
    let capability: String = row.get(1).ok()?;
    // Same bounds as live writes: ids that fit a pagination cursor,
    // and the per-slot field-count and byte caps.
    if device_id.is_empty()
        || capability.is_empty()
        || device_id.len() > MAX_RESTORED_ID_LEN
        || capability.len() > MAX_RESTORED_ID_LEN
    {
        return None;
    }
    Some(DeviceState {
        device_id,
        capability,
        owner_instance: row.get(2).ok()?,
        owner_plugin: row.get(3).ok()?,
        owner_install: row.get(10).ok()?,
        fields,
        global_revision: to_u64(row.get(5).ok()?),
        received_ms: row.get(6).ok()?,
        observed_ms: to_u64(row.get(7).ok()?),
        // A generation near `u64::MAX` would overflow the owner's
        // next restart: damage.
        source_generation: Some(to_u64(row.get(8).ok()?))
            .filter(|g| *g <= MAX_RESTORABLE_REVISION)?,
        quality: match quality.as_str() {
            "fresh" => StateQuality::Fresh,
            "stale" => StateQuality::Stale,
            _ => return None,
        },
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

    /// Stop the background flusher without a final flush, so the
    /// writes that follow are lost on drop like in a crash.
    fn stop_flusher(store: &DeviceStateStore) {
        let backing = store.backing.as_ref().expect("backing");
        backing.signal.close();
        if let Some(handle) = backing
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            handle.join().expect("flusher");
        }
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
        store.bind_owner_plugin("inst", "example.switch", "inst-uuid");
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
        assert_eq!(a.owner_install, "inst-uuid");
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
    fn restored_base_revision_is_a_valid_cursor() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        store.mark_device_stale("dev-a");
        assert!(store.close_persistence());
        drop(store);
        // Nothing fresh to flip at boot: the store sits at its base.
        let store = open(&dir);
        let base = store.current_revision();
        let page = store.deltas_since_with_revision(base, 10);
        assert!(
            !page.reset_required,
            "a snapshot's revision must be pollable"
        );
        assert!(page.entries.is_empty());
        assert!(store.close_persistence());
    }

    #[test]
    fn unflushed_changes_are_lost_and_their_cursors_reset() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        store.flush().expect("flush");
        let flushed = store.current_revision();
        stop_flusher(&store);
        // Not flushed: dropped like a crash.
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

    #[test]
    fn non_finite_floats_bytes_and_large_timestamps_round_trip() {
        let dir = tempdir();
        let store = open(&dir);
        let fields = vec![
            KeyValue {
                key: "nan".into(),
                value: Value::FloatVal(f64::NAN),
            },
            KeyValue {
                key: "inf".into(),
                value: Value::FloatVal(f64::NEG_INFINITY),
            },
            KeyValue {
                key: "raw".into(),
                value: Value::BytesVal(vec![0, 0xff, 0x10]),
            },
            KeyValue {
                key: "on".into(),
                value: Value::BoolVal(true),
            },
        ];
        store.replace_snapshot(
            "dev-a".into(),
            "inst".into(),
            "s".into(),
            fields,
            u64::MAX,
            3,
        );
        assert!(store.close_persistence());
        drop(store);
        let store = open(&dir);
        let e = store.snapshot_capability("dev-a", "s").expect("restored");
        assert_eq!(e.observed_ms, u64::MAX);
        let by_key = |k: &str| &e.fields.iter().find(|f| f.key == k).expect(k).value;
        assert!(matches!(by_key("nan"), Value::FloatVal(f) if f.is_nan()));
        assert!(matches!(by_key("inf"), Value::FloatVal(f) if *f == f64::NEG_INFINITY));
        assert!(matches!(by_key("raw"), Value::BytesVal(b) if b == &[0, 0xff, 0x10]));
        assert!(matches!(by_key("on"), Value::BoolVal(true)));
        assert!(store.close_persistence());
    }

    #[test]
    fn unreadable_persisted_state_expires_every_cursor() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        put(&store, "dev-b", true);
        let cursor = store.current_revision();
        let epoch = store.epoch();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute(
                "UPDATE device_state SET fields_blob = x'00' WHERE device_id = 'dev-b'",
                [],
            )
        })
        .expect("corrupt a row");
        drop(db);
        let store = open(&dir);
        assert_ne!(store.epoch(), epoch);
        assert!(store.deltas_since_with_revision(cursor, 10).reset_required);
        assert!(store.snapshot_capability("dev-a", "switch").is_some());
        let recovered_epoch = store.epoch();
        let recovered_cursor = store.current_revision();
        assert!(store.close_persistence());
        drop(store);
        // The bad row is gone: the next boot keeps the new epoch and
        // the cursors issued after recovery.
        let store = open(&dir);
        assert_eq!(store.epoch(), recovered_epoch);
        assert!(
            !store
                .deltas_since_with_revision(recovered_cursor, 10)
                .reset_required
        );
        assert!(store.close_persistence());
    }

    /// Rows without a meta row are recovered like damage: an old
    /// cursor resets instead of matching a renumbered slot.
    #[test]
    fn rows_without_a_meta_row_reset_old_cursors() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        assert!(store.close_persistence());
        let cursor = store.current_revision() + 1;
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| c.execute("DELETE FROM device_state_meta", []))
            .expect("drop meta");
        drop(db);
        let store = open(&dir);
        assert!(store.deltas_since_with_revision(cursor, 10).reset_required);
        assert!(store.close_persistence());
    }

    /// A backup whose meta row is damaged in ways the integrity check
    /// accepts (invalid UTF-8 text, a BLOB hole list) still restores,
    /// and every earlier cursor resets after the next boot.
    #[test]
    fn restore_invalidation_rewrites_a_damaged_meta_row() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        let cursor = store.current_revision();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute(
                "UPDATE device_state_meta SET writer = CAST(x'ff' AS TEXT), holes_json = x'00'",
                [],
            )?;
            invalidate_cursors_after_restore(c)
        })
        .expect("invalidate");
        drop(db);
        let store = open(&dir);
        assert!(store.deltas_since_with_revision(cursor, 10).reset_required);
        assert!(store.current_revision() > REVISION_GAP);
        // A missing meta row is rewritten too.
        let cursor = store.current_revision();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute("DELETE FROM device_state_meta", [])?;
            invalidate_cursors_after_restore(c)
        })
        .expect("invalidate");
        drop(db);
        let store = open(&dir);
        assert!(store.deltas_since_with_revision(cursor, 10).reset_required);
        assert!(store.close_persistence());
    }

    #[test]
    fn restore_invalidation_expires_every_cursor() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        let cursor = store.current_revision();
        let epoch = store.epoch();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| invalidate_cursors_after_restore(c))
            .expect("invalidate");
        drop(db);
        let store = open(&dir);
        assert_ne!(store.epoch(), epoch);
        assert!(store.deltas_since_with_revision(cursor, 10).reset_required);
        assert!(
            !store
                .deltas_since_with_revision(store.current_revision(), 10)
                .reset_required
        );
        // The re-marked meta row passed its consistency check: the
        // revisions continue past the restored history instead of
        // starting over.
        assert!(store.current_revision() > REVISION_GAP);
        assert!(store.close_persistence());
    }

    /// Follow-up to H2 round 4: a meta row or row set that changed
    /// after its flush (an inflated revision, a lost or added row)
    /// fails the consistency marker and starts a new history, so no
    /// earlier cursor survives.
    #[test]
    fn damage_that_still_decodes_fails_the_consistency_marker() {
        for corrupt in [
            "UPDATE device_state_meta SET revision = revision + 5",
            "UPDATE device_state_meta SET evicted_through = evicted_through + 1",
            "DELETE FROM device_state WHERE device_id = 'dev-b'",
            "INSERT INTO device_state SELECT 'dev-c', capability, owner_instance, \
             owner_plugin, owner_install, fields_blob, global_revision, received_ms, \
             observed_ms, source_generation, quality FROM device_state \
             WHERE device_id = 'dev-a'",
        ] {
            let dir = tempdir();
            let store = open(&dir);
            put(&store, "dev-a", true);
            put(&store, "dev-b", true);
            let epoch = store.epoch();
            let cursor = store.current_revision();
            assert!(store.close_persistence());
            let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
            drop(store);
            db.write(|c| c.execute(corrupt, [])).expect("corrupt");
            drop(db);
            let store = open(&dir);
            assert_ne!(store.epoch(), epoch, "{corrupt}");
            assert!(
                store.deltas_since_with_revision(cursor, 10).reset_required,
                "{corrupt}"
            );
            let (epoch, cursor) = (store.epoch(), store.current_revision());
            assert!(store.close_persistence());
            drop(store);
            // The boot flush re-marked the table: the next boot keeps
            // the new history.
            let store = open(&dir);
            assert_eq!(store.epoch(), epoch, "{corrupt}");
            assert!(
                !store.deltas_since_with_revision(cursor, 10).reset_required,
                "{corrupt}"
            );
            assert!(store.close_persistence());
        }
    }

    /// A meta row written before the marker existed (a bare hole list)
    /// is accepted once, and the boot flush adds the marker.
    #[test]
    fn a_meta_row_without_a_marker_is_accepted() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        let epoch = store.epoch();
        let cursor = store.current_revision();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute(
                "UPDATE device_state_meta SET holes_json = json_extract(holes_json, '$.holes')",
                [],
            )
        })
        .expect("strip the marker");
        let stripped: String = db
            .read(|c| c.query_row("SELECT holes_json FROM device_state_meta", [], |r| r.get(0)))
            .expect("read");
        assert!(stripped.starts_with('['), "{stripped}");
        drop(db);
        let store = open(&dir);
        assert_eq!(store.epoch(), epoch);
        assert!(!store.deltas_since_with_revision(cursor, 10).reset_required);
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        let marked: String = db
            .read(|c| c.query_row("SELECT holes_json FROM device_state_meta", [], |r| r.get(0)))
            .expect("read");
        assert!(marked.contains("\"check\""), "{marked}");
        assert!(store.close_persistence());
    }

    /// Follow-up to H2: a failing flush reports the store degraded with
    /// its error, keeps the changes queued, and a later success clears
    /// it.
    #[test]
    fn failing_flushes_report_degraded_until_one_succeeds() {
        let dir = tempdir();
        let store = open(&dir);
        stop_flusher(&store);
        assert!(!store.flush_health().degraded);
        assert!(store.flush_health().last_flush_ms.is_some());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        db.write(|c| c.execute("ALTER TABLE device_state RENAME TO device_state_away", []))
            .expect("hide the table");
        put(&store, "dev-a", true);
        assert!(store.flush().is_err());
        let health = store.flush_health();
        assert!(health.degraded);
        assert!(health.degraded_since_ms.is_some());
        assert!(health.last_error.is_some());
        assert_eq!(health.failed_flushes_total, 1);
        assert_eq!(health.pending_keys, 1);
        db.write(|c| c.execute("ALTER TABLE device_state_away RENAME TO device_state", []))
            .expect("restore the table");
        assert!(store.flush().expect("flush"));
        let health = store.flush_health();
        assert!(!health.degraded);
        assert_eq!(health.last_error, None);
        assert_eq!(health.failed_flushes_total, 1);
        assert_eq!(health.pending_keys, 0);
        assert_eq!(
            DeviceStateStore::new().flush_health(),
            DeviceStateHealth::default()
        );
    }

    #[test]
    fn legacy_pagination_cursor_is_a_restart() {
        let store = DeviceStateStore::new();
        assert_eq!(
            store.verify_cursor("epoch-00.12.dev-x.00000000000000000000000000000000"),
            Err(CursorError::EpochChanged)
        );
        assert_eq!(store.verify_cursor("x.1.y.z"), Err(CursorError::Bad));
    }

    /// Round-3: a slot already stale on disk, whose newer write was
    /// lost, comes back above every surviving cursor, so a client
    /// polling from the flushed revision is sent it again.
    #[test]
    fn restored_stale_slots_are_redelivered_to_surviving_cursors() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        store.mark_device_stale("dev-a");
        store.flush().expect("flush");
        let pin = store.current_revision();
        stop_flusher(&store);
        put(&store, "dev-a", false);
        drop(store);
        let store = open(&dir);
        let page = store.deltas_since_with_revision(pin, 10);
        assert!(!page.reset_required);
        assert!(
            page.entries.iter().any(|e| e.device_id == "dev-a"),
            "the restored slot must be re-sent",
        );
        assert!(store.close_persistence());
    }

    /// Round-3: once a newer store has claimed the table, a batch from
    /// an older store is refused instead of overwriting its meta.
    #[test]
    fn a_superseded_store_cannot_flush() {
        let dir = tempdir();
        let old = open(&dir);
        stop_flusher(&old);
        put(&old, "dev-a", true);
        let new = open(&dir);
        let new_revision = new.current_revision();
        assert!(old.flush().is_err(), "old store must be refused");
        assert!(new.close_persistence());
        drop(new);
        drop(old);
        let store = open(&dir);
        assert!(store.current_revision() > new_revision);
        assert!(store.close_persistence());
    }

    /// Round-3: owner bindings are released with their last holder,
    /// and an older holder can't release a newer installation's.
    #[test]
    fn owner_bindings_are_refcounted() {
        let store = DeviceStateStore::new();
        store.bind_owner_plugin("i", "p", "u1");
        store.bind_owner_plugin("i", "p", "u1");
        store.unbind_owner_plugin("i", "u1");
        assert_eq!(store.inner_read().owner_identity("i").install, "u1");
        store.bind_owner_plugin("i", "p", "u2");
        store.unbind_owner_plugin("i", "u1");
        assert_eq!(store.inner_read().owner_identity("i").install, "u2");
        store.unbind_owner_plugin("i", "u2");
        assert!(store.inner_read().owner_plugins.is_empty());
    }

    /// Round-3: a row with a column of the wrong SQL type is skipped
    /// like any other damage instead of failing the boot.
    #[test]
    fn a_row_with_a_wrong_column_type_is_skipped() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        put(&store, "dev-b", true);
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute(
                "UPDATE device_state SET global_revision = 'x' WHERE device_id = 'dev-b'",
                [],
            )
        })
        .expect("corrupt a row");
        drop(db);
        let store = open(&dir);
        assert!(store.snapshot_capability("dev-a", "switch").is_some());
        assert!(store.snapshot_capability("dev-b", "switch").is_none());
        assert!(store.close_persistence());
    }

    /// Round-4: unusable metadata (a wrong SQL type, or a revision
    /// with no room left) starts a new history instead of failing the
    /// boot or overflowing.
    #[test]
    fn unusable_meta_starts_a_new_history() {
        for corrupt in [
            "UPDATE device_state_meta SET holes_json = x'00'",
            "UPDATE device_state_meta SET revision = -1",
            "UPDATE device_state_meta SET evicted_through = -1",
            "UPDATE device_state_meta SET epoch = ''",
            "UPDATE device_state_meta SET revision = 0",
            "UPDATE device_state_meta SET holes_json = '[[1,2]]'",
        ] {
            let dir = tempdir();
            let store = open(&dir);
            put(&store, "dev-a", true);
            let epoch = store.epoch();
            let cursor = store.current_revision();
            assert!(store.close_persistence());
            let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
            drop(store);
            db.write(|c| c.execute(corrupt, [])).expect("corrupt meta");
            drop(db);
            let store = open(&dir);
            assert_ne!(store.epoch(), epoch, "{corrupt}");
            // Expired by the watermark too, unless the revision had no
            // room left (`-1`) and the history restarted from zero.
            assert!(
                store.deltas_since_with_revision(cursor, 10).reset_required
                    || store.current_revision() < REVISION_GAP,
                "{corrupt}"
            );
            assert!(store.snapshot_capability("dev-a", "switch").is_some());
            assert!(store.close_persistence());
        }
    }

    /// Round-5: a row with an out-of-range generation is dropped as
    /// damage instead of seeding an overflowing counter.
    #[test]
    fn a_row_with_a_huge_generation_is_skipped() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        put(&store, "dev-b", true);
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        db.write(|c| {
            c.execute(
                "UPDATE device_state SET source_generation = -1 WHERE device_id = 'dev-b'",
                [],
            )
        })
        .expect("corrupt a row");
        drop(db);
        let store = open(&dir);
        assert!(store.snapshot_capability("dev-b", "switch").is_none());
        assert!(store.snapshot_capability("dev-a", "switch").is_some());
        assert!(store.close_persistence());
    }

    /// PR round 1: restoring more fresh slots than the runtime stale
    /// cap keeps every one of them (and on disk).
    #[test]
    fn restore_keeps_more_slots_than_the_stale_cap() {
        let dir = tempdir();
        let store = open(&dir);
        let n = super::super::MAX_STALE_ENTRIES + 3;
        for i in 0..n {
            put(&store, &format!("dev-{i:05}"), true);
        }
        assert!(store.close_persistence());
        drop(store);
        let store = open(&dir);
        assert_eq!(
            store
                .snapshot_page_capped(
                    None,
                    usize::MAX,
                    usize::MAX,
                    crate::state::PageSizing::Estimate,
                    usize::MAX,
                    |_| true,
                )
                .devices
                .len(),
            n
        );
        assert!(store.close_persistence());
        drop(store);
        let store = open(&dir);
        // A supervisor starting (a no-op stale sweep) must not evict.
        let _ = store.restart_generation("inst");
        let _ = store.restart_generation("other-inst");
        assert_eq!(
            store
                .snapshot_page_capped(
                    None,
                    usize::MAX,
                    usize::MAX,
                    crate::state::PageSizing::Estimate,
                    usize::MAX,
                    |_| true,
                )
                .devices
                .len(),
            n
        );
        assert!(store.close_persistence());
    }

    /// PR round 3: a persisted range shifted onto a surviving row, an
    /// oversized id and a slot over the field cap are all damage.
    #[test]
    fn shifted_ranges_and_oversized_rows_are_damage() {
        let dir = tempdir();
        let store = open(&dir);
        put(&store, "dev-a", true);
        assert!(store.close_persistence());
        drop(store);
        // Second boot: one range recorded, dev-a renumbered above it.
        let store = open(&dir);
        let epoch = store.epoch();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        let (lo, hi): (i64, i64) = db
            .read(|c| {
                c.query_row(
                    "SELECT json_extract(holes_json, '$.holes') FROM device_state_meta",
                    [],
                    |r| r.get::<_, String>(0),
                )
            })
            .map(|j| {
                let v: Vec<(i64, i64)> = serde_json::from_str(&j).expect("holes");
                *v.last().expect("a range")
            })
            .expect("meta");
        let row_rev: i64 = db
            .read(|c| c.query_row("SELECT global_revision FROM device_state", [], |r| r.get(0)))
            .expect("row");
        // Shift the range up so it ends on the surviving row (written
        // as a bare list, which has no marker to fail).
        let shift = row_rev - hi;
        db.write(|c| {
            c.execute(
                "UPDATE device_state_meta SET holes_json = ?1",
                [format!("[[{},{}]]", lo + shift, hi + shift)],
            )
        })
        .expect("shift range");
        drop(db);
        let store = open(&dir);
        assert_ne!(store.epoch(), epoch, "shifted range must be damage");
        // Oversized id and too many fields: rows skipped.
        let big = "x".repeat(MAX_RESTORED_ID_LEN + 1);
        let many: Vec<KeyValue> = (0..=super::super::MAX_FIELDS_PER_SLOT)
            .map(|i| KeyValue {
                key: format!("k{i}"),
                value: Value::BoolVal(true),
            })
            .collect();
        assert!(store.close_persistence());
        let db = Arc::clone(&store.backing.as_ref().expect("backing").db);
        drop(store);
        let blob = encode_fields(&many).expect("encode");
        db.write(|c| {
            c.execute(
                "INSERT INTO device_state SELECT ?1, capability, owner_instance, owner_plugin, \
                 owner_install, fields_blob, global_revision + 1, received_ms, observed_ms, \
                 source_generation, quality FROM device_state WHERE device_id = 'dev-a'",
                [&big],
            )?;
            c.execute(
                "INSERT INTO device_state SELECT 'dev-many', capability, owner_instance, \
                 owner_plugin, owner_install, ?1, global_revision + 2, received_ms, \
                 observed_ms, source_generation, quality FROM device_state WHERE device_id = 'dev-a'",
                [&blob],
            )
        })
        .expect("insert bad rows");
        drop(db);
        let store = open(&dir);
        assert!(store.snapshot_capability(&big, "switch").is_none());
        assert!(store.snapshot_capability("dev-many", "switch").is_none());
        assert!(store.snapshot_capability("dev-a", "switch").is_some());
        assert!(store.close_persistence());
    }
}
