//! Purging a removed script sandbox's storage (ADR-0001, follow-up to
//! the purge-on-`stop-sandbox` of #205).
//!
//! Two races made that purge unreliable, and this module closes both:
//!
//! - **A storage write still running.** A stop cancels a guest call
//!   blocked past the grace period, but a KV or blob operation it had
//!   handed to a blocking thread keeps running, and could land after
//!   the purge. [`StorageOps`] counts the operations in flight per
//!   instance id; the purge waits until there are none.
//! - **A failed purge freeing the id.** A purge that fails (or is cut
//!   off by a shutdown or a crash) used to free the sandbox id anyway,
//!   so a new sandbox under it would inherit the old rows. The purge is
//!   now announced by a persisted marker (migration 22,
//!   `sandbox_removal`) written before it starts and deleted once it
//!   succeeds. While a marker exists, `start-sandbox` refuses the id;
//!   at boot, before any plugin runs, every marker's purge is run
//!   again.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::params;

use crate::state::{BlobStore, Db, KvStore};

/// How long a purge waits for the storage operations a cancelled call
/// left running. Past it the purge is left to the next boot.
pub(crate) const STORAGE_OP_DRAIN: Duration = Duration::from_secs(5);

/// KV and blob operations in flight, per `(installation_uuid,
/// instance_id)`: the key the purge and its marker use, so another
/// installation's stalled write under a reused id doesn't hold it up.
#[derive(Debug, Default)]
pub(crate) struct StorageOps {
    counts: Mutex<HashMap<Removal, usize>>,
    idle: tokio::sync::Notify,
}

/// One storage operation in flight; moved into the blocking task that
/// runs it, so it ends when the operation does, not when the guest
/// call that started it is cancelled.
#[derive(Debug)]
pub(crate) struct StorageOpGuard {
    ops: Arc<StorageOps>,
    key: Removal,
}

impl StorageOps {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Removal, usize>> {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count an operation for the instance until the guard drops.
    pub(crate) fn enter(
        self: &Arc<Self>,
        installation_uuid: &str,
        instance_id: &str,
    ) -> StorageOpGuard {
        let key = (installation_uuid.to_owned(), instance_id.to_owned());
        *self.lock().entry(key.clone()).or_default() += 1;
        StorageOpGuard {
            ops: Arc::clone(self),
            key,
        }
    }

    fn in_flight(&self, key: &Removal) -> usize {
        self.lock().get(key).copied().unwrap_or(0)
    }

    /// Wait up to `timeout` until the instance has no operation in
    /// flight. `true` when it has none.
    pub(crate) async fn wait_idle(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        timeout: Duration,
    ) -> bool {
        let key = (installation_uuid.to_owned(), instance_id.to_owned());
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Registered before the check, so a guard dropping in
            // between still wakes this wait.
            notified.as_mut().enable();
            if self.in_flight(&key) == 0 {
                return true;
            }
            // Other instances' operations wake this too; they can't
            // stretch the bound.
            if tokio::time::Instant::now() >= deadline
                || tokio::time::timeout_at(deadline, notified).await.is_err()
            {
                return self.in_flight(&key) == 0;
            }
        }
    }
}

impl Drop for StorageOpGuard {
    fn drop(&mut self) {
        let mut counts = self.ops.lock();
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
                drop(counts);
                self.ops.idle.notify_waiters();
            }
        }
    }
}

/// A sandbox whose storage purge hasn't completed:
/// `(installation_uuid, instance_id)`.
pub(crate) type Removal = (String, String);

/// Persist the marker for a purge about to start. Committed with
/// `synchronous = FULL`, so a power cut can't lose it while keeping the
/// storage it announces the purge of.
pub(crate) fn mark(db: &Db, installation_uuid: &str, instance_id: &str) -> rusqlite::Result<()> {
    db.write(|conn| {
        conn.pragma_update(None, "synchronous", "FULL")?;
        let result = conn
            .execute(
                "INSERT OR IGNORE INTO sandbox_removal (installation_uuid, instance_id, created_ms) \
                 VALUES (?1, ?2, ?3)",
                params![
                    installation_uuid,
                    instance_id,
                    crate::state::event_log::now_unix_ms()
                ],
            )
            .map(drop);
        // A failed restore leaves the connection at FULL: safe, only
        // slower.
        if let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
            tracing::warn!(error = %err, "failed to restore synchronous = NORMAL after a removal marker");
        }
        result
    })
}

/// Where the reaper finds the removal marker `stop-sandbox` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerState {
    Persisted,
    /// The write failed (or there was none): the reaper writes it.
    Failed,
    /// Still being written past [`STORAGE_OP_DRAIN`] (a stalled
    /// database writer): it lands later, and the next boot purges.
    Writing,
}

/// What `stop-sandbox` tells the reaper once it has tried to persist a
/// removal: the installation the sandbox's storage belongs to, and
/// whether the marker committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marked {
    pub(crate) installation_uuid: String,
    pub(crate) persisted: bool,
}

/// Every marker left, oldest first.
pub(crate) fn pending(db: &Db) -> rusqlite::Result<Vec<Removal>> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT installation_uuid, instance_id FROM sandbox_removal \
             ORDER BY created_ms, instance_id",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    })
}

/// Forget the markers of an uninstalled installation: its whole
/// storage was purged.
pub(crate) fn forget_installation(db: &Db, installation_uuid: &str) -> rusqlite::Result<()> {
    db.write(|conn| {
        conn.execute(
            "DELETE FROM sandbox_removal WHERE installation_uuid = ?1",
            params![installation_uuid],
        )
        .map(drop)
    })
}

/// Purge one removed sandbox's KV and blob storage, then delete its
/// marker. Idempotent; on an error the marker stays.
pub(crate) fn purge(
    db: &Db,
    kv: &KvStore,
    blobs: &BlobStore,
    installation_uuid: &str,
    instance_id: &str,
) -> Result<(), String> {
    kv.purge_instance(installation_uuid, instance_id)
        .map_err(|err| format!("kv: {err}"))?;
    blobs
        .purge_instance(installation_uuid, instance_id)
        .map_err(|err| format!("blobs: {err}"))?;
    db.write(|conn| {
        conn.execute(
            "DELETE FROM sandbox_removal WHERE installation_uuid = ?1 AND instance_id = ?2",
            params![installation_uuid, instance_id],
        )
    })
    .map_err(|err| format!("clearing the removal marker: {err}"))?;
    Ok(())
}

/// Boot: run every purge a previous process left unfinished. Returns
/// the removals still pending (their ids stay blocked); markers that
/// can't be read fail the boot rather than free their ids.
pub(crate) fn resume(
    db: &Db,
    kv: &KvStore,
    blobs: &BlobStore,
) -> rusqlite::Result<HashSet<Removal>> {
    let removals = pending(db)?;
    let mut left = HashSet::new();
    for (uuid, id) in removals {
        match purge(db, kv, blobs, &uuid, &id) {
            Ok(()) => {
                tracing::info!(instance_id = %id, "removed script sandbox's storage purged at startup");
            }
            Err(err) => {
                tracing::error!(
                    instance_id = %id,
                    error = %err,
                    "purging a removed script sandbox's storage failed again; its id stays \
                     blocked until a later start succeeds",
                );
                left.insert((uuid, id));
            }
        }
    }
    Ok(left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_purge_waits_for_operations_in_flight() {
        let ops = Arc::new(StorageOps::default());
        let guard = ops.enter("u", "a~s");
        let other = ops.enter("u", "b");
        assert!(!ops.wait_idle("u", "a~s", Duration::from_millis(20)).await);
        // Another installation's instance of the same id doesn't count.
        assert!(ops.wait_idle("v", "a~s", Duration::ZERO).await);
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(guard);
        });
        assert!(ops.wait_idle("u", "a~s", Duration::from_secs(5)).await);
        release.await.unwrap();
        // Another instance's operation doesn't count.
        assert_eq!(ops.in_flight(&("u".into(), "b".into())), 1);
        drop(other);
        assert!(ops.wait_idle("u", "b", Duration::ZERO).await);
    }

    #[test]
    fn a_marker_survives_until_its_purge_succeeds() {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let kv = KvStore::new(Arc::clone(&db));
        let blobs = BlobStore::new(Arc::clone(&db), None);
        mark(&db, "inst-u", "p~s").unwrap();
        mark(&db, "inst-u", "p~s").unwrap();
        assert_eq!(pending(&db).unwrap(), [("inst-u".into(), "p~s".into())]);
        // The blob store refuses an unsafe id: the purge fails and the
        // marker stays.
        mark(&db, "inst-u", "../x").unwrap();
        let left = resume(&db, &kv, &blobs).unwrap();
        assert_eq!(left, HashSet::from([("inst-u".into(), "../x".into())]));
        assert_eq!(pending(&db).unwrap(), [("inst-u".into(), "../x".into())]);
        forget_installation(&db, "inst-u").unwrap();
        assert_eq!(pending(&db).unwrap(), []);
    }
}
