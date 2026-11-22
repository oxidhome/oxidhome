//! Instance-id bookkeeping shared by a [`crate::TestHost`] and the
//! instances it hands out.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oxidhome_core::Engine;

use crate::TestHostError;

/// Ids of the instances currently alive on one host, direct or
/// supervised. Each claim gets a generation so a late release of an
/// old claim can't free the id a newer instance holds.
#[derive(Default)]
pub(crate) struct LiveIds {
    ids: Mutex<HashMap<String, u64>>,
    next_generation: AtomicU64,
}

impl LiveIds {
    /// Claim `id`, refusing one a live instance on this host holds —
    /// including one started straight on the engine and not yet reaped.
    pub(crate) fn claim(
        self: &Arc<Self>,
        engine: &Engine,
        id: String,
    ) -> Result<IdLease, TestHostError> {
        let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        if ids.contains_key(&id) || engine.instance(&id).is_some() {
            return Err(TestHostError::DuplicateInstanceId(id));
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        ids.insert(id.clone(), generation);
        Ok(IdLease {
            live: Arc::clone(self),
            id,
            generation,
        })
    }

    fn release(&self, id: &str, generation: u64) {
        let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        if ids.get(id) == Some(&generation) {
            ids.remove(id);
        }
    }
}

/// One claim on an instance id; dropping it frees the id.
pub(crate) struct IdLease {
    live: Arc<LiveIds>,
    id: String,
    generation: u64,
}

impl IdLease {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for IdLease {
    fn drop(&mut self) {
        self.live.release(&self.id, self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_release_keeps_a_newer_claim() {
        let engine = Engine::new().expect("engine");
        let live = Arc::new(LiveIds::default());
        let first = live.claim(&engine, "a".into()).expect("claim");
        assert!(matches!(
            live.claim(&engine, "a".into()),
            Err(TestHostError::DuplicateInstanceId(_))
        ));
        let stale_generation = first.generation;
        drop(first);
        let second = live.claim(&engine, "a".into()).expect("reclaim");
        live.release("a", stale_generation);
        assert!(live.claim(&engine, "a".into()).is_err(), "newer claim lost");
        drop(second);
        assert_eq!(live.claim(&engine, "a".into()).expect("free").id(), "a");
    }
}
