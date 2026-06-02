//! In-memory service registry — Phase 7.
//!
//! Parallel to [`DeviceRegistry`](crate::state::DeviceRegistry): holds
//! every service any plugin instance has registered, keyed by the
//! host-assigned `service-id`, remembering the owning instance so the
//! Phase-7c dispatcher can route `call-service` back to it.
//!
//! Owner-scoping matches `host-devices`: `update` / `remove` / `get`
//! reject a non-owner with `NotFound` (indistinguishable from "id never
//! existed") so a plugin can't probe another plugin's service ids. The
//! dispatcher uses the unscoped [`Self::get_owner`] (owner-only) on the
//! hot routing path and [`Self::get_any`] when it needs the full meta.
//!
//! **Concurrency.** All methods are synchronous. The `inner` map lives
//! behind a `std::sync::RwLock` and the active-call counter behind a
//! `std::sync::Mutex` — none of the registry operations await across
//! the lock, so the async wrappers from the earlier `tokio::sync::*`
//! shape were paying for a fairness queue we never used. Holding both
//! sync locks together is bounded by a `HashMap` lookup + a counter
//! check, and `CallGuard::Drop` decrements without needing a tokio
//! runtime handle (closes the cancel/teardown leak path).
//!
//! **Cheap reads.** `get` / `get_any` / `list` return `Arc<ServiceMeta>`
//! rather than deep-cloning the meta (which carries `ServiceInfo` with
//! its `Vec<CommandSpec>` + `Vec<KeyValue>` and several `String`s).
//! Plugin-facing `host_services::get-service` still has to hand the
//! wasm caller an owned `ServiceInfo`, so it pays one clone of `info`
//! — but the `id` / `owner_instance` outer fields and per-entry
//! deep-copies on `list` are gone.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, ServiceId};

/// Per-`ServiceId` in-flight call counters. Bumped by [`CallGuard`]
/// at acquire time, decremented on Drop.
type ActiveCalls = HashMap<ServiceId, u32>;

/// What the registry stores per service. Held behind `Arc` so reads
/// are an atomic bump rather than a deep clone of the contained
/// `ServiceInfo`.
#[derive(Debug)]
pub struct ServiceMeta {
    /// Stable host-assigned id, the registry's key.
    pub id: ServiceId,
    /// The plugin-instance that registered (and owns) this service.
    pub owner_instance: String,
    /// Plugin-supplied registration data — name, metadata, commands.
    pub info: ServiceInfo,
}

/// In-memory service registry, one per [`Engine`](crate::Engine).
///
/// IDs are minted from an atomic counter as `svc-<n>` — a distinct
/// id-space from the device registry's `dev-<n>`.
#[derive(Default, Debug)]
pub struct ServiceRegistry {
    inner: RwLock<HashMap<ServiceId, Arc<ServiceMeta>>>,
    /// In-flight call refcounts per service. Separate `Mutex` so
    /// `meta` reads don't have to take a write lock to bump the
    /// counter, `remove` can fail fast on `count > 0` without
    /// cloning meta, and [`CallGuard::drop`] can decrement
    /// synchronously without holding a tokio runtime handle.
    active_calls: Mutex<ActiveCalls>,
    next_id: AtomicU64,
}

impl ServiceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_id(&self) -> ServiceId {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("svc-{n}")
    }

    // Poison-tolerant lock accessors. `std::sync::*` poisons on a
    // panic-under-lock, after which every `.unwrap()` / `.expect()` on
    // the lock panics too — a single hiccup would brick the registry
    // for the engine's lifetime. None of our critical sections can
    // leave the map invariant-violated (atomic `HashMap` ops + Arc /
    // String clones + integer math), so recovering the inner guard is
    // both correct and far less alarming than a cascading panic.
    fn services_read(&self) -> RwLockReadGuard<'_, HashMap<ServiceId, Arc<ServiceMeta>>> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn services_write(&self) -> RwLockWriteGuard<'_, HashMap<ServiceId, Arc<ServiceMeta>>> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }
    fn calls_lock(&self) -> MutexGuard<'_, ActiveCalls> {
        self.active_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a service on behalf of `owner_instance`. Returns the
    /// fresh host-assigned id.
    pub fn register(&self, owner_instance: String, info: ServiceInfo) -> ServiceId {
        let id = self.mint_id();
        let meta = Arc::new(ServiceMeta {
            id: id.clone(),
            owner_instance,
            info,
        });
        self.services_write().insert(id.clone(), meta);
        id
    }

    /// Replace an already-registered service's info, scoped to the
    /// caller's instance. A mismatched (or missing) owner returns
    /// `NotFound` to avoid leaking existence.
    pub fn update(
        &self,
        owner_instance: &str,
        id: &ServiceId,
        info: ServiceInfo,
    ) -> Result<(), WitError> {
        let mut guard = self.services_write();
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                // Rebuild the Arc rather than mutating in place —
                // outstanding `Arc<ServiceMeta>` clones from `get` /
                // `list` are immutable snapshots; the new Arc takes
                // over the slot, old observers keep what they had.
                let new = Arc::new(ServiceMeta {
                    id: meta.id.clone(),
                    owner_instance: meta.owner_instance.clone(),
                    info,
                });
                guard.insert(id.clone(), new);
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("service {id} not registered"))),
        }
    }

    /// Drop a service from the registry, scoped to the caller's
    /// instance. `NotFound` if the id is missing or owned by another
    /// instance; [`WitError::Unavailable`] if a `call-service` against
    /// it is still in flight (the dispatcher's [`CallGuard`] holds a
    /// refcount). Lock order (`inner` → `active_calls`) matches
    /// [`Self::acquire_call`] to keep the two linearizable.
    pub fn remove(&self, owner_instance: &str, id: &ServiceId) -> Result<(), WitError> {
        let mut guard = self.services_write();
        let mut calls = self.calls_lock();
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                let in_flight = calls.get(id).copied().unwrap_or(0);
                if in_flight > 0 {
                    return Err(WitError::Unavailable(format!(
                        "service {id} has {in_flight} active call(s); retry after they complete"
                    )));
                }
                guard.remove(id);
                calls.remove(id);
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("service {id} not registered"))),
        }
    }

    /// Look up a service by id, scoped to the caller's instance.
    /// Returns a cheap `Arc<ServiceMeta>` (atomic bump, no deep copy).
    pub fn get(&self, owner_instance: &str, id: &ServiceId) -> Result<Arc<ServiceMeta>, WitError> {
        let guard = self.services_read();
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => Ok(Arc::clone(meta)),
            _ => Err(WitError::NotFound(format!("service {id} not registered"))),
        }
    }

    /// Cross-instance lookup — the dispatcher's full-meta primitive
    /// when it needs more than the owner (e.g. error messages, the
    /// API/MCP read paths). Not owner-scoped. Plugin-facing reads
    /// go through [`Self::get`].
    pub fn get_any(&self, id: &ServiceId) -> Result<Arc<ServiceMeta>, WitError> {
        self.services_read()
            .get(id)
            .map(Arc::clone)
            .ok_or_else(|| WitError::NotFound(format!("service {id} not registered")))
    }

    /// Cross-instance owner lookup — what the dispatcher actually
    /// needs on the routing hot path. Avoids cloning the full
    /// `ServiceMeta` (with its `Vec<CommandSpec>` etc.) when the
    /// caller only needs to route the call to its owner.
    #[must_use]
    pub fn get_owner(&self, id: &ServiceId) -> Option<String> {
        self.services_read()
            .get(id)
            .map(|m| m.owner_instance.clone())
    }

    /// Bump the in-flight refcount for `id`; the returned [`CallGuard`]
    /// decrements on drop. The dispatcher acquires one before sending
    /// `ControlCommand::ExecuteService` and hands it to the callee's
    /// supervisor so the refcount tracks real execution. Returns
    /// `NotFound` if `id` isn't registered (checked under the same
    /// services read lock as the counter increment so an in-flight
    /// removal can't race the bump).
    pub fn acquire_call(self: &Arc<Self>, id: &ServiceId) -> Result<CallGuard, WitError> {
        let services = self.services_read();
        if !services.contains_key(id) {
            return Err(WitError::NotFound(format!("service {id} not registered")));
        }
        let mut calls = self.calls_lock();
        *calls.entry(id.clone()).or_insert(0) += 1;
        Ok(CallGuard {
            registry: Arc::clone(self),
            id: id.clone(),
        })
    }

    /// Internal: decrement the in-flight refcount for `id`. Called
    /// from [`CallGuard::drop`]. Tolerant of an over-release.
    fn release_call(&self, id: &ServiceId) {
        let mut calls = self.calls_lock();
        if let Some(n) = calls.get_mut(id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                calls.remove(id);
            }
        }
    }

    /// Snapshot of the in-flight refcount for `id`. Test helper.
    #[doc(hidden)]
    #[must_use]
    pub fn active_call_count(&self, id: &ServiceId) -> u32 {
        self.calls_lock().get(id).copied().unwrap_or(0)
    }

    /// Snapshot of every registered service — cheap (one `Arc::clone`
    /// per entry, no deep copies). Allocate-and-collect on purpose;
    /// fine for the API/MCP read paths, avoid in hot loops. The
    /// `Vec` is pre-sized to the registry length so the `Arc::clone`
    /// loop doesn't realloc-grow under the read lock.
    #[must_use]
    pub fn list(&self) -> Vec<Arc<ServiceMeta>> {
        let guard = self.services_read();
        let mut out = Vec::with_capacity(guard.len());
        out.extend(guard.values().map(Arc::clone));
        out
    }

    /// Drop every service owned by `instance_id`. Called by the
    /// supervisor when an instance reaches a terminal state *and* at
    /// the top of every restart attempt — without it, a plugin that
    /// `register-service`s in `init` and crash-loops stacks a fresh
    /// entry per restart life.
    ///
    /// Sweeps `active_calls` for the same ids. In the expected flow
    /// the supervisor's task drop runs every owned `CallGuard::Drop`
    /// before `wait_terminal()` returns, so the refcounts are
    /// already 0 by the time the reaper calls us — but matching
    /// [`Self::remove`]'s contract (clean both maps) means stale
    /// state from any unexpected path can't leak.
    ///
    /// Returns the number of `inner` entries removed (the public
    /// "what got swept" figure; the parallel `active_calls` cleanup
    /// is bookkeeping).
    pub fn remove_by_owner(&self, instance_id: &str) -> usize {
        let mut guard = self.services_write();
        let mut calls = self.calls_lock();
        let mut removed_ids: Vec<ServiceId> = Vec::new();
        guard.retain(|id, m| {
            if m.owner_instance == instance_id {
                removed_ids.push(id.clone());
                false
            } else {
                true
            }
        });
        for id in &removed_ids {
            calls.remove(id);
        }
        removed_ids.len()
    }
}

/// Shared `Arc` alias, parallel to `SharedDeviceRegistry`.
pub type SharedServiceRegistry = Arc<ServiceRegistry>;

/// RAII handle on an in-flight call refcount. The dispatcher takes
/// one with [`ServiceRegistry::acquire_call`] before dispatching and
/// hands it to the *callee's* supervisor inside the
/// `ControlCommand::ExecuteService` message; the supervisor holds it
/// across the wasm call and `Drop` decrements when the supervisor
/// finishes (or when the message is dropped without being processed
/// — e.g. control channel closed).
///
/// `Drop` is synchronous (the underlying counter is a
/// `std::sync::Mutex`) and reliable — no tokio runtime needed at
/// drop time, no detached spawn, no leak path on cancellation or
/// runtime teardown.
pub struct CallGuard {
    registry: Arc<ServiceRegistry>,
    id: ServiceId,
}

impl std::fmt::Debug for CallGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallGuard")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        self.registry.release_call(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str) -> ServiceInfo {
        ServiceInfo {
            local_id: name.to_string(),
            name: name.to_string(),
            metadata: Vec::new(),
            commands: Vec::new(),
        }
    }

    #[test]
    fn register_mints_distinct_svc_ids() {
        let reg = ServiceRegistry::new();
        let a = reg.register("alpha".into(), info("house-mode"));
        let b = reg.register("alpha".into(), info("evening"));
        assert!(a.starts_with("svc-"));
        assert_ne!(a, b);
        assert_eq!(reg.list().len(), 2);
    }

    /// `update`/`remove`/`get` reject a non-owner with `NotFound`,
    /// indistinguishable from "id never existed".
    #[test]
    fn cross_instance_access_is_rejected() {
        let reg = ServiceRegistry::new();
        let id = reg.register("alpha".into(), info("house-mode"));

        reg.get("alpha", &id).expect("owner can get");
        reg.update("alpha", &id, info("house-mode"))
            .expect("owner can update");

        for bad in ["beta", "gamma"] {
            assert!(matches!(
                reg.get(bad, &id).unwrap_err(),
                WitError::NotFound(_)
            ));
            assert!(matches!(
                reg.update(bad, &id, info("x")).unwrap_err(),
                WitError::NotFound(_)
            ));
            assert!(matches!(
                reg.remove(bad, &id).unwrap_err(),
                WitError::NotFound(_)
            ));
        }

        reg.get("alpha", &id).expect("still alpha's");
        reg.remove("alpha", &id).expect("owner can remove");
        reg.get("alpha", &id).expect_err("gone after remove");
    }

    /// `get_owner` lets the dispatcher route without pulling the
    /// full `ServiceMeta` (and its `Vec<CommandSpec>`) through the
    /// lock.
    #[test]
    fn get_owner_returns_just_the_owner() {
        let reg = ServiceRegistry::new();
        let id = reg.register("alpha".into(), info("house-mode"));
        assert_eq!(reg.get_owner(&id).as_deref(), Some("alpha"));
        assert_eq!(reg.get_owner(&"svc-nonexistent".to_string()), None);
    }

    /// `update` rebuilds the Arc — outstanding `get` snapshots see
    /// the *old* info, the new snapshot sees the update. Guarantees
    /// reads-while-update don't observe a partially-written meta.
    #[test]
    fn update_swaps_arc_without_disturbing_outstanding_snapshots() {
        let reg = ServiceRegistry::new();
        let id = reg.register("alpha".into(), info("v1"));
        let before = reg.get("alpha", &id).expect("get");
        assert_eq!(before.info.name, "v1");

        reg.update("alpha", &id, info("v2")).expect("update");
        let after = reg.get("alpha", &id).expect("get");
        assert_eq!(after.info.name, "v2");
        // The pre-update snapshot still observes the original name.
        assert_eq!(before.info.name, "v1");
    }

    /// `acquire_call` bumps the refcount; `remove` then refuses with
    /// `Unavailable`. The guard's `Drop` synchronously decrements
    /// — so dropping it lets the next `remove` succeed.
    #[test]
    fn remove_refuses_while_call_in_flight() {
        let reg = Arc::new(ServiceRegistry::new());
        let id = reg.register("alpha".into(), info("house-mode"));

        let guard = reg.acquire_call(&id).expect("acquire");
        assert_eq!(reg.active_call_count(&id), 1);

        match reg.remove("alpha", &id) {
            Err(WitError::Unavailable(msg)) => {
                assert!(
                    msg.contains("active call") && msg.contains(&id),
                    "expected the Unavailable message to name the active call + id, got: {msg}",
                );
            }
            other => panic!("expected Unavailable while in flight, got {other:?}"),
        }

        drop(guard);
        assert_eq!(reg.active_call_count(&id), 0);
        reg.remove("alpha", &id).expect("now removable");
    }

    /// `CallGuard::Drop` runs synchronously through a plain `Mutex`
    /// — no `tokio::runtime::Handle` lookup. A fresh `block_on`
    /// builds, acquires, drops, and the next `block_on` still sees
    /// the count back to 0.
    #[test]
    fn call_guard_drop_works_without_active_runtime() {
        let reg = Arc::new(ServiceRegistry::new());
        let id = reg.register("alpha".into(), info("ring"));

        let guard = reg.acquire_call(&id).expect("acquire");
        assert_eq!(reg.active_call_count(&id), 1);
        drop(guard);
        assert_eq!(reg.active_call_count(&id), 0);
    }

    /// `remove_by_owner` cleans `active_calls` alongside `inner`. In
    /// the supervised flow `CallGuard::Drop` already takes the count
    /// to 0 before the reaper runs, but this defends against any
    /// stale state from an unexpected path (and matches `remove`'s
    /// contract of clearing both maps).
    #[test]
    fn remove_by_owner_clears_active_calls_for_owner() {
        let reg = Arc::new(ServiceRegistry::new());
        let a1 = reg.register("alpha".into(), info("svc1"));
        let _a2 = reg.register("alpha".into(), info("svc2"));
        let b1 = reg.register("beta".into(), info("ring"));

        // Force a stale `active_calls` entry for an alpha service by
        // forgetting the guard (simulating a worst-case where the
        // refcount didn't drop cleanly).
        let alpha_guard = reg.acquire_call(&a1).expect("acquire alpha");
        let beta_guard = reg.acquire_call(&b1).expect("acquire beta");
        std::mem::forget(alpha_guard);
        assert_eq!(reg.active_call_count(&a1), 1);
        assert_eq!(reg.active_call_count(&b1), 1);

        let removed = reg.remove_by_owner("alpha");
        assert_eq!(removed, 2);
        // Alpha's stale active-call entry is gone — defense in depth.
        assert_eq!(reg.active_call_count(&a1), 0);
        // Beta's untouched (different owner).
        assert_eq!(reg.active_call_count(&b1), 1);
        drop(beta_guard);
        assert_eq!(reg.active_call_count(&b1), 0);
    }
}
