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
//! cross-instance lookup the dispatcher needs (`get_any`) and the
//! active-call refcount that makes `remove` refuse while a call is in
//! flight land in 7c alongside the dispatcher that uses them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;

use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, ServiceId};

/// Internal: per-`ServiceId` in-flight call counters. Bumped by the
/// dispatcher's [`CallGuard`] before invoking `execute-service-command`,
/// decremented on guard drop. `remove` consults this to refuse removal
/// while a call is in flight. Held under a plain `std::sync::Mutex` so
/// the guard's `Drop` can always reclaim the refcount synchronously
/// — no tokio runtime required at drop time.
type ActiveCalls = HashMap<ServiceId, u32>;

/// What the registry stores per service.
#[derive(Clone, Debug)]
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
    inner: RwLock<HashMap<ServiceId, ServiceMeta>>,
    /// In-flight call refcounts per service. Separate sync `Mutex` so
    /// reads / writes against `meta` don't have to take a write lock
    /// just to bump the counter, `remove` can fail fast on `count > 0`
    /// without cloning meta, and the dispatcher's [`CallGuard::drop`]
    /// can decrement synchronously without holding (or needing) a
    /// tokio runtime handle.
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

    /// Register a service on behalf of `owner_instance`. Returns the
    /// fresh host-assigned id.
    pub async fn register(&self, owner_instance: String, info: ServiceInfo) -> ServiceId {
        let id = self.mint_id();
        let meta = ServiceMeta {
            id: id.clone(),
            owner_instance,
            info,
        };
        self.inner.write().await.insert(id.clone(), meta);
        id
    }

    /// Replace an already-registered service's info, scoped to the
    /// caller's instance. A mismatched (or missing) owner returns
    /// `NotFound` to avoid leaking existence.
    pub async fn update(
        &self,
        owner_instance: &str,
        id: &ServiceId,
        info: ServiceInfo,
    ) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        match guard.get_mut(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                meta.info = info;
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("service {id} not registered"))),
        }
    }

    /// Drop a service from the registry, scoped to the caller's
    /// instance. `NotFound` if the id is missing or owned by another
    /// instance; [`WitError::Unavailable`] if a `call-service` against
    /// it is still in flight (the dispatcher's [`CallGuard`] holds a
    /// refcount). Take both locks in a fixed order
    /// (`inner` → `active_calls`) to keep linearizable against
    /// [`Self::acquire_call`].
    pub async fn remove(&self, owner_instance: &str, id: &ServiceId) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        let mut calls = self.active_calls.lock().expect("active_calls poisoned");
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
    pub async fn get(&self, owner_instance: &str, id: &ServiceId) -> Result<ServiceMeta, WitError> {
        let guard = self.inner.read().await;
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => Ok(meta.clone()),
            _ => Err(WitError::NotFound(format!("service {id} not registered"))),
        }
    }

    /// Cross-instance lookup — the dispatcher's routing primitive.
    /// Unlike [`Self::get`], this is *not* owner-scoped: the caller is
    /// looking up *someone else's* service in order to call it. Use
    /// only from `runtime::dispatcher` and host-side API/MCP code;
    /// plugin-facing reads go through `get`.
    pub async fn get_any(&self, id: &ServiceId) -> Result<ServiceMeta, WitError> {
        self.inner
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| WitError::NotFound(format!("service {id} not registered")))
    }

    /// Bump the in-flight refcount for `id`; the returned [`CallGuard`]
    /// decrements on drop. The dispatcher holds one across each
    /// `execute-service-command` invocation so `remove-service` refuses
    /// while a call is alive. Returns `NotFound` if `id` isn't
    /// registered (checked under the same services lock as the
    /// increment so an in-flight removal can't race the bump).
    ///
    /// Lock order across this call and [`Self::remove`]: services
    /// first, then `active_calls`. Both operations follow it, so
    /// they're linearizable.
    pub async fn acquire_call(self: &Arc<Self>, id: &ServiceId) -> Result<CallGuard, WitError> {
        let services = self.inner.read().await;
        if !services.contains_key(id) {
            return Err(WitError::NotFound(format!("service {id} not registered")));
        }
        let mut calls = self.active_calls.lock().expect("active_calls poisoned");
        *calls.entry(id.clone()).or_insert(0) += 1;
        Ok(CallGuard {
            registry: Arc::clone(self),
            id: id.clone(),
        })
    }

    /// Internal: decrement the in-flight refcount for `id`. Called
    /// from [`CallGuard::drop`] — synchronous on purpose so it never
    /// needs to await a runtime. Tolerant of an over-release.
    fn release_call(&self, id: &ServiceId) {
        let mut calls = self.active_calls.lock().expect("active_calls poisoned");
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
        self.active_calls
            .lock()
            .expect("active_calls poisoned")
            .get(id)
            .copied()
            .unwrap_or(0)
    }

    /// Snapshot of every registered service. Allocates — fine for the
    /// API/MCP read paths, avoid in hot loops.
    pub async fn list(&self) -> Vec<ServiceMeta> {
        self.inner.read().await.values().cloned().collect()
    }

    /// Drop every service owned by `instance_id`. Called by the
    /// supervisor when an instance reaches a terminal state, *and* at
    /// the top of every restart attempt — without it, a plugin that
    /// `register-service`s in `init` and then crash-loops would stack
    /// a fresh entry per restart life, and even on clean stop its
    /// services would outlive the instance. Returns the number of
    /// entries removed (for tracing).
    pub async fn remove_by_owner(&self, instance_id: &str) -> usize {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, m| m.owner_instance != instance_id);
        before - guard.len()
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

    #[tokio::test(flavor = "current_thread")]
    async fn register_mints_distinct_svc_ids() {
        let reg = ServiceRegistry::new();
        let a = reg.register("alpha".into(), info("house-mode")).await;
        let b = reg.register("alpha".into(), info("evening")).await;
        assert!(a.starts_with("svc-"));
        assert_ne!(a, b);
        assert_eq!(reg.list().await.len(), 2);
    }

    /// `update`/`remove`/`get` reject a non-owner with `NotFound`,
    /// indistinguishable from "id never existed".
    #[tokio::test(flavor = "current_thread")]
    async fn cross_instance_access_is_rejected() {
        let reg = ServiceRegistry::new();
        let id = reg.register("alpha".into(), info("house-mode")).await;

        reg.get("alpha", &id).await.expect("owner can get");
        reg.update("alpha", &id, info("house-mode"))
            .await
            .expect("owner can update");

        for bad in ["beta", "gamma"] {
            assert!(matches!(
                reg.get(bad, &id).await.unwrap_err(),
                WitError::NotFound(_)
            ));
            assert!(matches!(
                reg.update(bad, &id, info("x")).await.unwrap_err(),
                WitError::NotFound(_)
            ));
            assert!(matches!(
                reg.remove(bad, &id).await.unwrap_err(),
                WitError::NotFound(_)
            ));
        }

        // Still owned by alpha after the failed non-owner removes.
        reg.get("alpha", &id).await.expect("still alpha's");
        reg.remove("alpha", &id).await.expect("owner can remove");
        reg.get("alpha", &id).await.expect_err("gone after remove");
    }

    /// `acquire_call` bumps the refcount; `remove` then refuses with
    /// `Unavailable`. The guard's `Drop` synchronously decrements
    /// (no tokio runtime required) — so dropping it lets the next
    /// `remove` succeed.
    #[tokio::test(flavor = "current_thread")]
    async fn remove_refuses_while_call_in_flight() {
        let reg = Arc::new(ServiceRegistry::new());
        let id = reg.register("alpha".into(), info("house-mode")).await;

        let guard = reg.acquire_call(&id).await.expect("acquire");
        assert_eq!(reg.active_call_count(&id), 1);

        match reg.remove("alpha", &id).await {
            Err(WitError::Unavailable(msg)) => {
                assert!(
                    msg.contains("active call") && msg.contains(&id),
                    "expected the Unavailable message to name the active call + id, got: {msg}",
                );
            }
            other => panic!("expected Unavailable while in flight, got {other:?}"),
        }

        // Dropping the guard releases the refcount synchronously.
        drop(guard);
        assert_eq!(reg.active_call_count(&id), 0);
        reg.remove("alpha", &id).await.expect("now removable");
    }

    /// `CallGuard::Drop` runs synchronously through a plain `Mutex`
    /// — no `tokio::runtime::Handle` lookup, no detached spawn. A
    /// fresh `Runtime::block_on` builds, acquires, drops, and the
    /// next `block_on` still sees the count back to 0.
    #[test]
    fn call_guard_drop_works_without_active_runtime() {
        use tokio::runtime::Builder;

        let reg = Arc::new(ServiceRegistry::new());
        let rt = Builder::new_current_thread().build().expect("rt");
        let id = rt.block_on(reg.register("alpha".into(), info("ring")));

        let guard = rt
            .block_on(reg.acquire_call(&id))
            .expect("acquire under runtime");
        assert_eq!(reg.active_call_count(&id), 1);

        // Tear the runtime down *first*, then drop the guard. With
        // the old `tokio::sync::RwLock` + `Handle::try_current()`
        // design this would have silently leaked the refcount.
        drop(rt);
        drop(guard);
        assert_eq!(reg.active_call_count(&id), 0);
    }
}
