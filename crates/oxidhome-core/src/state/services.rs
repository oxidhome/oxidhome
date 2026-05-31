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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, ServiceId};

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
    /// instance. (7c adds an active-call check that refuses removal
    /// while a `call-service` is in flight.)
    pub async fn remove(&self, owner_instance: &str, id: &ServiceId) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                guard.remove(id);
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
}
