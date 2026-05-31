//! In-memory device registry.
//!
//! Holds every device any plugin instance has registered, keyed by
//! the host-assigned `device-id`. Each entry remembers the
//! plugin-instance that owns the device so the host can route
//! `execute-command` calls back to the right instance.
//!
//! The registry is `Arc<RwLock<…>>`-friendly: many readers (host-call
//! handlers, the future API/MCP surface) share access, occasional
//! writers (register / update / remove) take exclusive access. Phase
//! 5a swaps the in-memory `HashMap` for a `SQLite`-backed store
//! (see the storage-backend appendix in the plan).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, Error as WitError};

/// What the registry stores per device.
///
/// Cheap-to-clone (`DeviceInfo` is mostly small `String`s and a list
/// of capability specs). Read paths clone the meta out under a read
/// lock and drop the lock before forwarding to a plugin.
#[derive(Clone, Debug)]
pub struct DeviceMeta {
    /// Stable host-assigned id, the registry's key.
    pub id: DeviceId,
    /// The plugin-instance that registered (and therefore owns) this
    /// device. Commands targeting this device are routed back to this
    /// instance via [`PluginInstance::execute_command`](crate::PluginInstance::execute_command).
    pub owner_instance: String,
    /// Plugin-supplied registration data — name, manufacturer,
    /// capabilities, optional initial state, metadata.
    pub info: DeviceInfo,
}

/// In-memory device registry, one per [`Engine`](crate::Engine).
///
/// The current `RwLock<HashMap<…>>` shape is sufficient for Phase 3's
/// "simulated-switch + test harness listener" scenario; multi-instance
/// concurrency lands with Phase 6 (more readers, lock contention
/// becomes worth measuring), and Phase 5a moves the storage to `SQLite`.
///
/// IDs are minted from an atomic counter as `dev-<n>`. Stable enough
/// for tests and the in-memory phase; Phase 5a will swap for ULIDs
/// minted alongside the `SQLite`-persisted store so IDs survive
/// restart.
#[derive(Default, Debug)]
pub struct DeviceRegistry {
    inner: RwLock<HashMap<DeviceId, DeviceMeta>>,
    next_id: AtomicU64,
}

impl DeviceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_id(&self) -> DeviceId {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("dev-{n}")
    }

    /// Register a device on behalf of `owner_instance`. Returns the
    /// fresh host-assigned id.
    pub async fn register(&self, owner_instance: String, info: DeviceInfo) -> DeviceId {
        let id = self.mint_id();
        let meta = DeviceMeta {
            id: id.clone(),
            owner_instance,
            info,
        };
        self.inner.write().await.insert(id.clone(), meta);
        id
    }

    /// Replace an already-registered device's info, **scoped to the
    /// caller's plugin instance**. The WIT `host-devices` interface
    /// scopes every read/write to the calling plugin's own devices —
    /// a mismatched (or missing) owner returns `Error::NotFound`,
    /// deliberately indistinguishable from "id never existed" so a
    /// malicious plugin can't probe for other plugins' device ids.
    /// Doesn't change the owner; re-registration under a new owner
    /// has to go through `remove` + `register`.
    pub async fn update(
        &self,
        owner_instance: &str,
        id: &DeviceId,
        info: DeviceInfo,
    ) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        match guard.get_mut(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                meta.info = info;
                Ok(())
            }
            // Either no entry, or it exists under a different owner.
            // Both collapse to NotFound to avoid leaking existence.
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Drop a device from the registry, **scoped to the caller's
    /// plugin instance** (see [`Self::update`] for rationale). Returns
    /// `Error::NotFound` if the id is missing *or* owned by another
    /// instance.
    pub async fn remove(&self, owner_instance: &str, id: &DeviceId) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                guard.remove(id);
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Look up a device by id, **scoped to the caller's plugin
    /// instance** (see [`Self::update`] for rationale). Returns a
    /// snapshot of the metadata or `Error::NotFound`.
    pub async fn get(&self, owner_instance: &str, id: &DeviceId) -> Result<DeviceMeta, WitError> {
        let guard = self.inner.read().await;
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => Ok(meta.clone()),
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Snapshot of every registered device. Allocates — fine for the
    /// API/MCP read paths, avoid in hot loops.
    pub async fn list(&self) -> Vec<DeviceMeta> {
        self.inner.read().await.values().cloned().collect()
    }

    /// Drop every device owned by `instance_id`. Called by the
    /// Phase-6 supervisor when an instance reaches a terminal state
    /// *and* at the top of every restart attempt — without it, a
    /// plugin that `register-device`s in `init` and then crash-loops
    /// would stack a fresh entry per restart life, and even on clean
    /// stop its devices would outlive the instance. Returns the
    /// number of entries removed.
    pub async fn remove_by_owner(&self, instance_id: &str) -> usize {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, m| m.owner_instance != instance_id);
        before - guard.len()
    }
}

/// Bundle the registry into a shared `Arc` for [`Engine`] /
/// [`PluginState`](crate::runtime::PluginState) clones.
pub type SharedDeviceRegistry = Arc<DeviceRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_info() -> DeviceInfo {
        DeviceInfo {
            local_id: String::new(),
            name: String::new(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: Vec::new(),
            initial_state: Vec::new(),
            metadata: Vec::new(),
        }
    }

    /// `update`/`remove`/`get` must reject calls from a non-owner
    /// instance with `NotFound`, indistinguishable from "id never
    /// existed". The bug would let plugin B mutate plugin A's
    /// devices.
    #[tokio::test(flavor = "current_thread")]
    async fn cross_instance_access_is_rejected() {
        let reg = DeviceRegistry::new();
        let id = reg.register("alpha".into(), empty_info()).await;

        // Owner — happy path.
        reg.get("alpha", &id).await.expect("owner can get");
        reg.update("alpha", &id, empty_info())
            .await
            .expect("owner can update");

        // Non-owner — `NotFound`, regardless of method.
        let err = reg.get("beta", &id).await.unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
        let err = reg.update("beta", &id, empty_info()).await.unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
        let err = reg.remove("beta", &id).await.unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");

        // After a non-owner remove attempt, the device is still there
        // for its real owner.
        reg.get("alpha", &id)
            .await
            .expect("device still owned by alpha");

        // Owner can finally remove.
        reg.remove("alpha", &id).await.expect("owner can remove");
        reg.get("alpha", &id)
            .await
            .expect_err("device gone after remove");
    }
}
