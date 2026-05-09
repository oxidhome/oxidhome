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
//! 5a swaps the in-memory `HashMap` for the `SQLite`-backed store
//! described in `.claude/docs/03_core.md` Appendix A.

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

    /// Replace an already-registered device's info. Errors with
    /// `Error::NotFound` if the id isn't known. Doesn't change the
    /// owner — re-registration under a new owner has to go through
    /// `remove` + `register`.
    pub async fn update(&self, id: &DeviceId, info: DeviceInfo) -> Result<(), WitError> {
        let mut guard = self.inner.write().await;
        match guard.get_mut(id) {
            Some(meta) => {
                meta.info = info;
                Ok(())
            }
            None => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Drop a device from the registry. Errors with `Error::NotFound`
    /// if the id isn't known.
    pub async fn remove(&self, id: &DeviceId) -> Result<(), WitError> {
        match self.inner.write().await.remove(id) {
            Some(_) => Ok(()),
            None => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Look up a device by id, returning a snapshot of its metadata.
    /// Errors with `Error::NotFound` if the id isn't known.
    pub async fn get(&self, id: &DeviceId) -> Result<DeviceMeta, WitError> {
        self.inner
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| WitError::NotFound(format!("device {id} not registered")))
    }

    /// Snapshot of every registered device. Allocates — fine for the
    /// API/MCP read paths, avoid in hot loops.
    pub async fn list(&self) -> Vec<DeviceMeta> {
        self.inner.read().await.values().cloned().collect()
    }
}

/// Bundle the registry into a shared `Arc` for [`Engine`] /
/// [`PluginState`](crate::runtime::PluginState) clones.
pub type SharedDeviceRegistry = Arc<DeviceRegistry>;
