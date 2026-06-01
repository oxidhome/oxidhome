//! In-memory device registry.
//!
//! Holds every device any plugin instance has registered, keyed by
//! the host-assigned `device-id`. Each entry remembers the
//! plugin-instance that owns the device so the host can route
//! `execute-command` calls back to the right instance.
//!
//! **Concurrency.** All methods are synchronous, behind a
//! `std::sync::RwLock`. None of the registry operations await across
//! the lock, so the earlier `tokio::sync::RwLock` wrapper was paying
//! for an async fairness queue we never used. Reads dominate (host
//! routing + the future API/MCP surface); the sync lock is ~10× the
//! throughput on uncontended acquires.
//!
//! **Cheap reads.** `get` / `list` return `Arc<DeviceMeta>` rather
//! than deep-cloning `DeviceInfo` (which carries a `Vec<CapabilitySpec>`,
//! optional state, manufacturer / model / firmware strings, and a
//! metadata bag). Plugin-facing `host_devices::get-device` still has
//! to clone `info` once to hand off ownership at the WIT boundary,
//! but the outer fields and per-entry list copies are gone.
//!
//! Phase 5a's storage-backend appendix swaps the in-memory `HashMap`
//! for a `SQLite`-backed store; that work happens later.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, Error as WitError};

/// What the registry stores per device. Held behind `Arc` so reads
/// are an atomic bump rather than a deep clone of the contained
/// `DeviceInfo`.
#[derive(Debug)]
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
/// IDs are minted from an atomic counter as `dev-<n>`. Stable enough
/// for tests and the in-memory phase; Phase 5a will swap for ULIDs
/// minted alongside the `SQLite`-persisted store so IDs survive
/// restart.
#[derive(Default, Debug)]
pub struct DeviceRegistry {
    inner: RwLock<HashMap<DeviceId, Arc<DeviceMeta>>>,
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
    pub fn register(&self, owner_instance: String, info: DeviceInfo) -> DeviceId {
        let id = self.mint_id();
        let meta = Arc::new(DeviceMeta {
            id: id.clone(),
            owner_instance,
            info,
        });
        self.inner
            .write()
            .expect("devices lock poisoned")
            .insert(id.clone(), meta);
        id
    }

    /// Replace an already-registered device's info, scoped to the
    /// caller's plugin instance. The WIT `host-devices` interface
    /// scopes every read/write to the calling plugin's own devices —
    /// a mismatched (or missing) owner returns `Error::NotFound`,
    /// deliberately indistinguishable from "id never existed" so a
    /// malicious plugin can't probe for other plugins' device ids.
    /// Doesn't change the owner; re-registration under a new owner
    /// has to go through `remove` + `register`. The Arc is rebuilt
    /// rather than mutated so outstanding read snapshots see the
    /// pre-update info.
    pub fn update(
        &self,
        owner_instance: &str,
        id: &DeviceId,
        info: DeviceInfo,
    ) -> Result<(), WitError> {
        let mut guard = self.inner.write().expect("devices lock poisoned");
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                let new = Arc::new(DeviceMeta {
                    id: meta.id.clone(),
                    owner_instance: meta.owner_instance.clone(),
                    info,
                });
                guard.insert(id.clone(), new);
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Drop a device from the registry, scoped to the caller's
    /// plugin instance (see [`Self::update`] for rationale).
    pub fn remove(&self, owner_instance: &str, id: &DeviceId) -> Result<(), WitError> {
        let mut guard = self.inner.write().expect("devices lock poisoned");
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                guard.remove(id);
                Ok(())
            }
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Look up a device by id, scoped to the caller's instance.
    /// Returns a cheap `Arc<DeviceMeta>` (atomic bump, no deep copy).
    pub fn get(&self, owner_instance: &str, id: &DeviceId) -> Result<Arc<DeviceMeta>, WitError> {
        let guard = self.inner.read().expect("devices lock poisoned");
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => Ok(Arc::clone(meta)),
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Snapshot of every registered device — cheap (one `Arc::clone`
    /// per entry, no deep copies).
    #[must_use]
    pub fn list(&self) -> Vec<Arc<DeviceMeta>> {
        self.inner
            .read()
            .expect("devices lock poisoned")
            .values()
            .map(Arc::clone)
            .collect()
    }

    /// Drop every device owned by `instance_id`. Called by the
    /// Phase-6 supervisor when an instance reaches a terminal state
    /// *and* at the top of every restart attempt — without it, a
    /// plugin that `register-device`s in `init` and then crash-loops
    /// would stack a fresh entry per restart life. Returns the
    /// number of entries removed.
    pub fn remove_by_owner(&self, instance_id: &str) -> usize {
        let mut guard = self.inner.write().expect("devices lock poisoned");
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
    /// existed".
    #[test]
    fn cross_instance_access_is_rejected() {
        let reg = DeviceRegistry::new();
        let id = reg.register("alpha".into(), empty_info());

        // Owner — happy path.
        reg.get("alpha", &id).expect("owner can get");
        reg.update("alpha", &id, empty_info())
            .expect("owner can update");

        // Non-owner — `NotFound`, regardless of method.
        let err = reg.get("beta", &id).unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
        let err = reg.update("beta", &id, empty_info()).unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");
        let err = reg.remove("beta", &id).unwrap_err();
        assert!(matches!(err, WitError::NotFound(_)), "got {err:?}");

        // After a non-owner remove attempt, the device is still there
        // for its real owner.
        reg.get("alpha", &id).expect("device still owned by alpha");

        reg.remove("alpha", &id).expect("owner can remove");
        reg.get("alpha", &id).expect_err("device gone after remove");
    }

    /// `update` rebuilds the Arc so outstanding `get` snapshots see
    /// the *pre-update* info — reads-while-update can't observe a
    /// partially-written meta.
    #[test]
    fn update_swaps_arc_without_disturbing_outstanding_snapshots() {
        let reg = DeviceRegistry::new();
        let mut original = empty_info();
        original.name = "v1".into();
        let id = reg.register("alpha".into(), original);
        let before = reg.get("alpha", &id).expect("get");
        assert_eq!(before.info.name, "v1");

        let mut updated = empty_info();
        updated.name = "v2".into();
        reg.update("alpha", &id, updated).expect("update");
        let after = reg.get("alpha", &id).expect("get");
        assert_eq!(after.info.name, "v2");
        assert_eq!(before.info.name, "v1");
    }
}
