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
//! ## Stable ids (architecture-review C1 / C1b)
//!
//! Host-minted device ids are **deterministic** from the tuple
//! `(installation_uuid, instance_id, local_id)` — SHA-256 truncated
//! to 8 bytes, rendered as `dev-<16 hex chars>`. Pre-C1 the registry
//! minted `dev-<n>` from an atomic counter, so every restart (and
//! every fresh engine) renumbered every device and broke any
//! external reference — audit rows citing a device id, API paths
//! like `POST /api/v1/devices/{id}/command`, `logs query
//! --field device_id=…`, and so on. C1 fixed restart aliasing;
//! C1b closes the uninstall-reinstall aliasing that a reusable
//! `plugin_id` still left open by minting a fresh installation UUID
//! per install and threading it through the derivation.
//!
//! With the deterministic shape, a plugin that re-registers the
//! same `local_id` from the same `instance_id` gets the same
//! `device_id` back — across restart, across engine re-open,
//! across process. Uninstalling and reinstalling the same plugin
//! mints a fresh installation UUID and therefore fresh device ids,
//! so the new install can't inherit the old install's audit / API
//! surface. Callers that provide stable instance ids (which the
//! daemon already does) inherit stable device ids automatically;
//! no on-disk device table needed. Full `SQLite` persistence for
//! device metadata stays a follow-up if a use case surfaces (a
//! plugin that wants to *observe* previously-registered devices
//! without re-registering).

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use sha2::{Digest, Sha256};

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
/// IDs are deterministic — `dev-<16 hex chars>` from
/// `SHA-256(installation_uuid || instance_id || local_id)` with a
/// version tag and length-prefixed fields (see [`stable_device_id`]).
/// Same tuple → same id, across restarts, across engine re-opens,
/// across processes. See the module doc for the C1 rationale.
#[derive(Default, Debug)]
pub struct DeviceRegistry {
    inner: RwLock<HashMap<DeviceId, Arc<DeviceMeta>>>,
}

/// Compute the deterministic host-side device id for an
/// `(installation_uuid, instance_id, local_id)` tuple. Public inside
/// the crate so the pending-migration follow-up (a SQLite-backed
/// device table) can use the same key material to correlate stored
/// rows with fresh registrations.
///
/// **Encoding.** Each field is preceded by its byte length as a
/// big-endian `u32` — unambiguous tuple encoding. A plain
/// `"::"` delimiter (which the first cut used, and PR #84 review
/// caught, defect F1) collides for any tuple where an id itself
/// contains `"::"`: `("p", "alpha::beta", "d")` and
/// `("p", "alpha", "beta::d")` hash identical bytes and produce
/// the same device id. Length-prefix framing is the standard
/// fix — the digest byte stream now describes the tuple bijectively.
///
/// **Why `installation_uuid` and not `plugin_id`.** C1b:
/// the manifest's `plugin.id` is a reusable name. Uninstall +
/// reinstall (or a replacement plugin sharing the id) inherits every
/// audit / API / history reference from the previous installation.
/// Threading a fresh installation UUID minted per-install through
/// this hash means a reinstall gets a different UUID and therefore
/// different device ids — the reviewer's identity-reuse concern
/// from PR #84 is closed. The `instance_id` argument stays a name
/// for now (C1c may swap it for an instance UUID once the instance
/// registry gets its own persistence table).
///
/// A leading domain-separation tag pins this hash to
/// `oxidhome:device-id:v2` — bumped from v1 in C1b because the tuple
/// shape changed (first field is now the installation UUID, not the
/// plugin id). Ids from a pre-C1b install would collide with the new
/// derivation otherwise. Pre-1.0 upgrade behaviour: existing device
/// ids are re-minted at the first registration after upgrade; no
/// external references outlive the upgrade window in practice yet.
///
/// SHA-256 truncated to 8 bytes = 64 bits of collision space. On a
/// single host with ≤10^6 devices the birthday collision risk is
/// ~2^{-24}; well below any operational threshold. Widening the
/// truncation would bump the version tag so old and new ids don't
/// alias.
#[must_use]
pub fn stable_device_id(installation_uuid: &str, instance_id: &str, local_id: &str) -> DeviceId {
    let mut h = Sha256::new();
    // Domain-separation tag — locks this digest to the current
    // encoding version. Bumped to v2 in C1b when the first field
    // changed from `plugin_id` to `installation_uuid`.
    let tag = b"oxidhome:device-id:v2";
    #[allow(clippy::cast_possible_truncation)]
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    for field in [installation_uuid, instance_id, local_id] {
        let bytes = field.as_bytes();
        // `u32` big-endian length prefix is enough for any real
        // identifier (max 4 GiB); a name that overflows a `u32`
        // would already be broken everywhere else.
        #[allow(clippy::cast_possible_truncation)]
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(bytes);
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("dev-{hex}")
}

impl DeviceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Poison-tolerant accessors — see the matching note on
    // `ServiceRegistry::services_read`. The critical sections are
    // atomic `HashMap` ops + Arc / String clones, so recovering the
    // inner guard after a panic-under-lock is consistent.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<DeviceId, Arc<DeviceMeta>>> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn write(&self) -> RwLockWriteGuard<'_, HashMap<DeviceId, Arc<DeviceMeta>>> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a device on behalf of `owner_instance`. Returns the
    /// deterministic host-assigned id — same `(installation_uuid,
    /// owner_instance, info.local_id)` tuple always maps to the
    /// same id, so a plugin's re-registration on restart resurrects
    /// the previous id and every external reference (audit rows,
    /// API paths, log queries) keeps working.
    ///
    /// C1b note: `installation_uuid` is the host-minted UUID from
    /// [`crate::state::InstalledPluginRegistry`] — one per install of
    /// the plugin. Uninstall + reinstall picks up a fresh UUID, so
    /// devices minted by the old install don't collide with the new
    /// one. Callers that don't go through the installed-plugin
    /// registry (in-memory dev / test loads) may pass the
    /// `manifest.plugin.id` as a synthetic UUID — see
    /// [`PluginState`](crate::runtime::state::PluginState) for the
    /// fallback used by [`PluginInstance::load`](crate::PluginInstance::load).
    ///
    /// C1 note: a repeat registration of the same tuple overwrites
    /// the previous entry's `info`. That matches the pre-C1
    /// behaviour (the atomic counter minted a fresh id for every
    /// call, so overwrite couldn't happen, but a plugin
    /// re-registering with a new capability set would just stack a
    /// second entry — arguably worse). Callers that need to
    /// preserve the old entry should `update` explicitly; callers
    /// that intend a fresh registration should change the
    /// `local_id`.
    pub fn register(
        &self,
        installation_uuid: &str,
        owner_instance: String,
        info: DeviceInfo,
    ) -> DeviceId {
        let id = stable_device_id(installation_uuid, &owner_instance, &info.local_id);
        let meta = Arc::new(DeviceMeta {
            id: id.clone(),
            owner_instance,
            info,
        });
        self.write().insert(id.clone(), meta);
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
    ///
    /// **C1 immutability.** `info.local_id` must match the
    /// original registration's `local_id` — the host-minted device
    /// id is derived from it (see [`stable_device_id`]), so
    /// changing `local_id` mid-life would silently break the
    /// restart-stability contract (the plugin would compute a
    /// different id after restart, and every external reference
    /// citing the old id — audit rows, API paths, log queries —
    /// would point nowhere). A caller that wants to rename the
    /// physical device must `remove` + `register` under the new
    /// name explicitly, which the audit trail correctly attributes
    /// as a distinct device. Mismatched `local_id` ⇒
    /// `WitError::InvalidArgument`.
    pub fn update(
        &self,
        owner_instance: &str,
        id: &DeviceId,
        info: DeviceInfo,
    ) -> Result<(), WitError> {
        let mut guard = self.write();
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => {
                if meta.info.local_id != info.local_id {
                    return Err(WitError::InvalidArgument(format!(
                        "update-device: local_id is immutable after registration \
                         (was `{}`, got `{}`) — use remove-device + register-device to rename",
                        meta.info.local_id, info.local_id,
                    )));
                }
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
        let mut guard = self.write();
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
        let guard = self.read();
        match guard.get(id) {
            Some(meta) if meta.owner_instance == owner_instance => Ok(Arc::clone(meta)),
            _ => Err(WitError::NotFound(format!("device {id} not registered"))),
        }
    }

    /// Cross-instance lookup — the host-routing primitive. Unlike
    /// [`Self::get`], this is *not* owner-scoped: the caller is the
    /// host (API, CLI, future MCP), not a plugin, so the
    /// scope-by-owner property doesn't apply. Mirrors
    /// [`ServiceRegistry::get_any`](crate::state::ServiceRegistry::get_any)
    /// for the device registry. Returns `None` if the id isn't
    /// registered.
    #[must_use]
    pub fn get_any(&self, id: &DeviceId) -> Option<Arc<DeviceMeta>> {
        self.read().get(id).map(Arc::clone)
    }

    /// Cross-instance owner-only lookup — what the API's
    /// device-command handler actually needs. Returns just the
    /// owning instance id (one `String` clone, no `Arc<DeviceMeta>`
    /// and no `Vec` allocation), parallel to
    /// [`ServiceRegistry::get_owner`](crate::state::ServiceRegistry::get_owner).
    #[must_use]
    pub fn get_owner(&self, id: &DeviceId) -> Option<String> {
        self.read().get(id).map(|m| m.owner_instance.clone())
    }

    /// Snapshot of every registered device — cheap (one `Arc::clone`
    /// per entry, no deep copies). The `Vec` is pre-sized so the
    /// `Arc::clone` loop doesn't realloc-grow under the read lock.
    #[must_use]
    pub fn list(&self) -> Vec<Arc<DeviceMeta>> {
        let guard = self.read();
        let mut out = Vec::with_capacity(guard.len());
        out.extend(guard.values().map(Arc::clone));
        out
    }

    /// Drop every device owned by `instance_id`. Called by the
    /// Phase-6 supervisor when an instance reaches a terminal state
    /// *and* at the top of every restart attempt — without it, a
    /// plugin that `register-device`s in `init` and then crash-loops
    /// would stack a fresh entry per restart life. Returns the
    /// number of entries removed.
    pub fn remove_by_owner(&self, instance_id: &str) -> usize {
        let mut guard = self.write();
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
        let id = reg.register("plugin.a", "alpha".into(), empty_info());

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
        let id = reg.register("plugin.a", "alpha".into(), original);
        let before = reg.get("alpha", &id).expect("get");
        assert_eq!(before.info.name, "v1");

        let mut updated = empty_info();
        updated.name = "v2".into();
        reg.update("alpha", &id, updated).expect("update");
        let after = reg.get("alpha", &id).expect("get");
        assert_eq!(after.info.name, "v2");
        assert_eq!(before.info.name, "v1");
    }

    /// C1: the id function is deterministic and injective across
    /// each of its three inputs.
    #[test]
    fn stable_device_id_is_deterministic_and_injective() {
        let base = stable_device_id("inst-a", "alpha", "front-door");
        // Same inputs → same id.
        assert_eq!(base, stable_device_id("inst-a", "alpha", "front-door"));
        // Different installation_uuid → different id.
        assert_ne!(base, stable_device_id("inst-b", "alpha", "front-door"));
        // Different instance_id → different id.
        assert_ne!(base, stable_device_id("inst-a", "beta", "front-door"));
        // Different local_id → different id.
        assert_ne!(base, stable_device_id("inst-a", "alpha", "back-door"));
        // Format guard: `dev-` prefix + 16 hex chars.
        assert!(base.starts_with("dev-"));
        let hex = &base["dev-".len()..];
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// C1: the whole point — a re-registration after cleanup (the
    /// exact shape the Phase-6 supervisor's `remove_by_owner`-
    /// then-re-init cycle produces) returns the *same* device id
    /// the caller had before, so audit rows / API paths / log
    /// queries citing that id keep working across restart.
    #[test]
    fn re_registration_after_cleanup_reuses_id() {
        let reg = DeviceRegistry::new();
        let mut info = empty_info();
        info.local_id = "front-door".into();
        let first = reg.register("plugin.a", "alpha".into(), info.clone());

        // Simulate a supervisor restart: sweep this instance's
        // devices, then re-register from a fresh init.
        assert_eq!(reg.remove_by_owner("alpha"), 1);
        let second = reg.register("plugin.a", "alpha".into(), info);
        assert_eq!(
            first, second,
            "same (plugin, instance, local_id) must yield the same device id across restarts",
        );
    }

    /// PR #84 review, F1 regression — the pre-fix `"::"` delimiter
    /// collided for any tuple containing `"::"` in an id. Two
    /// distinct legal tuples hashed identical bytes and the second
    /// registration silently overwrote the first, mis-routing every
    /// subsequent command. Length-prefix framing makes the digest
    /// stream bijective; distinct tuples get distinct ids.
    #[test]
    fn delimiter_ambiguity_no_longer_collides() {
        // Both would have hashed `inst-a::alpha::beta::front-door`
        // under the pre-fix encoding.
        let a = stable_device_id("inst-a", "alpha::beta", "front-door");
        let b = stable_device_id("inst-a", "alpha", "beta::front-door");
        assert_ne!(a, b, "length-prefix encoding must disambiguate `::`");
    }

    /// C1b: a fresh installation UUID yields a fresh device id for
    /// the same `(instance_id, local_id)`. This is the whole point
    /// of the C1b remediation — uninstall + reinstall cannot alias
    /// onto the previous install's audit / API surface.
    #[test]
    fn different_installation_uuid_yields_different_device_id() {
        let old = stable_device_id("inst-old-uuid", "kitchen", "light-1");
        let new = stable_device_id("inst-new-uuid", "kitchen", "light-1");
        assert_ne!(
            old, new,
            "reinstall must produce a distinct device id even when \
             (instance_id, local_id) match the pre-uninstall pair",
        );
    }

    /// PR #84 review, F2 regression — `update-device` must refuse a
    /// changed `local_id`. Silently accepting it would break the
    /// C1 restart-stability contract: the plugin's next
    /// registration would compute a *different* id from the new
    /// `local_id`, and every external reference to the old id
    /// would point nowhere.
    #[test]
    fn update_rejects_local_id_change() {
        let reg = DeviceRegistry::new();
        let mut original = empty_info();
        original.local_id = "front-door".into();
        original.name = "Front Door".into();
        let id = reg.register("plugin.a", "alpha".into(), original);

        // Legitimate update — same local_id, different `name`.
        let mut renamed = empty_info();
        renamed.local_id = "front-door".into();
        renamed.name = "Foyer Door".into();
        reg.update("alpha", &id, renamed).expect("rename ok");

        // Illegitimate update — different local_id.
        let mut moved = empty_info();
        moved.local_id = "back-door".into();
        let err = reg.update("alpha", &id, moved).unwrap_err();
        assert!(
            matches!(err, WitError::InvalidArgument(_)),
            "changing local_id must be refused, got {err:?}",
        );

        // Registry still has the original device unchanged.
        let after = reg.get("alpha", &id).expect("still there");
        assert_eq!(after.info.local_id, "front-door");
        assert_eq!(after.info.name, "Foyer Door");
    }
}
