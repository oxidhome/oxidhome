//! Per-engine registry of supervised plugin instances — Phase 6d.
//!
//! [`InstanceRegistry`] is what makes `Engine::start_instance` reject
//! a duplicate `instance_id` or a second start of a `singleton = true`
//! plugin, and what lets host-side callers look running instances up
//! by id (or list them). [`Engine`](crate::Engine) owns one shared
//! registry; the [`InstanceHandle`]s it holds are cheap clones of what
//! `supervise` returned.
//!
//! A small reaper task per registration watches the handle's `watch`
//! channel; when an instance reaches a terminal state ([`Stopped`] or
//! [`Failed`]) the entry is removed and any singleton slot it held is
//! freed, so a fresh `start_instance` can take its place.
//!
//! [`Stopped`]: super::lifecycle::InstanceState::Stopped
//! [`Failed`]: super::lifecycle::InstanceState::Failed

use std::collections::HashMap;
use std::sync::Mutex;

use super::lifecycle::InstanceHandle;

/// Internal registry state — instance handles keyed by id, plus a
/// reverse map from singleton `plugin_id` → currently-running
/// `instance_id`. Both maps mutate together inside the same `Mutex`.
#[derive(Default)]
struct RegistryInner {
    instances: HashMap<String, InstanceHandle>,
    /// `plugin_id` → the `instance_id` currently holding its
    /// singleton slot. Only `singleton = true` plugins appear.
    singletons: HashMap<String, String>,
}

/// Per-`Engine` registry of supervised instances.
#[derive(Default)]
pub struct InstanceRegistry {
    inner: Mutex<RegistryInner>,
}

/// Why a [`InstanceRegistry::register`] call was rejected.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Another instance with the same `instance_id` is already
    /// running on this engine.
    #[error("instance `{instance_id}` is already running")]
    DuplicateInstanceId { instance_id: String },
    /// The plugin declared `singleton = true` in its manifest and an
    /// instance is already running.
    #[error(
        "singleton plugin `{plugin_id}` already has a running instance `{existing_instance_id}`"
    )]
    SingletonInUse {
        plugin_id: String,
        existing_instance_id: String,
    },
}

impl InstanceRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically check the singleton / duplicate-id constraints,
    /// then (if both clear) build the handle via `factory` and insert
    /// it. The whole check + spawn + insert happens under one lock,
    /// so two racing `start_instance` calls for the same singleton
    /// can't both succeed *and* we don't spawn a supervisor task
    /// whose slot turns out to be taken.
    ///
    /// `factory` runs while a `std::sync::Mutex` is held, so it must
    /// not `.await`. Today's caller only calls `tokio::spawn` +
    /// `supervise_with_tuning` (both synchronous); a future supervisor
    /// pre-flight that needs to await — e.g. a host-DB row insert —
    /// would force a redesign to a `tokio::sync::Mutex` or a two-phase
    /// reserve / commit shape.
    ///
    /// `pub(crate)` because the singleton-enforcement invariants only
    /// hold when the caller went through [`Engine::start_instance`]
    /// (which reads the manifest); the read-side accessors below stay
    /// public.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when the slot is taken; `factory`
    /// is not called in that case.
    ///
    /// [`Engine::start_instance`]: crate::Engine::start_instance
    pub(crate) fn register<F>(
        &self,
        instance_id: String,
        plugin_id: String,
        singleton: bool,
        factory: F,
    ) -> Result<InstanceHandle, RegistryError>
    where
        F: FnOnce() -> InstanceHandle,
    {
        let mut guard = self.inner.lock().expect("instance registry mutex poisoned");
        if guard.instances.contains_key(&instance_id) {
            return Err(RegistryError::DuplicateInstanceId { instance_id });
        }
        // TODO(phase 7+): `singleton` is read from the *caller's*
        // manifest, but a different install dir with the same
        // `plugin_id` could carry `singleton = false`. That would let
        // a non-singleton instance coexist with a singleton one. The
        // host-side plugin ledger Phase 7+ adds is where the canonical
        // per-`plugin_id` singleton flag belongs; for now Phase 6
        // accepts the per-instance reading.
        if singleton && let Some(existing) = guard.singletons.get(&plugin_id) {
            return Err(RegistryError::SingletonInUse {
                plugin_id,
                existing_instance_id: existing.clone(),
            });
        }
        let handle = factory();
        guard.instances.insert(instance_id.clone(), handle.clone());
        if singleton {
            guard.singletons.insert(plugin_id, instance_id);
        }
        Ok(handle)
    }

    /// Remove an entry once its supervisor reaches a terminal state.
    /// Frees the singleton slot iff *this* instance still owns it
    /// (paranoia against a future race where the slot was already
    /// taken back by something else).
    ///
    /// `pub(crate)`: only the reaper task spawned by
    /// [`Engine::start_instance`] is supposed to call this. An
    /// external caller could otherwise free a singleton slot while
    /// the supervisor task is still running.
    ///
    /// [`Engine::start_instance`]: crate::Engine::start_instance
    pub(crate) fn unregister(&self, instance_id: &str, plugin_id: &str) {
        let mut guard = self.inner.lock().expect("instance registry mutex poisoned");
        guard.instances.remove(instance_id);
        if guard.singletons.get(plugin_id).map(String::as_str) == Some(instance_id) {
            guard.singletons.remove(plugin_id);
        }
    }

    /// Lookup by `instance_id`. Returns a clone of the handle.
    #[must_use]
    pub fn get(&self, instance_id: &str) -> Option<InstanceHandle> {
        self.inner
            .lock()
            .expect("instance registry mutex poisoned")
            .instances
            .get(instance_id)
            .cloned()
    }

    /// Snapshot of every registered handle. Cheap-ish — clones the
    /// `InstanceHandle`s out of the map under the lock.
    #[must_use]
    pub fn list(&self) -> Vec<InstanceHandle> {
        self.inner
            .lock()
            .expect("instance registry mutex poisoned")
            .instances
            .values()
            .cloned()
            .collect()
    }
}
