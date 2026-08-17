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
    /// Round-8 F1: shutdown gate protected by the SAME
    /// mutex as `instances`. Set by
    /// [`InstanceRegistry::begin_shutdown`] (called from
    /// [`Engine::stop_all_supervised_instances`] before
    /// its snapshot); checked inside
    /// [`InstanceRegistry::register`] under the same lock,
    /// so a `start_instance` that clears the outer
    /// `Engine::shutting_down` fast-path but is still
    /// mid-flight when shutdown begins can't slip a fresh
    /// supervisor into the registry after the shutdown
    /// snapshot. The outer `AtomicBool` remains for
    /// fail-fast before the manifest read; this inner
    /// bool is the authoritative gate.
    shutting_down: bool,
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
    /// Round-8 F1: engine is shutting down. Set by
    /// [`InstanceRegistry::begin_shutdown`] under the
    /// registry lock, checked inside
    /// [`InstanceRegistry::register`] under the same
    /// lock — an in-flight start that raced shutdown past
    /// the outer `AtomicBool` fast-path lands here rather
    /// than slipping a supervisor into the registry.
    #[error(
        "engine is shutting down: no new supervised instances may be started (stop_all_supervised_instances was called)"
    )]
    ShuttingDown,
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
        // Round-8 F1: authoritative shutdown gate check
        // under the SAME lock as the insert. Closes the
        // TOCTOU where a start_instance cleared the outer
        // `AtomicBool` fast-path, then awaited manifest I/O
        // while `stop_all_supervised_instances` set the
        // flag and snapshotted the registry, then resumed
        // and inserted a fresh entry the snapshot had
        // missed. The Engine's `stop_all` calls
        // `begin_shutdown` (which takes this same lock)
        // BEFORE snapshotting, so either this register
        // runs entirely before shutdown-set (insert is
        // visible in the snapshot) or entirely after
        // (this branch refuses).
        if guard.shutting_down {
            return Err(RegistryError::ShuttingDown);
        }
        if guard.instances.contains_key(&instance_id) {
            return Err(RegistryError::DuplicateInstanceId { instance_id });
        }
        // Phase-6 leftover fix + round-2 F1: singleton
        // enforcement has two rules, both keyed on
        // `plugin_id` regardless of the callers' declared
        // flags:
        //
        // 1. An incoming singleton start must find NO
        //    existing instance of the same `plugin_id`,
        //    even if that existing instance was itself
        //    registered with `singleton = false`.
        //    Pre-fix, the check only walked the
        //    `singletons` map (which is populated only
        //    when `singleton = true`), so a dev instance
        //    registered as non-singleton could coexist
        //    with a newly-started singleton — two
        //    supervisors under one identity, defeating
        //    singleton semantics.
        //
        // 2. If a singleton slot for `plugin_id` already
        //    exists, every new start of that `plugin_id`
        //    is refused — regardless of whether the new
        //    start's flag is singleton. Singleton means
        //    exclusive; a non-singleton coexisting with
        //    a running singleton violates the same
        //    invariant from the other direction.
        //
        // Both rules find every existing instance under
        // `plugin_id` by scanning `instances.values()`
        // once (bounded by the total instance count —
        // small in practice, and we already hold the
        // registry lock).
        if singleton {
            if let Some(existing) = guard
                .instances
                .values()
                .find(|h| h.plugin_id() == plugin_id)
            {
                return Err(RegistryError::SingletonInUse {
                    plugin_id,
                    existing_instance_id: existing.instance_id().to_string(),
                });
            }
        } else if let Some(existing) = guard.singletons.get(&plugin_id) {
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

    /// Round-8 F1: flip the shutdown gate under the
    /// registry lock. Called from
    /// [`Engine::stop_all_supervised_instances`] BEFORE
    /// its snapshot. Combined with the paired flag-check
    /// inside [`Self::register`] (which acquires the same
    /// lock), this closes the interleaving where a
    /// mid-flight start that had cleared the outer
    /// `AtomicBool` fast-path could still slip a fresh
    /// entry into the registry after the shutdown
    /// snapshot.
    ///
    /// [`Engine::stop_all_supervised_instances`]: crate::Engine::stop_all_supervised_instances
    pub(crate) fn begin_shutdown(&self) {
        let mut guard = self.inner.lock().expect("instance registry mutex poisoned");
        guard.shutting_down = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-9 F2: deterministic regression for the inner
    /// shutdown gate. Once `begin_shutdown` has run,
    /// every subsequent `register` returns
    /// `RegistryError::ShuttingDown` — regardless of
    /// singleton flag / prior registrations / any race
    /// with the caller's `.await` timing. This is the
    /// property the concurrent integration test only
    /// samples probabilistically; this unit test asserts
    /// it directly against the registry API and would
    /// fail deterministically if the flag check or its
    /// lock ordering were dropped.
    #[test]
    fn register_after_begin_shutdown_returns_shutting_down() {
        let reg = InstanceRegistry::new();
        // Pre-shutdown register succeeds.
        reg.register("a".into(), "plugin".into(), false, || {
            InstanceHandle::for_registry_test("a", "plugin")
        })
        .expect("pre-shutdown register");
        // Flip the gate.
        reg.begin_shutdown();
        // Post-shutdown register (fresh id, no duplicate
        // /singleton conflict possible) must be refused
        // with ShuttingDown — no factory should even run.
        let called_factory = std::sync::atomic::AtomicBool::new(false);
        let err = reg
            .register("b".into(), "plugin-b".into(), false, || {
                called_factory.store(true, std::sync::atomic::Ordering::Relaxed);
                InstanceHandle::for_registry_test("b", "plugin-b")
            })
            .expect_err("post-shutdown register must refuse");
        assert!(
            matches!(err, RegistryError::ShuttingDown),
            "expected RegistryError::ShuttingDown, got {err:?}",
        );
        assert!(
            !called_factory.load(std::sync::atomic::Ordering::Relaxed),
            "factory must not run when the shutdown gate refuses",
        );
        // The pre-shutdown entry stays intact (shutdown
        // doesn't retroactively evict).
        assert!(reg.get("a").is_some());
    }
}
