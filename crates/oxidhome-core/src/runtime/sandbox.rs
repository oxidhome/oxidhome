//! One sandbox per script — ADR-0001.
//!
//! A scripting plugin runs each user script in a **sandbox**: a child
//! instance of the calling (*parent*) instance, built from the same
//! component and the same pinned manifest, with its own Wasmtime
//! `Store` and its own supervisor. Scripts then call each other with
//! the ordinary cross-instance `host-services::call-service`, so the
//! dispatcher's grants, deadlines, cycle checks and audit apply.
//!
//! - **Identity.** A sandbox's instance id is
//!   `<parent-instance>~<local-id>` ([`sandbox_instance_id`]). `~`
//!   is reserved: [`crate::Engine::start_instance`] refuses it in an
//!   operator-chosen id, so the two namespaces can't collide.
//! - **Lifecycle.** [`SandboxRegistry`] tracks the live sandboxes per
//!   parent. A sandbox's own reaper removes its entry when it reaches
//!   a terminal state; a parent's reaper stops all of its sandboxes.
//!   A parent *restart* leaves them running, and `start-sandbox` with
//!   the same source re-adopts them.
//! - **Capabilities.** A sandbox loads under the parent's load mode
//!   and manifest, so it has the same installation identity and
//!   effective capabilities; `[capabilities] script_sandboxes` bounds
//!   how many one parent may run.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use oxidhome_manifest::PluginManifest;

use crate::Engine;
use crate::host_impl::plugin::oxidhome::plugin::host_sandboxes::{
    self, SandboxInfo, SandboxScript as WitSandboxScript,
};
use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;

use super::instance::{ComponentCache, LoadMode};
use super::lifecycle::{InstanceHandle, InstanceState, SupervisorTuning};
use super::registry::RegistryError;
use super::sandbox_purge::{Marked, Removal};
use super::state::PluginState;

/// Separator between the parent instance id and the script's
/// `local-id` in a sandbox's instance id. Reserved in operator-chosen
/// instance ids.
pub const SANDBOX_SEPARATOR: char = '~';

/// Longest accepted script `local-id`.
pub const MAX_SANDBOX_LOCAL_ID_BYTES: usize = 64;

/// Longest accepted script source handed to `start-sandbox`.
pub const MAX_SANDBOX_SOURCE_BYTES: usize = 64 * 1024;

/// The instance id of the sandbox `local_id` started by `parent`.
#[must_use]
pub fn sandbox_instance_id(parent: &str, local_id: &str) -> String {
    format!("{parent}{SANDBOX_SEPARATOR}{local_id}")
}

/// `local-id` rule: 1..=64 bytes of `[a-z0-9_-]`, first byte a
/// letter or digit.
fn check_local_id(local_id: &str) -> Result<(), WitError> {
    let ok = !local_id.is_empty()
        && local_id.len() <= MAX_SANDBOX_LOCAL_ID_BYTES
        && local_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && local_id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(WitError::InvalidArgument(format!(
            "sandbox local-id `{}` must be 1-{MAX_SANDBOX_LOCAL_ID_BYTES} bytes of \
             [a-z0-9_-] starting with a letter or digit",
            crate::auth::invocation::audit_cap(local_id),
        )))
    }
}

/// What one sandbox runs. Shared by its supervisor (across restarts)
/// and its `PluginState`, which serves it to `current-sandbox`.
#[derive(Debug)]
pub(crate) struct SandboxScript {
    local_id: String,
    pub(crate) instance_id: String,
    parent_instance: String,
    source: Arc<str>,
}

impl SandboxScript {
    /// The script's id within its parent.
    pub(crate) fn local_id(&self) -> &str {
        &self.local_id
    }

    /// The instance that started the sandbox.
    pub(crate) fn parent_instance(&self) -> &str {
        &self.parent_instance
    }

    fn info(&self) -> SandboxInfo {
        SandboxInfo {
            local_id: self.local_id.clone(),
            instance_id: self.instance_id.clone(),
            parent_instance: self.parent_instance.clone(),
        }
    }
}

/// Everything a supervised parent needs to start a sandbox of itself:
/// the inputs its own supervisor was spawned with.
pub(crate) struct SandboxLauncher {
    pub(crate) engine: Engine,
    pub(crate) plugin_dir: PathBuf,
    pub(crate) overrides: Option<toml::Value>,
    pub(crate) mode: LoadMode,
    pub(crate) tuning: SupervisorTuning,
    pub(crate) pinned_manifest: Option<(Vec<u8>, PluginManifest)>,
    /// The parent supervisor's compiled component: every sandbox (and
    /// each of its restarts) instantiates it rather than compiling the
    /// `.wasm` again, and so runs exactly the parent's bytes.
    pub(crate) component_cache: Arc<ComponentCache>,
}

impl std::fmt::Debug for SandboxLauncher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxLauncher")
            .field("plugin_dir", &self.plugin_dir)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// A supervised instance's place in the sandbox model, attached to its
/// `PluginState` after every load. Unsupervised instances (direct
/// `PluginInstance` loads, the test host) have none.
#[derive(Debug, Clone)]
pub(crate) enum SandboxRole {
    /// An ordinary instance; may start sandboxes.
    Parent(Arc<SandboxLauncher>),
    /// A sandbox; may not start sandboxes.
    Child(Arc<SandboxScript>),
}

/// One sandbox in [`SandboxRegistry`], from `start-sandbox` until its
/// reaper runs.
struct Entry {
    script: Arc<SandboxScript>,
    handle: InstanceHandle,
    /// Distinguishes this entry from a later sandbox with the same
    /// `local-id`, so a late reaper can't remove its replacement.
    generation: u64,
    /// Asked to stop, not yet terminal. Hidden from `list-sandboxes`
    /// but still counted against the parent's limit, so a start/stop
    /// loop can't pile up stores that are still loading or shutting
    /// down.
    stopping: bool,
    /// `Some` once its parent removed it (`stop-sandbox`): the reaper
    /// purges its storage and per-instance bookkeeping. It holds a
    /// [`Marked`] once `stop-sandbox` has tried to persist the removal
    /// marker, and the reaper waits for that, so the marker can't land
    /// after the purge deleted it. A sandbox stopped any other way (its
    /// parent stopping, an operator, shutdown) keeps them for the
    /// parent to re-create it.
    retire: Option<tokio::sync::watch::Receiver<Option<Marked>>>,
}

impl Entry {
    /// Live: not asked to stop here, and not stopping or stopped by
    /// anyone else (an operator stopping the instance directly, which
    /// counts from the request on).
    fn is_live(&self) -> bool {
        !self.stopping
            && !self.handle.stop_requested()
            && !matches!(self.handle.state(), InstanceState::Stopping)
            && !self.handle.state().is_terminal()
    }
}

/// Sandboxes per parent instance, live or stopping. Owned by the
/// [`Engine`].
#[derive(Default)]
pub struct SandboxRegistry {
    inner: Mutex<HashMap<String, BTreeMap<String, Entry>>>,
    generation: AtomicU64,
    /// Removed sandboxes whose storage purge hasn't succeeded; their
    /// instance ids can't be started again (see `sandbox_purge`).
    /// Locked after `inner` when both are held.
    removals: Mutex<HashSet<Removal>>,
}

impl SandboxRegistry {
    /// A registry whose `removals` ids are blocked until their purge
    /// succeeds.
    pub(crate) fn with_pending_removals(removals: HashSet<Removal>) -> Self {
        Self {
            removals: Mutex::new(removals),
            ..Self::default()
        }
    }

    fn removals(&self) -> std::sync::MutexGuard<'_, HashSet<Removal>> {
        self.removals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block `removal`'s instance id until [`Self::unblock_removal`].
    pub(crate) fn block_removal(&self, removal: Removal) {
        self.removals().insert(removal);
    }

    /// The purge of `removal` succeeded.
    pub(crate) fn unblock_removal(&self, removal: &Removal) {
        self.removals().remove(removal);
    }

    /// An uninstall purged every sandbox of `installation_uuid`.
    pub(crate) fn forget_removals_of(&self, installation_uuid: &str) {
        self.removals()
            .retain(|(uuid, _)| uuid != installation_uuid);
    }

    fn refuse_while_purging(
        &self,
        installation_uuid: &str,
        local_id: &str,
        instance_id: &str,
    ) -> Result<(), WitError> {
        // Storage keys on the installation too: another installation's
        // leftovers under a reused parent id don't block this one.
        if self
            .removals()
            .iter()
            .any(|(uuid, id)| uuid == installation_uuid && id == instance_id)
        {
            return Err(WitError::Unavailable(format!(
                "sandbox `{local_id}` was removed and its storage is still being purged; retry \
                 later (a failed purge is retried when the host restarts)"
            )));
        }
        Ok(())
    }

    /// How many of `parent`'s removed sandboxes (under
    /// `installation_uuid`), no longer in `children`, still await their
    /// purge.
    fn purges_pending_of(
        &self,
        installation_uuid: &str,
        parent: &str,
        children: &BTreeMap<String, Entry>,
    ) -> usize {
        let prefix = format!("{parent}{SANDBOX_SEPARATOR}");
        self.removals()
            .iter()
            .filter(|(uuid, _)| uuid == installation_uuid)
            .filter_map(|(_, id)| id.strip_prefix(&prefix))
            .filter(|local_id| !children.contains_key(*local_id))
            .count()
    }

    /// Whether a purge of `instance_id`'s storage is still pending.
    #[must_use]
    pub fn removal_pending(&self, instance_id: &str) -> bool {
        self.removals().iter().any(|(_, id)| id == instance_id)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BTreeMap<String, Entry>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The sandboxes `parent` started that are live (not stopping), as
    /// `(local-id, instance-id)` ordered by `local-id`.
    #[must_use]
    pub fn list(&self, parent: &str) -> Vec<(String, String)> {
        self.lock().get(parent).map_or_default(|children| {
            children
                .values()
                .filter(|e| e.is_live())
                .map(|e| (e.script.local_id.clone(), e.script.instance_id.clone()))
                .collect()
        })
    }

    fn infos(&self, parent: &str) -> Vec<SandboxInfo> {
        self.lock().get(parent).map_or_default(|children| {
            children
                .values()
                .filter(|e| e.is_live())
                .map(|e| e.script.info())
                .collect()
        })
    }

    /// Whether `parent` has sandboxes that haven't been reaped yet.
    #[must_use]
    pub fn has_children(&self, parent: &str) -> bool {
        self.lock().contains_key(parent)
    }

    /// Reaper hook: drop the entry for `(parent, local_id)` if it is
    /// still the sandbox of `generation`.
    pub(crate) fn remove_if_current(&self, parent: &str, local_id: &str, generation: u64) {
        let mut guard = self.lock();
        if let Some(children) = guard.get_mut(parent) {
            if children
                .get(local_id)
                .is_some_and(|e| e.generation == generation)
            {
                children.remove(local_id);
            }
            if children.is_empty() {
                guard.remove(parent);
            }
        }
    }

    /// Mark every live sandbox of `parent` stopping and return their
    /// handles, for the caller to stop. Each entry stays until its own
    /// reaper removes it.
    pub(crate) fn take_children(&self, parent: &str) -> Vec<InstanceHandle> {
        self.lock().get_mut(parent).map_or_default(|children| {
            children
                .values_mut()
                .filter(|e| !e.stopping)
                .map(|e| {
                    e.stopping = true;
                    e.handle.clone()
                })
                .collect()
        })
    }

    /// `stop-sandbox`: mark one live sandbox stopping and retired, and
    /// return its handle and the sender that reports its removal
    /// marker persisted (see [`Entry::retire`]).
    fn take_child(
        &self,
        parent: &str,
        local_id: &str,
    ) -> Option<(InstanceHandle, tokio::sync::watch::Sender<Option<Marked>>)> {
        let mut guard = self.lock();
        let entry = guard.get_mut(parent)?.get_mut(local_id)?;
        if !entry.is_live() {
            return None;
        }
        let (marked, rx) = tokio::sync::watch::channel(None);
        entry.stopping = true;
        entry.retire = Some(rx);
        Some((entry.handle.clone(), marked))
    }

    /// Reaper hook: if the sandbox in `slot` was removed by its parent,
    /// what reports its removal marker persisted (see
    /// [`Entry::retire`]).
    pub(crate) fn retirement(
        &self,
        slot: &SandboxSlot,
    ) -> Option<tokio::sync::watch::Receiver<Option<Marked>>> {
        self.lock()
            .get(&slot.parent)
            .and_then(|children| children.get(&slot.local_id))
            .filter(|e| e.generation == slot.generation)
            .and_then(|e| e.retire.clone())
    }
}

/// Where a sandbox's reaper finds its registry entry.
pub(crate) struct SandboxSlot {
    pub(crate) parent: String,
    pub(crate) local_id: String,
    pub(crate) generation: u64,
}

impl Engine {
    /// `start-sandbox` for `parent`. Synchronous: everything happens
    /// under the sandbox registry lock, so two concurrent starts of the
    /// same `local-id` can't both spawn.
    #[allow(clippy::too_many_arguments)]
    fn start_sandbox(
        &self,
        launcher: &SandboxLauncher,
        parent: &str,
        plugin_id: &str,
        installation_uuid: &str,
        limit: u32,
        local_id: String,
        source: String,
    ) -> Result<String, WitError> {
        check_local_id(&local_id)?;
        if source.len() > MAX_SANDBOX_SOURCE_BYTES {
            return Err(WitError::InvalidArgument(format!(
                "sandbox source is {} bytes; the limit is {MAX_SANDBOX_SOURCE_BYTES}",
                source.len(),
            )));
        }
        let instance_id = sandbox_instance_id(parent, &local_id);
        if !crate::state::is_safe_instance_id(&instance_id) {
            return Err(WitError::InvalidArgument(format!(
                "sandbox instance id `{}` is too long; use a shorter local-id",
                crate::auth::invocation::audit_cap(&instance_id),
            )));
        }
        // Before re-adopting too: a host that is shutting down hands
        // out no sandbox ids.
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(WitError::Unavailable("the host is shutting down".into()));
        }
        let registry = self.sandboxes();
        let mut guard = registry.lock();
        // A removed sandbox's id stays taken until its storage is
        // purged, so a new one can't inherit the old rows.
        if !guard.get(parent).is_some_and(|c| c.contains_key(&local_id)) {
            registry.refuse_while_purging(installation_uuid, &local_id, &instance_id)?;
        }
        let children = guard.entry(parent.to_owned()).or_default();
        if let Some(existing) = children.get(&local_id) {
            return if !existing.is_live() {
                Err(WitError::Unavailable(format!(
                    "sandbox `{local_id}` is still stopping; retry shortly"
                )))
            } else if *existing.script.source == *source {
                Ok(existing.script.instance_id.clone())
            } else {
                Err(WitError::InvalidArgument(format!(
                    "sandbox `{local_id}` is already running different source; stop it first"
                )))
            };
        }
        // A removed sandbox whose purge hasn't succeeded still holds
        // its storage, so it still counts.
        let held = children.len() + registry.purges_pending_of(installation_uuid, parent, children);
        if held >= limit as usize {
            let err = WitError::Unavailable(format!(
                "instance `{parent}` already has {held} sandboxes running, stopping or \
                 awaiting their storage purge; the limit (capabilities.script_sandboxes) is \
                 {limit}",
            ));
            if children.is_empty() {
                guard.remove(parent);
            }
            return Err(err);
        }
        let generation = registry.generation.fetch_add(1, Ordering::Relaxed);
        let script = Arc::new(SandboxScript {
            local_id: local_id.clone(),
            instance_id: instance_id.clone(),
            parent_instance: parent.to_owned(),
            source: Arc::from(source),
        });
        let spawned = self.spawn_sandbox_supervisor(
            launcher,
            plugin_id,
            Arc::clone(&script),
            SandboxSlot {
                parent: parent.to_owned(),
                local_id: local_id.clone(),
                generation,
            },
        );
        let handle = match spawned {
            Ok(handle) => handle,
            Err(err) => {
                if children.is_empty() {
                    guard.remove(parent);
                }
                return Err(match err {
                    RegistryError::DuplicateInstanceId { .. } => WitError::Unavailable(format!(
                        "sandbox `{local_id}` is still stopping; retry shortly"
                    )),
                    RegistryError::ShuttingDown => {
                        WitError::Unavailable("the host is shutting down".into())
                    }
                    other @ RegistryError::SingletonInUse { .. } => {
                        WitError::Unavailable(other.to_string())
                    }
                });
            }
        };
        tracing::info!(
            parent_instance = %parent,
            instance_id = %instance_id,
            "script sandbox started",
        );
        children.insert(
            local_id,
            Entry {
                script,
                handle,
                generation,
                stopping: false,
                retire: None,
            },
        );
        Ok(instance_id)
    }

    /// Stop every sandbox `parent` started, in the background. Called
    /// when `parent` reaches a terminal state.
    pub(crate) fn stop_sandboxes_of(&self, parent: &str) {
        for handle in self.sandboxes().take_children(parent) {
            tokio::spawn(async move {
                let _ = handle.stop().await;
            });
        }
    }
}

impl PluginState {
    fn sandbox_launcher(&self) -> Result<&Arc<SandboxLauncher>, WitError> {
        match &self.sandbox {
            Some(SandboxRole::Parent(launcher)) => Ok(launcher),
            Some(SandboxRole::Child(_)) => Err(WitError::PermissionDenied(
                "a script sandbox cannot start or stop sandboxes".into(),
            )),
            None => Err(WitError::Unavailable(
                "script sandboxes need a supervised instance".into(),
            )),
        }
    }
}

impl host_sandboxes::Host for PluginState {
    async fn start_sandbox(
        &mut self,
        local_id: String,
        source: String,
    ) -> Result<String, WitError> {
        // A singleton's manifest can't ask for sandboxes (validation),
        // but a zero limit is the gate either way; the singleton check
        // keeps a hand-edited grant from reopening it.
        let limit = if self.manifest.runtime.singleton {
            0
        } else {
            self.granted_capabilities.script_sandboxes
        };
        let launcher = match self.sandbox_launcher() {
            Err(WitError::Unavailable(_)) | Ok(_) if limit == 0 => {
                return Err(WitError::PermissionDenied(
                    "start-sandbox requires `capabilities.script_sandboxes` > 0 in the \
                     plugin manifest and grant"
                        .into(),
                ));
            }
            launcher => Arc::clone(launcher?),
        };
        let result = launcher.engine.start_sandbox(
            &launcher,
            &self.instance_id,
            &self.manifest.plugin.id,
            &self.installation_uuid,
            limit,
            local_id,
            source,
        );
        if let Err(err) = &result {
            // Debug, not warn: a plugin retrying a refused start would
            // otherwise flood the host log.
            tracing::debug!(instance_id = %self.instance_id, error = ?err, "start-sandbox refused");
        }
        result
    }

    async fn stop_sandbox(&mut self, local_id: String) -> Result<(), WitError> {
        let launcher = Arc::clone(self.sandbox_launcher()?);
        let (handle, marked) = launcher
            .engine
            .sandboxes()
            .take_child(&self.instance_id, &local_id)
            .ok_or_else(|| {
                WitError::NotFound(format!(
                    "no sandbox `{}` started by this instance",
                    crate::auth::invocation::audit_cap(&local_id),
                ))
            })?;
        tracing::info!(
            parent_instance = %self.instance_id,
            instance_id = %handle.instance_id(),
            "script sandbox stopping",
        );
        // The removal is persisted before this returns and before the
        // sandbox stops, so a crash or a shutdown before its reaper's
        // purge still purges at the next boot. The work runs in its own
        // task, so a cancelled guest call can't leave the sandbox marked
        // stopping but never stopped.
        // Stopped at once, not behind the marker write: its parent's
        // stop skips a sandbox already stopping. The reaper still waits
        // for the marker before it purges.
        handle.request_stop();
        let db = Arc::clone(&launcher.engine.db);
        let uuid = self.installation_uuid.to_string();
        let (persisted_tx, persisted) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let id = handle.instance_id().to_owned();
            let (db_uuid, db_id) = (uuid.clone(), id);
            let write = tokio::task::spawn_blocking(move || {
                super::sandbox_purge::mark(&db, &db_uuid, &db_id).map_err(|err| err.to_string())
            })
            .await
            .unwrap_or_else(|join| Err(join.to_string()));
            marked.send_replace(Some(Marked {
                installation_uuid: uuid,
                persisted: write.is_ok(),
            }));
            let _ = persisted_tx.send(write);
            let _ = handle.stop().await;
        });
        match persisted.await {
            Ok(Ok(())) => Ok(()),
            // The sandbox is stopping and the reaper still tries the
            // purge, but a crash before it would leave the storage for
            // a new sandbox under this id: not a clean removal.
            Ok(Err(err)) => {
                tracing::error!(
                    parent_instance = %self.instance_id,
                    local_id = %local_id,
                    error = %err,
                    "persisting the sandbox removal marker failed",
                );
                Err(WitError::Internal(format!(
                    "sandbox `{}` is stopping, but its removal could not be recorded: {err}",
                    crate::auth::invocation::audit_cap(&local_id),
                )))
            }
            Err(_) => Err(WitError::Internal(
                "the sandbox stop task ended before persisting its removal".into(),
            )),
        }
    }

    async fn list_sandboxes(&mut self) -> Vec<SandboxInfo> {
        match &self.sandbox {
            Some(SandboxRole::Parent(launcher)) => {
                launcher.engine.sandboxes().infos(&self.instance_id)
            }
            _ => Vec::new(),
        }
    }

    async fn current_sandbox(&mut self) -> Option<WitSandboxScript> {
        match &self.sandbox {
            Some(SandboxRole::Child(script)) => Some(WitSandboxScript {
                info: script.info(),
                source: script.source.to_string(),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_id_rules() {
        for ok in ["a", "house-mode", "x_1", "0", &"a".repeat(64)] {
            assert!(check_local_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-a", "_a", "A", "a~b", "a/b", "a.b", &"a".repeat(65)] {
            assert!(
                matches!(check_local_id(bad), Err(WitError::InvalidArgument(_))),
                "{bad}"
            );
        }
    }

    fn entry(registry: &SandboxRegistry, parent: &str, local_id: &str) -> u64 {
        let instance_id = sandbox_instance_id(parent, local_id);
        let generation = registry.generation.fetch_add(1, Ordering::Relaxed);
        registry
            .lock()
            .entry(parent.to_owned())
            .or_default()
            .insert(
                local_id.to_owned(),
                Entry {
                    script: Arc::new(SandboxScript {
                        local_id: local_id.to_owned(),
                        instance_id: instance_id.clone(),
                        parent_instance: parent.to_owned(),
                        source: Arc::from(""),
                    }),
                    handle: InstanceHandle::running_for_test(&instance_id, "p"),
                    generation,
                    stopping: false,
                    retire: None,
                },
            );
        generation
    }

    /// A stopped sandbox leaves the list at once but stays registered
    /// (counted) until its reaper removes it; a stale reaper can't
    /// remove a newer entry.
    /// A sandbox an operator stopped directly isn't live either.
    #[test]
    fn stopped_handles_are_not_listed() {
        let registry = SandboxRegistry::default();
        entry(&registry, "main", "a");
        registry
            .lock()
            .get_mut("main")
            .and_then(|c| c.get_mut("a"))
            .expect("entry")
            .handle = InstanceHandle::for_registry_test("main~a", "p");
        assert_eq!(registry.list("main"), Vec::<(String, String)>::new());
        assert!(registry.take_child("main", "a").is_none());
        assert!(registry.has_children("main"));
    }

    /// A removed sandbox still awaiting its purge counts against its
    /// parent's limit once its entry is gone, and only once.
    #[test]
    fn pending_purges_count_against_their_parent() {
        let registry = SandboxRegistry::with_pending_removals(HashSet::from([
            ("u".to_owned(), "main~a".to_owned()),
            ("u".to_owned(), "main~gone".to_owned()),
            ("u".to_owned(), "other~b".to_owned()),
            ("v".to_owned(), "main~c".to_owned()),
        ]));
        entry(&registry, "main", "a");
        let guard = registry.lock();
        assert_eq!(registry.purges_pending_of("u", "main", &guard["main"]), 1);
        assert_eq!(
            registry.purges_pending_of("u", "other", &BTreeMap::new()),
            1
        );
        assert_eq!(registry.purges_pending_of("u", "none", &BTreeMap::new()), 0);
        // Another installation's leftovers under a reused parent id.
        assert_eq!(registry.purges_pending_of("v", "main", &guard["main"]), 1);
    }

    #[test]
    fn stopping_entries_stay_until_their_reaper_runs() {
        let registry = SandboxRegistry::default();
        let gen_a = entry(&registry, "main", "a");
        entry(&registry, "main", "b");
        assert!(registry.take_child("main", "a").is_some());
        assert!(
            registry.take_child("main", "a").is_none(),
            "already stopping"
        );
        assert_eq!(
            registry.list("main"),
            [("b".to_owned(), "main~b".to_owned())]
        );
        assert_eq!(registry.lock()["main"].len(), 2);

        registry.remove_if_current("main", "a", gen_a + 100);
        assert_eq!(registry.lock()["main"].len(), 2, "stale generation");
        registry.remove_if_current("main", "a", gen_a);
        assert_eq!(registry.lock()["main"].len(), 1);

        assert_eq!(registry.take_children("main").len(), 1);
        assert_eq!(registry.take_children("main").len(), 0, "already stopping");
        assert_eq!(registry.list("main"), Vec::<(String, String)>::new());
    }

    #[test]
    fn instance_id_joins_with_the_separator() {
        assert_eq!(sandbox_instance_id("main", "house-mode"), "main~house-mode");
    }
}
