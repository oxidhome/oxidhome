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

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use oxidhome_manifest::PluginManifest;

use crate::Engine;
use crate::host_impl::plugin::oxidhome::plugin::host_sandboxes::{
    self, SandboxInfo, SandboxScript as WitSandboxScript,
};
use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;

use super::instance::LoadMode;
use super::lifecycle::{InstanceHandle, SupervisorTuning};
use super::registry::RegistryError;
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

/// One live sandbox in [`SandboxRegistry`].
struct Entry {
    script: Arc<SandboxScript>,
    handle: InstanceHandle,
    /// Distinguishes this entry from a later sandbox with the same
    /// `local-id`, so a late reaper can't remove its replacement.
    generation: u64,
}

/// Live sandboxes per parent instance. Owned by the [`Engine`].
#[derive(Default)]
pub struct SandboxRegistry {
    inner: Mutex<HashMap<String, BTreeMap<String, Entry>>>,
    generation: AtomicU64,
}

impl SandboxRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BTreeMap<String, Entry>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The sandboxes `parent` started that are still live, ordered by
    /// `local-id`.
    #[must_use]
    pub fn list(&self, parent: &str) -> Vec<(String, String)> {
        self.lock().get(parent).map_or_default(|children| {
            children
                .values()
                .map(|e| (e.script.local_id.clone(), e.script.instance_id.clone()))
                .collect()
        })
    }

    fn infos(&self, parent: &str) -> Vec<SandboxInfo> {
        self.lock()
            .get(parent)
            .map_or_default(|children| children.values().map(|e| e.script.info()).collect())
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

    /// Remove every sandbox of `parent` and return their handles, for
    /// the caller to stop.
    pub(crate) fn take_children(&self, parent: &str) -> Vec<InstanceHandle> {
        self.lock()
            .remove(parent)
            .map_or_default(|children| children.into_values().map(|e| e.handle).collect())
    }

    fn take_child(&self, parent: &str, local_id: &str) -> Option<InstanceHandle> {
        let mut guard = self.lock();
        let children = guard.get_mut(parent)?;
        let entry = children.remove(local_id);
        if children.is_empty() {
            guard.remove(parent);
        }
        entry.map(|e| e.handle)
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
    fn start_sandbox(
        &self,
        launcher: &SandboxLauncher,
        parent: &str,
        plugin_id: &str,
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
        let registry = self.sandboxes();
        let mut guard = registry.lock();
        let children = guard.entry(parent.to_owned()).or_default();
        if let Some(existing) = children.get(&local_id) {
            return if *existing.script.source == *source {
                Ok(existing.script.instance_id.clone())
            } else {
                Err(WitError::InvalidArgument(format!(
                    "sandbox `{local_id}` is already running different source; stop it first"
                )))
            };
        }
        if children.len() >= limit as usize {
            let err = WitError::Unavailable(format!(
                "instance `{parent}` already runs {} sandboxes, the limit \
                 (capabilities.script_sandboxes) is {limit}",
                children.len(),
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
        let limit = self.granted_capabilities.script_sandboxes;
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
            limit,
            local_id,
            source,
        );
        if let Err(err) = &result {
            tracing::warn!(instance_id = %self.instance_id, error = ?err, "start-sandbox refused");
        }
        result
    }

    async fn stop_sandbox(&mut self, local_id: String) -> Result<(), WitError> {
        let launcher = Arc::clone(self.sandbox_launcher()?);
        let handle = launcher
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
        tokio::spawn(async move {
            let _ = handle.stop().await;
        });
        Ok(())
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

    #[test]
    fn instance_id_joins_with_the_separator() {
        assert_eq!(sandbox_instance_id("main", "house-mode"), "main~house-mode");
    }
}
