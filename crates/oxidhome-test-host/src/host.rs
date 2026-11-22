//! [`TestHost`] and its load options.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use oxidhome_core::runtime::{LoadMode, read_manifest_with_bytes};
use oxidhome_core::{Engine, PluginInstance};
use oxidhome_manifest::CapabilitiesSection;

use crate::TestHostError;
use crate::grant::grant_excess;
use crate::instance::TestPluginInstance;
use crate::tempdir::TempDir;

/// Ids of the instances currently alive on one host. Shared with each
/// [`TestPluginInstance`] so dropping it frees the id.
pub(crate) type LiveIds = Arc<Mutex<HashSet<String>>>;

/// An in-process plugin host for tests.
///
/// Wraps a production [`Engine`] backed by a fresh `SQLite` database
/// and blob root in a temporary directory, removed when the host is
/// dropped. Instances loaded on the same host share its device
/// registry, event bus, and stores, exactly as instances in one daemon
/// do; use separate hosts for isolated tests.
pub struct TestHost {
    // Field order matters: `engine` holds the database open, so it
    // drops before the directory it lives in is removed.
    engine: Engine,
    live: LiveIds,
    next_id: AtomicU64,
    state_dir: TempDir,
}

/// Per-load knobs for [`TestHost::load_with`]. `Default` loads the
/// plugin the way `oxidhome-core` dev-loads it: a generated instance
/// id, manifest defaults for every config field, and the capabilities
/// the manifest requests.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    instance_id: Option<String>,
    config: Option<toml::Value>,
    grant: Option<CapabilitiesSection>,
}

impl LoadOptions {
    /// Same as [`LoadOptions::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the plugin under this instance id instead of a generated
    /// `test-<n>`. Storage, device ids, and event origins are keyed by
    /// it, so reloading with the same id sees the previous
    /// instance's persisted state, as a daemon restart would.
    #[must_use]
    pub fn instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Per-instance config overrides, as a TOML table keyed by the
    /// manifest's `[config.*]` field names. Merged with the manifest
    /// defaults by the production config merge, so unknown keys and
    /// type mismatches fail the load just as they do in the daemon.
    #[must_use]
    pub fn config(mut self, overrides: toml::Value) -> Self {
        self.config = Some(overrides);
        self
    }

    /// Run the plugin under this grant instead of the manifest's full
    /// request — typically to test how it behaves when a capability
    /// is denied.
    ///
    /// The grant takes the path an installed plugin's grant takes: the
    /// loader checks it against the capability-count limits and
    /// applies `requested ∩ granted`. A grant that asks for anything
    /// the manifest doesn't request is refused with
    /// [`TestHostError::GrantExceedsRequest`] (see
    /// [`crate::grant_excess`]), because production would quietly
    /// drop the extra and the test wouldn't be testing what it says.
    #[must_use]
    pub fn grant(mut self, grant: CapabilitiesSection) -> Self {
        self.grant = Some(grant);
        self
    }
}

impl TestHost {
    /// Build a host with an empty state directory.
    ///
    /// # Errors
    ///
    /// [`TestHostError::StateDir`] if the temporary directory can't
    /// be created; [`TestHostError::Engine`] if the engine or its
    /// database can't be set up.
    pub fn new() -> Result<Self, TestHostError> {
        let state_dir =
            TempDir::new().map_err(|(path, source)| TestHostError::StateDir { path, source })?;
        let engine = Engine::with_state_dir(state_dir.path())
            .map_err(|e| TestHostError::Engine(e.into()))?;
        Ok(Self {
            engine,
            live: LiveIds::default(),
            next_id: AtomicU64::new(1),
            state_dir,
        })
    }

    /// The underlying production engine, for assertions the harness
    /// doesn't wrap (device-state projection, event bus subscriptions,
    /// blob store, …).
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The host's state directory (`SQLite` database, blob root).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        self.state_dir.path()
    }

    /// Load the plugin in `plugin_dir` with default [`LoadOptions`].
    /// Does not call `init`.
    ///
    /// # Errors
    ///
    /// See [`Self::load_with`].
    pub async fn load(
        &self,
        plugin_dir: impl AsRef<Path>,
    ) -> Result<TestPluginInstance, TestHostError> {
        self.load_with(plugin_dir, LoadOptions::default()).await
    }

    /// Load the plugin in `plugin_dir` — a directory holding
    /// `manifest.toml` and the component its `[runtime] wasm` entry
    /// points at. Does not call `init`.
    ///
    /// # Errors
    ///
    /// - [`TestHostError::InvalidInstanceId`] /
    ///   [`TestHostError::DuplicateInstanceId`] for an id the daemon
    ///   would refuse, or one a live instance on this host holds.
    /// - [`TestHostError::Manifest`] when the manifest can't be read,
    ///   parsed, or validated.
    /// - [`TestHostError::GrantExceedsRequest`] for an injected grant
    ///   wider than the manifest's request.
    /// - [`TestHostError::Load`] when the production loader refuses
    ///   the plugin or the component fails to instantiate.
    pub async fn load_with(
        &self,
        plugin_dir: impl AsRef<Path>,
        options: LoadOptions,
    ) -> Result<TestPluginInstance, TestHostError> {
        let plugin_dir = plugin_dir.as_ref();
        let LoadOptions {
            instance_id,
            config,
            grant,
        } = options;
        let reservation = match instance_id {
            Some(id) => {
                if !oxidhome_core::state::is_safe_instance_id(&id) {
                    return Err(TestHostError::InvalidInstanceId(id));
                }
                Reservation::claim(&self.live, id)?
            }
            None => Reservation::claim_generated(&self.live, &self.next_id),
        };
        let instance_id = reservation.id().to_owned();

        // Read the manifest once and pin it for the load, as
        // `Engine::start_instance` does, so the grant check below and
        // the loader see the same bytes.
        let (manifest_bytes, manifest) =
            read_manifest_with_bytes(plugin_dir)
                .await
                .map_err(|e| TestHostError::Manifest {
                    path: plugin_dir.to_path_buf(),
                    source: e.into(),
                })?;
        let plugin_id = manifest.plugin.id.clone();

        let mode = match grant {
            None => LoadMode::Dev,
            Some(grant) => {
                let excess = grant_excess(&manifest.capabilities, &grant);
                if !excess.is_empty() {
                    return Err(TestHostError::GrantExceedsRequest { plugin_id, excess });
                }
                LoadMode::Granted {
                    granted: Arc::new(grant),
                }
            }
        };

        let inner = PluginInstance::load_with_pinned_manifest(
            &self.engine,
            plugin_dir,
            instance_id,
            config.as_ref(),
            mode,
            manifest_bytes,
            manifest,
        )
        .await
        .map_err(|e| TestHostError::Load {
            plugin_id,
            source: e.into(),
        })?;
        Ok(TestPluginInstance::new(
            self.engine.clone(),
            inner,
            reservation.keep(),
        ))
    }
}

/// Holds an instance id in the host's live set until the load either
/// succeeds (ownership moves to the instance) or fails (dropped here,
/// freeing the id).
struct Reservation {
    live: LiveIds,
    id: Option<String>,
}

impl Reservation {
    fn claim(live: &LiveIds, id: String) -> Result<Self, TestHostError> {
        let mut guard = live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.insert(id.clone()) {
            return Err(TestHostError::DuplicateInstanceId(id));
        }
        Ok(Self {
            live: Arc::clone(live),
            id: Some(id),
        })
    }

    /// Claim the next free `test-<n>` id, skipping any a caller chose
    /// explicitly.
    fn claim_generated(live: &LiveIds, next: &AtomicU64) -> Self {
        loop {
            let id = format!("test-{}", next.fetch_add(1, Ordering::Relaxed));
            if let Ok(reservation) = Self::claim(live, id) {
                return reservation;
            }
        }
    }

    fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }

    fn keep(mut self) -> LiveIds {
        self.id = None;
        Arc::clone(&self.live)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
        }
    }
}
