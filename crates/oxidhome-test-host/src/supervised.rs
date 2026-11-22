//! [`SupervisedInstance`] — a plugin run by the production supervisor.

use std::sync::Arc;
use std::time::Duration;

use oxidhome_core::state::{BlobInfo, DeviceMeta, HistoricalEvent, ServiceMeta};
use oxidhome_core::{Engine, InstanceHandle, InstanceState};
use tokio::task::JoinHandle;

use crate::TestHostError;
use crate::live::IdLease;
use crate::snapshot::Snapshot;
use crate::tempdir::TempDir;
use crate::view::{InstanceRef, StorageView};
use crate::wit::devices::{Command, CommandResult};
use crate::wit::types::{DeviceId, ServiceId};

/// A plugin instance started by [`crate::TestHost::start`] and run by
/// the daemon's own supervisor task: it ticks on the manifest's
/// cadence in real time, receives subscribed events as they are
/// published, serves `call-service` requests from other plugins,
/// restarts after a crash per its `restart` policy, and is
/// interrupted by the liveness watchdog when a call wedges.
///
/// The assertion helpers read the same host stores as
/// [`crate::TestPluginInstance`]'s. Because the supervisor works in
/// the background, what they return can change between two reads.
///
/// [`Self::stop`] shuts the instance down and waits for the host-side
/// teardown. Dropping it without `stop` asks the supervisor to shut
/// down in the background.
pub struct SupervisedInstance {
    handle: InstanceHandle,
    engine: Engine,
    plugin_id: Arc<str>,
    /// Resolves to the terminal state once the supervisor has ended
    /// *and* the reaper has torn the instance down; it then frees the
    /// instance id. `None` once [`Self::stop`] has awaited it.
    watcher: Option<JoinHandle<InstanceState>>,
    runtime: tokio::runtime::Handle,
    state_dir: Arc<TempDir>,
}

impl SupervisedInstance {
    pub(crate) fn new(
        engine: Engine,
        handle: InstanceHandle,
        lease: IdLease,
        state_dir: Arc<TempDir>,
    ) -> Self {
        let plugin_id: Arc<str> = handle.plugin_id().into();
        let watcher = {
            let handle = handle.clone();
            let engine = engine.clone();
            // The supervisor may still be shutting down after the host
            // and this handle are gone; keep its state dir until then.
            let state_dir = Arc::clone(&state_dir);
            tokio::spawn(async move {
                let _state_dir = state_dir;
                let state = handle.wait_terminal().await;
                // The engine's reaper releases the instance's devices
                // and services, then unregisters it; only after that
                // may the id go to a new instance.
                while engine.instance(lease.id()).is_some() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                drop(lease);
                state
            })
        };
        Self {
            handle,
            engine,
            plugin_id,
            watcher: Some(watcher),
            runtime: tokio::runtime::Handle::current(),
            state_dir,
        }
    }

    /// The instance id the plugin runs under.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.handle.instance_id()
    }

    /// The `plugin.id` of the manifest the supervisor runs.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The installation identity storage and device ids are keyed by:
    /// the manifest's `plugin.id`, as for a directly loaded instance.
    #[must_use]
    pub fn installation_uuid(&self) -> Arc<str> {
        self.handle
            .installation_uuid()
            .map_or_else(|| Arc::clone(&self.plugin_id), Arc::from)
    }

    /// The supervisor's handle, for anything the harness doesn't wrap.
    #[must_use]
    pub fn handle(&self) -> &InstanceHandle {
        &self.handle
    }

    /// The supervisor's current lifecycle state.
    #[must_use]
    pub fn state(&self) -> InstanceState {
        self.handle.state()
    }

    /// Wait until the plugin is loaded, `init` succeeded, and the
    /// supervisor is serving it. A crash before that doesn't end the
    /// wait while the restart policy still allows another attempt.
    ///
    /// # Errors
    ///
    /// [`TestHostError::NotRunning`] with the state it ended in when
    /// the instance stops or fails first.
    pub async fn wait_for_running(&self) -> Result<(), TestHostError> {
        self.handle
            .wait_for_running()
            .await
            .map_err(|_| TestHostError::NotRunning {
                instance_id: self.instance_id().to_owned(),
                state: self.handle.state(),
            })
    }

    /// Wait until the supervisor gives up or is stopped, and return
    /// its terminal state ([`InstanceState::Stopped`] or
    /// [`InstanceState::Failed`]).
    pub async fn wait_terminal(&self) -> InstanceState {
        self.handle.wait_terminal().await
    }

    /// Run the plugin's `execute-command` for `device` on its
    /// supervisor task, as a host-origin command — the daemon's
    /// command path minus the API surface.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the supervisor isn't running or
    /// the export traps (which also crashes the instance). A command
    /// the plugin rejects is an `Ok(CommandResult::Err(_))`.
    pub async fn send_command(
        &self,
        device: impl Into<DeviceId>,
        command: Command,
    ) -> Result<CommandResult, TestHostError> {
        self.handle
            .execute_command(device.into(), command)
            .await
            .map_err(|e| TestHostError::call("execute-command", e))
    }

    /// Ask the supervisor to call `on-shutdown` and stop, then wait
    /// until the host has torn the instance down (its devices and
    /// services gone, its id free for reuse). Returns the terminal
    /// state: `Stopped`, or `Failed` if the instance had already
    /// failed.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Supervisor`] if the background task that
    /// tracks the teardown panicked or was cancelled.
    pub async fn stop(mut self) -> Result<InstanceState, TestHostError> {
        // `InstanceHandle::stop` reports nothing but success today.
        let _ = self.handle.stop().await;
        match self.watcher.take() {
            Some(watcher) => watcher
                .await
                .map_err(|e| TestHostError::Supervisor(e.into())),
            None => Ok(self.handle.state()),
        }
    }

    /// Devices this instance currently has registered, sorted by
    /// device id.
    #[must_use]
    pub fn devices(&self) -> Vec<Arc<DeviceMeta>> {
        self.view().devices()
    }

    /// Services this instance currently has registered, sorted by
    /// local id.
    #[must_use]
    pub fn services(&self) -> Vec<Arc<ServiceMeta>> {
        self.view().services()
    }

    /// The host-minted id (`svc-N`) of this instance's service with
    /// `local_id`, once it has registered one.
    #[must_use]
    pub fn service_id(&self, local_id: &str) -> Option<ServiceId> {
        self.view().service_id(local_id)
    }

    /// Every event this instance id has published, oldest first. See
    /// [`crate::TestPluginInstance::events`].
    ///
    /// # Errors
    ///
    /// [`TestHostError::EventLog`] if the log can't be read.
    pub fn events(&self) -> Result<Vec<HistoricalEvent>, TestHostError> {
        self.view().events()
    }

    /// This instance's KV storage.
    #[must_use]
    pub fn storage(&self) -> StorageView {
        self.view().storage()
    }

    /// Blobs this instance has written, sorted by name.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Blobs`] if the blob index can't be read.
    pub fn blobs(&self) -> Result<Vec<BlobInfo>, TestHostError> {
        self.view().blobs()
    }

    /// The contents of this instance's blob called `name`.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Blobs`] if there is no such blob or it can't
    /// be read.
    pub fn read_blob(&self, name: &str) -> Result<Vec<u8>, TestHostError> {
        self.view().read_blob(name)
    }

    /// A [`Snapshot`] of everything this instance has in the host.
    ///
    /// # Errors
    ///
    /// When the event log, storage, or blob index can't be read.
    pub fn snapshot(&self) -> Result<Snapshot, TestHostError> {
        self.view().snapshot()
    }

    fn view(&self) -> InstanceRef<'_> {
        InstanceRef {
            engine: &self.engine,
            state_dir: &self.state_dir,
            installation_uuid: self.installation_uuid(),
            instance_id: self.instance_id(),
        }
    }
}

impl Drop for SupervisedInstance {
    fn drop(&mut self) {
        if self.watcher.is_some() {
            // The watcher keeps running and frees the id once the
            // teardown is done.
            let handle = self.handle.clone();
            drop(self.runtime.spawn(async move { handle.stop().await }));
        }
    }
}
