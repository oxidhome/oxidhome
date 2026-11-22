//! [`TestPluginInstance`] — one loaded plugin plus assertion helpers.

use std::sync::Arc;

use oxidhome_core::state::{DeviceMeta, EventQuery, HistoricalEvent, KvStore};
use oxidhome_core::{Engine, PluginInstance};
use oxidhome_manifest::PluginManifest;

use crate::TestHostError;
use crate::host::LiveIds;
use crate::tempdir::TempDir;
use crate::wit::devices::{Command, CommandResult};
use crate::wit::events::Event;
use crate::wit::types::{DeviceId, Value};

/// A plugin instance loaded by a [`crate::TestHost`].
///
/// Each driver method calls the matching plugin export once, on the
/// caller's task, and returns when the export does — there is no
/// background supervisor, so `tick` and event delivery happen exactly
/// when the test asks for them.
///
/// Dropping the instance (or calling [`Self::shutdown`]) runs the
/// host-side teardown the daemon's supervisor runs when an instance
/// stops: its devices and services leave the registries and its
/// device-state projection turns stale.
///
/// The instance keeps its host's state directory alive, so it stays
/// usable even after the [`crate::TestHost`] that loaded it is dropped.
pub struct TestPluginInstance {
    // Field order: the store and engine close before the state
    // directory they live in is removed.
    inner: PluginInstance,
    engine: Engine,
    live: LiveIds,
    state_dir: Arc<TempDir>,
}

impl TestPluginInstance {
    pub(crate) fn new(
        engine: Engine,
        inner: PluginInstance,
        live: LiveIds,
        state_dir: Arc<TempDir>,
    ) -> Self {
        Self {
            inner,
            engine,
            live,
            state_dir,
        }
    }

    /// The instance id the plugin runs under.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.inner.instance_id()
    }

    /// The installation identity storage and device ids are keyed by.
    /// For a test load this is the manifest's `plugin.id`.
    #[must_use]
    pub fn installation_uuid(&self) -> Arc<str> {
        self.inner.installation_uuid()
    }

    /// The parsed manifest the instance was loaded from.
    #[must_use]
    pub fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    /// Call the plugin's `init` export.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Init`] when `init` returns an error, traps,
    /// or runs past the liveness watchdog.
    pub async fn init(&mut self) -> Result<(), TestHostError> {
        Ok(self.inner.init().await?)
    }

    /// Call the plugin's `tick` export once.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out.
    pub async fn tick(&mut self) -> Result<(), TestHostError> {
        self.inner
            .tick()
            .await
            .map_err(|e| TestHostError::call("tick", e))
    }

    /// Call the plugin's `execute-command` export for `device`. The
    /// result goes through the same post-processing as in the daemon:
    /// an `ok-with-state` reply updates the host's device-state
    /// projection (or is downgraded to an error when it exceeds the
    /// projection's caps).
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out. A
    /// command the plugin rejects is an `Ok(CommandResult::Err(_))`.
    pub async fn send_command(
        &mut self,
        device: impl Into<DeviceId>,
        command: Command,
    ) -> Result<CommandResult, TestHostError> {
        self.inner
            .execute_command(device.into(), command)
            .await
            .map_err(|e| TestHostError::call("execute-command", e))
    }

    /// Publish `event` on the host's event bus, then hand this
    /// instance every event waiting on its subscriptions through its
    /// `on-event` export. Returns how many events the plugin received.
    ///
    /// Delivery follows production rules: the plugin only sees the
    /// event if it subscribed with a matching filter, which in turn
    /// needs the `subscribes_events` capability. Other instances on
    /// the same host receive the event too, on their next
    /// [`Self::deliver_pending_events`]. The event is published the
    /// way host-side simulators publish: it skips the durable event
    /// log, so the plugin sees `row-id: none` and the origin fields
    /// exactly as the test set them.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when `on-event` traps or times out.
    pub async fn deliver_event(&mut self, event: Event) -> Result<usize, TestHostError> {
        self.engine.events().publish(event);
        self.deliver_pending_events().await
    }

    /// Hand this instance every event waiting on its subscriptions
    /// through its `on-event` export, as the daemon's supervisor does
    /// when the bus wakes it. Returns how many events were delivered.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when `on-event` traps or times out.
    pub async fn deliver_pending_events(&mut self) -> Result<usize, TestHostError> {
        self.inner
            .drain_events()
            .await
            .map_err(|e| TestHostError::call("on-event", e))
    }

    /// Call the plugin's `on-shutdown` export, then run the host-side
    /// teardown (see the type docs).
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out; the
    /// teardown runs either way.
    pub async fn shutdown(mut self) -> Result<(), TestHostError> {
        // `Drop` runs the teardown once `self` goes out of scope.
        self.inner
            .shutdown()
            .await
            .map_err(|e| TestHostError::call("on-shutdown", e))
    }

    /// Devices this instance currently has registered, sorted by
    /// device id.
    #[must_use]
    pub fn devices(&self) -> Vec<Arc<DeviceMeta>> {
        let id = self.instance_id();
        let mut devices: Vec<_> = self
            .engine
            .devices()
            .list()
            .into_iter()
            .filter(|d| d.owner_instance == id)
            .collect();
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        devices
    }

    /// Every event this instance id has published, oldest first, as
    /// recorded in the host's durable event log — with the host-stamped
    /// origin and receive time. Includes events from earlier instances
    /// loaded under the same id on this host.
    ///
    /// # Errors
    ///
    /// [`TestHostError::EventLog`] if the log can't be read.
    pub fn events(&self) -> Result<Vec<HistoricalEvent>, TestHostError> {
        let query = EventQuery {
            instance_id: Some(self.instance_id().to_owned()),
            ..EventQuery::default()
        };
        let mut events = self.engine.event_log().query(&query, usize::MAX)?;
        // The log returns newest first.
        events.reverse();
        Ok(events)
    }

    /// Read-only view of this instance's KV storage.
    #[must_use]
    pub fn storage(&self) -> StorageView {
        StorageView {
            kv: self.engine.kv(),
            _state_dir: Arc::clone(&self.state_dir),
            installation_uuid: self.installation_uuid(),
            instance_id: self.instance_id().to_owned(),
        }
    }

    /// The production instance this wraps, for calls the harness
    /// doesn't cover yet (e.g. `execute-service-command`).
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut PluginInstance {
        &mut self.inner
    }
}

impl Drop for TestPluginInstance {
    fn drop(&mut self) {
        let id = self.inner.instance_id().to_owned();
        self.engine.release_instance_state(&id);
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }
}

/// Read-only access to one instance's KV storage, for assertions.
pub struct StorageView {
    kv: Arc<KvStore>,
    // Keeps the database's directory alive as long as the view.
    _state_dir: Arc<TempDir>,
    installation_uuid: Arc<str>,
    instance_id: String,
}

impl StorageView {
    /// The value stored under `key`, if any.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Storage`] if the store can't be read.
    pub fn get(&self, key: &str) -> Result<Option<Value>, TestHostError> {
        Ok(self
            .kv
            .get(&self.installation_uuid, &self.instance_id, key)?)
    }

    /// Keys starting with `prefix` (`""` for all), sorted.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Storage`] if the store can't be read.
    pub fn keys(&self, prefix: &str) -> Result<Vec<String>, TestHostError> {
        Ok(self
            .kv
            .list_keys(&self.installation_uuid, &self.instance_id, prefix)?)
    }
}
