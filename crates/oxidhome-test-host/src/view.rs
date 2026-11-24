//! Read-side queries shared by [`crate::TestPluginInstance`] and
//! [`crate::SupervisedInstance`]: both look at the same engine stores,
//! keyed by instance id and installation identity.

use std::sync::{Arc, Mutex};

use oxidhome_core::Engine;
use oxidhome_core::state::{
    BlobInfo, DeviceMeta, EventQuery, HistoricalEvent, KvStore, ServiceMeta,
};

use crate::TestHostError;
use crate::snapshot::{CommandRecord, HostRecords, Snapshot, SnapshotOptions};
use crate::tempdir::TempDir;
use crate::wit::types::Value;

/// Which instance a query is about.
pub(crate) struct InstanceRef<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) state_dir: &'a Arc<TempDir>,
    pub(crate) installation_uuid: Arc<str>,
    pub(crate) instance_id: &'a str,
    /// The host's secret config values, masked in snapshots.
    pub(crate) secrets: &'a HostRecords,
    /// Commands the test sent through the harness.
    pub(crate) commands: &'a Mutex<Vec<CommandRecord>>,
}

impl InstanceRef<'_> {
    pub(crate) fn devices(&self) -> Vec<Arc<DeviceMeta>> {
        let mut devices: Vec<_> = self
            .engine
            .devices()
            .list()
            .into_iter()
            .filter(|d| d.owner_instance == self.instance_id)
            .collect();
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        devices
    }

    pub(crate) fn services(&self) -> Vec<Arc<ServiceMeta>> {
        let mut services: Vec<_> = self
            .engine
            .services()
            .list()
            .into_iter()
            .filter(|s| s.owner_instance == self.instance_id)
            .collect();
        services.sort_by(|a, b| a.info.local_id.cmp(&b.info.local_id));
        services
    }

    pub(crate) fn service_id(&self, local_id: &str) -> Option<String> {
        self.services()
            .into_iter()
            .find(|s| s.info.local_id == local_id)
            .map(|s| s.id.clone())
    }

    pub(crate) fn events(&self) -> Result<Vec<HistoricalEvent>, TestHostError> {
        let query = EventQuery {
            instance_id: Some(self.instance_id.to_owned()),
            ..EventQuery::default()
        };
        let mut events = self.engine.event_log().query(&query, usize::MAX)?;
        // The log returns newest first.
        events.reverse();
        Ok(events)
    }

    pub(crate) fn storage(&self) -> StorageView {
        StorageView {
            kv: self.engine.kv(),
            _state_dir: Arc::clone(self.state_dir),
            installation_uuid: Arc::clone(&self.installation_uuid),
            instance_id: self.instance_id.to_owned(),
        }
    }

    pub(crate) fn blobs(&self) -> Result<Vec<BlobInfo>, TestHostError> {
        Ok(self
            .engine
            .blobs()
            .list_blobs(&self.installation_uuid, self.instance_id, "")?)
    }

    pub(crate) fn read_blob(&self, name: &str) -> Result<Vec<u8>, TestHostError> {
        Ok(self
            .engine
            .blobs()
            .read_by_name(&self.installation_uuid, self.instance_id, name)?)
    }

    pub(crate) fn snapshot(&self, options: &SnapshotOptions) -> Result<Snapshot, TestHostError> {
        Snapshot::capture(self, options)
    }
}

/// Access to one instance's KV storage, for assertions and for
/// seeding state before a call.
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

    /// Write `value` under `key` through the production store, as if
    /// the plugin had — same per-instance quota accounting. For
    /// seeding state a test then drives the plugin against.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Storage`] when the write fails, including
    /// when the instance has no storage quota or the write would
    /// exceed it.
    pub fn set(&self, key: &str, value: Value) -> Result<(), TestHostError> {
        Ok(self
            .kv
            .set(&self.installation_uuid, &self.instance_id, key, value)?)
    }
}
