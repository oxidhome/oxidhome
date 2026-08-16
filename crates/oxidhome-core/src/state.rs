//! In-memory host state shared across plugin instances.
//!
//! Phase 3 introduces two singletons (per [`Engine`](crate::Engine)):
//!
//! - [`DeviceRegistry`] — the canonical list of devices any plugin
//!   instance has registered, plus the mapping from `device-id` to
//!   the instance that owns it (used by the host to route commands).
//! - [`EventBus`] — a tokio broadcast channel that fans every
//!   `publish-event` call out to all subscribers (host-side test
//!   harnesses today, plugin-side `on-event` delivery once Phase 6
//!   wires per-instance dispatch loops).
//!
//! Both are `Send + Sync` and meant to live behind `Arc` — the engine
//! holds one `Arc` clone, every [`PluginState`](crate::runtime::PluginState)
//! takes another at load time, and host-import callbacks reach them
//! through `PluginState`.

pub mod audit_log;
pub mod auth_token;
pub mod blobs;
pub mod dashboards;
pub mod db;
pub mod device_state;
pub mod devices;
pub mod event_log;
pub mod events;
pub mod installed_plugins;
pub mod kv;
pub mod log_store;
pub mod services;

pub use audit_log::{AuditEntry, AuditLog, AuditLogError, AuditQuery, credential_fingerprint};
pub use auth_token::{IssuedToken, TokenError, TokenRecord, TokenStore};
pub use blobs::{BlobError, BlobInfo, BlobStore, is_safe_instance_id};
pub use dashboards::{
    Dashboard, DashboardError, DashboardInput, DashboardStore, SharedDashboardStore,
};
pub use db::Db;
pub use device_state::{
    CursorError, DeltaPage, DeviceState, DeviceStateStore, MAX_BYTES_PER_SLOT, MAX_FIELDS_PER_SLOT,
    MAX_PROJECTED_BYTES_PER_INSTANCE, MAX_STALE_ENTRIES, SharedDeviceStateStore, SlotCapExceeded,
    StateQuality,
};
pub use devices::{
    DeviceMeta, DeviceRegistry, MAX_CAPABILITIES_PER_DEVICE, MAX_DEVICES_PER_INSTANCE,
};
pub use event_log::{EventLog, EventLogError, EventQuery, HistoricalEvent, TopicMatch};
pub use events::{EventBus, EventSubscription, PublishDenied, SubscriberMessage};
pub use installed_plugins::{
    InstallError, InstalledPlugin, InstalledPluginRegistry, UninstallError, any_grant_matches,
    content_digest, effective_capabilities, read_installed_bytes, recompute_digest_and_manifest,
    recompute_installed_digest,
};
pub(crate) use kv::stored_value_size;
pub use kv::{KvError, KvStore};
pub use log_store::{
    HistoricalLogEvent, LogLevel, LogQuery, LogStore, LogStoreError, LogValue, SqliteLayer,
};
pub use services::{CallGuard, ServiceMeta, ServiceRegistry};
