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

pub mod db;
pub mod devices;
pub mod events;
pub mod kv;

pub use db::Db;
pub use devices::{DeviceMeta, DeviceRegistry};
pub use events::{EventBus, EventSubscription};
pub use kv::{KvError, KvStore};
