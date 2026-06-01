//! Plugin SDK for `OxidHome`.
//!
//! A [`Plugin`] trait + a [`plugin!`](crate::plugin) macro that wires
//! it to the wit-bindgen-generated guest exports for the standard
//! `plugin` world, plus thin host-import wrappers and ergonomic
//! builders.
//!
//! What's available today, by category:
//!
//! - **Lifecycle & events** — `init` / `shutdown` / `on_event` /
//!   `tick` / `execute_command` / `execute_service_command` on
//!   [`Plugin`]; [`plugin!`] generates the canonical-ABI glue.
//! - **Devices** — [`Device`] builder; [`host::register_device`] /
//!   `update_device` / `remove_device` / `get_device`; gated by
//!   `[capabilities] declares_devices`.
//! - **Services** (Phase 7) — [`Service`] + [`CommandSpec`] builders;
//!   [`host::register_service`] / `update_service` / `remove_service`
//!   / `get_service`; gated by `[capabilities] declares_services`.
//!   [`host::call_service`] dispatches synchronously to another
//!   plugin's (or this plugin's) service; the host rejects A→…→A
//!   cycles at instance granularity. Cross-plugin example pair:
//!   `examples/service-counter` + `examples/service-caller`.
//! - **Events** — [`host::publish_event`] / `publish_state_change` /
//!   `publish_custom_event` / `subscribe` / `unsubscribe`.
//! - **Storage** ([`host::storage`]) — per-instance KV; manifest
//!   `[capabilities] storage_quota_kb` (default 0 = denied).
//! - **Blobs** ([`host::blobs`]) — filesystem-backed bytes + a
//!   `SQLite` name index; `[capabilities] blob_quota_mb`.
//! - **Config** ([`host::config`]) — `get` / `get_typed::<T>` /
//!   `list` against the manifest's `[config]` schema folded with
//!   per-instance overrides.
//! - **Logging** ([`logging::init`]) — installs a `tracing` ↔ host
//!   `logging` bridge so [`tracing`] macros from plugin code reach
//!   the host's log store.
//!
//! Streaming / AI worlds land in later phases; everything above is
//! the standard `plugin` world.
//!
//! # Hello world
//!
//! ```ignore
//! #[derive(Default)]
//! struct HelloWorld;
//!
//! impl oxidhome_sdk::Plugin for HelloWorld {
//!     fn init(&mut self) -> Result<(), String> {
//!         // Install the `tracing` ↔ host `logging` bridge so the
//!         // events below reach the host. Idempotent — the host runs
//!         // each instance in its own wasm store, and the test harness
//!         // can call `init()` more than once across tests.
//!         let _ = oxidhome_sdk::logging::init();
//!         oxidhome_sdk::tracing::info!("hello");
//!         Ok(())
//!     }
//!     fn shutdown(&mut self) {
//!         oxidhome_sdk::tracing::info!("bye");
//!     }
//! }
//!
//! oxidhome_sdk::plugin!(HelloWorld);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

/// Re-export of [`tracing`]. Plugin authors use the macros here
/// (`oxidhome_sdk::tracing::info!`, etc.) and the bridge in
/// [`logging::init`] forwards events to the host.
pub use tracing;

/// Generated guest bindings for the standard `plugin` world. Re-exported
/// so the [`plugin!`] macro and plugin code can reach generated types
/// (`Event`, `Command`, `CommandResult`, …) without a direct dep on
/// `oxidhome-wit`.
pub use oxidhome_wit::plugin as bindings;

mod device;
pub use device::Device;

mod service;
pub use service::{CommandSpec, Service};

pub mod host;

mod plugin;
pub use plugin::Plugin;

pub mod logging;

#[doc(hidden)]
pub mod __private;
