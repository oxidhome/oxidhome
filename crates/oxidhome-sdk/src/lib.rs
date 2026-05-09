//! Plugin SDK for `OxidHome`.
//!
//! Phase 2 surface: a [`Plugin`] trait, a [`plugin!`](crate::plugin)
//! macro that wires the trait to the wit-bindgen-generated guest exports
//! for the standard `plugin` world, and a [`logging::init`] bridge that
//! forwards `tracing` events to the host's `logging` import. Streaming /
//! AI worlds + structured fields + storage helpers land in later phases
//! per `.claude/docs/02_sdk.md`.
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

mod plugin;
pub use plugin::Plugin;

pub mod logging;

#[doc(hidden)]
pub mod __private;
