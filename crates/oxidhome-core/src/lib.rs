//! `OxidHome` host runtime — library surface.
//!
//! `oxidhome-core` ships a binary, but the runtime building blocks live
//! here so integration tests and (later) the `oxidhome-test-host`
//! harness can compose a host without spinning up the daemon.

// `oxidhome-core` is a host-internal runtime crate; its public surface
// stabilizes only at Phase 11 (external API). Until then, every public
// fn returning `Result` would need a `# Errors` section that's almost
// always restating "the operation failed" — defer the doc churn until
// the API is settled.
#![allow(clippy::missing_errors_doc)]

pub mod host_impl;
pub mod runtime;
pub mod state;

pub use runtime::{Engine, PluginInstance};
pub use state::{DeviceMeta, DeviceRegistry, EventBus, EventSubscription};
