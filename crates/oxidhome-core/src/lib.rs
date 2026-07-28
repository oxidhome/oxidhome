//! `OxidHome` host runtime — library surface.
//!
//! `oxidhome-core` ships a binary, but the runtime building blocks live
//! here so integration tests and (later) the `oxidhome-test-host`
//! harness can compose a host without spinning up the daemon.

// `oxidhome-core` is a host-internal runtime crate; its public surface
// stabilizes only at Phase 12 (external API). Until then, every public
// fn returning `Result` would need a `# Errors` section that's almost
// always restating "the operation failed" — defer the doc churn until
// the API is settled. Same applies to `# Panics` sections for mutex
// `.expect("poisoned")` lines and similar host-internal assertions.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod api;
pub mod auth;
pub mod host_impl;
pub mod runtime;
pub mod state;

pub use auth::{Actor, ActorKind};
pub use runtime::{
    Engine, InitError, InstanceHandle, InstanceRegistry, InstanceState, PluginInstance,
    RegistryError, SupervisorTuning, supervise, supervise_with_tuning,
};
pub use state::{DeviceMeta, DeviceRegistry, EventBus, EventSubscription};

/// SDK version this host ships with. Plugins loaded by this build
/// declare their own `sdk_version` in the manifest; the loader runs
/// [`oxidhome_manifest::compatibility::check`] against this constant
/// (and [`MIN_SUPPORTED_SDK_VERSION`]) before instantiating.
///
/// Bumped in lockstep with the `oxidhome-sdk` release for external
/// plugin authors — see the WIT/SDK versioning note in
/// `ARCHITECTURE.md`.
///
/// **0.2.0 (this bump):** the WIT `event` record grew required
/// `origin-plugin-id` / `origin-instance-id` fields (architecture-
/// review C2b). That's a structural component-type change — a
/// plugin compiled against 0.1.x has an incompatible `on-event`
/// signature and Wasmtime rejects it at instantiation. Pre-1.0
/// policy treats each minor as its own ABI line
/// ([`oxidhome_manifest::compatibility::check`]), so bumping to
/// 0.2.0 turns that opaque runtime failure into a clean load-time
/// preflight error naming the mismatch.
pub const OXIDHOME_SDK_VERSION: &str = "0.2.0";

/// Oldest `sdk_version` the host will accept from a plugin manifest.
/// Below this, the load fails with a clear "rebuild your plugin
/// against SDK ≥ X" error.
pub const MIN_SUPPORTED_SDK_VERSION: &str = "0.2.0";
