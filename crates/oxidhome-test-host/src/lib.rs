//! `oxidhome-test-host` — run an `OxidHome` plugin inside a `#[test]`.
//!
//! The harness loads a plugin component in-process and lets a test
//! drive its lifecycle (`init`, `tick`, `execute-command`, `on-event`,
//! `on-shutdown`) and inspect what it did (devices registered, events
//! published, storage written) without starting the `oxidhome-core`
//! daemon.
//!
//! # One host, not a lookalike
//!
//! The harness does **not** mock the host imports. A [`TestHost`]
//! owns a real [`oxidhome_core::Engine`] on a throwaway state
//! directory, and every plugin goes through the production loader
//! ([`oxidhome_core::PluginInstance`]): the same manifest validation,
//! SDK compatibility check, config merge, capability gates, quotas,
//! and host-import implementations the daemon uses. What the harness
//! leaves out is the daemon *around* the runtime — the supervisor
//! task, the HTTP/Connect/MCP surfaces, and plugin installation — so
//! a test calls the plugin's exports directly and deterministically.
//!
//! Capability injection goes through the production grant boundary
//! too: an injected grant is validated and intersected with the
//! manifest's request by the same core code that applies an installed
//! plugin's grant, and a grant asking for something the manifest
//! doesn't request is refused (see [`LoadOptions::grant`]). A test
//! therefore can't run a plugin under a grant production could never
//! issue.
//!
//! The crate's `tests/conformance.rs` holds the host-interface
//! conformance suite: one set of scenarios run against both the
//! production install-and-load path and this harness, so the two
//! can't drift apart silently.
//!
//! # Example
//!
//! ```no_run
//! use oxidhome_test_host::TestHost;
//! use oxidhome_test_host::wit::devices::Command;
//!
//! # async fn demo() -> Result<(), oxidhome_test_host::TestHostError> {
//! let host = TestHost::new()?;
//! // A plugin directory holds `manifest.toml` plus the component
//! // its `[runtime] wasm` entry points at.
//! let mut switch = host.load("examples/simulated-switch").await?;
//! switch.init().await?;
//!
//! let device = switch.devices()[0].id.clone();
//! switch
//!     .send_command(
//!         device,
//!         Command {
//!             capability: "switch".into(),
//!             action: "toggle".into(),
//!             args: Vec::new(),
//!         },
//!     )
//!     .await?;
//! assert_eq!(switch.events()?.len(), 1);
//!
//! switch.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! The plugin's exports are `async` (Wasmtime runs components on its
//! async engine), so tests run on a Tokio runtime, e.g.
//! `#[tokio::test(flavor = "current_thread")]`.

mod error;
mod grant;
mod host;
mod instance;
mod tempdir;

pub use error::TestHostError;
pub use grant::grant_excess;
pub use host::{LoadOptions, TestHost};
pub use instance::{StorageView, TestPluginInstance};

/// Host-side types the harness hands back, re-exported so tests don't
/// need a direct `oxidhome-core` dependency for the common cases.
pub use oxidhome_core::state::{DeviceMeta, HistoricalEvent};
pub use oxidhome_core::{Engine, InitError};
pub use oxidhome_manifest::CapabilitiesSection;

/// WIT types of the `plugin` world, as the host sees them: the
/// `Command` / `CommandResult` a test sends and receives, the `Event`
/// it delivers, the `Value` it reads back from storage.
pub mod wit {
    pub use oxidhome_core::host_impl::plugin::oxidhome::plugin::{
        capabilities, devices, events, types,
    };
}
