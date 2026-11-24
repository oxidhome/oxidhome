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
//! leaves out is the daemon *around* the runtime — the
//! HTTP/Connect/MCP surfaces and plugin installation. The supervisor
//! task is opt-in: a directly loaded plugin has none, so a test calls
//! its exports itself, deterministically; a started one runs under the
//! production supervisor (see "Driven or supervised" below).
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
//!             id: "cmd-test".into(),
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
//! # Driven or supervised
//!
//! [`TestHost::load`] gives a [`TestPluginInstance`] the test drives
//! itself: each method calls one export and returns, nothing runs in
//! between, and [`TestPluginInstance::advance`] runs the ticks the
//! manifest schedules. [`TestHost::start`]
//! gives a [`SupervisedInstance`] run by the daemon's own supervisor
//! task — needed to serve `call-service` requests from other plugins
//! and to exercise the restart policy and the liveness watchdog.
//! Both kinds share one host, so a directly driven plugin can call a
//! supervised one's services; [`TestHost::call_service`] makes such a
//! call from the test itself.
//!
//! # Time
//!
//! [`TestHost::new`] runs on the real clock. On
//! [`TestHost::with_virtual_clock`] the engine reads a [`VirtualClock`]
//! (`oxidhome-core`'s clock seam; the daemon always uses the system
//! clock) that stands still until the test moves it. It drives:
//!
//! - supervised ticks (`tick_interval_ms`) and directly driven ones
//!   ([`TestPluginInstance::advance`]);
//! - the `accepted`-command TTL (H5);
//! - the liveness watchdog: a hung call is interrupted only once the
//!   test moves time past the deadline;
//! - the guest's `wasi:clocks` wall and monotonic clocks;
//! - event receive times, device-state `received_ms`, and audit-row
//!   times (except the command journal's `COMMAND` rows, which keep
//!   real time).
//!
//! [`TestHost::advance`] moves the clock one timer at a time and waits
//! for the work each one triggers, so ticks and expiries happen in
//! order and exactly as often as the span allows;
//! [`TestHost::run_until_idle`] waits for that work without moving
//! time; [`VirtualClock::advance`] jumps without waiting — the way past
//! a plugin call that never returns. Not on the clock: a guest's WASI
//! sleep still takes real time, as do request and `call-service`
//! deadlines, restart backoff, shutdown grace periods, and KV and blob
//! write times (see [`oxidhome_core::clock`]).
//!
//! On a real-clock host, [`TestPluginInstance::advance`] still runs a
//! directly driven plugin's ticks on schedule, on a clock of its own
//! that nothing else reads.
//!
//! # Snapshots
//!
//! `snapshot()` on either instance kind renders its devices,
//! services, events, storage, and blobs as stable text that
//! [`Snapshot::assert_matches`] compares against an inline expected
//! string (or [`Snapshot::assert_matches_file`], a file kept up to
//! date with `OXIDHOME_UPDATE_SNAPSHOTS=1`), with a line diff on
//! mismatch. `snapshot_with(&SnapshotOptions)` adds the device-state
//! projection, the commands the test sent with their H5 outcomes, the
//! audit rows, and timestamps (relative to the virtual clock). Every
//! snapshot is redacted: host-minted ids become numbered placeholders
//! and the instance's secrets are masked, so it can be committed as a
//! golden file. The text works with any snapshot tool as well.
//!
//! # Async
//!
//! The plugin's exports are `async` (Wasmtime runs components on its
//! async engine), so tests run on a Tokio runtime, e.g.
//! `#[tokio::test(flavor = "multi_thread")]` — or a plain `#[test]`
//! wrapping each call in [`block_on`].
//!
//! The crate's `README.md` walks through testing a plugin end to end.

mod block_on;
mod clock;
mod error;
mod grant;
mod host;
mod instance;
mod live;
mod snapshot;
mod supervised;
mod tempdir;
mod view;

pub use block_on::block_on;
pub use error::TestHostError;
pub use grant::grant_excess;
pub use host::{LoadOptions, TestHost, test_supervision};
pub use instance::TestPluginInstance;
pub use snapshot::{Snapshot, SnapshotOptions, UPDATE_SNAPSHOTS_ENV, render_value};
pub use supervised::SupervisedInstance;
pub use view::StorageView;

/// Host-side types the harness hands back, re-exported so tests don't
/// need a direct `oxidhome-core` dependency for the common cases.
pub use oxidhome_core::state::{BlobInfo, DeviceMeta, HistoricalEvent, ServiceMeta};
pub use oxidhome_core::{
    CommandOutcome, CommandReport, Engine, InitError, InstanceHandle, InstanceState,
    SupervisorTuning, VirtualClock,
};
pub use oxidhome_manifest::{CapabilitiesSection, ServiceGrant};

/// WIT types of the `plugin` world, as the host sees them: the
/// `Command` / `CommandResult` a test sends and receives, the `Event`
/// it delivers, the `Value` it reads back from storage, the service
/// schema types.
pub mod wit {
    pub use oxidhome_core::host_impl::plugin::oxidhome::plugin::{
        capabilities, devices, events, services, types,
    };
}

// Compile the README's examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
