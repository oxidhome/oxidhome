//! `OxidHome` plugin manifest — `TOML` schema, parser, validator, and the
//! supporting types every other crate consumes when loading a plugin.
//!
//! Phase 4 surface:
//! - [`PluginManifest`] + its sub-records: [`PluginSection`],
//!   [`RuntimeSection`], [`CapabilitiesSection`], [`ConfigField`],
//!   plus the [`World`] enum.
//! - Capability gating types: [`NetworkRule`] and its parts
//!   ([`Proto`], [`HostMatch`], [`PortMatch`]) parsed eagerly at
//!   manifest load so a malformed rule fails install, not first
//!   connect.
//! - [`validate()`] — collects every problem in one pass instead of
//!   bailing on the first.
//! - [`merge`] — folds a manifest's `[config]` defaults with a
//!   user-supplied override `toml::Value` into a typed
//!   [`InstanceConfig`].
//! - [`compatibility::check`] — the host's preflight that a plugin's
//!   declared `sdk_version` is acceptable.
//!
//! The crate has no I/O of its own — callers read the TOML bytes and
//! hand them in. That keeps the unit tests pure and fast, and lets
//! `oxidhome-core` decide where manifests come from (filesystem, blob
//! store, registry, etc.).

pub mod compatibility;
pub mod config;
pub mod network;
pub mod validate;

mod manifest;

pub use compatibility::{CompatError, check as check_compatibility};
pub use config::{ConfigField, ConfigFieldType, ConfigValue, InstanceConfig, merge};
pub use manifest::{
    CapabilitiesSection, PluginManifest, PluginSection, RuntimeSection, UiPermissions, UiSection,
    World,
};
pub use network::{HostMatch, NetworkRule, NetworkRuleParseError, PortMatch, Proto};
pub use validate::{ValidationError, WasmPathProblem, validate};
