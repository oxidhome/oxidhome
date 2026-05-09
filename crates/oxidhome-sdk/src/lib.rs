//! Plugin SDK for `OxidHome`.
//!
//! At the moment this crate is a thin re-export shell over `oxidhome-wit`.
//! Phase 2 of the plan introduces the trait-based plugin entry points and
//! the `tracing` ↔ `logging` bridge; Phases 3+ layer in devices, events,
//! storage, etc. See `.claude/docs/02_sdk.md`.
//!
//! Each plugin world is exposed as its own submodule. Plugin authors pick
//! the world that matches the capabilities their plugin needs and import
//! types and the corresponding export macro from there.

pub use oxidhome_wit::{ai_plugin, plugin, streaming_ai_plugin, streaming_plugin};
