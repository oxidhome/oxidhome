//! Validation for plugin input to native media and inference (H7).
//!
//! Native media (Phase 9) and inference (Phase 10) run inside the host
//! process with strict limits — see
//! `docs/adr/0002-in-process-native-media-and-inference.md`. Every value a
//! plugin hands to native code must pass these checks first, because a
//! native parser that sees a bad value has no sandbox around it.
//!
//! The rules here are the ones the WIT `media` and `inference` interfaces
//! document; the WIT doc comments and these functions must agree.
//!
//! **Not wired in yet.** There is no media pipeline or inference runtime
//! to call these from: only the `plugin` world is linked, and
//! [`crate::host_impl`]'s `HostPipelineHandle` / `HostModel` are still
//! placeholders. Phases 9/10 call these helpers before native code sees a
//! `media-pipeline` or a `named-tensor`.
//!
//! - [`endpoint`]: `network-endpoint` syntax and the resolved-address
//!   policy (applied on every connection and every redirect hop).
//! - [`names`]: sink, recording-profile, and model name grammar.
//! - [`pipeline`]: pipeline-size, frame, frame-rate, audio, encoder, and
//!   normalize bounds.
//! - [`tensor`]: tensor rank, shape, element-count, and byte limits with
//!   overflow-checked arithmetic.

pub mod endpoint;
pub mod names;
pub mod pipeline;
pub mod tensor;
