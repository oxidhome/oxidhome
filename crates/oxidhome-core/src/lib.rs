//! `OxidHome` host runtime — library surface.
//!
//! `oxidhome-core` is primarily a binary, but the runtime building blocks
//! live in this library so integration tests and (later) the
//! `oxidhome-test-host` harness can compose a host without spinning up the
//! daemon. Phase 1 only wires the host-side WIT bindings; real runtime
//! pieces land in Phase 2+.

pub mod host_impl;
