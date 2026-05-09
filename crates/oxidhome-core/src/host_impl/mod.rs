//! Host-side WIT bindings for the OxidHome plugin contract.
//!
//! [`wasmtime::component::bindgen!`] generates a host trait for every
//! interface the plugin world imports, plus the linker glue to wire host
//! state into a Wasmtime [`Linker`]. Phase 1 only proves the bindings
//! compile against the same WIT the guest side consumes — no host trait
//! impls yet (those land in Phases 2+).
//!
//! [`Linker`]: wasmtime::component::Linker
//!
//! ## Why we bindgen the superset world
//!
//! Bindgen is invoked for `streaming-ai-plugin` — the world that
//! transitively imports every interface the contract defines. A linker
//! built from these bindings can satisfy any of the four worlds: a
//! `plugin`-world component requires a strict subset of the imports the
//! superset linker provides, and a Wasmtime `Linker` having extra
//! interfaces beyond what the component requires is fine.
//!
//! Per-world export-side calling glue (e.g. `setup-pipeline` on the
//! streaming worlds) is dispatched dynamically at instantiation time,
//! so generating a single set of host import bindings is enough.
//!
//! ## `with:` mappings
//!
//! - **Plugin-defined resources** (`pipeline-handle`, `pipe-writer`,
//!   `model`) map to placeholder host structs in this module. Phase 8
//!   replaces the media handles with real pipeline state; Phase 9 does
//!   the same for the inference model.
//! - **WASI imports** are *not* remapped here, even though they will be
//!   in Phase 7 when streaming plugins start using sockets/HTTP. Some
//!   WASI interfaces (`wasi:sockets/network`, `wasi:http/types`) carry
//!   `@unstable` features whose `add_to_linker` signatures take a
//!   `LinkOptions` parameter; remapping them via `with:` made our
//!   bindgen emit 2-arg call sites against the runtime's 3-arg
//!   functions. Wiring this up correctly belongs with the work that
//!   actually instantiates plugins against a `Linker` (Phase 2 + Phase
//!   7) — bindgen here generates fresh WASI types instead, which is
//!   fine for the compile-only validation Phase 1 needs.

#![allow(missing_docs, clippy::all, clippy::pedantic)]

/// Placeholder for a running media pipeline owned by the host. Real
/// pipeline state lands in Phase 8 (`media::Pipeline`).
pub struct HostPipelineHandle;

/// Placeholder for a host-side writer feeding a `plugin-pipe` source.
/// Backed by a tokio mpsc channel in Phase 8.
pub struct HostPipeWriter;

/// Placeholder for a loaded ML model handle. Real `ort`-backed handle
/// lands in Phase 9 (`inference::ModelRegistry`).
pub struct HostModel;

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "streaming-ai-plugin",
    imports: { default: async },
    exports: { default: async },
    with: {
        // Host-owned resources: bind the WIT resource types to the
        // placeholder structs above. Phase 2+ swaps these for real types.
        // Path syntax: `package:namespace/interface.resource`.
        "oxidhome:plugin/media.pipeline-handle": HostPipelineHandle,
        "oxidhome:plugin/media.pipe-writer": HostPipeWriter,
        "oxidhome:plugin/inference.model": HostModel,
    },
});

#[cfg(test)]
mod tests {
    //! Compile-only smoke target. References one type per generated host
    //! interface plus the world wrapper to confirm the host bindgen
    //! reached Rust against the same WIT the guest consumes.

    use super::oxidhome::plugin::{
        capabilities, devices, events, host_config, host_devices, host_events, host_media,
        inference, logging, media, storage, types,
    };
    use super::{StreamingAiPlugin, StreamingAiPluginPre};

    #[test]
    fn host_bindings_resolve() {
        // Shared types
        let _ = types::Error::Unavailable(String::new());
        let _: types::KeyValue;
        let _ = types::Value::BoolVal(true);

        // Capabilities — verify the spec/state split surfaces correctly
        let _ = capabilities::CapabilitySpec::Switch;
        let _ = capabilities::CapabilityState::Switch(capabilities::Switchable { state: true });

        // Device + event records
        let _: devices::DeviceInfo;
        let _: devices::Command;
        let _: events::Event;
        let _: events::EventFilter;

        // Host import interfaces — each one's generated `Host` trait is
        // what oxidhome-core impls in Phase 2+. We only reference them
        // here; no impl is required for the compile check.
        fn _accepts_host_devices<H: host_devices::Host>() {}
        fn _accepts_host_events<H: host_events::Host>() {}
        fn _accepts_host_config<H: host_config::Host>() {}
        fn _accepts_host_media<H: host_media::Host>() {}
        fn _accepts_storage<H: storage::Host>() {}
        fn _accepts_logging<H: logging::Host>() {}

        // Resources are wired through `Host` for their parent interface
        // — this is where the `with:` mapping connects to the
        // placeholder structs above.
        fn _accepts_media<H: media::Host + media::HostPipelineHandle + media::HostPipeWriter>() {}
        fn _accepts_inference<H: inference::Host + inference::HostModel>() {}

        // World wrappers — the type the host instantiates against a
        // component plus its pre-instantiated counterpart.
        let _: Option<StreamingAiPlugin>;
        let _: Option<StreamingAiPluginPre<()>>;
    }
}
