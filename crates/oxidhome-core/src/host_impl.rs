//! Host-side WIT bindings for the OxidHome plugin contract.
//!
//! [`wasmtime::component::bindgen!`] generates a host trait for every
//! interface a world imports, plus a typed `WorldName`/`WorldNamePre`
//! wrapper Phase 2+ uses to instantiate a component and call its
//! exports. Phase 1 only proves the bindings compile against the same
//! WIT the guest side consumes — no host trait impls yet (those land
//! in Phases 2+).
//!
//! ## Per-world bindings
//!
//! All four plugin worlds get their own bindgen module. Wasmtime's
//! typed wrappers are world-specific: `Plugin::new()` expects a
//! component that exports exactly the `plugin` world's exports, and
//! `StreamingAiPlugin::new()` expects the streaming-ai-plugin world's
//! superset. They are not interchangeable, so we generate one wrapper
//! per world rather than relying on a single superset.
//!
//! Each `wasmtime::component::bindgen!` invocation lives in its own
//! `pub mod` so the per-interface trait impls stay scoped to that
//! module — overlapping `Host` trait names across worlds (e.g. every
//! world re-imports `host-devices`) would otherwise collide.
//!
//! ## `with:` mappings
//!
//! - **Plugin-defined resources** (`pipeline-handle`, `pipe-writer`,
//!   `model`) map to the placeholder host structs in this module.
//!   Phase 9 replaces the media handles with real pipeline state;
//!   Phase 10 does the same for the inference model. Each world only
//!   declares the mappings whose interfaces it actually imports —
//!   `plugin` has none, `streaming-plugin` has the media pair,
//!   `ai-plugin` has model, and `streaming-ai-plugin` has all three.
//! - **WASI imports** are *not* remapped, even though they will be in
//!   Phase 8 when streaming plugins start using sockets/HTTP. Some
//!   WASI interfaces (`wasi:sockets/network`, `wasi:http/types`) carry
//!   `@unstable` features whose `add_to_linker` signatures take a
//!   `LinkOptions` parameter; remapping them via `with:` made our
//!   bindgen emit 2-arg call sites against the runtime's 3-arg
//!   functions. Wiring this up correctly belongs with the work that
//!   actually instantiates plugins against a `Linker` (Phase 2 +
//!   Phase 8) — bindgen here generates fresh WASI types instead,
//!   which is fine for the compile-only validation Phase 1 needs.

#![allow(missing_docs, clippy::all, clippy::pedantic)]

/// Placeholder for a running media pipeline owned by the host. Real
/// pipeline state lands in Phase 9 (`media::Pipeline`).
pub struct HostPipelineHandle;

/// Placeholder for a host-side writer feeding a `plugin-pipe` source.
/// Backed by a tokio mpsc channel in Phase 9.
pub struct HostPipeWriter;

/// Placeholder for a loaded ML model handle. Real `ort`-backed handle
/// lands in Phase 10 (`inference::ModelRegistry`).
pub struct HostModel;

/// Standard plugin world — no raw I/O. No resource mappings needed
/// because the world doesn't import `host-media` or `inference`.
pub mod plugin {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "plugin",
        imports: { default: async },
        exports: { default: async },
    });
}

/// Streaming plugin world — adds `host-media` (carries the media
/// resources) and the WASI imports. Inference is not in this world,
/// so only the media resources are remapped.
pub mod streaming_plugin {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "streaming-plugin",
        imports: { default: async },
        exports: { default: async },
        with: {
            "oxidhome:plugin/media.pipeline-handle": super::HostPipelineHandle,
            "oxidhome:plugin/media.pipe-writer": super::HostPipeWriter,
        },
    });
}

/// AI plugin world — adds `inference` (carries the model resource).
/// Media is not in this world, so only the model resource is remapped.
pub mod ai_plugin {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "ai-plugin",
        imports: { default: async },
        exports: { default: async },
        with: {
            "oxidhome:plugin/inference.model": super::HostModel,
        },
    });
}

/// Streaming + AI plugin world — combines streaming and inference;
/// remaps all three plugin-defined resources.
pub mod streaming_ai_plugin {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "streaming-ai-plugin",
        imports: { default: async },
        exports: { default: async },
        with: {
            "oxidhome:plugin/media.pipeline-handle": super::HostPipelineHandle,
            "oxidhome:plugin/media.pipe-writer": super::HostPipeWriter,
            "oxidhome:plugin/inference.model": super::HostModel,
        },
    });
}

#[cfg(test)]
mod tests {
    //! Compile-only smoke target. References each world's typed
    //! wrapper (`World` + `WorldPre`) plus one type from each
    //! generated host import to confirm the host bindgen reached Rust
    //! against the same WIT the guest consumes.

    #[test]
    fn plugin_world_resolves() {
        use super::plugin::oxidhome::plugin::{
            capabilities, devices, events, host_config, host_devices, host_events, logging,
            storage, types,
        };
        use super::plugin::{Plugin, PluginPre};

        let _ = types::Error::Unavailable(String::new());
        let _ = types::Value::BoolVal(true);
        let _ = capabilities::CapabilitySpec::Switch;
        let _ = capabilities::CapabilityState::Switch(capabilities::Switchable { state: true });
        let _: devices::DeviceInfo;
        let _: events::EventFilter;

        fn _accepts<H>()
        where
            H: host_devices::Host
                + host_events::Host
                + host_config::Host
                + storage::Host
                + logging::Host,
        {
        }

        let _: Option<Plugin>;
        let _: Option<PluginPre<()>>;
    }

    #[test]
    fn streaming_plugin_world_resolves() {
        use super::streaming_plugin::oxidhome::plugin::{host_media, media};
        use super::streaming_plugin::{StreamingPlugin, StreamingPluginPre};

        fn _accepts<H>()
        where
            H: host_media::Host + media::Host + media::HostPipelineHandle + media::HostPipeWriter,
        {
        }

        let _: Option<StreamingPlugin>;
        let _: Option<StreamingPluginPre<()>>;
    }

    #[test]
    fn ai_plugin_world_resolves() {
        use super::ai_plugin::oxidhome::plugin::inference;
        use super::ai_plugin::{AiPlugin, AiPluginPre};

        fn _accepts<H>()
        where
            H: inference::Host + inference::HostModel,
        {
        }

        let _: Option<AiPlugin>;
        let _: Option<AiPluginPre<()>>;
    }

    #[test]
    fn streaming_ai_plugin_world_resolves() {
        use super::streaming_ai_plugin::oxidhome::plugin::{host_media, inference, media};
        use super::streaming_ai_plugin::{StreamingAiPlugin, StreamingAiPluginPre};

        fn _accepts<H>()
        where
            H: host_media::Host
                + media::Host
                + media::HostPipelineHandle
                + media::HostPipeWriter
                + inference::Host
                + inference::HostModel,
        {
        }

        let _: Option<StreamingAiPlugin>;
        let _: Option<StreamingAiPluginPre<()>>;
    }
}
