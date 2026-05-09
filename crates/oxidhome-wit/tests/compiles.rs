//! Compile-only smoke target. Confirms each world's `wit-bindgen` output
//! reaches Rust and that the type names we expect to consume from the SDK
//! are actually present. No runtime behavior — these tests pass by
//! compiling.
//!
//! Each world is gated behind its corresponding Cargo feature; CI runs
//! these tests with `--all-features` so all four are exercised.

#![allow(dead_code, unused_imports)]

/// `plugin` world: standard imports + lifecycle exports.
#[cfg(feature = "plugin")]
mod plugin_world {
    use oxidhome_wit::plugin::oxidhome::plugin::capabilities::{
        CapabilitySpec, CapabilityState, ColorLightSpec, SensorSpec, Switchable,
    };
    use oxidhome_wit::plugin::oxidhome::plugin::devices::{Command, CommandResult, DeviceInfo};
    use oxidhome_wit::plugin::oxidhome::plugin::events::{Event, EventFilter, EventPayload};
    use oxidhome_wit::plugin::oxidhome::plugin::types::{Error, KeyValue, Value};

    #[test]
    fn plugin_types_resolve() {
        let _ = CapabilitySpec::Switch;
        let _ = CapabilityState::Switch(Switchable { state: true });
        let _: ColorLightSpec;
        let _: SensorSpec;
        let _: DeviceInfo;
        let _: Command;
        let _: CommandResult;
        let _: Event;
        let _: EventFilter;
        let _: EventPayload;
        let _: KeyValue;
        let _: Value;
        let _: Error;
    }
}

/// `streaming-plugin` world: adds host-media + WASI imports.
#[cfg(feature = "streaming-plugin")]
mod streaming_plugin_world {
    use oxidhome_wit::streaming_plugin::oxidhome::plugin::media::{
        MediaPipeline, MediaSource, OutputSink, PipelineStep,
    };

    #[test]
    fn streaming_types_resolve() {
        let _: MediaPipeline;
        let _: MediaSource;
        let _: OutputSink;
        let _: PipelineStep;
    }
}

/// `ai-plugin` world: standard plugin + inference import.
#[cfg(feature = "ai-plugin")]
mod ai_plugin_world {
    use oxidhome_wit::ai_plugin::oxidhome::plugin::inference::{
        ModelInfo, NamedTensor, TensorDtype,
    };

    #[test]
    fn ai_types_resolve() {
        let _ = TensorDtype::F32;
        let _: NamedTensor;
        let _: ModelInfo;
    }
}

/// `streaming-ai-plugin` world: combines streaming + inference.
#[cfg(feature = "streaming-ai-plugin")]
mod streaming_ai_plugin_world {
    use oxidhome_wit::streaming_ai_plugin::oxidhome::plugin::inference::TensorDtype;
    use oxidhome_wit::streaming_ai_plugin::oxidhome::plugin::media::MediaPipeline;

    #[test]
    fn streaming_ai_types_resolve() {
        let _ = TensorDtype::F16;
        let _: MediaPipeline;
    }
}
