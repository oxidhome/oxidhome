//! Guest-side WIT bindings for `OxidHome` plugin worlds.
//!
//! Each plugin world gets its own module with `wit-bindgen`-generated types
//! and the canonical-ABI export glue. This crate is internal —
//! `oxidhome-sdk` re-exports the surface plugin authors actually use, and
//! Phase 2 wraps the world-specific export macros in a single `plugin!`
//! SDK macro so plugin authors don't pick world plumbing by hand.
//!
//! The cabi helper macros are intentionally **not** `#[macro_export]`'d
//! (we leave `pub_export_macro` at its default `false`). Multiple worlds
//! share interfaces (e.g. `streaming-plugin` and `streaming-ai-plugin`
//! both export the `streaming` interface), and `#[macro_export]` would
//! pull the per-interface cabi helpers up to the crate root and collide.

#![allow(clippy::all, clippy::pedantic)]

/// Standard plugin world: device integrations, automations, no raw I/O.
pub mod plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "plugin",
        generate_all,
    });
}

/// Streaming plugin world: adds host-media + WASI sockets/HTTP.
pub mod streaming_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "streaming-plugin",
        generate_all,
    });
}

/// AI plugin world: adds host-managed inference.
pub mod ai_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "ai-plugin",
        generate_all,
    });
}

/// Streaming + AI plugin world: streaming I/O combined with inference.
pub mod streaming_ai_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "streaming-ai-plugin",
        generate_all,
    });
}
