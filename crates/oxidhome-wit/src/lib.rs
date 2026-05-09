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

// ── Feature-set sanity checks ───────────────────────────────────────────
//
// Per-world features exist because each `wit_bindgen::generate!` embeds a
// component-type custom section in the resulting wasm; `wasm-component-ld`
// rejects guest binaries carrying multiple worlds' metadata. The errors
// below catch misconfiguration at compile time so callers see a clear
// message instead of a deep linker failure.

#[cfg(not(any(
    feature = "plugin",
    feature = "streaming-plugin",
    feature = "ai-plugin",
    feature = "streaming-ai-plugin",
)))]
compile_error!(
    "oxidhome-wit requires at least one world feature: \
     plugin, streaming-plugin, ai-plugin, or streaming-ai-plugin"
);

// On wasm targets, world features are mutually exclusive — exactly one
// must be enabled. Native targets (tests, host bindgen) freely enable
// all four.
#[cfg(all(
    target_family = "wasm",
    feature = "plugin",
    feature = "streaming-plugin"
))]
compile_error!(
    "oxidhome-wit features `plugin` and `streaming-plugin` are mutually \
     exclusive on wasm targets — pick exactly one"
);
#[cfg(all(target_family = "wasm", feature = "plugin", feature = "ai-plugin"))]
compile_error!(
    "oxidhome-wit features `plugin` and `ai-plugin` are mutually exclusive \
     on wasm targets — pick exactly one"
);
#[cfg(all(
    target_family = "wasm",
    feature = "plugin",
    feature = "streaming-ai-plugin"
))]
compile_error!(
    "oxidhome-wit features `plugin` and `streaming-ai-plugin` are mutually \
     exclusive on wasm targets — pick exactly one"
);
#[cfg(all(
    target_family = "wasm",
    feature = "streaming-plugin",
    feature = "ai-plugin"
))]
compile_error!(
    "oxidhome-wit features `streaming-plugin` and `ai-plugin` are mutually \
     exclusive on wasm targets — pick exactly one"
);
#[cfg(all(
    target_family = "wasm",
    feature = "streaming-plugin",
    feature = "streaming-ai-plugin"
))]
compile_error!(
    "oxidhome-wit features `streaming-plugin` and `streaming-ai-plugin` are \
     mutually exclusive on wasm targets — pick exactly one"
);
#[cfg(all(
    target_family = "wasm",
    feature = "ai-plugin",
    feature = "streaming-ai-plugin"
))]
compile_error!(
    "oxidhome-wit features `ai-plugin` and `streaming-ai-plugin` are mutually \
     exclusive on wasm targets — pick exactly one"
);

/// Standard plugin world: device integrations, automations, no raw I/O.
///
/// `pub_export_macro: true` lifts the world's `__export_plugin_impl` macro
/// to crate root via `#[macro_export]` so `oxidhome-sdk`'s `plugin!` macro
/// can invoke it from an external crate. Safe here because the `plugin`
/// world doesn't share any exported interfaces with another world (the
/// `streaming` interface is the only shared export, and lives only in the
/// streaming-{plugin,ai-plugin} worlds).
#[cfg(feature = "plugin")]
pub mod plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "plugin",
        generate_all,
        pub_export_macro: true,
    });
}

/// Streaming plugin world: adds host-media + WASI sockets/HTTP.
#[cfg(feature = "streaming-plugin")]
pub mod streaming_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "streaming-plugin",
        generate_all,
    });
}

/// AI plugin world: adds host-managed inference.
#[cfg(feature = "ai-plugin")]
pub mod ai_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "ai-plugin",
        generate_all,
    });
}

/// Streaming + AI plugin world: streaming I/O combined with inference.
#[cfg(feature = "streaming-ai-plugin")]
pub mod streaming_ai_plugin {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "streaming-ai-plugin",
        generate_all,
    });
}
