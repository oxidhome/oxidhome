//! Phase 4 manifest-loader integration tests.
//!
//! Cover the bits the per-plugin round-trip tests don't: loading
//! refuses cleanly when the manifest is missing or invalid, and the
//! call-site capability gate refuses a *real* guest-side
//! `register-device` call when the manifest doesn't declare it. The
//! simulated-switch wasm is reused as the guest fixture — its `init`
//! propagates the host's error through `map_err(...)?`, so the
//! permission-denied surfaces as the `init()` Result.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::{Engine, PluginInstance};

/// Plugin directory with no manifest → load errors loudly.
#[tokio::test(flavor = "current_thread")]
async fn missing_manifest_fails_with_clear_error() {
    let empty_dir = tempdir();
    let engine = Engine::new().expect("engine");
    // `PluginInstance` doesn't implement `Debug` (holds a
    // `wasmtime::Store`), so `.expect_err` won't type-check.
    let Err(err) = PluginInstance::load(&engine, empty_dir.path(), "missing_manifest").await else {
        panic!("load without manifest must fail")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("manifest.toml"),
        "error should mention manifest.toml, got: {msg}",
    );
}

/// Manifest that fails `oxidhome_manifest::validate` → load errors
/// with the collected validator findings inline.
#[tokio::test(flavor = "current_thread")]
async fn invalid_manifest_fails_with_validator_errors() {
    let dir = tempdir();
    // `plugin.id` doesn't match the reverse-DNS shape → validator
    // emits `InvalidPluginId`.
    std::fs::write(
        dir.path().join("manifest.toml"),
        r#"manifest_version = 1
[plugin]
id = "NotReverseDNS"
name = "broken"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "irrelevant.wasm"
"#,
    )
    .expect("write manifest");

    let engine = Engine::new().expect("engine");
    let Err(err) = PluginInstance::load(&engine, dir.path(), "broken").await else {
        panic!("invalid manifest must fail")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("InvalidPluginId") || msg.contains("reverse-DNS"),
        "error should name the InvalidPluginId finding, got: {msg}",
    );
}

/// Manifest whose `sdk_version` is below the host's
/// `MIN_SUPPORTED_SDK_VERSION` → load fails the compatibility
/// preflight before instantiation.
#[tokio::test(flavor = "current_thread")]
async fn sdk_below_minimum_fails_compat_preflight() {
    let dir = tempdir();
    std::fs::write(
        dir.path().join("manifest.toml"),
        r#"manifest_version = 1
[plugin]
id = "example.too-old"
name = "Too Old"
version = "0.1.0"
world = "plugin"
sdk_version = "0.0.1"
[runtime]
wasm = "irrelevant.wasm"
"#,
    )
    .expect("write manifest");

    let engine = Engine::new().expect("engine");
    let Err(err) = PluginInstance::load(&engine, dir.path(), "too_old").await else {
        panic!("plugin below MIN_SUPPORTED_SDK_VERSION must fail")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("below the host's minimum supported version") || msg.contains("incompatible"),
        "error should describe the SDK mismatch, got: {msg}",
    );
}

/// **Definition-of-done end-to-end gating check.**
///
/// Per `07_manifest.md`: *"a plugin instantiates fine, then tries to
/// call `register-device` without `declares_devices` set, and
/// observes `permission-denied`."* This is the literal version of
/// that — no `PluginState`-direct shortcuts.
///
/// The simulated-switch wasm is reused as the guest fixture. Its
/// `init` calls `host::register_device(...)` for a `switch`-capability
/// device and propagates any host error via `map_err(...)?`, so a
/// `permission-denied` from the host surfaces directly through the
/// returned `init()` Result. The test builds the wasm, copies it into
/// a tempdir, writes a manifest with `declares_devices = []`
/// alongside it, loads through `PluginInstance::load` (which proves
/// instantiation succeeds — the gate fires at the call site, not at
/// load time), and asserts `init()` fails with a message naming
/// `permission-denied` and `switch`.
#[tokio::test(flavor = "current_thread")]
async fn loader_path_register_device_for_undeclared_capability_denied() {
    let wasm_src = support::build_example("simulated-switch", "simulated_switch.wasm");
    assert!(wasm_src.is_file(), "missing build artifact: {wasm_src:?}");

    // Tempdir laid out as a real plugin install dir: `manifest.toml`
    // alongside the wasm. The manifest's `wasm` key is relative
    // (absolute paths trip `RuntimeWasmPathEscapes`), so the wasm
    // file is *copied* into the tempdir rather than referenced via a
    // symlink (which the loader's canonicalize check would refuse
    // for landing outside the plugin dir).
    let dir = tempdir();
    let wasm_dst = dir.path().join("simulated_switch.wasm");
    std::fs::copy(&wasm_src, &wasm_dst).expect("copy wasm");
    std::fs::write(
        dir.path().join("manifest.toml"),
        // declares_devices is intentionally absent → empty → the
        // simulated-switch's `register_device(.. CapabilitySpec::Switch ..)`
        // call inside `init` must come back denied.
        r#"manifest_version = 1
[plugin]
id = "example.bare-switch"
name = "Bare Switch"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "simulated_switch.wasm"
[capabilities]
"#,
    )
    .expect("write manifest");

    let engine = Engine::new().expect("engine");

    // Load must succeed — gating is at the call site, not at
    // instantiation. The Wasmtime linker provides every host import
    // unconditionally; the manifest only filters at call time.
    let mut instance = PluginInstance::load(&engine, dir.path(), "bare_switch")
        .await
        .expect("plugin should instantiate even with empty declares_devices");

    // `init` runs guest code that calls host::register_device for a
    // switch. The host's gate returns permission-denied; the guest's
    // `map_err(...)?` propagates the error back through `init`'s
    // Result, which surfaces here as an anyhow::Error.
    let err = match instance.init().await {
        Ok(()) => panic!("expected init to fail for undeclared `switch` capability"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.to_ascii_lowercase().contains("permission")
            && msg.to_ascii_lowercase().contains("switch"),
        "expected error mentioning permission + switch, got: {msg}",
    );
}

/// Tiny tempdir helper. The integration tests already use
/// `tokio::fs` indirectly via the loader; using std `tempfile`-style
/// scratch here keeps the dep surface small.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort; if the test framework has already torn down
        // the directory we don't care.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn tempdir() -> TempDir {
    let base = std::env::temp_dir();
    let name = format!(
        "oxidhome-manifest-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}
