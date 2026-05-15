//! Phase 4 manifest-loader integration tests.
//!
//! Cover the bits the per-plugin round-trip tests don't: loading
//! refuses cleanly when the manifest is missing or invalid, and the
//! call-site capability gate prevents an undeclared device
//! registration from going through. The simulated-switch wasm is
//! reused so we don't rebuild a wasm fixture per scenario.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::host_devices;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
use oxidhome_core::{Actor, ActorKind, DeviceRegistry, Engine, EventBus, PluginInstance};

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

/// End-to-end gating check via the loader path. Loads
/// `simulated-switch` with a *swapped* manifest that doesn't
/// declare `switch`; calling `register_device` with a switch
/// capability through the WIT trait surface must return
/// `permission-denied`. Bypasses the wasm `init` so we don't need a
/// different .wasm built — we exercise the gate on `PluginState`
/// directly, simulating what a guest would see if the plugin tried
/// to register a capability the manifest didn't authorize.
#[tokio::test(flavor = "current_thread")]
async fn register_device_for_undeclared_capability_denied() {
    use oxidhome_manifest::{
        CapabilitiesSection, PluginManifest, PluginSection, RuntimeSection, World,
    };
    use semver::Version;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // Manifest that declares *no* device capabilities.
    let manifest = PluginManifest {
        manifest_version: 1,
        plugin: PluginSection {
            id: "example.bare".into(),
            name: "Bare".into(),
            version: Version::new(0, 1, 0),
            authors: Vec::new(),
            description: None,
            source: None,
            license: None,
            keywords: Vec::new(),
            world: World::Plugin,
            sdk_version: Version::new(0, 1, 0),
        },
        runtime: RuntimeSection {
            wasm: PathBuf::from("none.wasm"),
            singleton: false,
            tick_interval_ms: None,
            fuel_per_call: None,
            memory_max_mb: None,
            call_timeout_ms: None,
        },
        capabilities: CapabilitiesSection::default(),
        config: BTreeMap::new(),
        ui: None,
    };

    // Build a PluginState directly via oxidhome-core's library
    // surface. This bypasses Wasmtime entirely — we're exercising
    // the host trait impl, which is what the WIT linker call would
    // route into.
    let mut state = oxidhome_core::runtime::PluginState::new(
        "bare-0",
        Arc::new(manifest),
        Actor::plugin("bare-0"),
        oxidhome_manifest::InstanceConfig::new(),
        Arc::new(DeviceRegistry::new()),
        Arc::new(EventBus::new()),
    );
    assert_eq!(state.actor.kind(), ActorKind::Plugin);

    let info = DeviceInfo {
        local_id: "d-1".into(),
        name: "d-1".into(),
        manufacturer: None,
        model: None,
        firmware: None,
        capabilities: vec![CapabilitySpec::Switch],
        initial_state: Vec::new(),
        metadata: Vec::new(),
    };
    let err = host_devices::Host::register_device(&mut state, info)
        .await
        .expect_err("undeclared capability must be denied");
    assert!(
        matches!(err, WitError::PermissionDenied(ref msg) if msg.contains("switch")),
        "expected PermissionDenied with `switch`, got {err:?}",
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
