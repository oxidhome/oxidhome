//! WIT contract-compatibility fixtures (architecture review M1).
//!
//! The loader proves compatibility from the component binary
//! (`oxidhome_core::runtime::contract`), not from the manifest's
//! `sdk_version`. These tests pin that down:
//!
//! - real SDK-built example components are accepted;
//! - a component synthesized from the committed baseline of every
//!   contract version is accepted when the host serves that version
//!   (its own, or an older one on the same compatibility line) and
//!   refused otherwise;
//! - components whose types drift from the host's (changed signature,
//!   unknown function, missing export, other package version, no
//!   contract at all) are refused with an error naming the item;
//! - the full loader refuses such a component before instantiation.
//!
//! Synthetic components come from `wit_component::dummy_module`: a
//! core module whose imports/exports have exactly the shape of a WIT
//! world, wrapped into a component the same way `wit-bindgen` +
//! `wasm-component-ld` wrap a real plugin.

#[path = "support.rs"]
mod support;

use std::path::Path;

use oxidhome_core::runtime::contract::{ContractError, host_contract_version, verify_component};
use oxidhome_core::{Engine, PluginInstance};
use wit_component::{ComponentEncoder, StringEncoding, dummy_module, embed_component_metadata};
use wit_parser::{ManglingAndAbi, PackageId, Resolve, Type, WorldId, WorldKey};

/// `wit/` as the host sees it.
fn host_wit() -> (Resolve, PackageId) {
    let mut resolve = Resolve::default();
    let (pkg, _) = resolve
        .push_dir(support::workspace_root().join("wit"))
        .expect("wit/ parses");
    (resolve, pkg)
}

fn plugin_world(resolve: &Resolve, pkg: PackageId) -> WorldId {
    resolve.packages[pkg].worlds["plugin"]
}

/// A component with exactly the shape of `world`.
fn synthesize(resolve: &Resolve, world: WorldId) -> Vec<u8> {
    let mut module = dummy_module(resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, resolve, world, StringEncoding::UTF8)
        .expect("embed component-type metadata");
    ComponentEncoder::default()
        .module(&module)
        .expect("register dummy module")
        .validate(true)
        .encode()
        .expect("encode component")
}

fn plugin_component(mutate: impl FnOnce(&mut Resolve, PackageId)) -> Vec<u8> {
    let (mut resolve, pkg) = host_wit();
    mutate(&mut resolve, pkg);
    let world = plugin_world(&resolve, pkg);
    synthesize(&resolve, world)
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir");
    for entry in std::fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file_type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy");
        }
    }
}

#[test]
fn prebuilt_example_components_are_accepted() {
    for (dir, artifact) in [
        ("hello-world", "hello_world.wasm"),
        ("simulated-switch", "simulated_switch.wasm"),
        ("event-recorder", "event_recorder.wasm"),
    ] {
        let wasm = std::fs::read(support::build_example(dir, artifact)).expect("read example");
        verify_component(&wasm).unwrap_or_else(|e| panic!("{dir} must be accepted: {e}"));
    }
}

/// One fixture per committed contract version: the host accepts the
/// versions it serves and refuses every other one.
#[test]
fn every_baseline_contract_version_is_classified() {
    let host_version = host_contract_version();
    let baselines = support::workspace_root().join("crates/oxidhome-wit/baselines");
    let mut saw_host_version = false;
    for entry in std::fs::read_dir(&baselines).expect("read baselines") {
        let path = entry.expect("entry").path();
        let Some(version) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("oxidhome-plugin@"))
            .and_then(|n| n.strip_suffix(".wit"))
            .map(str::to_owned)
        else {
            continue;
        };

        // The baseline omits `deps/`; lay it out next to a copy of
        // `wit/deps` so its WASI references resolve.
        let dir = support::tempdir(&format!("wit-contract-{version}"));
        std::fs::copy(&path, dir.path().join("oxidhome.wit")).expect("copy baseline");
        copy_dir(
            &support::workspace_root().join("wit/deps"),
            &dir.path().join("deps"),
        );
        let mut resolve = Resolve::default();
        let (pkg, _) = resolve.push_dir(dir.path()).expect("baseline parses");
        let wasm = synthesize(&resolve, plugin_world(&resolve, pkg));

        let result = verify_component(&wasm);
        let parsed: semver::Version = version.parse().expect("baseline version");
        let host: semver::Version = host_version.parse().expect("host version");
        let same_line = if host.major == 0 {
            parsed.major == 0 && parsed.minor == host.minor
        } else {
            parsed.major == host.major
        };
        if version == host_version {
            saw_host_version = true;
        }
        if same_line && parsed <= host {
            result.unwrap_or_else(|e| panic!("baseline {version} must be accepted: {e}"));
        } else {
            assert_eq!(
                result,
                Err(ContractError::VersionMismatch {
                    plugin: version.clone(),
                    host: host_version.clone(),
                }),
                "baseline {version}",
            );
        }
    }
    assert!(
        saw_host_version,
        "no baseline for the host's contract version {host_version} in {}",
        baselines.display(),
    );
}

#[test]
fn changed_signature_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        let iface = resolve.packages[pkg].interfaces["host-devices"];
        let func = resolve.interfaces[iface]
            .functions
            .get_mut("register-device")
            .expect("register-device");
        func.params[0].ty = Type::U32;
    });
    let err = verify_component(&wasm).expect_err("drifted signature");
    let ContractError::SignatureMismatch { item, plugin, host } = &err else {
        panic!("expected SignatureMismatch, got {err}");
    };
    assert_eq!(
        item,
        &format!(
            "oxidhome:plugin/host-devices@{}#register-device",
            host_contract_version()
        )
    );
    assert!(plugin.starts_with("func(info: u32)"), "{plugin}");
    assert!(host.starts_with("func(info: record {"), "{host}");
    let msg = err.to_string();
    assert!(msg.contains("plugin: ") && msg.contains("host: "), "{msg}");
}

#[test]
fn unknown_function_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        let iface = resolve.packages[pkg].interfaces["host-devices"];
        let functions = &mut resolve.interfaces[iface].functions;
        let mut extra = functions["register-device"].clone();
        extra.name = "register-device-v2".to_owned();
        functions.insert(extra.name.clone(), extra);
    });
    assert_eq!(
        verify_component(&wasm),
        Err(ContractError::UnknownFunction {
            interface: format!("oxidhome:plugin/host-devices@{}", host_contract_version()),
            function: "register-device-v2".to_owned(),
        })
    );
}

#[test]
fn missing_export_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        let world = plugin_world(resolve, pkg);
        resolve.worlds[world]
            .exports
            .retain(|key, _| *key != WorldKey::Name("tick".to_owned()));
    });
    assert_eq!(
        verify_component(&wasm),
        Err(ContractError::MissingExport {
            name: "tick".to_owned()
        })
    );
}

#[test]
fn changed_world_export_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        let world = plugin_world(resolve, pkg);
        let Some(wit_parser::WorldItem::Function(tick)) = resolve.worlds[world]
            .exports
            .get_mut(&WorldKey::Name("tick".to_owned()))
        else {
            panic!("plugin world exports tick");
        };
        tick.result = Some(Type::U32);
    });
    let err = verify_component(&wasm).expect_err("drifted export");
    assert!(
        matches!(&err, ContractError::SignatureMismatch { item, .. } if item == "tick"),
        "{err}"
    );
}

/// The decoder merges an interface the component both imports and
/// exports, which would hide one side's types from the check.
#[test]
fn interface_imported_and_exported_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        let id = resolve.packages[pkg].interfaces["host-config"];
        let world = plugin_world(resolve, pkg);
        resolve.worlds[world].exports.insert(
            WorldKey::Interface(id),
            wit_parser::WorldItem::Interface {
                id,
                stability: wit_parser::Stability::default(),
                external_id: None,
                docs: wit_parser::Docs::default(),
                span: wit_parser::Span::default(),
            },
        );
    });
    let err = verify_component(&wasm).expect_err("import + export of one interface");
    assert!(
        matches!(&err, ContractError::ImportedAndExported { interface } if interface.contains("host-config")),
        "{err}"
    );
}

#[test]
fn other_contract_version_is_refused() {
    let wasm = plugin_component(|resolve, pkg| {
        resolve.packages[pkg].name.version = Some("0.999.0".parse().unwrap());
    });
    assert_eq!(
        verify_component(&wasm),
        Err(ContractError::VersionMismatch {
            plugin: "0.999.0".to_owned(),
            host: host_contract_version(),
        })
    );
}

#[test]
fn component_without_contract_is_refused() {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str(
            "other.wit",
            "package other:thing; world w { export run: func(); }",
        )
        .expect("parse");
    let world = resolve.packages[pkg].worlds["w"];
    let err = verify_component(&synthesize(&resolve, world)).expect_err("no contract");
    assert!(matches!(err, ContractError::NoContract { .. }), "{err}");
}

/// End to end: the loader refuses a drifted component with the
/// contract error, before Wasmtime ever links it.
#[tokio::test(flavor = "current_thread")]
async fn loader_refuses_incompatible_component() {
    let wasm = plugin_component(|resolve, pkg| {
        let iface = resolve.packages[pkg].interfaces["host-devices"];
        let func = resolve.interfaces[iface]
            .functions
            .get_mut("register-device")
            .expect("register-device");
        func.params[0].ty = Type::U32;
    });
    let dir = support::tempdir("wit-contract-loader");
    std::fs::write(dir.path().join("plugin.wasm"), wasm).expect("write wasm");
    std::fs::write(
        dir.path().join("manifest.toml"),
        r#"manifest_version = 1
[plugin]
id = "example.drifted"
name = "Drifted"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "plugin.wasm"
"#,
    )
    .expect("write manifest");

    let engine = Engine::new().expect("engine");
    let Err(err) = PluginInstance::load(&engine, dir.path(), "drifted").await else {
        panic!("a component that drifted from the contract must be refused");
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("incompatible with this host's WIT contract"),
        "{msg}"
    );
    assert!(
        msg.contains("host-devices") && msg.contains("register-device"),
        "{msg}"
    );
}
