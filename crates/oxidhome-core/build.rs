//! Bakes the host's `oxidhome:plugin` WIT contract into the binary.
//!
//! `wit/` (workspace root) is parsed with `wit-parser` and re-encoded
//! as a binary WIT package with `wit-component`. The loader decodes
//! that package once at runtime and compares every plugin component's
//! embedded types against it (`runtime::contract`). Shipping the
//! encoded package rather than reading `wit/` at runtime keeps the
//! host binary self-contained.

use std::path::PathBuf;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let wit_dir = manifest_dir.join("../../wit");
    println!("cargo:rerun-if-changed={}", wit_dir.display());

    let mut resolve = wit_parser::Resolve::default();
    let (pkg, sources) = resolve
        .push_dir(&wit_dir)
        .unwrap_or_else(|e| panic!("parsing {}: {e:?}", wit_dir.display()));
    for path in sources.paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    // `false`: keep full-version interface names (e.g. `@0.1.0`), matching
    // what `wit-bindgen` embeds in guests; canonical `@0.1` names are opt-in.
    let encoded = wit_component::encode(&resolve, pkg, false)
        .unwrap_or_else(|e| panic!("encoding the oxidhome:plugin WIT package: {e:?}"));

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets it"))
        .join("oxidhome-plugin-contract.wasm");
    std::fs::write(&out, encoded).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
