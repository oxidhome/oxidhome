//! Shared helpers for `oxidhome-core` integration tests.
//!
//! Each `tests/*.rs` file is its own crate, so `mod support;` pulls
//! this in per-test-binary; shared logic lives here so the `cargo
//! llvm-cov` env-scrub stays in one place.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Workspace root — derives from the test crate's
/// `CARGO_MANIFEST_DIR` (`<root>/crates/oxidhome-core`).
#[must_use]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Spawn a `cargo` invocation against `example_dir` with every
/// host-side coverage / target-dir env var removed. Local
/// `cargo test` runs are a no-op for the variables that aren't
/// set, so this is safe to use unconditionally; the value comes
/// from `cargo llvm-cov` runs where any of these would either:
///
/// - break the build (`RUSTFLAGS=-Cinstrument-coverage` ⇒
///   `wasm32-wasip2` has no `profiler_builtins`), or
/// - corrupt the host's coverage state (`CARGO_TARGET_DIR` ⇒
///   inner build writes into the host's coverage target dir).
///
/// `PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, and
/// `RUSTUP_TOOLCHAIN` are inherited so cargo can still locate its
/// registry, the toolchain, and the right rustc.
pub fn spawn_clean_cargo(example_dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(example_dir).args(args);
    for var in [
        // Coverage flags that propagate via the host's environment.
        // The killer is `RUSTC_WRAPPER`: cargo-llvm-cov installs
        // itself as the wrapper, and *that* is what injects
        // `-C instrument-coverage --cfg=coverage` into every rustc
        // invocation, including the inner `cargo build` for
        // `wasm32-wasip2`. Stripping `RUSTFLAGS` alone is not enough
        // — without also clearing the wrapper the wasm build still
        // gets instrumented and fails on the missing
        // `profiler_builtins`.
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_LLVM_COV_SHOW_ENV",
        "CARGO_LLVM_COV_TARGET_NAME",
        "LLVM_PROFILE_FILE",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Build a wasm32-wasip2 example through [`spawn_clean_cargo`] and
/// return the path to its `.wasm` artifact. Asserts the build
/// succeeded.
#[must_use]
pub fn build_example(dir: &str, artifact: &str) -> PathBuf {
    let example_dir = workspace_root().join("examples").join(dir);
    let status = spawn_clean_cargo(
        &example_dir,
        &["build", "--target", "wasm32-wasip2", "--locked"],
    )
    .status()
    .expect("invoking cargo build");
    assert!(status.success(), "{dir} build failed: {status}");
    example_dir
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join(artifact)
}
