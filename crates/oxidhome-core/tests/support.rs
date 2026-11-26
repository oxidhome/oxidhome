//! Shared helpers for `oxidhome-core` integration tests.
//!
//! Each `tests/*.rs` file is its own crate, so `mod support;` pulls
//! this in per-test-binary; shared logic lives here so the `cargo
//! llvm-cov` env-scrub stays in one place.

#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

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

/// A self-deleting temp directory for integration tests. Each
/// `tests/*.rs` is its own crate, so this lives here instead of being
/// copy-pasted per test file.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Absolute path of the directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a fresh temp directory under the system temp dir, named
/// `oxidhome-<prefix>-<pid>-<nanos>` so concurrent test binaries
/// don't collide. Removed on drop.
#[must_use]
pub fn tempdir(prefix: &str) -> TempDir {
    let name = format!(
        "oxidhome-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}

/// Stage a plugin install dir in a fresh tempdir: copy `wasm_src` in
/// as `wasm_name` and write `manifest` as `manifest.toml`. The
/// manifest's `runtime.wasm` should be the bare `wasm_name`. Lets a
/// test vary `[runtime]` knobs (e.g. `tick_interval_ms`) without a
/// committed fixture per scenario.
#[must_use]
pub fn stage_plugin(prefix: &str, wasm_src: &Path, wasm_name: &str, manifest: &str) -> TempDir {
    let dir = tempdir(prefix);
    std::fs::copy(wasm_src, dir.path().join(wasm_name)).expect("copy staged wasm");
    std::fs::write(dir.path().join("manifest.toml"), manifest).expect("write staged manifest");
    dir
}

/// Build a wasm32-wasip2 example through [`spawn_clean_cargo`] and
/// return the path to its `.wasm` artifact. Asserts the build
/// succeeded.
#[must_use]
pub fn build_example(dir: &str, artifact: &str) -> PathBuf {
    static BUILT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let example_dir = workspace_root().join("examples").join(dir);
    // Held across the build: concurrent tests in one binary wait for
    // the first build instead of relinking under each other.
    let mut built = BUILT
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !built.contains(dir) {
        build_once_per_run(&example_dir, || {
            let status = spawn_clean_cargo(
                &example_dir,
                &["build", "--target", "wasm32-wasip2", "--locked"],
            )
            .status()
            .expect("invoking cargo build");
            assert!(status.success(), "{dir} build failed: {status}");
        });
        built.insert(dir.to_owned());
    }
    example_dir
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join(artifact)
}

/// Run `build` for `example_dir` at most once per test run, across
/// processes and test crates.
///
/// cargo replaces an example's uplifted `.wasm` (unlink + relink) on
/// every `cargo build`, even a no-op one. nextest runs each test in
/// its own process, so one test rebuilding an example could briefly
/// remove the artifact another test was loading. An exclusive lock
/// on `<example>/target/.oxidhome-test-build.lock` serializes builds,
/// and a stamp keyed on `NEXTEST_RUN_ID` skips cargo after the run's
/// first build. Without nextest (plain `cargo test`, one process per
/// test binary) the caller's in-process memo covers the same case.
fn build_once_per_run(example_dir: &Path, build: impl FnOnce()) {
    let target = example_dir.join("target");
    std::fs::create_dir_all(&target).expect("create example target dir");
    let lock = std::fs::File::create(target.join(".oxidhome-test-build.lock"))
        .expect("open example build lock");
    lock.lock().expect("lock example build");
    let stamp = std::env::var("NEXTEST_RUN_ID")
        .ok()
        .map(|run| target.join(format!(".oxidhome-test-built-{run}")));
    if stamp.as_ref().is_some_and(|s| s.exists()) {
        return;
    }
    build();
    if let Some(stamp) = stamp {
        // Drop stamps of earlier runs, then mark this one.
        if let Ok(entries) = std::fs::read_dir(&target) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".oxidhome-test-built-")
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        std::fs::write(&stamp, b"").expect("write build stamp");
    }
}

/// Mint test tokens from a list of action names.
pub trait Mint {
    /// A token labelled `label` allowed `actions` (`*` for every role
    /// action, sensitive categories excluded): a fresh custom role
    /// granting exactly those, or no role at all for `[]`.
    ///
    /// # Errors
    ///
    /// The store's.
    fn mint(
        &self,
        label: &str,
        actions: &[&str],
    ) -> Result<oxidhome_core::state::IssuedToken, oxidhome_core::state::TokenError>;
}

impl Mint for oxidhome_core::state::TokenStore {
    fn mint(
        &self,
        label: &str,
        actions: &[&str],
    ) -> Result<oxidhome_core::state::IssuedToken, oxidhome_core::state::TokenError> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if actions.is_empty() {
            return self.create(label, &[] as &[&str]);
        }
        let name = format!(
            "t{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let grants = serde_json::json!([{ "actions": actions }]).to_string();
        self.create_role(&name, grants.as_bytes())
            .expect("test role");
        self.create(label, &[name])
    }
}
