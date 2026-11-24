//! Shared helpers for the `oxidhome-test-host` integration tests:
//! build an example plugin for `wasm32-wasip2` and stage it in a temp
//! directory with an (optionally edited) manifest.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Workspace root, from this crate's `CARGO_MANIFEST_DIR`
/// (`<root>/crates/oxidhome-test-host`).
#[must_use]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Example plugins the tests use: `(directory, wasm artifact)`.
pub const SIMULATED_SWITCH: (&str, &str) = ("simulated-switch", "simulated_switch.wasm");
pub const KV_COUNTER: (&str, &str) = ("kv-counter", "kv_counter.wasm");
pub const EVENT_RECORDER: (&str, &str) = ("event-recorder", "event_recorder.wasm");
pub const HELLO_WORLD: (&str, &str) = ("hello-world", "hello_world.wasm");
pub const SERVICE_COUNTER: (&str, &str) = ("service-counter", "service_counter.wasm");
pub const SERVICE_CALLER: (&str, &str) = ("service-caller", "service_caller.wasm");
pub const SERVICE_BOUNCER: (&str, &str) = ("service-bouncer", "service_bouncer.wasm");
pub const SNAPSHOT_SAVER: (&str, &str) = ("snapshot-saver", "snapshot_saver.wasm");
pub const CRASHER: (&str, &str) = ("crasher", "crasher.wasm");
pub const HANG: (&str, &str) = ("hang", "hang.wasm");
pub const DEFERRED_SWITCH: (&str, &str) = ("deferred-switch", "deferred_switch.wasm");
pub const SCRIPT_HOST: (&str, &str) = ("script-host", "script_host.wasm");
pub const NET_PROBE: (&str, &str) = ("net-probe", "net_probe.wasm");
pub const NETWORK_DISCOVERY: (&str, &str) = ("network-discovery", "network_discovery.wasm");
pub const CLOCK_PROBE: (&str, &str) = ("clock-probe", "clock_probe.wasm");

/// Build `examples/<dir>` for `wasm32-wasip2` (once per test binary)
/// and return the artifact path.
///
/// The child `cargo` runs with the coverage / target-dir variables
/// `cargo llvm-cov` sets removed — same list and reasoning as
/// `crates/oxidhome-core/tests/support.rs::spawn_clean_cargo`: an
/// instrumented wasm build fails on the missing `profiler_builtins`.
#[must_use]
pub fn build_example((dir, artifact): (&str, &str)) -> PathBuf {
    static BUILT: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    let built = BUILT.get_or_init(Mutex::default);
    // Held across the build: concurrent tests in one binary wait for
    // the first build instead of all racing for cargo's lock.
    let mut built = built
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(path) = built.get(dir) {
        return path.clone();
    }
    let example_dir = workspace_root().join("examples").join(dir);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&example_dir)
        .args(["build", "--target", "wasm32-wasip2", "--locked"]);
    for var in [
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
    build_once_per_run(&example_dir, || {
        let status = cmd.status().expect("invoking cargo build");
        assert!(status.success(), "{dir} build failed: {status}");
    });
    let path = example_dir
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join(artifact);
    assert!(path.is_file(), "missing build artifact: {}", path.display());
    built.insert(dir.to_owned(), path.clone());
    path
}

/// A self-deleting temp directory.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "oxidhome-th-{prefix}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

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

/// Stage `example` in a fresh directory: the built component as
/// `plugin.wasm`, and the example's `manifest.toml` with
/// `[runtime] wasm` pointed at it and `edit_caps` applied to its
/// `[capabilities]` table. A staged directory is self-contained, so
/// the production backend can install it as-is.
#[must_use]
pub fn stage(example: (&str, &str), edit_caps: impl FnOnce(&mut toml::Table)) -> TempDir {
    stage_with(example, |manifest| {
        let caps = manifest
            .entry("capabilities")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("[capabilities] table");
        edit_caps(caps);
    })
}

/// [`stage`] with `edit` applied to the whole manifest (after
/// `[runtime] wasm` is rewritten), e.g. to change `[plugin] world`.
#[must_use]
pub fn stage_with(example: (&str, &str), edit: impl FnOnce(&mut toml::Table)) -> TempDir {
    let wasm = build_example(example);
    let dir = TempDir::new(example.0);
    std::fs::copy(&wasm, dir.path().join("plugin.wasm")).expect("copy wasm");
    let manifest_src = workspace_root()
        .join("examples")
        .join(example.0)
        .join("manifest.toml");
    let text = std::fs::read_to_string(manifest_src).expect("read example manifest");
    let mut manifest: toml::Table = toml::from_str(&text).expect("parse example manifest");
    manifest
        .get_mut("runtime")
        .and_then(toml::Value::as_table_mut)
        .expect("[runtime] table")
        .insert("wasm".into(), toml::Value::String("plugin.wasm".into()));
    edit(&mut manifest);
    std::fs::write(
        dir.path().join("manifest.toml"),
        toml::to_string(&manifest).expect("serialize manifest"),
    )
    .expect("write staged manifest");
    dir
}

/// [`stage`] with the example's manifest unchanged.
#[must_use]
pub fn stage_unchanged(example: (&str, &str)) -> TempDir {
    stage(example, |_| {})
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
