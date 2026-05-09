//! Phase 2 end-to-end test.
//!
//! Builds the `examples/hello-world` plugin for `wasm32-wasip2`,
//! instantiates it through [`oxidhome_core::PluginInstance`], runs
//! `init` → `shutdown`, and asserts both log lines made it through the
//! `tracing` ↔ host `logging` import bridge.
//!
//! The example lives in a separate Cargo workspace under `examples/`
//! so the host build doesn't drag wasm targets through its graph; the
//! test invokes `cargo build` against that workspace and resolves the
//! `.wasm` artifact at a stable path. Slow on a cold cache, fast on a
//! warm one — same trade-off the Phase 4 examples doc accepts
//! (`.claude/docs/04_examples.md`).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::layer::SubscriberExt as _;

/// Workspace root of the `OxidHome` repo, derived from the test's own
/// `CARGO_MANIFEST_DIR`. The example workspace lives at
/// `<workspace>/examples/hello-world/`.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/oxidhome-core has a workspace root")
        .to_path_buf()
}

/// Builds `examples/hello-world` for `wasm32-wasip2` and returns the
/// resulting component path. Uses the example's own `target/`
/// directory — separate from the host's, since the workspaces are
/// distinct.
fn build_hello_world() -> PathBuf {
    let example_dir = workspace_root().join("examples").join("hello-world");
    let status = Command::new("cargo")
        .args(["build", "--target", "wasm32-wasip2"])
        .current_dir(&example_dir)
        .status()
        .expect("invoking cargo build for hello-world");
    assert!(status.success(), "hello-world build failed: {status}");
    example_dir
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join("hello_world.wasm")
}

/// `tracing` writer adapter that captures every line emitted by the
/// fmt layer into a shared buffer. The test inspects the buffer after
/// `init`/`shutdown` to confirm both log lines made the round-trip.
#[derive(Clone)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl std::io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("writer lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn hello_world_round_trip() {
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = CapturedWriter(captured.clone());

    // Local subscriber — `_guard` lives for the duration of the test
    // and the subscriber drops itself afterward, so we don't poison
    // the global slot for parallel tests.
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(false)
            .without_time(),
    );
    let _guard = tracing::subscriber::set_default(subscriber);

    let wasm_path = build_hello_world();
    assert!(wasm_path.is_file(), "missing build artifact: {wasm_path:?}");

    let engine = Engine::new().expect("engine");
    let mut instance = PluginInstance::load(&engine, &wasm_path)
        .await
        .expect("loaded hello-world");

    instance.init().await.expect("init");
    instance.shutdown().await.expect("shutdown");

    // Flush any buffered fmt layer writes.
    let _ = std::io::stdout().flush();

    let output = String::from_utf8(captured.lock().expect("capture lock").clone())
        .expect("captured bytes are utf-8");

    assert!(
        output.contains("hello"),
        "expected `hello` in captured output, got:\n{output}"
    );
    assert!(
        output.contains("bye"),
        "expected `bye` in captured output, got:\n{output}"
    );
    assert!(
        output.contains("instance_id=\"hello_world\""),
        "expected the instance_id field on the log records, got:\n{output}"
    );
}
