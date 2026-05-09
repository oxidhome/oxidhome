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

#[path = "support.rs"]
mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::layer::SubscriberExt as _;

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

// `flavor = "current_thread"` because the test installs a thread-local
// `tracing::subscriber::set_default` to capture log output. The default
// multi-thread runtime would poll the future on a worker thread that
// doesn't carry the subscriber, dropping the captured lines and making
// the test flaky.
#[tokio::test(flavor = "current_thread")]
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

    let wasm_path: PathBuf = support::build_example("hello-world", "hello_world.wasm");
    assert!(wasm_path.is_file(), "missing build artifact: {wasm_path:?}");

    let engine = Engine::new().expect("engine");
    let mut instance = PluginInstance::load(&engine, &wasm_path)
        .await
        .expect("loaded hello-world");

    instance.init().await.expect("init");
    instance.shutdown().await.expect("shutdown");

    // tracing-subscriber's fmt layer writes to the configured writer
    // synchronously per event, so by the time `init`/`shutdown` return,
    // the captured buffer already holds both lines — no flush needed.
    let output = String::from_utf8(captured.lock().expect("capture lock").clone())
        .expect("captured bytes are utf-8");

    // Match the message position specifically: tracing's fmt layer
    // renders `<span>: <message> <fields...>`, so `: hello ` is unique
    // to the init line. A bare `output.contains("hello")` would match
    // the `instance_id="hello_world"` field on either line and miss a
    // missing init message.
    let hello_at = output.find(": hello ").unwrap_or_else(|| {
        panic!("expected init message `: hello ` in captured output, got:\n{output}")
    });
    let bye_at = output.find(": bye ").unwrap_or_else(|| {
        panic!("expected shutdown message `: bye ` in captured output, got:\n{output}")
    });
    // Lifecycle sequencing: `hello` (init) must precede `bye`
    // (shutdown). If the host accidentally wired init/shutdown
    // backwards, both substrings would still be present, so the
    // ordering check is what makes the test fail loudly.
    assert!(
        hello_at < bye_at,
        "expected init `hello` (at {hello_at}) to precede shutdown `bye` (at {bye_at}), got:\n{output}"
    );
    assert!(
        output.contains("instance_id=\"hello_world\""),
        "expected the instance_id field on the log records, got:\n{output}"
    );
}
