//! Phase 3 plugin-side event-dispatch test.
//!
//! Confirms `PluginInstance::drain_events()` actually delivers
//! bus events to a plugin's `on-event` export, which is the
//! "host calls `on-event` on the subscriber" half of the Phase 3
//! plan from `.claude/docs/03_core.md`.
//!
//! Two plugins:
//!
//! - `simulated-switch` registers a `switch` device, takes a
//!   `switch::toggle` command, and publishes a `state-changed`
//!   event on every transition.
//! - `event-recorder` subscribes to every bus event during `init`
//!   and logs the topic + device id from `on-event`.
//!
//! The test wires them through one shared [`Engine`] (so they share
//! a [`DeviceRegistry`] + [`EventBus`]), drives a toggle on the
//! switch, calls `drain_events()` on the recorder, and asserts the
//! recorder emitted a log line that names the `switch` topic.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::Command as WitCommand;
use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::layer::SubscriberExt as _;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn build_example(dir: &str, artifact: &str) -> PathBuf {
    let example_dir = workspace_root().join("examples").join(dir);
    let status = Command::new("cargo")
        .args(["build", "--target", "wasm32-wasip2", "--locked"])
        .current_dir(&example_dir)
        .status()
        .expect("invoking cargo build");
    assert!(status.success(), "{dir} build failed: {status}");
    example_dir
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join(artifact)
}

#[derive(Clone, Default)]
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

#[tokio::test(flavor = "current_thread")]
async fn drain_events_dispatches_to_plugin_on_event() {
    let captured = CapturedWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_target(false)
            .without_time(),
    );
    let _guard = tracing::subscriber::set_default(subscriber);

    let switch_wasm = build_example("simulated-switch", "simulated_switch.wasm");
    let recorder_wasm = build_example("event-recorder", "event_recorder.wasm");

    let engine = Engine::new().expect("engine");

    let mut switch = PluginInstance::load(&engine, &switch_wasm)
        .await
        .expect("load simulated-switch");
    let mut recorder = PluginInstance::load(&engine, &recorder_wasm)
        .await
        .expect("load event-recorder");

    // `init` order matters: the recorder has to subscribe before the
    // switch publishes, otherwise broadcast::Receiver misses the
    // event. (The bus has no replay; that's Phase 5d's history
    // store.)
    recorder.init().await.expect("recorder init");
    switch.init().await.expect("switch init");

    let registry = engine.devices();
    let device_id = registry
        .list()
        .await
        .into_iter()
        .find(|m| m.owner_instance == switch.instance_id())
        .expect("switch registered a device")
        .id;

    // Toggle the switch — fires a state-changed event on the bus.
    switch
        .execute_command(
            device_id.clone(),
            WitCommand {
                capability: "switch".into(),
                action: "toggle".into(),
                args: Vec::new(),
            },
        )
        .await
        .expect("execute toggle");

    // Drain the recorder's pending subscription events. With the
    // switch already published, this should call recorder's
    // `on-event` exactly once.
    let delivered = recorder.drain_events().await.expect("drain recorder");
    assert_eq!(
        delivered, 1,
        "expected exactly one event delivered to recorder, got {delivered}"
    );

    // The recorder's `on_event` body logs `event-recorder received
    // event topic=… device=…`. Capture-buffer-side assertion: the
    // line for the switch toggle must be there.
    let output = String::from_utf8(captured.0.lock().unwrap().clone()).expect("utf-8 capture");
    assert!(
        output.contains("event-recorder received event"),
        "expected recorder log line, got:\n{output}"
    );
    // tracing's `%` (Display) formatter renders fields without
    // quotes; `?` (Debug) would quote them. Match the format we
    // actually emit.
    assert!(
        output.contains("topic=switch"),
        "expected `topic=switch` in recorder log line, got:\n{output}"
    );
    assert!(
        output.contains(&format!("device={device_id}")),
        "expected `device={device_id}` in recorder log line, got:\n{output}"
    );

    // Recorder should have nothing left to drain — calling again
    // returns 0.
    let delivered_again = recorder.drain_events().await.expect("drain recorder again");
    assert_eq!(delivered_again, 0, "no events expected on second drain");

    switch.shutdown().await.expect("switch shutdown");
    recorder.shutdown().await.expect("recorder shutdown");
}
