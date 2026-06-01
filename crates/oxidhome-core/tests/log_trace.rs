//! Phase 5c end-to-end log-capture test.
//!
//! Drives the `simulated-switch` example through one host lifetime
//! against a `<state_dir>`, with the `Engine`'s log-store layer
//! composed into a thread-local subscriber for the duration of the
//! test. The plugin emits three `tracing::info!` lines via its WIT
//! `logging` import (`simulated-switch ready` on init, `switch state
//! changed` on toggle, `simulated-switch stopped` on shutdown); the
//! host forwards each through its `logging::Host` impl as
//! `tracing::info!(instance_id, "{message}")`. After the test scope
//! ends we drain the writer thread, query the persisted
//! `log_event` table, and assert the three messages landed with the
//! right `instance_id` attribution and `plugin.*` span paths.
//!
//! Coverage matrix:
//!
//! - `state::log_store::tests::*` cover the layer/store mechanics in
//!   isolation (span chains, field types, drop counter, retention,
//!   reopen).
//! - This file is the integration smoke test that the wiring from
//!   guest `tracing` → WIT `logging::log` → host
//!   `tracing::info!(instance_id, ...)` → `SqliteLayer::on_event` →
//!   writer thread → `<state_dir>/oxidhome.db`'s `log_event` table
//!   actually closes the loop.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::state::{LogLevel, LogQuery};
use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::layer::SubscriberExt as _;

#[tokio::test(flavor = "current_thread")]
async fn plugin_logs_survive_host_restart() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let state_dir = tempdir();

    let device_id: String;
    let instance_id: String;

    {
        let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
        // Compose the store's layer into a thread-local subscriber.
        // `current_thread` tokio + `set_default` is the same shape the
        // other integration tests use — every host call below polls on
        // this thread, so this subscriber sees every event the host
        // emits during the test scope.
        let layer = engine.log_store().layer();
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut instance = PluginInstance::load(&engine, &plugin_dir, "switch_log")
            .await
            .expect("load");
        instance.init().await.expect("init");

        instance_id = instance.instance_id().to_owned();
        let meta = engine
            .devices()
            .list()
            .into_iter()
            .find(|m| m.owner_instance == instance_id)
            .expect("switch registered one device");
        device_id = meta.id.clone();

        // Toggle to drive the `switch state changed` log line.
        let result = instance
            .execute_command(
                device_id.clone(),
                Command {
                    capability: "switch".into(),
                    action: "toggle".into(),
                    args: Vec::new(),
                },
            )
            .await
            .expect("toggle");
        assert!(matches!(result, CommandResult::OkWithState(_)));

        instance.shutdown().await.expect("shutdown");

        // Drain the writer thread before we drop the subscriber.
        // Ownership: the writer owns the channel *receiver*; the
        // senders live on `LogStore` + every `SqliteLayer` clone the
        // subscriber holds. When `_guard` falls out of scope the
        // subscriber drops, dropping its Layer (and thus that
        // sender). Rows already in the channel still land on
        // `<state_dir>/oxidhome.db` because the writer drains them
        // out before its `recv` returns `Err` — draining here just
        // makes the assertions below deterministic without
        // additional polling.
        engine.log_store().wait_drained_for_test();
    }

    // Reopen the engine against the same `<state_dir>` — Phase-5a/5d
    // restart pattern. The log writer thread for the new Engine
    // starts fresh; we're just reading what the previous one
    // committed.
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine 2");
    let log = engine.log_store();

    let rows = log
        .query(
            &LogQuery {
                instance_id: Some(instance_id.clone()),
                min_level: Some(LogLevel::Info),
                ..LogQuery::default()
            },
            64,
        )
        .expect("query");

    // The plugin emits three info-level messages via the WIT logging
    // import; each lands as a `tracing::info!` on the host with
    // `instance_id` attached. Earlier-recorded "info" calls from the
    // logging::init bridge can land too — assert by presence of the
    // three known messages rather than an exact count.
    let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("simulated-switch ready")),
        "expected `simulated-switch ready` in host log lines; got {messages:?}",
    );
    assert!(
        messages.iter().any(|m| m.contains("switch state changed")),
        "expected `switch state changed` after toggle; got {messages:?}",
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("simulated-switch stopped")),
        "expected `simulated-switch stopped` after shutdown; got {messages:?}",
    );

    // Spot-check the span attribution: the `simulated-switch ready`
    // message fires under the `plugin.init` host span, so its
    // `span_path` should start with `plugin.init`.
    let ready = rows
        .iter()
        .find(|r| r.message.contains("simulated-switch ready"))
        .expect("ready row");
    assert_eq!(
        ready.span_path.as_deref(),
        Some("plugin.init"),
        "ready message should be attributed to the plugin.init span",
    );
    // The host's `logging::Host::log` impl emits the event with an
    // explicit `instance_id` field, so the layer's
    // "event-overrides-span" rule means a non-null `instance_id` on
    // the row only proves the *event* carried it — it doesn't prove
    // anything about span-chain attribution. `plugin_id` is the
    // load-bearing check: nothing in the host's logging impl emits
    // it, so the only way it can land on the row is via the
    // `plugin.init` span's recorded field. If that pipe is broken
    // (e.g. `instance.rs` stops adding `plugin_id` to the span), the
    // row would land with `plugin_id: None` and this assertion fires.
    assert_eq!(
        ready.plugin_id.as_deref(),
        Some("example.simulated-switch"),
        "ready message should pick up `plugin_id` from the plugin.init span chain",
    );
    // Belt-and-suspenders: `instance_id` matches the host's emit, but
    // doesn't *prove* the span-chain pipe works on its own.
    assert_eq!(ready.instance_id.as_deref(), Some(instance_id.as_str()));
}

// ── tempdir helper ──────────────────────────────────────────────────

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
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn tempdir() -> TempDir {
    let base = std::env::temp_dir();
    let name = format!(
        "oxidhome-log-trace-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}
