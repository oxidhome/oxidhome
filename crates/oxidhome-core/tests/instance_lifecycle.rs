//! Phase 6b — per-instance supervisor task.
//!
//! Exercises `supervise()` end-to-end: the spawned task loads + inits
//! the plugin, serves `execute-command` through the `InstanceHandle`,
//! ticks on the manifest cadence, drains bus events via its `select!`
//! wakeup arm, and stops cleanly.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
    CustomEvent, Event, EventPayload,
};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::{Engine, InstanceHandle, InstanceState, supervise};

/// kv-counter manifest without a tick cadence — the lifecycle tick
/// stays off so command-driven count assertions aren't racy.
const KV_COUNTER_NO_TICK: &str = r#"manifest_version = 1
[plugin]
id = "example.kv-counter"
name = "KV Counter"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "kv_counter.wasm"
[capabilities]
storage_quota_kb = 4
"#;

/// kv-counter manifest with a fast tick so the supervisor's interval
/// drives the counter without a slow test.
const KV_COUNTER_FAST_TICK: &str = r#"manifest_version = 1
[plugin]
id = "example.kv-counter"
name = "KV Counter"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "kv_counter.wasm"
tick_interval_ms = 10
[capabilities]
storage_quota_kb = 4
"#;

/// The supervisor serves `execute-command` through the handle and
/// stops cleanly on `stop()`.
#[tokio::test(flavor = "multi_thread")]
async fn supervisor_executes_commands_and_stops() {
    let wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let plugin = support::stage_plugin("sup-cmd", &wasm, "kv_counter.wasm", KV_COUNTER_NO_TICK);
    let state_dir = support::tempdir("sup-cmd-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");

    let handle = supervise(engine, plugin.path().to_path_buf(), "kv_counter", None);
    handle.wait_for_running().await.expect("reach Running");

    assert_eq!(read_count(&handle, "counter", "read").await, 0);
    assert_eq!(read_count(&handle, "counter", "tick").await, 1);
    assert_eq!(read_count(&handle, "counter", "read").await, 1);

    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);
}

/// The supervisor's `tokio::time::interval` drives the plugin's
/// lifecycle `tick()` — the kv-counter climbs without any command.
#[tokio::test(flavor = "multi_thread")]
async fn supervisor_ticks_on_manifest_cadence() {
    let wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let plugin = support::stage_plugin("sup-tick", &wasm, "kv_counter.wasm", KV_COUNTER_FAST_TICK);
    let state_dir = support::tempdir("sup-tick-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");

    let handle = supervise(engine, plugin.path().to_path_buf(), "kv_counter", None);
    handle.wait_for_running().await.expect("reach Running");

    let count = poll_count_until(&handle, "counter", "read", 3).await;
    assert!(
        count >= 3,
        "expected the tick interval to reach >=3, got {count}"
    );

    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);
}

/// A bus event published after the instance is Running wakes the
/// supervisor's `select!` arm, which drains it into the plugin's
/// `on-event`. The recorder counts deliveries; the count is readable
/// through the handle.
#[tokio::test(flavor = "multi_thread")]
async fn supervisor_delivers_bus_events() {
    let _wasm = support::build_example("event-recorder", "event_recorder.wasm");
    let recorder_dir = support::workspace_root()
        .join("examples")
        .join("event-recorder");
    let engine = Engine::new().expect("engine");

    let handle = supervise(engine.clone(), recorder_dir, "event_recorder", None);
    // Running ⇒ `init` finished ⇒ the recorder has subscribed.
    handle.wait_for_running().await.expect("reach Running");

    for topic in ["automation.morning", "automation.evening"] {
        engine.events().publish(Event {
            device: None,
            timestamp: 0,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: String::new(),
            }),
        });
    }

    // The publish wakes the supervisor; poll until both deliveries
    // land (the wakeup and the count command race in the `select!`).
    let count = poll_count_until(&handle, "recorder", "count", 2).await;
    assert_eq!(count, 2, "expected both events delivered to on-event");

    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);
}

/// Run a command through the handle and pull its `count` field.
async fn read_count(handle: &InstanceHandle, capability: &str, action: &str) -> i64 {
    let result = handle
        .execute_command(
            "no-device".into(),
            Command {
                capability: capability.into(),
                action: action.into(),
                args: Vec::new(),
            },
        )
        .await
        .expect("command through handle");
    let fields = match result {
        CommandResult::OkWithState(fields) => fields,
        other => panic!("expected OkWithState, got {other:?}"),
    };
    match fields
        .iter()
        .find(|kv| kv.key == "count")
        .map(|kv| &kv.value)
    {
        Some(Value::IntVal(n)) => *n,
        other => panic!("expected an IntVal `count` field, got {other:?}"),
    }
}

/// Poll `read_count` until it reaches `want` or a 10s deadline.
async fn poll_count_until(handle: &InstanceHandle, cap: &str, action: &str, want: i64) -> i64 {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let count = read_count(handle, cap, action).await;
        if count >= want || std::time::Instant::now() >= deadline {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
