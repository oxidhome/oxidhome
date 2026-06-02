//! Phase 5d end-to-end persistence test.
//!
//! Drives the `simulated-switch` example through one host lifetime
//! against a `<state_dir>`, toggles the switch (which publishes a
//! `state-changed` event), drops the [`Engine`], reopens against the
//! same dir, and queries `event_log`. The state-change must still be
//! there — closes the Phase 5d definition-of-done.
//!
//! Coverage matrix:
//!
//! - `counter_persists_across_host_restart` (in `storage_persistence.rs`)
//!   covers the KV side of the same pattern; this test exercises the
//!   parallel durable layer for events.
//! - `EventLog::query` filtering and `trim_older_than` are exercised
//!   by the lib unit tests in `state::event_log::tests` — this file
//!   is just the integration smoke test that the wiring from
//!   `host_impl::events::publish_event` → `EventLog::record` →
//!   `<state_dir>/oxidhome.db` actually closes the loop.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::EventPayload;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::state::EventQuery;
use oxidhome_core::{Engine, PluginInstance};

/// Toggle the switch once → drop engine → reopen → query → assert.
#[tokio::test(flavor = "current_thread")]
async fn state_changed_event_survives_host_restart() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let state_dir = tempdir();

    let device_id: String;
    let plugin_id: String;
    let instance_id: String;

    // Round 1 — publish
    {
        let engine = Engine::with_state_dir(state_dir.path()).expect("engine 1");
        let mut instance = PluginInstance::load(&engine, &plugin_dir, "switch_history")
            .await
            .expect("load 1");
        instance.init().await.expect("init 1");

        instance_id = instance.instance_id().to_owned();
        let dev_meta = engine
            .devices()
            .list()
            .into_iter()
            .find(|m| m.owner_instance == instance_id)
            .expect("switch registered one device");
        device_id = dev_meta.id.clone();

        // Pull the plugin_id from the *manifest* file itself rather
        // than the PluginInstance (which doesn't expose the manifest
        // today). Keeping it inline here as a string would couple the
        // test to the example's manifest.toml — read it instead.
        let manifest_text =
            std::fs::read_to_string(plugin_dir.join("manifest.toml")).expect("read manifest");
        plugin_id = manifest_text
            .lines()
            .find_map(|l| {
                let l = l.trim();
                l.strip_prefix("id = \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .map(str::to_owned)
            })
            .expect("manifest declares plugin.id");

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

        instance.shutdown().await.expect("shutdown 1");
    }

    // Round 2 — read history from a fresh engine pointed at the same
    // SQLite file. No plugin reload required — the read path is
    // host-side.
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine 2");
    let log = engine.event_log();
    let rows = log
        .query(&EventQuery::default(), 16)
        .expect("query event_log");

    assert!(
        !rows.is_empty(),
        "event_log should hold at least one event after toggle",
    );

    // Find the state-changed event for the toggled device.
    let state_change = rows
        .iter()
        .find(|r| {
            r.device_id.as_deref() == Some(device_id.as_str())
                && matches!(r.payload, EventPayload::StateChanged(_))
        })
        .expect("state-changed event for the toggled device must be in history");

    assert_eq!(state_change.instance_id, instance_id);
    assert_eq!(state_change.plugin_id, plugin_id);
    assert_eq!(state_change.topic, "switch");

    let EventPayload::StateChanged(sc) = &state_change.payload else {
        unreachable!("matched above")
    };
    assert_eq!(sc.capability, "switch");
    let state_field = sc
        .fields
        .iter()
        .find(|kv| kv.key == "state")
        .expect("state field");
    assert!(
        matches!(state_field.value, Value::BoolVal(true)),
        "first toggle should flip state to true, got {:?}",
        state_field.value,
    );
}

// ── tempdir helper ──────────────────────────────────────────────────
//
// Same shape as `tests/storage_persistence.rs` — kept local so the
// test crate doesn't pick up an external dep.

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
        "oxidhome-event-history-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}
