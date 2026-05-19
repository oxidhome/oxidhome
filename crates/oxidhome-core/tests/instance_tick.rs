//! Phase 6a — lifecycle `tick()` wrapper.
//!
//! Drives `PluginInstance::tick()` directly (the Phase-6 supervisor
//! that schedules it lands in 6b). The `kv-counter` example's
//! lifecycle `tick()` hook increments its persisted counter, so N
//! ticks must read back as N. Also checks the `manifest()` accessor
//! the supervisor will read its cadence + restart policy off.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::{Engine, PluginInstance};
use oxidhome_manifest::RestartPolicy;

/// Three `tick()` calls → drop the engine → reopen against the same
/// state dir → `counter::read` reads back 3.
#[tokio::test(flavor = "current_thread")]
async fn lifecycle_tick_increments_persistent_counter() {
    let _wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("kv-counter");

    let state_dir = tempdir();

    // Round 1 — tick three times through the lifecycle hook.
    {
        let engine = Engine::with_state_dir(state_dir.path()).expect("engine 1");
        let mut instance = PluginInstance::load(&engine, &plugin_dir, "kv_counter")
            .await
            .expect("load 1");

        // The supervisor reads these off `manifest()` in 6b.
        assert_eq!(instance.manifest().runtime.tick_interval_ms, Some(1000));
        assert_eq!(instance.manifest().runtime.restart, RestartPolicy::OnTrap);

        instance.init().await.expect("init 1");
        for _ in 0..3 {
            instance.tick().await.expect("tick");
        }
        instance.shutdown().await.expect("shutdown 1");
    }

    // Round 2 — fresh engine on the same SQLite file; `init` reloads
    // the persisted count, `counter::read` surfaces it.
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine 2");
    let mut instance = PluginInstance::load(&engine, &plugin_dir, "kv_counter")
        .await
        .expect("load 2");
    instance.init().await.expect("init 2");
    let result = instance
        .execute_command(
            "no-device".into(),
            Command {
                capability: "counter".into(),
                action: "read".into(),
                args: Vec::new(),
            },
        )
        .await
        .expect("read");
    let fields = match result {
        CommandResult::OkWithState(fields) => fields,
        other => panic!("expected OkWithState from read, got {other:?}"),
    };
    let count = fields
        .iter()
        .find(|kv| kv.key == "count")
        .map(|kv| kv.value.clone())
        .expect("count field present");
    assert!(
        matches!(count, Value::IntVal(3)),
        "expected count=3 after three ticks, got {count:?}",
    );

    instance.shutdown().await.expect("shutdown 2");
}

// ── tempdir helper (same shape as the other test crates) ───────────

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
        "oxidhome-tick-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}
