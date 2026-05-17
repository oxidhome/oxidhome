//! Phase 5a end-to-end persistence test.
//!
//! Drives the `kv-counter` example through two host lifetimes
//! against the same `<state_dir>` and asserts the counter survives.
//! This is the Definition-of-Done line from `03_core.md` §5a:
//! *"example plugin writes a value, restart the host, reads it
//! back."*
//!
//! Round 1: `init` → three `counter::tick` commands (final count =
//! 3) → `shutdown` → drop the [`Engine`] and the [`PluginInstance`].
//!
//! Round 2: a *fresh* [`Engine::with_state_dir`] points at the same
//! tempdir → `init` (reads the persisted value back) → `counter::read`
//! → assert the returned `count` is 3.
//!
//! The second test (`storage_off_surfaces_through_init`) loads the
//! same `kv-counter` wasm against a tempdir manifest with an empty
//! `[capabilities]` block — storage gated off — and confirms the
//! `permission-denied` from `host::storage::get` lands as the guest's
//! `init` Result.
//!
//! Quota-exceeded shape is covered in the lib unit tests on the
//! `storage::Host` impl (`storage_quota_exceeded_returns_permission_denied`)
//! — exercising the same WIT mapping that this end-to-end test
//! validates structurally.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::{Engine, PluginInstance};

/// Three increments → drop engine → reopen against the same state
/// dir → counter reads back as 3.
#[tokio::test(flavor = "current_thread")]
async fn counter_persists_across_host_restart() {
    let _wasm = support::build_example("kv-counter", "kv_counter.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("kv-counter");

    let state_dir = tempdir();

    // Round 1 — write
    {
        let engine = Engine::with_state_dir(state_dir.path()).expect("engine 1");
        let mut instance = PluginInstance::load(&engine, &plugin_dir, "kv_counter")
            .await
            .expect("load 1");
        instance.init().await.expect("init 1");
        for _ in 0..3 {
            let result = instance
                .execute_command(
                    // No device — the example deliberately doesn't
                    // register one. The execute-command routing path
                    // still works (the host doesn't gate on device
                    // existence for unregistered devices yet).
                    "no-device".into(),
                    Command {
                        capability: "counter".into(),
                        action: "tick".into(),
                        args: Vec::new(),
                    },
                )
                .await
                .expect("tick");
            assert!(
                matches!(result, CommandResult::OkWithState(_)),
                "tick should return OkWithState, got {result:?}",
            );
        }
        instance.shutdown().await.expect("shutdown 1");
    }

    // Round 2 — read back from a fresh engine pointing at the same
    // SQLite file. `init` runs `host::storage::get("count")` and
    // populates the in-memory `count`. A `counter::read` then
    // surfaces it.
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
        "expected count=3 after restart, got {count:?}",
    );

    instance.shutdown().await.expect("shutdown 2");
}

/// Storage gated off (`storage_quota_kb = 0`) and storage with a
/// tight quota are both covered by lib unit tests on the
/// `storage::Host` impl. This integration test exercises the
/// guest-path equivalent: a counter plugin loaded with a
/// `storage_quota_kb = 0` manifest fails `init` with the host's
/// `permission-denied` surfacing through the SDK's `get` →
/// `init`'s `?` propagation.
#[tokio::test(flavor = "current_thread")]
async fn storage_off_surfaces_through_init() {
    let _wasm = support::build_example("kv-counter", "kv_counter.wasm");

    // Tempdir laid out as a real plugin install dir, but with
    // `storage_quota_kb` absent (the default zero) so storage is
    // gated off.
    let dir = tempdir();
    let wasm_src = support::workspace_root()
        .join("examples")
        .join("kv-counter")
        .join("target")
        .join("wasm32-wasip2")
        .join("debug")
        .join("kv_counter.wasm");
    std::fs::copy(&wasm_src, dir.path().join("kv_counter.wasm")).expect("copy wasm");
    std::fs::write(
        dir.path().join("manifest.toml"),
        r#"manifest_version = 1
[plugin]
id = "example.kv-counter-bare"
name = "Bare KV Counter"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "kv_counter.wasm"
[capabilities]
"#,
    )
    .expect("write manifest");

    let engine = Engine::with_state_dir(state_dir_for_engine().path()).expect("engine");
    let mut instance = PluginInstance::load(&engine, dir.path(), "kv_counter_bare")
        .await
        .expect("load (instantiation must succeed)");
    let err = match instance.init().await {
        Ok(()) => panic!("init should fail with storage gated off"),
        Err(e) => e,
    };
    let msg = format!("{err:#}").to_ascii_lowercase();
    assert!(
        msg.contains("permission") && msg.contains("storage"),
        "expected `permission` + `storage` in error message, got: {msg}",
    );
}

// ── tempdir helper ──────────────────────────────────────────────────
//
// Same shape as the one in `manifest_loader.rs` — local so the test
// crate doesn't pick up an external dep.

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
        "oxidhome-storage-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}

fn state_dir_for_engine() -> TempDir {
    let base = std::env::temp_dir();
    let name = format!(
        "oxidhome-engine-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk engine state dir");
    TempDir { path }
}
