//! Phase 5b end-to-end persistence test.
//!
//! Drives the `snapshot-saver` example through one host lifetime
//! against a `<state_dir>`: init writes `snapshot-init`; a
//! `snapshot::write` command adds `snapshot-runtime` with a
//! caller-supplied payload. Drops the engine, reopens against the
//! same dir, and queries the host-side `BlobStore` directly to
//! confirm both blobs survived with their bytes intact and quota
//! accounting holds.
//!
//! Coverage matrix:
//!
//! - Lib unit tests (`state::blobs::tests::*`) cover the store
//!   mechanics in isolation — write/read round-trip, overwrite
//!   accounting, quota refusal, delete + refund, list prefix,
//!   cross-instance isolation, in-memory unavailable, reopen
//!   survival.
//! - This file is the integration smoke test that the wiring from
//!   guest `host::blobs::write` → WIT `blob-store::write` →
//!   `host_impl::blob_store::write` → `BlobStore::write` →
//!   `<state_dir>/oxidhome.db` + `<state_dir>/blobs/<instance>/<id>`
//!   actually closes the loop.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};
use oxidhome_core::{Engine, PluginInstance};

const INIT_PAYLOAD: &[u8] = b"snapshot:init";
const RUNTIME_PAYLOAD: &[u8] = b"snapshot:runtime-bytes";

#[tokio::test(flavor = "current_thread")]
async fn blobs_survive_host_restart() {
    let _wasm = support::build_example("snapshot-saver", "snapshot_saver.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("snapshot-saver");

    let state_dir = tempdir();
    let instance_id: String;

    {
        let engine = Engine::with_state_dir(state_dir.path()).expect("engine 1");
        let mut instance = PluginInstance::load(&engine, &plugin_dir, "snapshot_saver")
            .await
            .expect("load 1");
        instance_id = instance.instance_id().to_owned();
        instance.init().await.expect("init 1");

        // Drive a runtime `snapshot::write` with a caller-supplied
        // payload. The example's execute_command pulls `name` and
        // `payload` (bytes) out of the args.
        let result = instance
            .execute_command(
                "no-device".into(),
                Command {
                    capability: "snapshot".into(),
                    action: "write".into(),
                    args: vec![
                        KeyValue {
                            key: "name".into(),
                            value: Value::StringVal("snapshot-runtime".into()),
                        },
                        KeyValue {
                            key: "payload".into(),
                            value: Value::BytesVal(RUNTIME_PAYLOAD.into()),
                        },
                    ],
                },
            )
            .await
            .expect("snapshot::write");
        assert!(
            matches!(result, CommandResult::OkWithState(_)),
            "snapshot::write should return OkWithState, got {result:?}",
        );

        instance.shutdown().await.expect("shutdown 1");
    }

    // Reopen the engine against the same `<state_dir>`. The blob
    // store is host-side; no plugin reload is required — we read
    // through `Engine::blobs()` directly.
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine 2");
    let blobs = engine.blobs();

    let init_bytes = blobs
        .read_by_name(&instance_id, "snapshot-init")
        .expect("read snapshot-init");
    assert_eq!(init_bytes, INIT_PAYLOAD);

    let runtime_bytes = blobs
        .read_by_name(&instance_id, "snapshot-runtime")
        .expect("read snapshot-runtime");
    assert_eq!(runtime_bytes, RUNTIME_PAYLOAD);

    // List should hit both, in lexicographic order.
    let listed = blobs.list_blobs(&instance_id, "snapshot-").expect("list");
    let names: Vec<&str> = listed.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, vec!["snapshot-init", "snapshot-runtime"]);

    // Usage accounting matches the total payload bytes — quota
    // accounting is the load-bearing-for-overwrites bit, and the
    // restart proved the triggers ran on insert.
    let (used, quota) = blobs.usage(&instance_id).expect("usage").expect("present");
    let total_payload = u64::try_from(INIT_PAYLOAD.len() + RUNTIME_PAYLOAD.len())
        .expect("payload sums fit in u64");
    assert_eq!(
        used, total_payload,
        "bytes_used should equal the sum of the two payloads",
    );
    assert_eq!(
        quota,
        4 * 1024 * 1024,
        "quota should match the manifest's `blob_quota_mb = 4`",
    );
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
        "oxidhome-blob-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let path = base.join(name);
    std::fs::create_dir_all(&path).expect("mk tempdir");
    TempDir { path }
}
