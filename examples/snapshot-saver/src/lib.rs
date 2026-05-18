//! OxidHome Phase 5b example: snapshot saver.
//!
//! On `init` writes a single "snapshot" blob via
//! `host::blobs::write`. The integration test drives a
//! `snapshot::write` command to add another one, then queries the
//! host-side BlobStore directly to confirm both round-tripped.
//!
//! The example doesn't actually grab a camera frame — it just
//! writes deterministic synthetic bytes so the integration test
//! can compare byte-for-byte.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::host;

/// The deterministic payload an `init` write produces. The host-
/// side integration test compares against this byte-for-byte.
const INIT_PAYLOAD: &[u8] = b"snapshot:init";

#[derive(Default)]
struct SnapshotSaver;

impl Plugin for SnapshotSaver {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();

        let id = host::blobs::write("snapshot-init", INIT_PAYLOAD, Some("application/octet-stream"))
            .map_err(|e| format!("blob write failed: {e:?}"))?;
        oxidhome_sdk::tracing::info!(blob_id = %id, "snapshot-saver wrote init snapshot");
        Ok(())
    }

    fn shutdown(&mut self) {
        oxidhome_sdk::tracing::info!("snapshot-saver stopped");
    }

    fn execute_command(&mut self, _device: String, cmd: Command) -> CommandResult {
        if cmd.capability != "snapshot" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported capability {}",
                cmd.capability,
            )));
        }
        match cmd.action.as_str() {
            "write" => {
                // Pull "name" / "payload" out of the command args.
                let name = match arg_string(&cmd, "name") {
                    Some(s) => s,
                    None => {
                        return CommandResult::Err(Error::InvalidArgument(
                            "snapshot::write needs `name: string`".into(),
                        ));
                    }
                };
                let payload = arg_bytes(&cmd, "payload").unwrap_or_else(|| b"snapshot:cmd".to_vec());
                match host::blobs::write(&name, &payload, None) {
                    Ok(id) => CommandResult::OkWithState(vec![KeyValue {
                        key: "id".into(),
                        value: Value::StringVal(id),
                    }]),
                    Err(e) => CommandResult::Err(Error::InvalidArgument(format!(
                        "blob write failed: {e:?}"
                    ))),
                }
            }
            "list" => match host::blobs::list_blobs("") {
                Ok(rows) => {
                    let names = rows
                        .into_iter()
                        .map(|info| info.name)
                        .collect::<Vec<_>>()
                        .join(",");
                    CommandResult::OkWithState(vec![KeyValue {
                        key: "names".into(),
                        value: Value::StringVal(names),
                    }])
                }
                Err(e) => CommandResult::Err(Error::InvalidArgument(format!(
                    "blob list failed: {e:?}"
                ))),
            },
            other => CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported action snapshot::{other}"
            ))),
        }
    }
}

fn arg_string(cmd: &Command, key: &str) -> Option<String> {
    cmd.args.iter().find_map(|kv| {
        if kv.key == key {
            match &kv.value {
                Value::StringVal(s) => Some(s.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn arg_bytes(cmd: &Command, key: &str) -> Option<Vec<u8>> {
    cmd.args.iter().find_map(|kv| {
        if kv.key == key {
            match &kv.value {
                Value::BytesVal(b) => Some(b.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

oxidhome_sdk::plugin!(SnapshotSaver);
