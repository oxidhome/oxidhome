//! OxidHome Phase 5a example: persistent counter.
//!
//! On `init` the plugin reads its `count` key out of the host's KV
//! store. If the key is absent the counter starts at zero — covers
//! the "first boot" path. Each `execute_command` for the
//! `counter::tick` action increments the counter and writes it back
//! through `host::storage::set`. Restarting the host with the same
//! `<state_dir>` loads the persisted value.
//!
//! The example deliberately does *not* register a device — Phase 3's
//! device-registration gate is independent of Phase 5a's storage
//! gate. The host routes commands to plugins that have neither
//! devices nor capabilities; the `command::capability` field
//! identifies the action's namespace.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::host;

const COUNT_KEY: &str = "count";

#[derive(Default)]
struct KvCounter {
    /// Last value read from storage. Kept in memory so the plugin
    /// doesn't round-trip through the WIT for every increment — only
    /// the write to persist the new value.
    count: i64,
}

impl Plugin for KvCounter {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();

        // Read the persisted counter. `Ok(None)` means the host has
        // no entry yet — that's the first-boot path, start at 0 and
        // don't treat it as an error. Any other error (storage gated
        // off, deserialize mismatch, sqlite failure) surfaces from
        // init so the operator sees what happened.
        self.count = match host::storage::get(COUNT_KEY)
            .map_err(|e| format!("reading counter from storage: {e:?}"))?
        {
            Some(Value::IntVal(n)) => n,
            Some(other) => {
                return Err(format!(
                    "counter key has wrong type: expected IntVal, got {other:?}",
                ));
            }
            None => 0,
        };

        oxidhome_sdk::tracing::info!(count = self.count, "kv-counter ready");
        Ok(())
    }

    fn shutdown(&mut self) {
        oxidhome_sdk::tracing::info!(count = self.count, "kv-counter stopped");
    }

    fn execute_command(&mut self, _device: String, cmd: Command) -> CommandResult {
        if cmd.capability != "counter" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported capability {}",
                cmd.capability,
            )));
        }
        match cmd.action.as_str() {
            "tick" => {
                self.count += 1;
                if let Err(e) = host::storage::set(COUNT_KEY, &Value::IntVal(self.count)) {
                    // Surface as InvalidArgument since CommandResult
                    // doesn't carry a richer error variant — the
                    // string includes the underlying KV error so the
                    // operator can tell quota / sqlite / etc. apart.
                    return CommandResult::Err(Error::InvalidArgument(format!(
                        "writing counter to storage: {e:?}",
                    )));
                }
                CommandResult::OkWithState(vec![KeyValue {
                    key: "count".into(),
                    value: Value::IntVal(self.count),
                }])
            }
            "read" => CommandResult::OkWithState(vec![KeyValue {
                key: "count".into(),
                value: Value::IntVal(self.count),
            }]),
            other => CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported action counter::{other}",
            ))),
        }
    }
}

oxidhome_sdk::plugin!(KvCounter);
