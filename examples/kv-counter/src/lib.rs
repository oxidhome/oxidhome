//! OxidHome Phase 5a example: persistent counter.
//!
//! On `init` the plugin reads its `count` key out of the host's KV
//! store. If the key is absent the counter starts at zero — covers
//! the "first boot" path. Both the lifecycle `tick()` hook (driven by
//! the Phase-6 supervisor off `runtime.tick_interval_ms`) and the
//! `counter::tick` command action increment the counter and write it
//! back through `host::storage::set`. Restarting the host with the
//! same `<state_dir>` loads the persisted value.
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

    fn tick(&mut self) {
        // The lifecycle tick is the scheduled counterpart of the
        // `counter::tick` command. WIT `tick` returns `()`, so a
        // storage failure can only be logged here, not surfaced.
        match self.increment() {
            Ok(count) => oxidhome_sdk::tracing::info!(count, "kv-counter ticked"),
            Err(e) => oxidhome_sdk::tracing::error!(error = %e, "kv-counter tick failed"),
        }
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
            "tick" => match self.increment() {
                Ok(count) => CommandResult::OkWithState(vec![KeyValue {
                    key: "count".into(),
                    value: Value::IntVal(count),
                }]),
                // Surface as InvalidArgument since CommandResult
                // doesn't carry a richer error variant — the string
                // includes the underlying KV error so the operator
                // can tell quota / sqlite / etc. apart.
                Err(e) => CommandResult::Err(Error::InvalidArgument(e)),
            },
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

impl KvCounter {
    /// Bump the counter and persist it. Shared by the lifecycle
    /// `tick()` hook and the `counter::tick` command. Persists *before*
    /// committing the new value to `self.count`, so a storage failure
    /// leaves the in-memory counter in sync with what's on disk —
    /// otherwise a transient failure (which `tick()` only logs) would
    /// desync the two permanently. Returns the new count, or a
    /// storage-error message.
    fn increment(&mut self) -> Result<i64, String> {
        let next = self.count + 1;
        host::storage::set(COUNT_KEY, &Value::IntVal(next))
            .map_err(|e| format!("writing counter to storage: {e:?}"))?;
        self.count = next;
        Ok(next)
    }
}

oxidhome_sdk::plugin!(KvCounter);
