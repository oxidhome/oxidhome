//! OxidHome Phase 7 example: a counter exposed as a service.
//!
//! On `init` it registers a `counter` service exposing `increment` and
//! `get` commands, each with a typed `params` / `returns` schema the
//! host enforces. `execute_service_command` keeps an in-memory tally —
//! so once the Phase-7c dispatcher lands, a caller can drive the counter
//! cross-instance. For Phase 7b (registry + lifecycle, no dispatch yet)
//! the integration test just confirms the host registry sees the
//! registered service.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::CommandResult;
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Field, Service, host};

#[derive(Default)]
struct ServiceCounter {
    value: i64,
}

impl Plugin for ServiceCounter {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let id = host::register_service(
            Service::new("counter", "counter")
                .command(
                    CommandSpec::new("increment")
                        .description("Add `by` (default 1) to the counter")
                        .param(Field::int("by").optional().int_range(1, 1000))
                        .returns(Field::int("value")),
                )
                .command(
                    CommandSpec::new("get")
                        .description("Read the current value")
                        .returns(Field::int("value")),
                ),
        )
        .map_err(|e| format!("register-service failed: {e:?}"))?;
        oxidhome_sdk::tracing::info!(service_id = %id, "service-counter registered");
        Ok(())
    }

    fn shutdown(&mut self) {}

    fn execute_service_command(
        &mut self,
        _service: String,
        command: String,
        args: Vec<KeyValue>,
    ) -> CommandResult {
        // The host has already checked `args` against the declared
        // `params` schema: `by`, if present, is an int in 1..=1000.
        match command.as_str() {
            "increment" => {
                let by = args
                    .iter()
                    .find_map(|kv| match (kv.key.as_str(), &kv.value) {
                        ("by", Value::IntVal(n)) => Some(*n),
                        _ => None,
                    })
                    .unwrap_or(1);
                self.value = self.value.saturating_add(by);
                CommandResult::OkWithState(vec![KeyValue {
                    key: "value".into(),
                    value: Value::IntVal(self.value),
                }])
            }
            "get" => CommandResult::OkWithState(vec![KeyValue {
                key: "value".into(),
                value: Value::IntVal(self.value),
            }]),
            other => CommandResult::Err(Error::InvalidArgument(format!(
                "unknown counter command: {other}"
            ))),
        }
    }
}

oxidhome_sdk::plugin!(ServiceCounter);
