//! OxidHome Phase 7 example: a counter exposed as a service.
//!
//! On `init` it registers a `counter` service exposing `increment` and
//! `get` commands. `execute_service_command` keeps an in-memory tally —
//! so once the Phase-7c dispatcher lands, a caller can drive the counter
//! cross-instance. For Phase 7b (registry + lifecycle, no dispatch yet)
//! the integration test just confirms the host registry sees the
//! registered service.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::CommandResult;
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Service, host};

#[derive(Default)]
struct ServiceCounter {
    value: i64,
}

impl Plugin for ServiceCounter {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let id = host::register_service(
            Service::new("counter", "counter")
                .command(CommandSpec::new("increment").description("Add one to the counter"))
                .command(CommandSpec::new("get").description("Read the current value")),
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
        _args: Vec<KeyValue>,
    ) -> CommandResult {
        match command.as_str() {
            "increment" => {
                self.value += 1;
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
