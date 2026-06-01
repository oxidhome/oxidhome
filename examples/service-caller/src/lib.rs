//! OxidHome Phase 7c example: calls another plugin's `counter` service.
//!
//! On `init` it reads `target_service_id` from per-instance config
//! (the test populates it after `service-counter`'s service registers
//! and the host hands back the canonical `svc-N`), then drives:
//!
//!   counter.increment ×3 → counter.get
//!
//! and stores the final `value` in KV under the key `"final_value"`
//! so the integration test can verify routing end-to-end without
//! re-driving the dispatcher itself.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::CommandResult;
use oxidhome_sdk::bindings::oxidhome::plugin::types::Value;
use oxidhome_sdk::host;

#[derive(Default)]
struct ServiceCaller;

const FINAL_KEY: &str = "final_value";

fn extract_value(result: &CommandResult) -> Result<i64, String> {
    match result {
        CommandResult::OkWithState(fields) => {
            for kv in fields {
                if kv.key == "value" {
                    if let Value::IntVal(n) = kv.value {
                        return Ok(n);
                    }
                }
            }
            Err(format!("counter reply missing `value` int field: {fields:?}"))
        }
        CommandResult::Ok => Err("counter returned Ok without state".into()),
        CommandResult::Err(e) => Err(format!("counter returned err: {e:?}")),
    }
}

impl Plugin for ServiceCaller {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let target = host::config::get_typed::<String>("target_service_id")
            .map_err(|e| format!("reading target_service_id config: {e}"))?
            .ok_or_else(|| "target_service_id not configured".to_string())?;

        for _ in 0..3 {
            let result = host::call_service(&target, "increment", &[])
                .map_err(|e| format!("call counter.increment: {e:?}"))?;
            let _ = extract_value(&result)?;
        }
        let result = host::call_service(&target, "get", &[])
            .map_err(|e| format!("call counter.get: {e:?}"))?;
        let value = extract_value(&result)?;

        host::storage::set(FINAL_KEY, &Value::IntVal(value))
            .map_err(|e| format!("persisting final_value: {e:?}"))?;

        oxidhome_sdk::tracing::info!(value, "service-caller drove counter");
        Ok(())
    }

    fn shutdown(&mut self) {}
}

oxidhome_sdk::plugin!(ServiceCaller);
