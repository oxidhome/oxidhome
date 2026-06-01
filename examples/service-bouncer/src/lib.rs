//! OxidHome Phase 7c example: a service that bounces calls to a
//! configured target.
//!
//! On `init` it registers service `bouncer` with one command `kick`.
//! `kick` reads `bounce_to` from KV: if set, it calls
//! `bounce_to.kick` and returns that result; otherwise it returns
//! `Ok` with the configured `name` so the caller can confirm the hop
//! landed.
//!
//! Two instances configured to bounce to each other exercise the
//! Phase-7c cross-task cycle detection: A.kick → B.kick → A.kick must
//! be rejected by the dispatcher with `InvalidArgument`, not 30s
//! deadlocked.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::CommandResult;
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Service, host};

const BOUNCE_KEY: &str = "bounce_to";

#[derive(Default)]
struct Bouncer;

impl Plugin for Bouncer {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let id = host::register_service(
            Service::new("bouncer", "bouncer").command(CommandSpec::new("kick")),
        )
        .map_err(|e| format!("register-service failed: {e:?}"))?;
        oxidhome_sdk::tracing::info!(service_id = %id, "service-bouncer registered");
        Ok(())
    }

    fn shutdown(&mut self) {}

    fn execute_service_command(
        &mut self,
        _service: String,
        command: String,
        _args: Vec<KeyValue>,
    ) -> CommandResult {
        if command != "kick" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unknown bouncer command: {command}"
            )));
        }
        // Look up the bounce target in KV. If absent or wrong-typed,
        // there's no next hop — return Ok.
        let target = match host::storage::get(BOUNCE_KEY) {
            Ok(Some(Value::StringVal(s))) => s,
            Ok(_) => return CommandResult::Ok,
            Err(e) => {
                return CommandResult::Err(Error::Internal(format!(
                    "reading bounce_to: {e:?}"
                )));
            }
        };
        match host::call_service(&target, "kick", &[]) {
            Ok(result) => result,
            // Propagate the dispatcher error verbatim so the
            // integration test can see the `InvalidArgument` from
            // recursion rejection (or `Unavailable`, timeout, …).
            Err(e) => CommandResult::Err(e),
        }
    }
}

oxidhome_sdk::plugin!(Bouncer);
