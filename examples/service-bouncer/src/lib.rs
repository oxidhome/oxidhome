//! OxidHome Phase 7c example: a service that bounces calls to a
//! configured target.
//!
//! On `init` it registers service `bouncer` with one command `kick`.
//! `kick` reads `bounce_to` from KV: if set, it calls
//! `bounce_to.kick` and returns that result verbatim; otherwise it
//! returns an empty `CommandResult::Ok` to signal the leaf hop landed.
//!
//! Two instances configured to bounce to each other exercise the
//! Phase-7c cross-task cycle detection: A.kick → B.kick → A.kick must
//! be rejected by the dispatcher with `InvalidArgument`, not 30s
//! deadlocked.
//!
//! H6 slice 4 (event attribution): when KV `announce` is set, a leaf
//! `kick` (no `bounce_to`) publishes a custom event on topic [`RELAY_TOPIC`]. Every
//! bouncer subscribes to that topic; one whose KV `relay_to` names a
//! service id answers the event in `on-event` by calling that
//! service's `kick`, so a test can follow a reaction's hop back to
//! the request that caused the event. A leaf `kick` that succeeds sets
//! KV `kicked`, so a test can see that a relay landed. Don't point
//! `relay_to` at an announcing bouncer: each announcement would start
//! a fresh reaction, a loop only the publish quota stops.
//!
//! H6 slice 5 (a device command that calls a service): each bouncer
//! also registers a `button` device. Its `button::press` command does
//! what `kick` does with `bounce_to` — calls `bounce_to.kick` when KV
//! `bounce_to` is set, otherwise lands as a leaf — so a token's device
//! command starts a chain whose first hop the token must also be
//! allowed.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::CapabilitySpec;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::events::{Event, EventPayload};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Device, Service, host};

const BOUNCE_KEY: &str = "bounce_to";
const ANNOUNCE_KEY: &str = "announce";
const RELAY_KEY: &str = "relay_to";
/// Custom topic `kick` announces on when KV `announce` is set.
const RELAY_TOPIC: &str = "bouncer.relay";
/// KV key a successful leaf `kick` sets, so a test can see a relay
/// landed.
const KICKED_KEY: &str = "kicked";

/// A string value from KV, if set.
fn kv_string(key: &str) -> Option<String> {
    match host::storage::get(key) {
        Ok(Some(Value::StringVal(s))) => Some(s),
        _ => None,
    }
}

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
        host::register_device(
            Device::new("button", "Bouncer Button").capability(CapabilitySpec::Button),
        )
        .map_err(|e| format!("register-device failed: {e:?}"))?;
        // The relay is optional: without `subscribes_events` the
        // bouncer still serves `kick`.
        if let Err(e) = host::subscribe_topic(RELAY_TOPIC.to_owned()) {
            oxidhome_sdk::tracing::warn!("relay disabled: subscribe failed: {e:?}");
        }
        Ok(())
    }

    fn shutdown(&mut self) {}

    fn on_event(&mut self, event: Event) {
        if !matches!(&event.payload, EventPayload::Custom(c) if c.topic == RELAY_TOPIC) {
            return;
        }
        if let Some(target) = kv_string(RELAY_KEY) {
            match host::call_service(&target, "kick", &[]) {
                Ok(CommandResult::Err(e)) => {
                    oxidhome_sdk::tracing::warn!("relay kick refused: {e:?}");
                }
                Err(e) => oxidhome_sdk::tracing::warn!("relay kick failed: {e:?}"),
                Ok(_) => {}
            }
        }
    }

    fn execute_command(&mut self, _device: String, cmd: Command) -> CommandResult {
        if cmd.capability != "button" || cmd.action != "press" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unknown bouncer button command: {}::{}",
                cmd.capability, cmd.action
            )));
        }
        // Like `kick`: bounce when a target is set, else land.
        let Some(target) = kv_string(BOUNCE_KEY) else {
            if let Err(e) = host::storage::set(KICKED_KEY, &Value::BoolVal(true)) {
                oxidhome_sdk::tracing::warn!("marking kicked failed: {e:?}");
            }
            return CommandResult::Ok;
        };
        match host::call_service(&target, "kick", &[]) {
            Ok(result) => result,
            Err(e) => CommandResult::Err(e),
        }
    }

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
        // there's no next hop — return Ok. Only this leaf hop announces,
        // so an `Err` never follows a published event.
        let target = match host::storage::get(BOUNCE_KEY) {
            Ok(Some(Value::StringVal(s))) => s,
            Ok(_) => {
                if kv_string(ANNOUNCE_KEY).is_some()
                    && let Err(e) = host::publish_custom_event(None, RELAY_TOPIC, "{}")
                {
                    return CommandResult::Err(e);
                }
                // Last, so an `Err` above leaves nothing behind.
                if let Err(e) = host::storage::set(KICKED_KEY, &Value::BoolVal(true)) {
                    oxidhome_sdk::tracing::warn!("marking kicked failed: {e:?}");
                }
                return CommandResult::Ok;
            }
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
