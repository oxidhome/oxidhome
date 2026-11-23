//! OxidHome Phase 7a example: a plugin that never returns.
//!
//! The `phase` config picks which hook hangs:
//!
//! - `"tick"` (default) — `init` succeeds, then the lifecycle
//!   `tick()` enters an infinite loop;
//! - `"init"` — `init` itself never returns;
//! - `"command"` — `init` registers a switch device, then
//!   `execute_command` never returns. The H5 fixture for a deadline
//!   that passes while the plugin is running a command
//!   (`outcome_unknown`), and for a command that expires in the queue
//!   behind it (`timed_out`);
//! - `"service"` — `init` registers a `spinner` service whose `spin`
//!   command never returns. The same H5 fixture for `call-service`: a
//!   call whose deadline passes mid-call answers `unknown`, one that
//!   expires in the queue behind it `unavailable` (it never ran);
//! - `"sleep"` — `tick` blocks in a WASI `sleep` for an hour. The epoch
//!   watchdog can't interrupt a guest parked in a host import; the
//!   fixture for a stop cancelling the call instead;
//! - `"shutdown-sleep"` — `on-shutdown` blocks in a WASI `sleep` for an
//!   hour; the fixture for the host bounding `on-shutdown`.
//! - `"gate"` — `init` registers the `spinner` service with a
//!   releasable `hold` command, which waits until the KV key `release`
//!   is set (the test sets it from the host side), and `mark`, which
//!   counts its runs in the KV key `runs`. The H5 fixture for a call
//!   withdrawn while queued behind `hold`: once released, the callee
//!   dequeues it and must not run it.
//!
//! It's the fixture for the liveness-watchdog tests: the host must be
//! able to interrupt the wedged call (`Trap::Interrupt`) so the
//! supervisor can reclaim the instance instead of hanging forever.

use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::CapabilitySpec;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Device, Plugin, Service, host};

#[derive(Default)]
struct Hang;

fn cfg_phase() -> String {
    host::config::get_typed::<String>("phase")
        .ok()
        .flatten()
        .unwrap_or_else(|| "tick".to_string())
}

/// Block in a host import (`wasi:clocks` + `wasi:io/poll`) rather
/// than in guest code.
fn sleep_an_hour() {
    std::thread::sleep(std::time::Duration::from_secs(3600));
}

fn spin() -> ! {
    // A tight loop the watchdog (epoch interruption) cuts short.
    // `black_box` keeps the optimiser from removing the body.
    let mut x: u64 = 0;
    loop {
        x = x.wrapping_add(1);
        std::hint::black_box(x);
    }
}

impl Plugin for Hang {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        match cfg_phase().as_str() {
            "init" => spin(),
            "command" => {
                host::register_device(
                    Device::new("switch-1", "Hanging Switch").capability(CapabilitySpec::Switch),
                )
                .map_err(|e| format!("register-device failed: {e:?}"))?;
            }
            "service" => {
                host::register_service(
                    Service::new("spinner", "spinner").command(CommandSpec::new("spin")),
                )
                .map_err(|e| format!("register-service failed: {e:?}"))?;
            }
            "gate" => {
                host::register_service(
                    Service::new("spinner", "spinner")
                        .command(CommandSpec::new("hold"))
                        .command(CommandSpec::new("mark")),
                )
                .map_err(|e| format!("register-service failed: {e:?}"))?;
            }
            _ => {}
        }
        oxidhome_sdk::tracing::info!("hang ready — will spin on first tick");
        Ok(())
    }

    fn tick(&mut self) {
        match cfg_phase().as_str() {
            "tick" => spin(),
            "sleep" => sleep_an_hour(),
            _ => {}
        }
    }

    fn execute_command(&mut self, _device: String, _cmd: Command) -> CommandResult {
        spin();
    }

    fn execute_service_command(
        &mut self,
        _service: String,
        command: String,
        _args: Vec<KeyValue>,
    ) -> CommandResult {
        if cfg_phase() != "gate" {
            spin();
        }
        match command.as_str() {
            "hold" => {
                // Polls between short host sleeps: released by the
                // host, still bounded by the watchdog.
                while !matches!(host::storage::get("release"), Ok(Some(_))) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                CommandResult::Ok
            }
            "mark" => {
                let runs = match host::storage::get("runs") {
                    Ok(Some(Value::IntVal(n))) => n,
                    _ => 0,
                };
                match host::storage::set("runs", &Value::IntVal(runs + 1)) {
                    Ok(()) => CommandResult::Ok,
                    Err(e) => CommandResult::Err(e),
                }
            }
            _ => spin(),
        }
    }

    fn shutdown(&mut self) {
        if cfg_phase() == "shutdown-sleep" {
            sleep_an_hour();
        }
    }
}

oxidhome_sdk::plugin!(Hang);
