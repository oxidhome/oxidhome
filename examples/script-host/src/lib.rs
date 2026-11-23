//! OxidHome example: a toy scripting plugin with one sandbox per script
//! (ADR-0001).
//!
//! The same component plays two roles:
//!
//! - **Manager** — the instance the operator starts. It registers the
//!   `scripts` service with `load {id, source}`, `unload {id}` and
//!   `crash` (trap the manager; its scripts keep running),
//!   starts one sandbox per loaded script, and keeps the sources in KV
//!   so its next life (or the next daemon start) re-creates them,
//!   retrying on `tick` while a previous sandbox is still stopping.
//! - **Script** — a sandbox the manager started. `init` reads the
//!   script with `host::sandboxes::current()` and registers the
//!   service `script` with one command per script line.
//!
//! The "language" is one command per line, `<command> <action>`:
//!
//! - `ok` — reply `ok`;
//! - `call <script> <command>` — call `<command>` on the sibling script
//!   `<script>` through `host::call_service` and reply with its result;
//! - `sleep <ms>` — sleep (at most 10 s), then reply `ok`;
//! - `trap` — panic (the sandbox crashes and restarts on its own).
//!
//! Blank lines and lines starting with `#` are ignored.

use std::collections::BTreeMap;
use std::time::Duration;

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::CommandResult;
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::{CommandSpec, Field, Service, host};

const PLUGIN_ID: &str = "example.script-host";
const SCRIPT_SERVICE: &str = "script";
const KV_PREFIX: &str = "script/";

enum Action {
    Ok,
    Call { script: String, command: String },
    Sleep(u64),
    Trap,
}

enum Role {
    /// `pending` holds saved scripts whose restore hit a transient
    /// `unavailable` (a previous sandbox with that id still stopping);
    /// `tick` retries them.
    Manager {
        pending: BTreeMap<String, String>,
        /// Whether the saved scripts have been read; a storage error
        /// leaves this `false` for `tick` to retry.
        scanned: bool,
    },
    Script {
        parent: String,
        commands: BTreeMap<String, Action>,
    },
}

#[derive(Default)]
struct ScriptHost {
    role: Option<Role>,
}

/// The host's `start-sandbox` source limit.
const MAX_SOURCE_BYTES: usize = 64 * 1024;
/// The host's limits on a service's commands (`register-service`).
const MAX_COMMANDS: usize = 64;
const MAX_COMMAND_NAME: usize = 64;

fn is_command_name(name: &str) -> bool {
    name.len() <= MAX_COMMAND_NAME
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn parse(source: &str) -> Result<BTreeMap<String, Action>, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(format!("script is over {MAX_SOURCE_BYTES} bytes"));
    }
    let mut commands = BTreeMap::new();
    for (n, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let action = match words.as_slice() {
            [_, "ok"] => Action::Ok,
            [_, "trap"] => Action::Trap,
            [_, "sleep", ms] => Action::Sleep(
                ms.parse()
                    .map_err(|e| format!("line {}: bad sleep: {e}", n + 1))?,
            ),
            [_, "call", script, command] => Action::Call {
                script: (*script).to_owned(),
                command: (*command).to_owned(),
            },
            _ => return Err(format!("line {}: cannot parse `{line}`", n + 1)),
        };
        if !is_command_name(words[0]) {
            return Err(format!(
                "line {}: command `{}` must be 1-{MAX_COMMAND_NAME} characters of \
                 [A-Za-z0-9_-], starting with a letter or digit",
                n + 1,
                words[0],
            ));
        }
        commands.insert(words[0].to_owned(), action);
        if commands.len() > MAX_COMMANDS {
            return Err(format!("more than {MAX_COMMANDS} commands"));
        }
    }
    Ok(commands)
}

fn string_arg<'a>(args: &'a [KeyValue], name: &str) -> Option<&'a str> {
    args.iter().find_map(|kv| match (&kv.key, &kv.value) {
        (k, Value::StringVal(s)) if k == name => Some(s.as_str()),
        _ => None,
    })
}

/// Read the saved scripts into `pending`. `false` on a storage error,
/// so `tick` reads them again rather than leaving them offline.
fn scan(pending: &mut BTreeMap<String, String>) -> bool {
    let read = || -> Result<Vec<(String, String)>, Error> {
        let mut saved = Vec::new();
        for key in host::storage::list_keys(KV_PREFIX)? {
            if let (Some(id), Some(Value::StringVal(source))) =
                (key.strip_prefix(KV_PREFIX), host::storage::get(&key)?)
            {
                saved.push((id.to_owned(), source));
            }
        }
        Ok(saved)
    };
    match read() {
        Ok(saved) => {
            // A sandbox whose script isn't saved any more was unloaded
            // by a previous life that crashed before stopping it.
            for sandbox in host::sandboxes::list() {
                if !saved.iter().any(|(id, _)| *id == sandbox.local_id) {
                    let _ = host::sandboxes::stop(&sandbox.local_id);
                }
            }
            pending.extend(saved);
            true
        }
        // No storage grant: nothing was ever saved, and retrying won't
        // change that.
        Err(Error::PermissionDenied(_)) => true,
        Err(e) => {
            oxidhome_sdk::tracing::warn!(error = ?e, "reading saved scripts failed; retrying");
            false
        }
    }
}

/// Start every pending script; keep the ones refused as `unavailable`
/// Longest `sleep` a script may ask for, in milliseconds.
const MAX_SLEEP_MS: u64 = 10_000;

/// (retried on the next tick) and drop the rest.
fn restore(pending: &mut BTreeMap<String, String>) {
    pending.retain(|id, source| match host::sandboxes::start(id, source) {
        Ok(_) => false,
        Err(Error::Unavailable(_)) => true,
        Err(e) => {
            oxidhome_sdk::tracing::warn!(script = %id, error = ?e, "restoring script failed");
            false
        }
    });
}

impl ScriptHost {
    fn init_manager(&mut self) -> Result<(), String> {
        host::register_service(
            Service::new("scripts", "scripts")
                .command(
                    CommandSpec::new("load")
                        .description("Start (or re-adopt) a script in its own sandbox")
                        .param(Field::string("id"))
                        .param(Field::string("source"))
                        .returns(Field::string("instance_id")),
                )
                .command(
                    CommandSpec::new("unload")
                        .description("Stop a script")
                        .param(Field::string("id")),
                )
                .command(
                    CommandSpec::new("crash").description(
                        "Trap the manager; its scripts keep running and are re-adopted",
                    ),
                ),
        )
        .map_err(|e| format!("register-service failed: {e:?}"))?;
        // Re-adopt (after a manager crash) or re-create (after a daemon
        // restart) every script this instance had loaded.
        let mut pending = BTreeMap::new();
        let scanned = scan(&mut pending);
        restore(&mut pending);
        self.role = Some(Role::Manager { pending, scanned });
        Ok(())
    }

    fn init_script(&mut self, script: host::sandboxes::SandboxScript) -> Result<(), String> {
        let commands = parse(&script.source)?;
        let mut service = Service::new(SCRIPT_SERVICE, SCRIPT_SERVICE);
        for name in commands.keys() {
            service = service.command(CommandSpec::new(name.clone()));
        }
        host::register_service(service).map_err(|e| format!("register-service failed: {e:?}"))?;
        self.role = Some(Role::Script {
            parent: script.info.parent_instance,
            commands,
        });
        Ok(())
    }

    fn manage(
        pending: &mut BTreeMap<String, String>,
        command: &str,
        args: &[KeyValue],
    ) -> CommandResult {
        if command == "crash" {
            panic!("manager asked to crash");
        }
        let Some(id) = string_arg(args, "id") else {
            return CommandResult::Err(Error::InvalidArgument("missing `id`".into()));
        };
        let key = format!("{KV_PREFIX}{id}");
        match command {
            // Save first, so a script that is running is always one the
            // next life restores; undo the save if the start is refused.
            "load" => {
                let source = string_arg(args, "source").unwrap_or_default();
                // Never save a script its sandbox would refuse to run.
                if let Err(e) = parse(source) {
                    return CommandResult::Err(Error::InvalidArgument(e));
                }
                let previous = match host::storage::get(&key) {
                    Ok(previous) => previous,
                    Err(e) => return CommandResult::Err(e),
                };
                // A live script keeps its saved source: refuse a
                // different one before touching KV, so a crash here
                // can't leave KV disagreeing with the running script.
                let running = host::sandboxes::list().iter().any(|s| s.local_id == id);
                let same = matches!(&previous, Some(Value::StringVal(saved)) if saved == source);
                if running && !same {
                    return CommandResult::Err(Error::InvalidArgument(format!(
                        "script `{id}` is running different source; unload it first"
                    )));
                }
                if let Err(e) = host::storage::set(&key, &Value::StringVal(source.into())) {
                    return CommandResult::Err(e);
                }
                match host::sandboxes::start(id, source) {
                    Ok(instance_id) => {
                        pending.remove(id);
                        CommandResult::OkWithState(vec![KeyValue {
                            key: "instance_id".into(),
                            value: Value::StringVal(instance_id),
                        }])
                    }
                    Err(e) => {
                        let undone = match previous {
                            Some(previous) => host::storage::set(&key, &previous),
                            None => host::storage::delete(&key),
                        };
                        match undone {
                            Ok(()) => CommandResult::Err(e),
                            Err(_) => CommandResult::Unknown(format!(
                                "start refused ({e:?}) and the saved source could not be restored"
                            )),
                        }
                    }
                }
            }
            // Forget first, so a stopped script never comes back.
            "unload" => {
                let saved = match host::storage::get(&key) {
                    Ok(saved) => saved.is_some(),
                    Err(e) => return CommandResult::Err(e),
                };
                if let Err(e) = host::storage::delete(&key) {
                    return CommandResult::Err(e);
                }
                pending.remove(id);
                match host::sandboxes::stop(id) {
                    Ok(()) => CommandResult::Ok,
                    // Not running (pending, failed, stopped by the
                    // operator, or this manager isn't supervised):
                    // forgetting the saved script was enough.
                    Err(Error::NotFound(_) | Error::Unavailable(_)) if saved => CommandResult::Ok,
                    Err(e) => CommandResult::Err(e),
                }
            }
            other => CommandResult::Err(Error::InvalidArgument(format!(
                "unknown scripts command: {other}"
            ))),
        }
    }

    fn run(parent: &str, action: &Action) -> CommandResult {
        match action {
            Action::Ok => CommandResult::Ok,
            Action::Sleep(ms) => {
                // Bounded: a guest blocked in a host sleep can't be
                // interrupted by the epoch watchdog or a shutdown.
                std::thread::sleep(Duration::from_millis((*ms).min(MAX_SLEEP_MS)));
                CommandResult::Ok
            }
            Action::Trap => panic!("script asked to trap"),
            Action::Call { script, command } => {
                let instance = host::sandboxes::instance_id(parent, script);
                let target = match host::resolve_service(PLUGIN_ID, &instance, SCRIPT_SERVICE) {
                    Ok(target) => target,
                    Err(e) => return CommandResult::Err(e),
                };
                host::call_service(&target, command, &[]).unwrap_or_else(CommandResult::Err)
            }
        }
    }
}

impl Plugin for ScriptHost {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        match host::sandboxes::current() {
            None => self.init_manager(),
            Some(script) => self.init_script(script),
        }
    }

    fn shutdown(&mut self) {}

    fn tick(&mut self) {
        if let Some(Role::Manager { pending, scanned }) = &mut self.role {
            if !*scanned {
                *scanned = scan(pending);
            }
            restore(pending);
        }
    }

    fn execute_service_command(
        &mut self,
        _service: String,
        command: String,
        args: Vec<KeyValue>,
    ) -> CommandResult {
        match &mut self.role {
            Some(Role::Manager { pending, .. }) => Self::manage(pending, &command, &args),
            Some(Role::Script { parent, commands }) => match commands.get(&command) {
                Some(action) => Self::run(parent, action),
                None => CommandResult::Err(Error::InvalidArgument(format!(
                    "unknown script command: {command}"
                ))),
            },
            None => CommandResult::Err(Error::Unavailable("not initialized".into())),
        }
    }
}

oxidhome_sdk::plugin!(ScriptHost);
