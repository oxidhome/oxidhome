//! OxidHome example: a toy scripting plugin with one sandbox per script
//! (ADR-0001).
//!
//! The same component plays two roles:
//!
//! - **Manager** — the instance the operator starts. It registers the
//!   `scripts` service with `load {id, source}` and `unload {id}`,
//!   starts one sandbox per loaded script, and keeps the sources in KV
//!   so its next life (or the next daemon start) re-creates them.
//! - **Script** — a sandbox the manager started. `init` reads the
//!   script with `host::sandboxes::current()` and registers the
//!   service `script` with one command per script line.
//!
//! The "language" is one command per line, `<command> <action>`:
//!
//! - `ok` — reply `ok`;
//! - `call <script> <command>` — call `<command>` on the sibling script
//!   `<script>` through `host::call_service` and reply with its result;
//! - `sleep <ms>` — sleep, then reply `ok`;
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
    Manager,
    Script {
        parent: String,
        commands: BTreeMap<String, Action>,
    },
}

#[derive(Default)]
struct ScriptHost {
    role: Option<Role>,
}

fn parse(source: &str) -> Result<BTreeMap<String, Action>, String> {
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
        commands.insert(words[0].to_owned(), action);
    }
    Ok(commands)
}

fn string_arg<'a>(args: &'a [KeyValue], name: &str) -> Option<&'a str> {
    args.iter().find_map(|kv| match (&kv.key, &kv.value) {
        (k, Value::StringVal(s)) if k == name => Some(s.as_str()),
        _ => None,
    })
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
                ),
        )
        .map_err(|e| format!("register-service failed: {e:?}"))?;
        // Re-adopt (after a manager crash) or re-create (after a daemon
        // restart) every script this instance had loaded.
        let keys = host::storage::list_keys(KV_PREFIX).unwrap_or_default();
        for key in keys {
            let Some(id) = key.strip_prefix(KV_PREFIX) else {
                continue;
            };
            if let Ok(Some(Value::StringVal(source))) = host::storage::get(&key)
                && let Err(e) = host::sandboxes::start(id, &source)
            {
                oxidhome_sdk::tracing::warn!(script = id, error = ?e, "re-starting script failed");
            }
        }
        self.role = Some(Role::Manager);
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

    fn manage(command: &str, args: &[KeyValue]) -> CommandResult {
        let Some(id) = string_arg(args, "id") else {
            return CommandResult::Err(Error::InvalidArgument("missing `id`".into()));
        };
        let key = format!("{KV_PREFIX}{id}");
        match command {
            "load" => {
                let source = string_arg(args, "source").unwrap_or_default();
                match host::sandboxes::start(id, source) {
                    Ok(instance_id) => {
                        if let Err(e) = host::storage::set(&key, &Value::StringVal(source.into())) {
                            return CommandResult::Err(e);
                        }
                        CommandResult::OkWithState(vec![KeyValue {
                            key: "instance_id".into(),
                            value: Value::StringVal(instance_id),
                        }])
                    }
                    Err(e) => CommandResult::Err(e),
                }
            }
            "unload" => {
                let _ = host::storage::delete(&key);
                match host::sandboxes::stop(id) {
                    Ok(()) => CommandResult::Ok,
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
                std::thread::sleep(Duration::from_millis(*ms));
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

    fn execute_service_command(
        &mut self,
        _service: String,
        command: String,
        args: Vec<KeyValue>,
    ) -> CommandResult {
        match &self.role {
            Some(Role::Manager) => Self::manage(&command, &args),
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
