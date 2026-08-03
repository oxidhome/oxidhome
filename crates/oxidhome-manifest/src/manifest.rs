//! Manifest types — the deserialized shape of a `manifest.toml`.
//!
//! Layout mirrors the TOML schema sketched in the per-crate plan:
//!
//! ```toml
//! manifest_version = 1
//! [plugin] id = "..." version = "..." world = "plugin" sdk_version = "0.1.0"
//! [runtime] wasm = "..." singleton = false tick_interval_ms = 1000
//!           restart = "on-trap"
//! [capabilities] network = [...] storage_quota_kb = 64 ...
//!                # Phase 7 amendment: declares_services = [...]
//! [config.<key>] type = "bool" default = false description = "..."
//! [ui] config = "ui/config.js" ...                  # Phase 13 amendment
//! [ui.permissions] network = "self-only" ...        # Phase 13 amendment
//! ```
//!
//! Phase 7 / Phase 13 fields are accepted by the deserializer in 0.1
//! so plugin authors can adopt them without a host-side change. Their
//! *enforcement* lands with the phases that use them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::config::ConfigField;
use crate::network::NetworkRule;

/// Top-level `manifest.toml`.
///
/// Use `toml::from_str` to deserialize, then run [`crate::validate()`] to
/// surface every problem in one pass.
//
// `Eq` is omitted on purpose: `ConfigFieldType::Float` carries an
// `f64`, which is `PartialEq` but not `Eq`. `PartialEq` is enough for
// the round-trip tests and for any reasonable equality check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Version of the *manifest format itself*. Only `1` exists today;
    /// see the format-evolution note in the per-crate plan for the
    /// migration policy.
    pub manifest_version: u32,
    pub plugin: PluginSection,
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub capabilities: CapabilitiesSection,
    /// Per-instance config schema. Keys are config field names; the
    /// host renders these into an install dialog and stores user
    /// overrides under the same names.
    #[serde(default)]
    pub config: BTreeMap<String, ConfigField>,
    /// Phase-13 UI fields. Accepted + validated in 0.1, but no host
    /// consumer of `[ui]` panels exists until the UI track ships.
    #[serde(default)]
    pub ui: Option<UiSection>,
}

/// `[plugin]` block — identity, authorship, and the world the plugin
/// implements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSection {
    /// Globally-unique reverse-DNS-style id, e.g. `example.simulated-switch`.
    pub id: String,
    pub name: String,
    /// Semver of the *plugin*, mirrored from its `Cargo.toml`.
    pub version: Version,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    /// Free-form keywords the UI uses for filtering and grouping
    /// (`camera`, `lighting`, `matter`, `home-assistant-compat`, …).
    /// Each is lowercase kebab-case, 1–50 chars; up to
    /// [`crate::validate::MAX_KEYWORDS`] per plugin. Mirrors Cargo's
    /// `[package].keywords` convention.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Which plugin world this component was built against.
    pub world: World,
    /// `oxidhome-sdk` version the plugin was built against. The host
    /// compares this with its own range via [`crate::check_compatibility`].
    pub sdk_version: Version,
}

/// `[runtime]` block — Wasmtime store knobs + the path to the `.wasm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    /// Path to the `.wasm` component, resolved relative to the manifest's
    /// directory by the host loader.
    pub wasm: PathBuf,
    /// `true` ⇒ only one instance of the plugin may run at a time.
    #[serde(default)]
    pub singleton: bool,
    /// `tick()` cadence in ms. `None` ⇒ no ticks. The host rejects a
    /// value below [`crate::validate::MIN_TICK_INTERVAL_MS`].
    #[serde(default)]
    pub tick_interval_ms: Option<u64>,
    /// What the Phase-6 supervisor does when this instance crashes.
    /// Absent ⇒ [`RestartPolicy::OnTrap`].
    #[serde(default)]
    pub restart: RestartPolicy,
}

/// `[capabilities]` block — every host import the plugin wants to use
/// must be authorized here. Call-site gating (not instantiation
/// gating) consults this at runtime: missing or zero values cause the
/// matching host call to return `error::permission-denied(...)`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSection {
    /// Outbound network rules. Each entry is a typed
    /// [`NetworkRule`] parsed from the TOML string form
    /// (`"tcp://mqtt.example.com:1883"`, `"udp://192.168.1.0/24:5353"`,
    /// `"https://*.api.example.com"`, …).
    #[serde(default)]
    pub network: Vec<NetworkRule>,
    /// Per-instance KV quota (KiB). `0` (or absent) ⇒
    /// `storage::*` calls return `permission-denied`.
    #[serde(default)]
    pub storage_quota_kb: u64,
    /// Per-instance blob-store quota (MiB). `0` (or absent) ⇒
    /// `blob-store::*` calls return `permission-denied`.
    #[serde(default)]
    pub blob_quota_mb: u64,
    /// Device capabilities this plugin may register. Other capability
    /// names hit `permission-denied` from `register-device`.
    #[serde(default)]
    pub declares_devices: Vec<String>,
    /// Service names this plugin may register (Phase 7). Empty / absent
    /// ⇒ `register-service` returns `permission-denied`.
    #[serde(default)]
    pub declares_services: Vec<String>,
    /// H10: structured grants describing which services this plugin
    /// may invoke via `host-services::call-service`. Each entry is
    /// a resource selector on `(plugin, instance, service,
    /// commands, caller_instance)` — see [`ServiceGrant`]. Empty
    /// / absent ⇒ every cross-plugin `call-service` returns
    /// `permission-denied` before the callee's
    /// `execute-service-command` runs.
    ///
    /// The dispatch check runs on the target service's
    /// **immutable** `local-id` (not the human-readable `name`),
    /// so a callee that renames its service in `update-service`
    /// cannot silently bypass or shadow a grant.
    ///
    /// **Authorization is requested ∧ granted, checked at
    /// dispatch (H10 round-4).** The manifest-declared list here
    /// is the plugin's *requested* set. The operator-approved
    /// copy in `plugin_installation.granted_capabilities_json` is
    /// the *granted* set. A call is authorized iff **at least one
    /// entry in each list** matches the target-tuple. The granted
    /// copy does **not** simply override the request — both are
    /// consulted per call, so the plugin's manifest still acts as
    /// a ceiling (a call the plugin didn't request cannot be
    /// authorized just because the operator granted it). This
    /// mirrors requested ∩ granted semantics without materializing
    /// the intersection (which was O(N²) in a prior round). The
    /// list length is capped at
    /// [`crate::validate::MAX_CONSUMES_SERVICES_GRANTS`] and each
    /// entry's `commands` at
    /// [`crate::validate::MAX_COMMANDS_PER_GRANT`]; the host
    /// applies the same caps when loading the persisted grant.
    #[serde(default)]
    pub consumes_services: Vec<ServiceGrant>,
    /// Whether the plugin is allowed to observe the host event bus
    /// via `host-events::subscribe`. `false` (or absent) ⇒ every
    /// `subscribe` call returns `permission-denied`.
    /// Architecture-review C2c — before this gate every plugin
    /// could read every event, including ones published by
    /// unrelated instances. Publishers gate themselves through the
    /// C2/C2b ownership + capability checks; the subscribe side
    /// needs its own capability so the "who sees what" surface is
    /// declared in the manifest and reviewable at install time.
    #[serde(default)]
    pub subscribes_events: bool,
}

/// H10: one resource selector inside `[capabilities] consumes_services`.
///
/// Written as an array-of-tables in the manifest so a plugin can
/// list several distinct grants — different services, different
/// instances, or different command subsets — without collapsing
/// them into one plugin-wide toggle:
///
/// ```toml
/// [[capabilities.consumes_services]]
/// plugin          = "example.service-counter"
/// instance        = "counter"          # or "*" for any live instance
/// service         = "counter"          # immutable local-id of the target service
/// commands        = ["increment", "get"]  # or ["*"] for any command
/// caller_instance = "*"                # optional; narrows to specific caller instances
/// ```
///
/// The dispatcher authorizes a `call-service` when at least one
/// grant entry matches all five axes — plugin (exact), target
/// instance (exact or `*`), service local-id (exact — must be
/// immutable), command (in the list, or the list contains `*`),
/// and caller instance (exact or `*`). Empty `commands` is *not*
/// implicitly "any"; it means "no commands are authorized under
/// this grant", so an operator can seed the grant structure
/// without opening any call path.
///
/// **`caller_instance` scoping (H10 round-3).** Plugin-authored
/// manifests typically leave this `"*"` (all instances of the
/// caller may use the grant). Operator-narrowed granted copies
/// (persisted in `plugin_installation.granted_capabilities_json`)
/// can pin the grant to specific caller instances, so a
/// multi-instance caller plugin doesn't get one instance's grant
/// applied to every other instance. The wildcard `"*"` is a
/// reserved sentinel: `Engine::start_instance` refuses `"*"` as
/// an instance-id, and `register-service` refuses `"*"` as a
/// command name, so a real identifier can never collide with the
/// wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceGrant {
    /// `plugin.id` of the target plugin. Exact-match, no wildcards.
    /// A plugin listing its own id here (self-referential) authorizes
    /// A→B calls between two instances of the same plugin.
    pub plugin: String,
    /// Target instance selector: an exact instance-id (as passed to
    /// `Engine::start_instance`) or the string `"*"` to match any
    /// live instance of `plugin`.
    pub instance: String,
    /// Target service's `local-id` — the immutable per-plugin key
    /// the callee chose at `register-service` time. Not the
    /// human-readable `name`, which `update-service` can change and
    /// which the dispatcher deliberately does not authorize on.
    pub service: String,
    /// Command names this grant authorizes. Either a list of exact
    /// command names, or a list containing `"*"` to authorize every
    /// command the target service exposes.
    #[serde(default)]
    pub commands: Vec<String>,
    /// **Caller** instance selector. Defaults to `"*"` (every
    /// instance of the plugin declaring this grant may use it).
    /// Narrowing this to an exact caller instance-id lets an
    /// operator apply the grant to specific caller instances only
    /// — the review-fixed shape for the multi-instance-caller
    /// gap (H10 round-3, finding 2).
    #[serde(default = "any_selector")]
    pub caller_instance: String,
}

fn any_selector() -> String {
    ServiceGrant::ANY.into()
}

impl ServiceGrant {
    /// Wildcard sentinel — reserved at instance-id and command-name
    /// validation boundaries so a real identifier can never look
    /// like the wildcard. See `Engine::start_instance` and
    /// `register-service` for the enforcement points.
    pub const ANY: &'static str = "*";
    /// Instance-selector wildcard sentinel. Kept as a distinct alias
    /// so grant call sites read as "any target instance" rather than
    /// the raw string.
    pub const ANY_INSTANCE: &'static str = Self::ANY;
    /// Commands wildcard sentinel — the element written into
    /// `commands` to authorize every command.
    pub const ANY_COMMAND: &'static str = Self::ANY;
    /// Caller-instance wildcard sentinel — grant applies to every
    /// instance of the declaring plugin.
    pub const ANY_CALLER_INSTANCE: &'static str = Self::ANY;

    /// Does this grant authorize a call on the tuple
    /// `(caller_instance, target_plugin, target_instance,
    /// service_local_id, command)`?
    #[must_use]
    pub fn matches(
        &self,
        caller_instance: &str,
        plugin: &str,
        target_instance: &str,
        service_local_id: &str,
        command: &str,
    ) -> bool {
        self.plugin == plugin
            && self.service == service_local_id
            && Self::selector_matches(&self.instance, target_instance)
            && Self::selector_matches(&self.caller_instance, caller_instance)
            && self
                .commands
                .iter()
                .any(|c| c == Self::ANY_COMMAND || c == command)
    }

    fn selector_matches(selector: &str, value: &str) -> bool {
        selector == Self::ANY || selector == value
    }
}

/// What the Phase-6 instance supervisor does after a crash. A "crash"
/// is the instance's tokio supervisor catching either a Wasmtime trap
/// or a plugin entry point returning `Err`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Restart on any crash, including a clean `init` failure.
    Always,
    /// Restart only on a Wasmtime trap (and, from Phase 7, on a
    /// fuel/memory exhaustion trap). A plugin `init` that returns
    /// `Err` is treated as a permanent misconfiguration and is *not*
    /// retried. This is the default.
    #[default]
    OnTrap,
    /// Never restart — the first crash is terminal.
    Never,
}

impl RestartPolicy {
    /// Stable name as it appears in the manifest TOML (kebab-case).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::Always => "always",
            RestartPolicy::OnTrap => "on-trap",
            RestartPolicy::Never => "never",
        }
    }
}

/// Which plugin world the component was built against. Drives which
/// WASI / host interfaces the host links into the `Linker` at load
/// time.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum World {
    /// Standard integrations, automations, logic. No raw I/O.
    Plugin,
    /// `plugin` + WASI sockets/HTTP for long-lived I/O (Phase 8).
    StreamingPlugin,
    /// `plugin` + `inference` for host-managed ML (Phase 10).
    AiPlugin,
    /// `streaming-plugin` + `inference`.
    StreamingAiPlugin,
}

impl World {
    /// Stable name as it appears in the manifest TOML (kebab-case).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            World::Plugin => "plugin",
            World::StreamingPlugin => "streaming-plugin",
            World::AiPlugin => "ai-plugin",
            World::StreamingAiPlugin => "streaming-ai-plugin",
        }
    }
}

/// Phase-13 `[ui]` block. Asset paths are accepted in 0.1 so plugins
/// can ship a `ui/` directory; the *consumer* of the assets (custom
/// panels / widgets) is 0.2+.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct UiSection {
    #[serde(default)]
    pub config: Option<PathBuf>,
    #[serde(default)]
    pub device_config: Option<PathBuf>,
    #[serde(default)]
    pub commands: Option<PathBuf>,
    #[serde(default)]
    pub widgets: Vec<PathBuf>,
    #[serde(default)]
    pub config_schema: Option<PathBuf>,
    #[serde(default)]
    pub commands_schema: Option<PathBuf>,
    #[serde(default)]
    pub permissions: UiPermissions,
}

/// Phase-13 `[ui.permissions]` block. String values map to CSP
/// directives at asset-serving time; the host enforces them in the
/// route layer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiPermissions {
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub storage: Option<String>,
    #[serde(default)]
    pub scripts: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact sketch from the per-crate plan must round-trip.
    /// Catches accidental schema drift in either direction.
    const SKETCH: &str = r#"
manifest_version = 1

[plugin]
id = "example.simulated-switch"
name = "Simulated Switch"
version = "0.1.0"
authors = ["The OxidHome Contributors"]
description = "A switch with no real hardware backing it."
source = "https://github.com/oxidhome/oxidhome/tree/main/examples/simulated-switch"
license = "MIT OR Apache-2.0"
keywords = ["switch", "example", "simulated"]
world = "plugin"
sdk_version = "0.1.0"

[runtime]
wasm = "simulated-switch.wasm"
singleton = false
tick_interval_ms = 1000
restart = "on-trap"

[capabilities]
network = []
storage_quota_kb = 64
blob_quota_mb = 0
declares_devices = ["switch"]
declares_services = []

[config.default_state]
type = "bool"
default = false
description = "Initial state of the switch."

[ui]
config = "ui/config.js"
device-config = "ui/device.js"
commands = "ui/commands.js"
widgets = ["ui/camera-tile.js"]
config-schema = "ui/config.schema.json"
commands-schema = "ui/commands.schema.json"

[ui.permissions]
network = "self-only"
storage = "session-only"
scripts = "none"
"#;

    #[test]
    fn sketch_parses() {
        let m: PluginManifest = toml::from_str(SKETCH).expect("sketch must parse");
        assert_eq!(m.manifest_version, 1);
        assert_eq!(m.plugin.id, "example.simulated-switch");
        assert_eq!(m.plugin.world, World::Plugin);
        assert_eq!(m.plugin.version, Version::new(0, 1, 0));
        assert_eq!(m.runtime.wasm, PathBuf::from("simulated-switch.wasm"));
        assert_eq!(
            m.plugin.keywords,
            vec![
                "switch".to_owned(),
                "example".to_owned(),
                "simulated".to_owned()
            ],
        );
        assert_eq!(m.runtime.tick_interval_ms, Some(1000));
        assert_eq!(m.runtime.restart, RestartPolicy::OnTrap);
        assert_eq!(m.capabilities.storage_quota_kb, 64);
        assert_eq!(m.capabilities.declares_devices, vec!["switch".to_string()]);
        assert!(m.config.contains_key("default_state"));
        let ui = m.ui.expect("ui present");
        assert_eq!(ui.config, Some(PathBuf::from("ui/config.js")));
        assert_eq!(ui.widgets.len(), 1);
        assert_eq!(ui.permissions.scripts.as_deref(), Some("none"));
    }

    #[test]
    fn sketch_roundtrips() {
        let parsed: PluginManifest = toml::from_str(SKETCH).expect("parse");
        let serialized = toml::to_string(&parsed).expect("serialize");
        let reparsed: PluginManifest = toml::from_str(&serialized).expect("re-parse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let err = toml::from_str::<PluginManifest>(
            r#"
manifest_version = 1
unknown_top_level = "boom"
[plugin]
id = "x"
name = "x"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "x.wasm"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got {err}");
    }

    #[test]
    fn world_strings_match_wit_kebab_case() {
        for (w, s) in [
            (World::Plugin, "plugin"),
            (World::StreamingPlugin, "streaming-plugin"),
            (World::AiPlugin, "ai-plugin"),
            (World::StreamingAiPlugin, "streaming-ai-plugin"),
        ] {
            assert_eq!(w.as_str(), s);
            let parsed: World = toml::from_str(&format!("v = \"{s}\"\n"))
                .map(|v: TestWorld| v.v)
                .unwrap();
            assert_eq!(parsed, w);
        }
    }

    #[derive(Deserialize)]
    struct TestWorld {
        v: World,
    }

    #[test]
    fn restart_policy_defaults_to_on_trap_when_absent() {
        let m: PluginManifest = toml::from_str(
            r#"
manifest_version = 1
[plugin]
id = "x"
name = "x"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "x.wasm"
"#,
        )
        .expect("parse");
        assert_eq!(m.runtime.restart, RestartPolicy::OnTrap);
    }

    #[test]
    fn restart_policy_strings_round_trip() {
        for (p, s) in [
            (RestartPolicy::Always, "always"),
            (RestartPolicy::OnTrap, "on-trap"),
            (RestartPolicy::Never, "never"),
        ] {
            assert_eq!(p.as_str(), s);
            let parsed: RestartPolicy = toml::from_str(&format!("v = \"{s}\"\n"))
                .map(|v: TestRestart| v.v)
                .unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn unknown_restart_policy_is_rejected() {
        let err = toml::from_str::<TestRestart>("v = \"reboot\"\n").unwrap_err();
        assert!(err.to_string().contains("reboot"), "got {err}");
    }

    #[derive(Debug, Deserialize)]
    struct TestRestart {
        v: RestartPolicy,
    }
}

#[cfg(test)]
mod service_grant_tests {
    use super::*;

    /// Default-caller-instance helper: builds a grant that
    /// applies to any caller instance (the plugin-authored
    /// default).
    fn g(plugin: &str, instance: &str, service: &str, commands: &[&str]) -> ServiceGrant {
        ServiceGrant {
            plugin: plugin.into(),
            instance: instance.into(),
            service: service.into(),
            commands: commands.iter().map(|s| (*s).into()).collect(),
            caller_instance: ServiceGrant::ANY_CALLER_INSTANCE.into(),
        }
    }

    /// Exact tuple match: all four axes required, caller wildcard
    /// matches any caller.
    #[test]
    fn matches_exact_tuple() {
        let grant = g("example.counter", "a", "counter", &["increment"]);
        // caller_instance="*" → matches any caller.
        assert!(grant.matches("caller-x", "example.counter", "a", "counter", "increment"));
        // Wrong on any single axis → no match.
        assert!(!grant.matches("caller-x", "example.other", "a", "counter", "increment"));
        assert!(!grant.matches("caller-x", "example.counter", "b", "counter", "increment"));
        assert!(!grant.matches("caller-x", "example.counter", "a", "different", "increment"));
        assert!(!grant.matches("caller-x", "example.counter", "a", "counter", "get"));
    }

    /// `instance = "*"` matches any target instance-id.
    #[test]
    fn instance_wildcard_matches_any_instance() {
        let grant = g("example.counter", "*", "counter", &["increment"]);
        assert!(grant.matches("cx", "example.counter", "a", "counter", "increment"));
        assert!(grant.matches("cx", "example.counter", "b", "counter", "increment"));
        assert!(grant.matches(
            "cx",
            "example.counter",
            "any-name-here",
            "counter",
            "increment"
        ));
        // Other axes still exact.
        assert!(!grant.matches("cx", "example.other", "a", "counter", "increment"));
    }

    /// `commands = ["*"]` matches any command.
    #[test]
    fn command_wildcard_matches_any_command() {
        let grant = g("example.counter", "a", "counter", &["*"]);
        assert!(grant.matches("cx", "example.counter", "a", "counter", "increment"));
        assert!(grant.matches("cx", "example.counter", "a", "counter", "get"));
        assert!(grant.matches("cx", "example.counter", "a", "counter", "anything"));
    }

    /// Empty `commands` authorizes nothing — an operator can seed
    /// the selector shape without opening any call path.
    #[test]
    fn empty_commands_matches_nothing() {
        let grant = g("example.counter", "*", "counter", &[]);
        assert!(!grant.matches("cx", "example.counter", "a", "counter", "increment"));
        assert!(!grant.matches("cx", "example.counter", "a", "counter", "get"));
    }

    /// H10 round-3 finding 2: `caller_instance` scoping. A grant
    /// with an exact caller-instance-id matches only that caller;
    /// the default (`"*"`) matches any.
    #[test]
    fn caller_instance_scoping() {
        let scoped = ServiceGrant {
            plugin: "example.counter".into(),
            instance: "*".into(),
            service: "counter".into(),
            commands: vec!["increment".into()],
            caller_instance: "caller-a".into(),
        };
        // Only the named caller passes.
        assert!(scoped.matches("caller-a", "example.counter", "any", "counter", "increment"));
        assert!(!scoped.matches("caller-b", "example.counter", "any", "counter", "increment"));
        assert!(!scoped.matches(
            "other-caller",
            "example.counter",
            "any",
            "counter",
            "increment"
        ));

        // The default plugin-authored grant (caller_instance="*")
        // matches every caller.
        let any_caller = g("example.counter", "*", "counter", &["increment"]);
        assert!(any_caller.matches("caller-a", "example.counter", "any", "counter", "increment"));
        assert!(any_caller.matches("caller-b", "example.counter", "any", "counter", "increment"));
    }

    #[derive(serde::Deserialize)]
    struct Wrapper {
        grants: Vec<ServiceGrant>,
    }

    /// The array-of-tables shape parses from TOML.
    #[test]
    fn round_trips_from_array_of_tables() {
        let toml_src = r#"
[[grants]]
plugin   = "example.counter"
instance = "*"
service  = "counter"
commands = ["increment", "get"]

[[grants]]
plugin   = "example.other"
instance = "specific"
service  = "svc"
commands = ["*"]
"#;
        let parsed: Wrapper = toml::from_str(toml_src).expect("parse");
        assert_eq!(parsed.grants.len(), 2);
        assert_eq!(parsed.grants[0].plugin, "example.counter");
        assert_eq!(parsed.grants[0].instance, "*");
        assert_eq!(parsed.grants[0].commands, vec!["increment", "get"]);
        assert_eq!(parsed.grants[1].commands, vec!["*"]);
    }
}
