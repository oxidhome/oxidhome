//! Parity between [`authorize`] and the checks it replaced.
//!
//! Each [`Site`] is one authorization call site as it stood before
//! `authorize()`: the old check (route `require_scope`, the shared
//! `authorize_device_command`, the inline `plugins.*` constraint
//! checks, the install gate, `can_read_blobs`) next to the (action,
//! resource) the site now asks `authorize` about. Every site runs
//! against a table of tokens and targets; the two must agree on
//! allow / deny and on the deny's audit label.
//!
//! Tokens a transport's bearer middleware refuses at verify time
//! (a constraint key or field the transport does not enforce) never
//! reach a handler, so they are skipped for that transport's sites —
//! that admission check is unchanged by `authorize`.

use std::collections::HashMap;

use super::{Action, Resource, authorize};
use crate::api::auth::first_constraint_refusal;
use crate::api::mcp::MCP_ENFORCED_CONSTRAINTS;
use crate::api::scopes::{self, Scope, require_scope};
use crate::auth::policy::{DEVICE_COMMAND_ENFORCED, EnforcedConstraint};
use crate::auth::{
    Actor, ActorKind, InvocationContext, Principal, ToolConstraint, Transport,
    authorize_device_command,
};

type Legacy = fn(&Actor, &str) -> Result<(), &'static str>;
type Modern = fn(&str) -> (Action, Resource);

/// One call site: where it is, which transport's admission applies,
/// the old check, and what it now asks `authorize`.
struct Site {
    name: &'static str,
    transport: Transport,
    legacy: Legacy,
    modern: Modern,
}

fn scope(actor: &Actor, required: Scope) -> Result<(), &'static str> {
    require_scope(actor, required).map_err(|d| d.required)
}

/// The inline `plugins.*` check the MCP tools ran after the scope
/// check, before `authorize` (14.4c).
fn legacy_plugin_constraint(
    actor: &Actor,
    key: &str,
    sentinel: &'static str,
    plugin_id: &str,
) -> Result<(), &'static str> {
    if let Some(cx) = actor.constraint(key)
        && !cx.allows_plugin(plugin_id)
    {
        return Err(sentinel);
    }
    Ok(())
}

/// The 14.4d install gate: the captured constraint against the
/// manifest-derived id.
fn legacy_install_gate(actor: &Actor, plugin_id: &str) -> Result<(), &'static str> {
    let constraint = actor.constraint("plugins.install").cloned();
    if let Some(cx) = &constraint
        && !cx.allows_plugin(plugin_id)
    {
        return Err("constraint:plugins.install:plugins");
    }
    Ok(())
}

macro_rules! flat {
    ($name:expr, $transport:expr, $scope:expr, $action:expr, $resource:expr) => {
        Site {
            name: $name,
            transport: $transport,
            legacy: |a, _| scope(a, $scope),
            modern: |_t| ($action, $resource),
        }
    };
}

#[allow(clippy::too_many_lines)]
fn sites() -> Vec<Site> {
    use Transport::{Connect, McpHttp, Rest};
    vec![
        // ── REST (`api/server.rs`) ──
        flat!(
            "rest GET /config",
            Rest,
            scopes::STATUS_READ,
            Action::HostStatus,
            Resource::Host
        ),
        flat!(
            "rest GET /instances",
            Rest,
            scopes::INSTANCES_LIST,
            Action::InstanceRead,
            Resource::instances()
        ),
        flat!(
            "rest GET /devices",
            Rest,
            scopes::DEVICES_LIST,
            Action::DeviceList,
            Resource::devices()
        ),
        Site {
            name: "rest GET /devices/{id}/state",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::DEVICES_READ),
            modern: |t| (Action::DeviceRead, Resource::device(t)),
        },
        flat!(
            "rest GET /devices/state",
            Rest,
            scopes::DEVICES_READ,
            Action::DeviceRead,
            Resource::devices()
        ),
        flat!(
            "rest GET /devices/state/changes",
            Rest,
            scopes::DEVICES_READ,
            Action::DeviceRead,
            Resource::devices()
        ),
        Site {
            name: "rest POST /devices/{id}/command",
            transport: Rest,
            legacy: |a, t| {
                scope(a, scopes::DEVICES_COMMAND)?;
                authorize_device_command(a, t)
            },
            modern: |t| (Action::DeviceCommand, Resource::device(t)),
        },
        flat!(
            "rest GET /plugins",
            Rest,
            scopes::PLUGINS_LIST,
            Action::PluginRead,
            Resource::plugins()
        ),
        Site {
            name: "rest GET /plugins/{id}/schema",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::PLUGINS_LIST),
            modern: |t| (Action::PluginRead, Resource::plugin(t)),
        },
        flat!(
            "rest POST /plugins",
            Rest,
            scopes::PLUGINS_INSTALL,
            Action::PluginInstall,
            Resource::Host
        ),
        Site {
            name: "rest POST /plugins/{id}/start",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::PLUGINS_START),
            modern: |t| (Action::InstanceStart, Resource::instance(t, None)),
        },
        Site {
            name: "rest POST /plugins/{id}/stop",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::PLUGINS_STOP),
            modern: |t| {
                (
                    Action::InstanceStop,
                    Resource::instance(t, Some("inst".into())),
                )
            },
        },
        Site {
            name: "rest DELETE /plugins/{id}",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::PLUGINS_UNINSTALL),
            modern: |t| (Action::PluginUninstall, Resource::plugin(t)),
        },
        Site {
            name: "rest POST /plugins/{id}/ui-session",
            transport: Rest,
            legacy: |a, _| scope(a, scopes::PLUGINS_UI),
            modern: |t| (Action::PluginUi, Resource::plugin(t)),
        },
        flat!(
            "rest GET /events/tail",
            Rest,
            scopes::EVENTS_TAIL,
            Action::EventSubscribe,
            Resource::events()
        ),
        flat!(
            "rest GET /events/tail?after_id",
            Rest,
            scopes::EVENTS_READ,
            Action::EventRead,
            Resource::events()
        ),
        flat!(
            "rest GET /logs",
            Rest,
            scopes::LOGS_READ,
            Action::HostLogs,
            Resource::Host
        ),
        flat!(
            "rest GET /events",
            Rest,
            scopes::EVENTS_READ,
            Action::EventRead,
            Resource::events()
        ),
        flat!(
            "rest GET /audit",
            Rest,
            scopes::AUDIT_READ,
            Action::HostAudit,
            Resource::Host
        ),
        flat!(
            "rest GET /dashboards",
            Rest,
            scopes::DASHBOARDS_READ,
            Action::DashboardRead,
            Resource::dashboards()
        ),
        flat!(
            "rest GET /dashboards/{id}",
            Rest,
            scopes::DASHBOARDS_READ,
            Action::DashboardRead,
            Resource::dashboard(7)
        ),
        flat!(
            "rest POST /dashboards",
            Rest,
            scopes::DASHBOARDS_WRITE,
            Action::DashboardWrite,
            Resource::dashboards()
        ),
        flat!(
            "rest PUT/DELETE /dashboards/{id}",
            Rest,
            scopes::DASHBOARDS_WRITE,
            Action::DashboardWrite,
            Resource::dashboard(7)
        ),
        flat!(
            "rest bytes-val withholding",
            Rest,
            scopes::BLOBS_READ,
            Action::BlobRead,
            Resource::blobs()
        ),
        // ── Connect (`api/connect_rpc.rs`) ──
        flat!(
            "connect ListInstances",
            Connect,
            scopes::INSTANCES_LIST,
            Action::InstanceRead,
            Resource::instances()
        ),
        flat!(
            "connect ListDevices",
            Connect,
            scopes::DEVICES_LIST,
            Action::DeviceList,
            Resource::devices()
        ),
        Site {
            name: "connect ExecuteCommand",
            transport: Connect,
            legacy: |a, t| {
                scope(a, scopes::DEVICES_COMMAND)?;
                authorize_device_command(a, t)
            },
            modern: |t| (Action::DeviceCommand, Resource::device(t)),
        },
        Site {
            name: "connect GetDeviceState",
            transport: Connect,
            legacy: |a, _| scope(a, scopes::DEVICES_READ),
            modern: |t| (Action::DeviceRead, Resource::device(t)),
        },
        flat!(
            "connect ListDeviceState(Changes)",
            Connect,
            scopes::DEVICES_READ,
            Action::DeviceRead,
            Resource::devices()
        ),
        flat!(
            "connect ListPlugins",
            Connect,
            scopes::PLUGINS_LIST,
            Action::PluginRead,
            Resource::plugins()
        ),
        flat!(
            "connect InstallPlugin",
            Connect,
            scopes::PLUGINS_INSTALL,
            Action::PluginInstall,
            Resource::Host
        ),
        Site {
            name: "connect StartPlugin",
            transport: Connect,
            legacy: |a, _| scope(a, scopes::PLUGINS_START),
            modern: |t| (Action::InstanceStart, Resource::instance(t, None)),
        },
        Site {
            name: "connect StopPlugin",
            transport: Connect,
            legacy: |a, _| scope(a, scopes::PLUGINS_STOP),
            modern: |t| (Action::InstanceStop, Resource::instance(t, None)),
        },
        Site {
            name: "connect UninstallPlugin",
            transport: Connect,
            legacy: |a, _| scope(a, scopes::PLUGINS_UNINSTALL),
            modern: |t| (Action::PluginUninstall, Resource::plugin(t)),
        },
        flat!(
            "connect QueryLogs",
            Connect,
            scopes::LOGS_READ,
            Action::HostLogs,
            Resource::Host
        ),
        flat!(
            "connect TailEvents",
            Connect,
            scopes::EVENTS_TAIL,
            Action::EventSubscribe,
            Resource::events()
        ),
        flat!(
            "connect TailEvents after_id",
            Connect,
            scopes::EVENTS_READ,
            Action::EventRead,
            Resource::events()
        ),
        flat!(
            "connect bytes-val withholding",
            Connect,
            scopes::BLOBS_READ,
            Action::BlobRead,
            Resource::blobs()
        ),
        // ── MCP tools (`api/mcp/tools.rs`): route pre-check ──
        flat!(
            "mcp tool device.send_command pre-check",
            McpHttp,
            scopes::DEVICES_COMMAND,
            Action::DeviceCommand,
            Resource::devices()
        ),
        flat!(
            "mcp tool logs.query",
            McpHttp,
            scopes::LOGS_READ,
            Action::HostLogs,
            Resource::Host
        ),
        flat!(
            "mcp tool events.history / events.subscribe",
            McpHttp,
            scopes::EVENTS_READ,
            Action::EventRead,
            Resource::events()
        ),
        flat!(
            "mcp tool plugins.list / plugins.show pre-check",
            McpHttp,
            scopes::PLUGINS_LIST,
            Action::PluginRead,
            Resource::plugins()
        ),
        flat!(
            "mcp tool plugins.stop pre-check",
            McpHttp,
            scopes::PLUGINS_STOP,
            Action::InstanceStop,
            Resource::instances()
        ),
        flat!(
            "mcp tool plugins.uninstall pre-check",
            McpHttp,
            scopes::PLUGINS_UNINSTALL,
            Action::PluginUninstall,
            Resource::plugins()
        ),
        flat!(
            "mcp tool plugins.start pre-check",
            McpHttp,
            scopes::PLUGINS_START,
            Action::InstanceStart,
            Resource::instances()
        ),
        flat!(
            "mcp tool plugins.install pre-check",
            McpHttp,
            scopes::PLUGINS_INSTALL,
            Action::PluginInstall,
            Resource::Host
        ),
        flat!(
            "mcp tool bytes-val withholding",
            McpHttp,
            scopes::BLOBS_READ,
            Action::BlobRead,
            Resource::blobs()
        ),
        // ── MCP tools: per-target checks (pre-check passed first) ──
        Site {
            name: "mcp tool device.send_command",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::DEVICES_COMMAND)?;
                authorize_device_command(a, t)
            },
            modern: |t| (Action::DeviceCommand, Resource::device(t)),
        },
        Site {
            name: "mcp tool plugins.show",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::PLUGINS_LIST)?;
                legacy_plugin_constraint(a, "plugins.show", "constraint:plugins.show:plugins", t)
            },
            modern: |t| (Action::PluginRead, Resource::plugin(t)),
        },
        Site {
            name: "mcp tool plugins.stop",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::PLUGINS_STOP)?;
                legacy_plugin_constraint(a, "plugins.stop", "constraint:plugins.stop:plugins", t)
            },
            modern: |t| (Action::InstanceStop, Resource::instance(t, None)),
        },
        Site {
            name: "mcp tool plugins.uninstall",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::PLUGINS_UNINSTALL)?;
                legacy_plugin_constraint(
                    a,
                    "plugins.uninstall",
                    "constraint:plugins.uninstall:plugins",
                    t,
                )
            },
            modern: |t| (Action::PluginUninstall, Resource::plugin(t)),
        },
        Site {
            name: "mcp tool plugins.start",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::PLUGINS_START)?;
                legacy_plugin_constraint(a, "plugins.start", "constraint:plugins.start:plugins", t)
            },
            modern: |t| {
                (
                    Action::InstanceStart,
                    Resource::instance(t, Some("inst".into())),
                )
            },
        },
        Site {
            name: "mcp tool plugins.install gate",
            transport: McpHttp,
            legacy: |a, t| {
                scope(a, scopes::PLUGINS_INSTALL)?;
                legacy_install_gate(a, t)
            },
            modern: |t| (Action::PluginInstall, Resource::plugin(t)),
        },
        // ── MCP resources (`api/mcp/resources.rs`) ──
        flat!(
            "mcp resource devices",
            McpHttp,
            scopes::DEVICES_LIST,
            Action::DeviceList,
            Resource::devices()
        ),
        Site {
            name: "mcp resource devices/{id}",
            transport: McpHttp,
            legacy: |a, _| scope(a, scopes::DEVICES_LIST),
            modern: |t| (Action::DeviceList, Resource::device(t)),
        },
        flat!(
            "mcp resource plugins and plugins/{id}",
            McpHttp,
            scopes::PLUGINS_LIST,
            Action::PluginRead,
            Resource::plugins()
        ),
        flat!(
            "mcp resource events",
            McpHttp,
            scopes::EVENTS_READ,
            Action::EventRead,
            Resource::events()
        ),
        flat!(
            "mcp resource logs",
            McpHttp,
            scopes::LOGS_READ,
            Action::HostLogs,
            Resource::Host
        ),
        flat!(
            "mcp resource status / config",
            McpHttp,
            scopes::STATUS_READ,
            Action::HostStatus,
            Resource::Host
        ),
        Site {
            name: "mcp resource blobs/{instance}/{name}",
            transport: McpHttp,
            legacy: |a, _| scope(a, scopes::BLOBS_READ),
            modern: |t| (Action::BlobRead, Resource::blob(t, "snap.jpg")),
        },
    ]
}

fn enforced_for(transport: Transport) -> &'static [EnforcedConstraint] {
    match transport {
        Transport::Rest | Transport::Connect => &[DEVICE_COMMAND_ENFORCED],
        Transport::McpHttp => MCP_ENFORCED_CONSTRAINTS,
        Transport::McpStdio | Transport::Host => &[],
    }
}

fn allow(list: &[&str]) -> Option<Vec<String>> {
    Some(list.iter().map(|s| (*s).to_string()).collect())
}

fn constrained(scopes: &[&str], entries: &[(&str, ToolConstraint)]) -> Actor {
    let constraints: HashMap<String, ToolConstraint> = entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    Actor::api_with_policy(
        "tok",
        scopes.iter().map(|s| (*s).to_string()).collect(),
        constraints,
    )
}

fn devices(list: &[&str]) -> ToolConstraint {
    ToolConstraint {
        devices: allow(list),
        plugins: None,
    }
}

fn plugins(list: &[&str]) -> ToolConstraint {
    ToolConstraint {
        devices: None,
        plugins: allow(list),
    }
}

#[allow(clippy::too_many_lines)]
fn tokens() -> Vec<(&'static str, Actor)> {
    let mut out: Vec<(&'static str, Actor)> = vec![
        ("no scopes", Actor::api("tok", vec![])),
        ("wildcard", Actor::api("tok", vec!["*".into()])),
        (
            "wildcard among literals",
            Actor::api("tok", vec!["logs:read".into(), "*".into()]),
        ),
        (
            "near misses",
            Actor::api(
                "tok",
                vec![
                    "Devices:List".into(),
                    "devices:*".into(),
                    " devices:read".into(),
                    "plugins".into(),
                    "**".into(),
                    String::new(),
                ],
            ),
        ),
        (
            "read-only mix",
            Actor::api(
                "tok",
                vec![
                    "devices:list".into(),
                    "devices:read".into(),
                    "plugins:list".into(),
                    "events:read".into(),
                ],
            ),
        ),
        (
            "device allowlist (literal + glob)",
            constrained(
                &["devices:command"],
                &[(
                    "device.send_command",
                    devices(&["dev-a1b2c3d4*", "dev-1122334455667788"]),
                )],
            ),
        ),
        (
            "device allowlist deny-all",
            constrained(&["*"], &[("device.send_command", devices(&[]))]),
        ),
        (
            "device allowlist, no command scope",
            constrained(
                &["devices:list"],
                &[("device.send_command", devices(&["dev-a1b2c3d4*"]))],
            ),
        ),
        (
            "device constraint with unenforced plugins field",
            constrained(
                &["*"],
                &[(
                    "device.send_command",
                    ToolConstraint {
                        devices: allow(&["dev-a1b2c3d4*"]),
                        plugins: allow(&["acme.*"]),
                    },
                )],
            ),
        ),
        (
            "unknown constraint key",
            constrained(&["*"], &[("devices.read", devices(&[]))]),
        ),
        (
            "plugins.* allowlists",
            constrained(
                &["*"],
                &[
                    ("plugins.show", plugins(&["acme.*"])),
                    ("plugins.start", plugins(&["acme.lamp"])),
                    ("plugins.stop", plugins(&["acme.*", "other.p"])),
                    ("plugins.uninstall", plugins(&[])),
                    ("plugins.install", plugins(&["acme.*"])),
                ],
            ),
        ),
        (
            "plugins.* allowlist without scopes",
            constrained(
                &["plugins:list"],
                &[
                    ("plugins.show", plugins(&["acme.*"])),
                    ("plugins.install", plugins(&["acme.*"])),
                ],
            ),
        ),
        (
            "plugins.show with a devices field",
            constrained(&["*"], &[("plugins.show", devices(&["dev-*"]))]),
        ),
        (
            "every constraint at once",
            constrained(
                &["*"],
                &[
                    ("device.send_command", devices(&["dev-ffff*"])),
                    ("plugins.show", plugins(&["other.p"])),
                    ("plugins.start", plugins(&[])),
                    ("plugins.stop", plugins(&["acme.lamp"])),
                    ("plugins.uninstall", plugins(&["acme.*"])),
                    ("plugins.install", plugins(&["other.*"])),
                ],
            ),
        ),
    ];
    for s in [
        "instances:list",
        "devices:list",
        "devices:read",
        "devices:command",
        "events:tail",
        "events:read",
        "logs:read",
        "audit:read",
        "plugins:list",
        "plugins:install",
        "plugins:start",
        "plugins:stop",
        "plugins:uninstall",
        "plugins:ui",
        "dashboards:read",
        "dashboards:write",
        "status:read",
        "blobs:read",
    ] {
        out.push(("single scope", Actor::api("tok", vec![s.into()])));
    }
    out
}

const TARGETS: &[&str] = &[
    "dev-a1b2c3d4e5f60718",
    "dev-a1b2c3d4",
    "dev-1122334455667788",
    "dev-11223344556677882",
    "dev-ffff000000000000",
    "acme.lamp",
    "acme.",
    "other.p",
    "other.q",
    "",
];

#[test]
fn authorize_matches_every_legacy_call_site() {
    let mut compared = 0usize;
    let mut denied = 0usize;
    for site in sites() {
        let enforced = enforced_for(site.transport);
        for (label, actor) in tokens() {
            if first_constraint_refusal(&actor, enforced).is_some() {
                // Refused by the bearer middleware before any handler.
                continue;
            }
            let ctx = InvocationContext::external(Principal::token(
                ActorKind::Api,
                &actor,
                site.transport,
            ));
            for target in TARGETS {
                let old = (site.legacy)(&actor, target);
                let (action, resource) = (site.modern)(target);
                let new = authorize(&ctx, action, &resource).into_result().map(drop);
                assert_eq!(
                    old, new,
                    "{}: token `{label}` {:?} target `{target}`",
                    site.name,
                    actor.scopes(),
                );
                compared += 1;
                denied += usize::from(new.is_err());
            }
        }
    }
    // The table exercises both outcomes heavily.
    assert!(compared > 5_000, "only {compared} comparisons");
    assert!(denied > 1_000 && compared - denied > 1_000);
}

/// The MCP stdio session's ambient `*` actor is allowed everything the
/// old checks allowed it.
#[test]
fn stdio_ambient_actor_matches_legacy() {
    let actor = Actor::api("mcp-stdio-parent-process", vec!["*".into()]);
    let ctx = InvocationContext::external(
        Principal::local_process(ActorKind::Mcp, actor.id(), Transport::McpStdio)
            .with_authority(super::Authority::of_local_process(&actor)),
    );
    for site in sites().into_iter().filter(|s| s.transport == Transport::McpHttp) {
        for target in TARGETS {
            let (action, resource) = (site.modern)(target);
            assert_eq!(
                (site.legacy)(&actor, target),
                authorize(&ctx, action, &resource).into_result().map(drop),
                "{} target `{target}`",
                site.name,
            );
        }
    }
}

/// A constraint-bearing token never reaches a REST / Connect handler
/// unless its only constraint is the device allowlist — the admission
/// check the parity table relies on to skip sites.
#[test]
fn rest_and_connect_admit_only_the_device_allowlist() {
    for (label, actor) in tokens() {
        let admitted = first_constraint_refusal(&actor, enforced_for(Transport::Rest)).is_none();
        let only_device_allowlist = actor.constraint_keys().all(|k| k == "device.send_command")
            && actor
                .constraint("device.send_command")
                .is_none_or(|c| c.plugins.is_none());
        assert_eq!(admitted, only_device_allowlist, "token `{label}`");
    }
}

/// Every action that a scope grants has exactly that scope as its
/// legacy mapping, and the mapping covers every scope constant.
#[test]
fn every_scope_constant_maps_to_one_action() {
    let all = [
        scopes::INSTANCES_LIST,
        scopes::DEVICES_LIST,
        scopes::DEVICES_READ,
        scopes::EVENTS_TAIL,
        scopes::EVENTS_READ,
        scopes::LOGS_READ,
        scopes::AUDIT_READ,
        scopes::DEVICES_COMMAND,
        scopes::PLUGINS_LIST,
        scopes::PLUGINS_INSTALL,
        scopes::PLUGINS_START,
        scopes::PLUGINS_STOP,
        scopes::PLUGINS_UNINSTALL,
        scopes::DASHBOARDS_READ,
        scopes::DASHBOARDS_WRITE,
        scopes::STATUS_READ,
        scopes::BLOBS_READ,
        scopes::PLUGINS_UI,
    ];
    for s in all {
        let actions: Vec<_> = Action::ALL
            .iter()
            .filter(|a| a.legacy_scope().is_some_and(|m| m.name() == s.name()))
            .collect();
        assert_eq!(actions.len(), 1, "scope {} maps to {actions:?}", s.name());
    }
}
