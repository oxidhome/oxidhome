//! Behaviour tests for [`authorize`] that need a larger fixture than
//! the unit tests next to it: the scope-to-action map, the sensitive
//! categories, and sample owner-defined roles checked against an
//! independent oracle, plus the deny list and owner-only actions.

use std::collections::HashMap;

use super::{Action, Resource, ResourceKind, authorize};
use crate::api::scopes;
use crate::auth::{
    Actor, ActorKind, DeviceCategory, DeviceClass, InvocationContext, Principal, SensitiveCategory,
    SensitiveGrant, TokenPolicy, ToolConstraint, Transport,
};

fn devices(list: &[&str]) -> ToolConstraint {
    ToolConstraint {
        devices: Some(list.iter().map(|s| (*s).to_string()).collect()),
        plugins: None,
    }
}

fn plugins(list: &[&str]) -> ToolConstraint {
    ToolConstraint {
        devices: None,
        plugins: Some(list.iter().map(|s| (*s).to_string()).collect()),
    }
}

fn constrained(scopes: &[&str], entries: &[(&str, ToolConstraint)]) -> Actor {
    Actor::api_with_policy(
        "tok",
        scopes.iter().map(|s| (*s).to_string()).collect(),
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    )
}

/// Scopes match exactly: a near miss (case, a `prefix:*`, whitespace,
/// a bare resource name, `**`) grants nothing and is refused with the
/// missing scope.
#[test]
fn near_miss_scopes_grant_nothing() {
    let actor = Actor::api(
        "tok",
        vec![
            "Devices:List".into(),
            "devices:*".into(),
            " devices:read".into(),
            "plugins".into(),
            "**".into(),
            String::new(),
        ],
    );
    let device = Resource::device(
        "dev-a1b2c3d4e5f60718",
        DeviceClass::of(DeviceCategory::Light),
    );
    for (action, resource, want) in [
        (
            Action::DeviceList,
            Resource::Collection(ResourceKind::Device),
            "devices:list",
        ),
        (Action::DeviceRead, device.clone(), "devices:read"),
        (Action::DeviceCommand, device, "devices:command"),
        (
            Action::PluginRead,
            Resource::plugin("acme.lamp"),
            "plugins:list",
        ),
        (Action::HostStatus, Resource::Host, "status:read"),
    ] {
        assert_eq!(
            decide(&actor, action, &resource),
            Err(want),
            "{}",
            action.as_str()
        );
    }
}

/// Each `plugins.*` allowlist narrows only its own action, so one
/// token can start one plugin and uninstall another.
#[test]
fn plugin_allowlists_narrow_only_their_own_action() {
    let actor = constrained(
        &["*"],
        &[
            ("plugins.show", plugins(&["acme.*"])),
            ("plugins.start", plugins(&["acme.lamp"])),
            ("plugins.stop", plugins(&["acme.*", "other.p"])),
            ("plugins.uninstall", plugins(&["other.*"])),
            ("plugins.install", plugins(&[])),
        ],
    );
    let instance = |id: &str| Resource::instance(id, None);
    let plugin = Resource::plugin;
    let cases = [
        (Action::PluginRead, plugin("acme.lamp"), Ok(())),
        (
            Action::PluginRead,
            plugin("other.p"),
            Err("constraint:plugins.show:plugins"),
        ),
        (Action::InstanceStart, instance("acme.lamp"), Ok(())),
        (
            Action::InstanceStart,
            instance("other.p"),
            Err("constraint:plugins.start:plugins"),
        ),
        (Action::InstanceStop, instance("other.p"), Ok(())),
        (
            Action::InstanceStop,
            instance("other.q"),
            Err("constraint:plugins.stop:plugins"),
        ),
        (Action::PluginUninstall, plugin("other.q"), Ok(())),
        (
            Action::PluginUninstall,
            plugin("acme.lamp"),
            Err("constraint:plugins.uninstall:plugins"),
        ),
        (
            Action::PluginInstall,
            plugin("acme.lamp"),
            Err("constraint:plugins.install:plugins"),
        ),
    ];
    for (action, resource, want) in cases {
        assert_eq!(
            decide(&actor, action, &resource),
            want,
            "{} {resource:?}",
            action.as_str()
        );
    }
}

/// A missing scope is reported before a constraint: a token with a
/// device allowlist but no `devices:command` is refused with the
/// scope, whether or not the allowlist covers the device.
#[test]
fn missing_scope_wins_over_a_constraint() {
    let actor = constrained(
        &["devices:list"],
        &[("device.send_command", devices(&["dev-a1b2*"]))],
    );
    for id in ["dev-a1b2c3d4e5f60718", "dev-ffff000000000000"] {
        let target = Resource::device(id, DeviceClass::of(DeviceCategory::Light));
        assert_eq!(
            decide(&actor, Action::DeviceCommand, &target),
            Err("devices:command"),
            "{id}"
        );
    }
    let actor = constrained(
        &["plugins:list"],
        &[("plugins.start", plugins(&["acme.*"]))],
    );
    assert_eq!(
        decide(
            &actor,
            Action::InstanceStart,
            &Resource::instance("acme.lamp", None)
        ),
        Err("plugins:start")
    );
}

/// Every scope constant is the `legacy_scope` of exactly one action.
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
        scopes::SERVICES_CALL,
    ];
    assert_eq!(
        all.len(),
        Action::ALL
            .iter()
            .filter(|a| a.legacy_scope().is_some())
            .count(),
        "a scope constant is missing from the list",
    );
    for s in all {
        let actions: Vec<_> = Action::ALL
            .iter()
            .filter(|a| a.legacy_scope().is_some_and(|m| m.name() == s.name()))
            .collect();
        assert_eq!(actions.len(), 1, "scope {} maps to {actions:?}", s.name());
    }
}

/// A command on a lock, opener or alarm and camera bytes need an
/// explicit sensitive grant on top of the scope (or the owner flag);
/// the wildcard alone is not enough.
#[test]
fn sensitive_targets_need_an_explicit_grant() {
    let dev = "dev-a1b2c3d4e5f60718";
    let wildcard = Actor::api("tok", vec!["*".into()]);
    let command = Actor::api("tok", vec!["devices:command".into()]);
    let blobs = Actor::api("tok", vec!["blobs:read".into()]);
    let owner = Actor::from_token_policy(
        "tok-owner",
        TokenPolicy {
            scopes: vec!["*".into()],
            ..TokenPolicy::default()
        },
        true,
    );
    let granted = |scope: &str, category| {
        Actor::from_token_policy(
            "tok-granted",
            TokenPolicy {
                scopes: vec![scope.into()],
                sensitive: vec![SensitiveGrant::all(category)],
                ..TokenPolicy::default()
            },
            false,
        )
    };
    let decide = |actor: &Actor, action, resource: &Resource| {
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest));
        authorize(&ctx, action, resource).into_result().map(drop)
    };

    for (category, sensitive) in [
        (DeviceCategory::Lock, SensitiveCategory::Lock),
        (DeviceCategory::Opener, SensitiveCategory::Opener),
        (DeviceCategory::Alarm, SensitiveCategory::Alarm),
    ] {
        let target = Resource::device(dev, DeviceClass::of(category));
        for actor in [&wildcard, &command] {
            assert_eq!(
                decide(actor, Action::DeviceCommand, &target),
                Err(sensitive.deny_label()),
                "{category:?}",
            );
        }
        assert_eq!(decide(&owner, Action::DeviceCommand, &target), Ok(()));
        assert_eq!(
            decide(
                &granted("devices:command", sensitive),
                Action::DeviceCommand,
                &target
            ),
            Ok(())
        );
        // Reading the device is unchanged.
        assert_eq!(decide(&wildcard, Action::DeviceRead, &target), Ok(()));
    }

    let camera = Resource::device(dev, DeviceClass::of(DeviceCategory::Camera));
    let camera_blob = Resource::blob("cam", "snap.jpg", true);
    for target in [&camera, &camera_blob] {
        for actor in [&wildcard, &blobs] {
            assert_eq!(
                decide(actor, Action::BlobRead, target),
                Err("sensitive:camera")
            );
        }
        assert_eq!(decide(&owner, Action::BlobRead, target), Ok(()));
        assert_eq!(
            decide(
                &granted("blobs:read", SensitiveCategory::Camera),
                Action::BlobRead,
                target
            ),
            Ok(())
        );
    }
    // Camera *control* is not sensitive (Q4).
    assert_eq!(decide(&wildcard, Action::DeviceCommand, &camera), Ok(()));
}

// ── Roles and the deny list ─────────────────────────────────────────

fn role_actor(roles: &[crate::auth::RoleDef], sensitive: Vec<SensitiveGrant>) -> Actor {
    Actor::from_token_policy(
        "tok-role",
        TokenPolicy {
            roles: roles.iter().map(|r| r.id.clone()).collect(),
            sensitive,
            ..TokenPolicy::default()
        },
        false,
    )
    .with_roles(roles.iter().cloned().map(std::sync::Arc::new).collect())
}

fn decide(actor: &Actor, action: Action, resource: &Resource) -> Result<(), &'static str> {
    let ctx = InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest));
    authorize(&ctx, action, resource).into_result().map(drop)
}

/// Every resource shape the evaluator distinguishes.
fn resources() -> Vec<Resource> {
    let mut out = vec![
        Resource::Host,
        Resource::plugin("acme.lamp"),
        Resource::instance("acme.lamp", Some("lamp".into())),
        Resource::blob("cam", "snap.jpg", true),
        Resource::blob("lamp", "x.bin", false),
        Resource::dashboard(7),
        Resource::service("acme.notify", "n", "notify", "send"),
    ];
    for kind in [
        ResourceKind::Device,
        ResourceKind::Event,
        ResourceKind::Blob,
        ResourceKind::Instance,
        ResourceKind::Plugin,
        ResourceKind::Dashboard,
    ] {
        out.push(Resource::Collection(kind));
        out.push(Resource::PreCheck(kind));
    }
    for category in DeviceCategory::ALL {
        for id in ["dev-a1b2c3d4e5f60718", "dev-ff00000000000000"] {
            out.push(Resource::device(id, DeviceClass::of(category)));
        }
    }
    // Offline: its display category is unknown.
    for id in ["dev-a1b2c3d4e5f60718", "dev-ff00000000000000"] {
        out.push(Resource::device(id, DeviceClass::unregistered()));
    }
    out
}

/// A sample role, through the stored-definition parser.
fn role(name: &str, definition: &str) -> crate::auth::RoleDef {
    crate::auth::RoleDef::parse(
        &format!("role-{:0>16}", name.len()),
        name,
        definition.as_bytes(),
    )
    .unwrap_or_else(|| panic!("{name}: {definition}"))
}

const READ: &[&str] = &[
    "device.list",
    "device.read",
    "event.read",
    "event.subscribe",
    "instance.read",
    "plugin.read",
    "host.status",
    "dashboard.read",
];

/// One oracle grant: actions, categories, device prefix.
type OracleGrant = (
    Vec<&'static str>,
    Option<Vec<DeviceCategory>>,
    Option<&'static str>,
);

/// Sample roles with the oracle's own reading of each:
/// `(role, grants, denied (action, category), sensitive)`.
#[allow(clippy::type_complexity)]
fn samples() -> Vec<(
    crate::auth::RoleDef,
    Vec<OracleGrant>,
    Vec<(&'static str, DeviceCategory)>,
    Vec<SensitiveCategory>,
)> {
    let with = |extra: &[&'static str]| {
        let mut v = READ.to_vec();
        v.extend_from_slice(extra);
        v
    };
    let use_ = vec!["device.list", "device.read", "device.command"];
    vec![
        (
            role(
                "household",
                r#"{"grants":[{"actions":["device.list","device.read","event.read","event.subscribe","instance.read","plugin.read","host.status","dashboard.read","device.command","blob.read"]}]}"#,
            ),
            vec![(with(&["device.command", "blob.read"]), None, None)],
            vec![],
            vec![],
        ),
        (
            role(
                "tablet",
                r#"{"grants":[{"actions":["device.list","device.read","device.command"],"category":["light"]}]}"#,
            ),
            vec![(use_.clone(), Some(vec![DeviceCategory::Light]), None)],
            vec![],
            vec![],
        ),
        (
            role(
                "visitor",
                r#"{"grants":[{"actions":["device.list","device.read","device.command"],"category":["light","media","climate"]}]}"#,
            ),
            vec![(
                use_.clone(),
                Some(vec![
                    DeviceCategory::Light,
                    DeviceCategory::Media,
                    DeviceCategory::Climate,
                ]),
                None,
            )],
            vec![],
            vec![],
        ),
        (
            role(
                "one-device",
                r#"{"grants":[{"actions":["device.read","device.command"],"devices":["dev-a1*"]}]}"#,
            ),
            vec![(vec!["device.read", "device.command"], None, Some("dev-a1"))],
            vec![],
            vec![],
        ),
        (
            role(
                "assistant",
                r#"{"grants":[{"actions":["device.list","device.read","event.read","event.subscribe","instance.read","plugin.read","host.status","dashboard.read"]},{"actions":["device.command"],"category":["light"]}],
                   "deny":[{"actions":["device.command"],"category":["lock"]}]}"#,
            ),
            vec![
                (READ.to_vec(), None, None),
                (
                    vec!["device.command"],
                    Some(vec![DeviceCategory::Light]),
                    None,
                ),
            ],
            vec![("device.command", DeviceCategory::Lock)],
            vec![],
        ),
        (
            role(
                "keyholder",
                r#"{"grants":[{"actions":["device.command"],"category":["lock","light"]}],"sensitive":["lock"]}"#,
            ),
            vec![(
                vec!["device.command"],
                Some(vec![DeviceCategory::Lock, DeviceCategory::Light]),
                None,
            )],
            vec![],
            vec![SensitiveCategory::Lock],
        ),
        (
            role("admin", r#"{"grants":[{"actions":["*"]}]}"#),
            vec![(
                Action::ALL
                    .into_iter()
                    .filter(|a| a.legacy_scope().is_some())
                    .map(Action::as_str)
                    .collect(),
                None,
                None,
            )],
            vec![],
            vec![],
        ),
    ]
}

/// What the oracle expects for one role token without its own
/// sensitive grants.
fn oracle(
    grants: &[OracleGrant],
    denies: &[(&'static str, DeviceCategory)],
    sensitive_granted: &[SensitiveCategory],
    action: Action,
    resource: &Resource,
) -> bool {
    let permitted = grants.iter().any(|(actions, categories, prefix)| {
        actions.contains(&action.as_str())
            && match (categories, prefix, resource) {
                (None, None, _) | (_, _, Resource::PreCheck(ResourceKind::Device)) => true,
                (_, _, Resource::Device(d)) => {
                    categories.as_ref().is_none_or(|c| {
                        d.class().is_registered() && c.contains(&d.class().category())
                    }) && prefix.is_none_or(|p| d.id().starts_with(p))
                }
                _ => false,
            }
    });
    let refused = denies.iter().any(|(a, c)| {
        *a == action.as_str()
            && matches!(resource, Resource::Device(d) if !d.class().is_registered()
                || d.class().category() == *c
                || c.sensitive().is_some_and(|s| d.class().sensitive().contains(s)))
    });
    let needed: Vec<SensitiveCategory> = match (action, resource) {
        (Action::DeviceCommand, Resource::Device(d)) => d
            .class()
            .sensitive()
            .iter()
            .filter(|c| c.guards_commands())
            .collect(),
        (Action::BlobRead, Resource::Device(d)) if d.class().is_camera() => {
            vec![SensitiveCategory::Camera]
        }
        (Action::BlobRead, Resource::Blob(b)) if b.is_camera() => vec![SensitiveCategory::Camera],
        _ => vec![],
    };
    permitted && !refused && needed.iter().all(|c| sensitive_granted.contains(c))
}

#[test]
fn every_role_matches_the_oracle() {
    let mut allowed = 0usize;
    let mut compared = 0usize;
    for (def, grants, denies, sensitive) in samples() {
        let actor = role_actor(std::slice::from_ref(&def), Vec::new());
        for action in Action::ALL {
            for resource in resources() {
                let got = decide(&actor, action, &resource).is_ok();
                assert_eq!(
                    got,
                    oracle(&grants, &denies, &sensitive, action, &resource),
                    "{} {} {resource:?}",
                    def.name,
                    action.as_str()
                );
                compared += 1;
                allowed += usize::from(got);
            }
        }
    }
    assert!(compared > 1_000 && allowed > 200, "{allowed}/{compared}");
}

/// A role whose grants are unnarrowed decides every action and
/// resource like the equivalent scope list does.
#[test]
fn unnarrowed_roles_match_their_scope_equivalents() {
    for (def, _, _, _) in samples()
        .into_iter()
        .filter(|(d, ..)| ["household", "admin"].contains(&d.name.as_str()))
    {
        let scopes: Vec<String> = def
            .actions()
            .iter()
            .filter_map(|a| a.legacy_scope().map(|s| s.name().to_owned()))
            .collect();
        let by_role = role_actor(std::slice::from_ref(&def), Vec::new());
        let by_scope = Actor::api("tok", scopes);
        for action in Action::ALL {
            for resource in resources() {
                assert_eq!(
                    decide(&by_role, action, &resource).is_ok(),
                    decide(&by_scope, action, &resource).is_ok(),
                    "{} {} {resource:?}",
                    def.name,
                    action.as_str(),
                );
            }
        }
    }
}

/// A token whose role ids weren't resolved (or were deleted) holds
/// nothing through them.
#[test]
fn unresolved_role_ids_grant_nothing() {
    let actor = Actor::from_token_policy(
        "tok",
        TokenPolicy {
            roles: vec!["role-00000000000000a1".into()],
            ..TokenPolicy::default()
        },
        false,
    );
    for action in Action::ALL {
        for resource in resources() {
            assert!(decide(&actor, action, &resource).is_err());
        }
    }
}

/// Sensitive grants and constraints apply on top of a role exactly as
/// on top of a scope; the assistant's deny beats a sensitive grant.
#[test]
fn roles_compose_with_sensitive_grants_constraints_and_denies() {
    let by_name = |n: &str| {
        samples()
            .into_iter()
            .find(|(d, ..)| d.name == n)
            .map(|(d, ..)| d)
            .unwrap()
    };
    let lock = Resource::device(
        "dev-a1b2c3d4e5f60718",
        DeviceClass::of(DeviceCategory::Lock),
    );
    let resident = role_actor(
        &[by_name("household")],
        vec![SensitiveGrant::all(SensitiveCategory::Lock)],
    );
    assert_eq!(decide(&resident, Action::DeviceCommand, &lock), Ok(()));
    let assistant = role_actor(
        &[by_name("assistant"), by_name("household")],
        vec![SensitiveGrant::all(SensitiveCategory::Lock)],
    );
    assert_eq!(
        decide(&assistant, Action::DeviceCommand, &lock),
        Err(super::DENIED_LABEL)
    );
    // Not on a light, which the resident role reaches.
    let light = Resource::device(
        "dev-a1b2c3d4e5f60718",
        DeviceClass::of(DeviceCategory::Light),
    );
    assert_eq!(decide(&assistant, Action::DeviceCommand, &light), Ok(()));

    // A 14.4 device allowlist narrows a role's command too.
    let mut constraints = HashMap::new();
    constraints.insert("device.send_command".to_string(), devices(&["dev-ffff*"]));
    let tablet = by_name("tablet");
    let narrowed = Actor::from_token_policy(
        "tok",
        TokenPolicy {
            roles: vec![tablet.id.clone()],
            constraints,
            ..TokenPolicy::default()
        },
        false,
    )
    .with_roles(vec![std::sync::Arc::new(tablet.clone())]);
    assert_eq!(
        decide(&narrowed, Action::DeviceCommand, &light),
        Err("constraint:device.send_command:devices")
    );
    let other_light = Resource::device(
        "dev-ffff000000000000",
        DeviceClass::of(DeviceCategory::Light),
    );
    assert_eq!(
        decide(&narrowed, Action::DeviceCommand, &other_light),
        Ok(())
    );

    // Labels: a scope it lacks entirely, `no-permit` for a role that
    // grants the action elsewhere.
    let dashboard = role_actor(&[tablet], Vec::new());
    assert_eq!(
        decide(&dashboard, Action::HostLogs, &Resource::Host),
        Err("logs:read")
    );
    assert_eq!(
        decide(&dashboard, Action::DeviceCommand, &lock),
        Err(super::NO_PERMIT_LABEL)
    );
}

/// A token's own deny list beats the wildcard and the owner flag, and
/// a deny with a selector never blocks a pre-check.
#[test]
fn deny_list_beats_every_grant() {
    use crate::auth::{ActionSet, DenyRule};
    let deny = vec![
        DenyRule {
            actions: ActionSet::of(&[Action::DeviceCommand]),
            categories: Some(vec![DeviceCategory::Alarm]),
            devices: None,
            services: None,
        },
        DenyRule {
            actions: ActionSet::of(&[Action::HostLogs]),
            categories: None,
            devices: None,
            services: None,
        },
    ];
    for owner in [false, true] {
        let actor = Actor::from_token_policy(
            "tok",
            TokenPolicy {
                scopes: vec!["*".into()],
                sensitive: vec![SensitiveGrant::all(SensitiveCategory::Alarm)],
                deny: deny.clone(),
                ..TokenPolicy::default()
            },
            owner,
        );
        let alarm = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Alarm),
        );
        assert_eq!(
            decide(&actor, Action::DeviceCommand, &alarm),
            Err(super::DENIED_LABEL)
        );
        assert_eq!(
            decide(&actor, Action::HostLogs, &Resource::Host),
            Err(super::DENIED_LABEL)
        );
        assert_eq!(
            decide(
                &actor,
                Action::DeviceCommand,
                &Resource::pre_check(ResourceKind::Device)
            ),
            Ok(())
        );
        let light = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light),
        );
        assert_eq!(decide(&actor, Action::DeviceCommand, &light), Ok(()));
        assert_eq!(decide(&actor, Action::HostStatus, &Resource::Host), Ok(()));
    }
}

/// `token.manage` is the owner's alone, like `policy.manage`.
#[test]
fn token_manage_is_owner_only() {
    let owner = Actor::from_token_policy(
        "tok-owner",
        TokenPolicy {
            scopes: vec!["*".into()],
            ..TokenPolicy::default()
        },
        true,
    );
    assert_eq!(decide(&owner, Action::TokenManage, &Resource::Host), Ok(()));
    assert!(
        decide(
            &Actor::api("tok", vec!["*".into()]),
            Action::TokenManage,
            &Resource::Host
        )
        .is_err()
    );
    for (role, ..) in samples() {
        for action in [Action::TokenManage, Action::PolicyManage] {
            assert!(
                decide(
                    &role_actor(std::slice::from_ref(&role), Vec::new()),
                    action,
                    &Resource::Host
                )
                .is_err()
            );
        }
    }
    // A role's sensitive category reaches the lock it grants.
    let keyholder = samples()
        .into_iter()
        .find(|(d, ..)| d.name == "keyholder")
        .unwrap()
        .0;
    let lock = Resource::device(
        "dev-a1b2c3d4e5f60718",
        DeviceClass::of(DeviceCategory::Lock),
    );
    assert_eq!(
        decide(
            &role_actor(&[keyholder], Vec::new()),
            Action::DeviceCommand,
            &lock
        ),
        Ok(())
    );
}
