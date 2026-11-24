//! Role presets, resource selectors and the deny list (H6 slice 3).
//!
//! A token can hold **roles** on top of (or instead of) its flat
//! scopes. A role is a host-shipped bundle of grants and denies; it is
//! stored by name in the token policy and expanded by
//! [`crate::auth::authorize()`] on every decision, so a host upgrade
//! that refines a preset applies to every token holding it. There is
//! no second check path: roles, scopes, the 14.4 constraints, the deny
//! list and the sensitive rule are all evaluated in that one function.
//!
//! | Role | Grants | Denies |
//! |------|--------|--------|
//! | `owner` | everything, every sensitive category | — |
//! | `admin` | every action a scope grants, except `plugin.install`, `plugin.uninstall`, `host.audit` | — |
//! | `resident` | the read group, `device.command`, `blob.read`, `dashboard.write`, `plugin.ui` | — |
//! | `guest` | `device.list`, `device.read`, `device.command` on `light`, `media`, `climate` devices | — |
//! | `dashboard` | `device.list`, `device.read`, `device.command` on `light` devices | — |
//! | `monitor` | the read group | — |
//! | `assistant` | the read group, `device.command` on `light` devices | `device.command` on `lock` devices |
//!
//! The **read group** is `device.list`, `device.read`, `event.read`,
//! `event.subscribe`, `instance.read`, `plugin.read`, `host.status`,
//! `dashboard.read`. It excludes `blob.read` (camera bytes), `host.logs`
//! and `host.audit`.
//!
//! `owner` is not assignable: the owner is the token the host recorded
//! at bootstrap or `recover-admin-token` (`auth_token.owner`), never a
//! role named in a policy. No role includes a sensitive category; a
//! token reaches locks, openers, alarms or camera bytes only through an
//! explicit [`crate::auth::SensitiveGrant`] on top of a role or scope
//! that already permits the action.
//!
//! # Selectors
//!
//! A grant narrowed to device categories ([`RoleGrant::categories`])
//! covers one device when the device's host-derived display category is
//! in the list. It also covers a *pre-check* on the device kind
//! ([`crate::auth::Resource::PreCheck`]), since the per-device check
//! follows; it never covers a whole collection (a list or stream that
//! releases every device's data), a plugin, an instance, a blob, a
//! dashboard or the host. List endpoints that filter per device
//! (`GET /api/v1/devices`, Connect `ListDevices`, MCP
//! `oxidhome://devices`) pre-check and then ask per row.
//!
//! # Deny list
//!
//! A [`DenyRule`] names actions (or `*`) and optionally narrows them to
//! device categories and device ids. A matching deny refuses the
//! action whatever grants it: a scope, a role, the wildcard, a
//! sensitive grant, the owner flag. Matching is conservative: a
//! category deny matches a device whose display category *or*
//! sensitive set names the category (and every device not registered
//! right now, whose display category is unknown); any rule with a
//! selector matches
//! a whole collection of devices, events or blobs (which may contain a
//! denied device); a device-narrowed rule matches every blob (a blob
//! names no device) and a category rule a camera instance's blob when
//! it names `camera`. No rule with a selector matches a pre-check, so a
//! deny on locks doesn't stop a token from commanding lights.

use std::fmt;
use std::str::FromStr;

use super::authorize::{Action, Resource, ResourceKind};
use super::category::{DeviceCategory, SensitiveCategory};
use super::policy::match_pattern;

/// A set of [`Action`]s, as a bit set over [`Action::ALL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ActionSet(u32);

impl ActionSet {
    /// No action.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Every action.
    pub const ALL: Self = Self::of(&Action::ALL);

    /// The set of `actions`.
    #[must_use]
    pub const fn of(actions: &[Action]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < actions.len() {
            bits |= actions[i].bit();
            i += 1;
        }
        Self(bits)
    }

    /// `self` with every action of `other` added.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `self` without the actions of `other`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// `true` when `action` is in the set.
    #[must_use]
    pub const fn contains(self, action: Action) -> bool {
        self.0 & action.bit() != 0
    }

    /// `true` for the empty set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The actions in [`Action::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Action> {
        Action::ALL.into_iter().filter(move |a| self.contains(*a))
    }

    /// Wire names: `["*"]` for every action, else each `kind.verb`.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        if self == Self::ALL {
            vec!["*"]
        } else {
            self.iter().map(Action::as_str).collect()
        }
    }

    /// Parse wire names (`kind.verb` or `*`).
    ///
    /// # Errors
    ///
    /// The first unknown name.
    pub fn parse<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, UnknownName> {
        let mut set = Self::empty();
        for name in names {
            set = set.union(if name == "*" {
                Self::ALL
            } else {
                Self::of(&[name.parse()?])
            });
        }
        Ok(set)
    }
}

impl FromIterator<Action> for ActionSet {
    fn from_iter<I: IntoIterator<Item = Action>>(iter: I) -> Self {
        iter.into_iter()
            .fold(Self::empty(), |set, a| set.union(Self::of(&[a])))
    }
}

/// An unknown action or role name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} `{name}`")]
pub struct UnknownName {
    /// `action` or `role`.
    pub kind: &'static str,
    /// The name as given.
    pub name: String,
}

impl FromStr for Action {
    type Err = UnknownName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .ok_or_else(|| UnknownName {
                kind: "action",
                name: s.to_owned(),
            })
    }
}

/// The read group: what `monitor` holds, and the base of `resident`
/// and `assistant`.
const READ: ActionSet = ActionSet::of(&[
    Action::DeviceList,
    Action::DeviceRead,
    Action::EventRead,
    Action::EventSubscribe,
    Action::InstanceRead,
    Action::PluginRead,
    Action::HostStatus,
    Action::DashboardRead,
]);

/// Every action some scope grants: what `*` reaches.
const SCOPED: ActionSet = ActionSet::ALL.without(ActionSet::of(&[
    Action::TokenManage,
    Action::PolicyManage,
    Action::ServiceCall,
    Action::StateRead,
]));

/// The host-admin actions the note marks sensitive and that only an
/// explicit scope (or the owner) reaches.
const SENSITIVE_ADMIN: ActionSet = ActionSet::of(&[
    Action::PluginInstall,
    Action::PluginUninstall,
    Action::HostAudit,
]);

/// List, read and command: what `guest` and `dashboard` may do to their
/// devices.
const DEVICE_USE: ActionSet = ActionSet::of(&[
    Action::DeviceList,
    Action::DeviceRead,
    Action::DeviceCommand,
]);

/// One grant of a role preset: actions, optionally narrowed to device
/// categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleGrant {
    /// Actions granted.
    pub actions: ActionSet,
    /// `None`: every resource. `Some`: only devices whose display
    /// category is listed (and the device pre-check).
    pub categories: Option<&'static [DeviceCategory]>,
}

/// One deny of a role preset: actions, optionally narrowed to device
/// categories. Same matching as a token's [`DenyRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleDeny {
    /// Actions denied.
    pub actions: ActionSet,
    /// `None`: every resource. `Some`: devices that fall under a listed
    /// category.
    pub categories: Option<&'static [DeviceCategory]>,
}

const ADMIN: &[RoleGrant] = &[RoleGrant {
    actions: SCOPED.without(SENSITIVE_ADMIN),
    categories: None,
}];

const RESIDENT: &[RoleGrant] = &[RoleGrant {
    actions: READ.union(ActionSet::of(&[
        Action::DeviceCommand,
        Action::BlobRead,
        Action::DashboardWrite,
        Action::PluginUi,
    ])),
    categories: None,
}];

const GUEST: &[RoleGrant] = &[RoleGrant {
    actions: DEVICE_USE,
    categories: Some(&[
        DeviceCategory::Light,
        DeviceCategory::Media,
        DeviceCategory::Climate,
    ]),
}];

const DASHBOARD: &[RoleGrant] = &[RoleGrant {
    actions: DEVICE_USE,
    categories: Some(&[DeviceCategory::Light]),
}];

const MONITOR: &[RoleGrant] = &[RoleGrant {
    actions: READ,
    categories: None,
}];

const ASSISTANT: &[RoleGrant] = &[
    RoleGrant {
        actions: READ,
        categories: None,
    },
    RoleGrant {
        actions: ActionSet::of(&[Action::DeviceCommand]),
        categories: Some(&[DeviceCategory::Light]),
    },
];

const ASSISTANT_DENY: &[RoleDeny] = &[RoleDeny {
    actions: ActionSet::of(&[Action::DeviceCommand]),
    categories: Some(&[DeviceCategory::Lock]),
}];

/// A host-shipped role preset. Stored by name in the token policy
/// (`"roles": ["resident"]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// The bootstrap / recovered owner token. Not assignable.
    Owner,
    /// Everything a scope grants, except installing and removing
    /// plugins and reading the audit ledger.
    Admin,
    /// A household member: read, command devices, read blobs, edit
    /// dashboards, open plugin UIs.
    Resident,
    /// A visitor: lights, media and climate devices only.
    Guest,
    /// A wall tablet: lights only.
    Dashboard,
    /// Read-only monitoring.
    Monitor,
    /// An AI assistant: read everything, command lights, never locks.
    Assistant,
}

impl Role {
    /// Every role, in display order.
    pub const ALL: [Role; 7] = [
        Role::Owner,
        Role::Admin,
        Role::Resident,
        Role::Guest,
        Role::Dashboard,
        Role::Monitor,
        Role::Assistant,
    ];

    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Resident => "resident",
            Role::Guest => "guest",
            Role::Dashboard => "dashboard",
            Role::Monitor => "monitor",
            Role::Assistant => "assistant",
        }
    }

    /// The label an allow this role decided carries (`role:<name>`),
    /// in place of the scope a scope-granted allow names.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Role::Owner => "role:owner",
            Role::Admin => "role:admin",
            Role::Resident => "role:resident",
            Role::Guest => "role:guest",
            Role::Dashboard => "role:dashboard",
            Role::Monitor => "role:monitor",
            Role::Assistant => "role:assistant",
        }
    }

    /// One line for listings.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Role::Owner => {
                "the bootstrap / recovered owner token: everything, every sensitive category \
                 (not assignable)"
            }
            Role::Admin => {
                "every action a scope grants except plugin.install, plugin.uninstall and \
                 host.audit"
            }
            Role::Resident => {
                "read, device.command, blob.read, dashboard.write and plugin.ui on everything"
            }
            Role::Guest => "list, read and command light, media and climate devices",
            Role::Dashboard => "list, read and command light devices",
            Role::Monitor => {
                "read devices, events, instances, plugins, status and dashboards; no blobs, \
                 logs or audit"
            }
            Role::Assistant => {
                "read like monitor, command light devices; never commands locks (a deny no \
                 grant overrides)"
            }
        }
    }

    /// `false` for `owner`, which only the host assigns.
    #[must_use]
    pub const fn assignable(self) -> bool {
        !matches!(self, Role::Owner)
    }

    /// The grants this role expands to. `owner` has none here: the
    /// owner's standing authority comes from its host-recorded flag.
    #[must_use]
    pub const fn grants(self) -> &'static [RoleGrant] {
        match self {
            Role::Owner => &[],
            Role::Admin => ADMIN,
            Role::Resident => RESIDENT,
            Role::Guest => GUEST,
            Role::Dashboard => DASHBOARD,
            Role::Monitor => MONITOR,
            Role::Assistant => ASSISTANT,
        }
    }

    /// The denies that come with this role.
    #[must_use]
    pub const fn denies(self) -> &'static [RoleDeny] {
        match self {
            Role::Assistant => ASSISTANT_DENY,
            _ => &[],
        }
    }

    /// Every action any grant of this role names.
    #[must_use]
    pub fn actions(self) -> ActionSet {
        self.grants()
            .iter()
            .fold(ActionSet::empty(), |set, g| set.union(g.actions))
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = UnknownName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| UnknownName {
                kind: "role",
                name: s.to_owned(),
            })
    }
}

/// One entry of a token's deny list.
///
/// Wire shape (`"deny"` in the token policy):
///
/// ```json
/// {"actions": ["device.command"], "category": ["lock", "alarm"], "devices": ["dev-a1b2*"]}
/// ```
///
/// `actions` is required and non-empty (`"*"` is every action);
/// `category` and `devices` are optional, non-empty when present, and
/// both must match when both are given. See the module docs for how a
/// deny matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyRule {
    /// Actions denied.
    pub actions: ActionSet,
    /// Device categories the deny is narrowed to.
    pub categories: Option<Vec<DeviceCategory>>,
    /// Device-id patterns (literal or `prefix*`) the deny is narrowed
    /// to.
    pub devices: Option<Vec<String>>,
}

impl DenyRule {
    /// `true` when this rule refuses `action` on `resource`.
    #[must_use]
    pub fn matches(&self, action: Action, resource: &Resource) -> bool {
        deny_matches(
            self.actions,
            self.categories.as_deref(),
            self.devices.as_deref(),
            action,
            resource,
        )
    }

    /// The wire form.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("actions".into(), serde_json::json!(self.actions.names()));
        if let Some(c) = &self.categories {
            obj.insert(
                "category".into(),
                serde_json::json!(c.iter().map(|c| c.as_str()).collect::<Vec<_>>()),
            );
        }
        if let Some(d) = &self.devices {
            obj.insert("devices".into(), serde_json::json!(d));
        }
        serde_json::Value::Object(obj)
    }

    /// A short human form: `device.command@lock,alarm[dev-a1*]`.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut s = self.actions.names().join(",");
        if let Some(c) = &self.categories {
            s.push('@');
            s.push_str(&c.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(","));
        }
        if let Some(d) = &self.devices {
            s.push('[');
            s.push_str(&d.join(" "));
            s.push(']');
        }
        s
    }
}

impl RoleDeny {
    /// `true` when this deny refuses `action` on `resource`.
    #[must_use]
    pub fn matches(&self, action: Action, resource: &Resource) -> bool {
        deny_matches(self.actions, self.categories, None, action, resource)
    }
}

impl RoleGrant {
    /// `true` when this grant permits `action` on `resource`.
    #[must_use]
    pub fn permits(&self, action: Action, resource: &Resource) -> bool {
        if !self.actions.contains(action) {
            return false;
        }
        let Some(categories) = self.categories else {
            return true;
        };
        match resource {
            Resource::Device(d) => categories.contains(&d.class().category()),
            Resource::PreCheck(ResourceKind::Device) => true,
            _ => false,
        }
    }
}

/// Does a device of `category` with sensitive set `sensitive` fall
/// under any of `selected`?
fn falls_under(
    selected: &[DeviceCategory],
    category: DeviceCategory,
    sensitive: super::category::SensitiveSet,
) -> bool {
    selected
        .iter()
        .any(|c| *c == category || c.sensitive().is_some_and(|s| sensitive.contains(s)))
}

/// The shared deny matcher. See the module docs.
fn deny_matches(
    actions: ActionSet,
    categories: Option<&[DeviceCategory]>,
    devices: Option<&[String]>,
    action: Action,
    resource: &Resource,
) -> bool {
    if !actions.contains(action) {
        return false;
    }
    if categories.is_none() && devices.is_none() {
        return true;
    }
    match resource {
        Resource::Device(d) => {
            let class = d.class();
            // An unregistered device's display category is unknown:
            // every category deny matches it.
            categories.is_none_or(|c| {
                !class.is_registered() || falls_under(c, class.category(), class.sensitive())
            }) && devices.is_none_or(|p| p.iter().any(|p| match_pattern(p, d.id())))
        }
        Resource::Blob(b) => {
            // A blob names no device: a device-narrowed deny refuses
            // it (whatever else it narrows to); a category deny refuses
            // a camera instance's blob when it names `camera`.
            devices.is_some()
                || categories.is_none_or(|c| {
                    b.is_camera() && falls_under(c, DeviceCategory::Camera, camera_set())
                })
        }
        // Every device, event or blob: may include a denied device.
        Resource::Collection(ResourceKind::Device | ResourceKind::Event | ResourceKind::Blob) => {
            true
        }
        // A pre-check: the per-target check that follows decides.
        Resource::PreCheck(_)
        | Resource::Collection(_)
        | Resource::Host
        | Resource::Plugin(_)
        | Resource::Instance(_)
        | Resource::Dashboard(_) => false,
    }
}

fn camera_set() -> super::category::SensitiveSet {
    [SensitiveCategory::Camera].into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DeviceClass;

    fn device(category: DeviceCategory) -> Resource {
        Resource::device("dev-a1b2c3d4e5f60718", DeviceClass::of(category))
    }

    /// An offline device's display category is unknown, so every
    /// category deny matches it; a light whose bytes are camera bytes
    /// keeps `light` for a deny on lights.
    #[test]
    fn category_denies_cover_offline_devices_and_camera_bytes() {
        let deny = |action: Action, c: DeviceCategory| DenyRule {
            actions: ActionSet::of(&[action]),
            categories: Some(vec![c]),
            devices: None,
        };
        let offline = Resource::device("dev-a1b2c3d4e5f60718", DeviceClass::unregistered());
        assert!(
            deny(Action::DeviceRead, DeviceCategory::Sensor).matches(Action::DeviceRead, &offline)
        );
        let registered_other = device(DeviceCategory::Other);
        assert!(
            !deny(Action::DeviceRead, DeviceCategory::Sensor)
                .matches(Action::DeviceRead, &registered_other)
        );
        let camera_light = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light).with_camera_bytes(),
        );
        assert!(
            deny(Action::BlobRead, DeviceCategory::Light).matches(Action::BlobRead, &camera_light)
        );
        assert!(
            deny(Action::BlobRead, DeviceCategory::Camera).matches(Action::BlobRead, &camera_light)
        );
    }

    #[test]
    fn names_round_trip() {
        for r in Role::ALL {
            assert_eq!(r.as_str().parse::<Role>(), Ok(r));
            assert_eq!(r.label(), format!("role:{}", r.as_str()));
        }
        for a in Action::ALL {
            assert_eq!(a.as_str().parse::<Action>(), Ok(a));
        }
        assert!("root".parse::<Role>().is_err());
        assert!("device.unlock".parse::<Action>().is_err());
    }

    #[test]
    fn action_set_parses_and_prints() {
        assert_eq!(ActionSet::parse(["*"]), Ok(ActionSet::ALL));
        assert_eq!(ActionSet::ALL.names(), vec!["*"]);
        let s = ActionSet::parse(["device.command", "service.call"]).unwrap();
        assert_eq!(s.names(), vec!["device.command", "service.call"]);
        assert!(ActionSet::parse(["device.command", "nope"]).is_err());
        assert_eq!(ActionSet::ALL.iter().count(), Action::ALL.len());
    }

    #[test]
    fn no_role_grants_owner_only_or_plugin_principal_actions() {
        for r in Role::ALL {
            for a in [
                Action::TokenManage,
                Action::PolicyManage,
                Action::ServiceCall,
                Action::StateRead,
            ] {
                assert!(!r.actions().contains(a), "{r} grants {}", a.as_str());
            }
        }
        // `admin` is `*` minus the explicit-only host actions.
        for a in Action::ALL {
            let expect = a.legacy_scope().is_some() && !SENSITIVE_ADMIN.contains(a);
            assert_eq!(Role::Admin.actions().contains(a), expect, "{}", a.as_str());
        }
    }

    #[test]
    fn category_grants_cover_devices_and_device_pre_checks_only() {
        let g = Role::Dashboard.grants()[0];
        assert!(g.permits(Action::DeviceCommand, &device(DeviceCategory::Light)));
        assert!(!g.permits(Action::DeviceCommand, &device(DeviceCategory::Switch)));
        assert!(!g.permits(Action::DeviceCommand, &device(DeviceCategory::Lock)));
        assert!(g.permits(
            Action::DeviceList,
            &Resource::PreCheck(ResourceKind::Device)
        ));
        assert!(!g.permits(Action::DeviceRead, &Resource::devices()));
        assert!(!g.permits(Action::DeviceRead, &Resource::Host));
        assert!(!g.permits(Action::DeviceRead, &Resource::PreCheck(ResourceKind::Event)));
        assert!(!g.permits(Action::EventRead, &Resource::events()));
    }

    #[test]
    fn deny_matching_is_conservative() {
        let lock = DenyRule {
            actions: ActionSet::of(&[Action::DeviceCommand]),
            categories: Some(vec![DeviceCategory::Lock]),
            devices: None,
        };
        assert!(lock.matches(Action::DeviceCommand, &device(DeviceCategory::Lock)));
        // A light that the host has ever seen as a lock still falls
        // under `lock` through its sensitive set.
        let raised = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light).raised(DeviceCategory::Lock),
        );
        assert!(lock.matches(Action::DeviceCommand, &raised));
        assert!(!lock.matches(Action::DeviceCommand, &device(DeviceCategory::Light)));
        assert!(!lock.matches(Action::DeviceRead, &device(DeviceCategory::Lock)));
        assert!(!lock.matches(
            Action::DeviceCommand,
            &Resource::PreCheck(ResourceKind::Device)
        ));
        assert!(lock.matches(Action::DeviceCommand, &Resource::devices()));
        assert!(!lock.matches(Action::DeviceCommand, &Resource::Host));

        let cam = DenyRule {
            actions: ActionSet::ALL,
            categories: Some(vec![DeviceCategory::Camera]),
            devices: None,
        };
        assert!(cam.matches(Action::BlobRead, &Resource::blob("c", "s", true)));
        assert!(!cam.matches(Action::BlobRead, &Resource::blob("c", "s", false)));
        assert!(cam.matches(Action::BlobRead, &Resource::blobs()));
        assert!(!cam.matches(Action::BlobRead, &Resource::PreCheck(ResourceKind::Blob)));

        let ids = DenyRule {
            actions: ActionSet::ALL,
            categories: None,
            devices: Some(vec!["dev-a1*".into()]),
        };
        assert!(ids.matches(Action::DeviceRead, &device(DeviceCategory::Other)));
        assert!(!ids.matches(
            Action::DeviceRead,
            &Resource::device("dev-ff00000000000000", DeviceClass::other())
        ));
        assert!(ids.matches(Action::BlobRead, &Resource::blob("c", "s", false)));
        // Narrowed to devices and a category: still every blob.
        let both = DenyRule {
            categories: Some(vec![DeviceCategory::Light]),
            ..ids.clone()
        };
        assert!(both.matches(Action::BlobRead, &Resource::blob("c", "s", false)));
        assert!(!ids.matches(Action::PluginRead, &Resource::plugin("acme.lamp")));

        let all = DenyRule {
            actions: ActionSet::of(&[Action::HostLogs]),
            categories: None,
            devices: None,
        };
        assert!(all.matches(Action::HostLogs, &Resource::Host));
        assert!(!all.matches(Action::HostStatus, &Resource::Host));
    }

    #[test]
    fn deny_rule_describes_and_serializes() {
        let d = DenyRule {
            actions: ActionSet::of(&[Action::DeviceCommand]),
            categories: Some(vec![DeviceCategory::Lock, DeviceCategory::Alarm]),
            devices: Some(vec!["dev-a1*".into()]),
        };
        assert_eq!(d.describe(), "device.command@lock,alarm[dev-a1*]");
        assert_eq!(
            d.to_json(),
            serde_json::json!({
                "actions": ["device.command"],
                "category": ["lock", "alarm"],
                "devices": ["dev-a1*"],
            })
        );
    }
}
