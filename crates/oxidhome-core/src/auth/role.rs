//! Owner-defined roles, resource selectors and the deny list (H6
//! slice 3).
//!
//! A **role** is a named bundle the owner stores in the host
//! (`auth_role`, migration 23): grants (actions, optionally narrowed to
//! device categories and device ids), sensitive categories and deny
//! entries. A token policy names its roles by id (`"roles":
//! ["role-…"]`); the bearer middleware resolves those ids to their
//! current definitions on every request, and
//! [`crate::auth::authorize()`] evaluates them. There is no second
//! check path: scopes, roles, the 14.4 constraints, the deny list and
//! the sensitive rule are all evaluated in that one function. Editing
//! a role changes every token holding it from the next request on; a
//! reference to a deleted role grants nothing.
//!
//! The host ships no roles. `owner` is not a role: it is the token the
//! host recorded at bootstrap or `recover-admin-token`
//! (`auth_token.owner`).
//!
//! # Grants
//!
//! A [`RoleGrant`] names actions (`*` is every action a scope can
//! grant; `token.manage`, `policy.manage`, `service.call` and
//! `state.read` can't be granted). Without selectors it covers every
//! resource. With a `category` and / or `devices` selector it covers a
//! device whose display category is listed and whose id matches a
//! pattern, and the *pre-check* on the device kind
//! ([`crate::auth::Resource::PreCheck`]), since the per-device check
//! follows; it never covers a whole collection (a list or stream that
//! releases every device's data), a plugin, an instance, a blob, a
//! dashboard or the host. List endpoints that filter per device
//! (`GET /api/v1/devices`, Connect `ListDevices`, MCP
//! `oxidhome://devices`) pre-check and then ask per row.
//!
//! A role's sensitive categories add to the token's own sensitive
//! grants: they still only apply on top of a grant for the action.
//!
//! # Deny list
//!
//! A [`DenyRule`] (on the token or on one of its roles) names actions
//! (or `*`) and optionally narrows them to device categories and
//! device ids. A matching deny refuses the action whatever grants it:
//! a scope, a role, the wildcard, a sensitive grant, the owner flag.
//! Matching is conservative: a category deny matches a device whose
//! display category *or* sensitive set names the category (and every
//! device not registered right now, whose display category is
//! unknown); any rule with a selector matches a whole collection of
//! devices, events or blobs (which may contain a denied device); a
//! device-narrowed rule matches every blob (a blob names no device) and
//! a category rule a camera instance's blob when it names `camera`. No
//! rule with a selector matches a pre-check, so a deny on locks doesn't
//! stop a token from commanding lights.

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

    /// `true` when every action of `other` is in the set.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    /// `self` with only the actions also in `other`.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
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

/// An unknown action name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} `{name}`")]
pub struct UnknownName {
    /// `action`.
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

/// Every action some scope grants: what `*` reaches, and what a role
/// grant may name.
pub const SCOPED: ActionSet = ActionSet::ALL.without(ActionSet::of(&[
    Action::TokenManage,
    Action::PolicyManage,
    Action::ServiceCall,
    Action::StateRead,
]));

/// The actions a role grant may narrow to devices: the ones whose
/// target is a device. A narrowed `*` means these.
pub const NARROWABLE: ActionSet = ActionSet::of(&[
    Action::DeviceList,
    Action::DeviceRead,
    Action::DeviceCommand,
]);

/// One grant of a role: actions, optionally narrowed to devices.
///
/// Wire shape: `{"actions": ["device.read"], "category": ["light"],
/// "devices": ["dev-a1b2*"]}`; `category` and `devices` are optional,
/// non-empty when present, and both must match when both are given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleGrant {
    /// Actions granted (a subset of [`SCOPED`]).
    pub actions: ActionSet,
    /// Display categories the grant is narrowed to.
    pub categories: Option<Vec<DeviceCategory>>,
    /// Device-id patterns (literal or `prefix*`) the grant is narrowed
    /// to.
    pub devices: Option<Vec<String>>,
}

impl RoleGrant {
    /// `true` when this grant permits `action` on `resource`.
    #[must_use]
    pub fn permits(&self, action: Action, resource: &Resource) -> bool {
        if !self.actions.contains(action) {
            return false;
        }
        if self.categories.is_none() && self.devices.is_none() {
            return true;
        }
        match resource {
            // A category needs a device registered right now: an
            // offline one's display category is unknown.
            Resource::Device(d) => {
                self.categories
                    .as_ref()
                    .is_none_or(|c| d.class().is_registered() && c.contains(&d.class().category()))
                    && self
                        .devices
                        .as_ref()
                        .is_none_or(|p| p.iter().any(|p| match_pattern(p, d.id())))
            }
            Resource::PreCheck(ResourceKind::Device) => true,
            _ => false,
        }
    }

    /// The wire form.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        selector_json(
            self.actions,
            self.categories.as_deref(),
            self.devices.as_deref(),
        )
    }

    /// A short human form: `device.read,device.command@light[dev-a1*]`.
    #[must_use]
    pub fn describe(&self) -> String {
        describe(
            self.actions,
            self.categories.as_deref(),
            self.devices.as_deref(),
        )
    }
}

/// An owner-defined role, resolved from `auth_role` for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDef {
    /// Stable id (`role-<16 hex>`), what token policies reference.
    pub id: String,
    /// Operator-facing name, unique.
    pub name: String,
    /// What the role grants.
    pub grants: Vec<RoleGrant>,
    /// Sensitive categories the role grants (on every device).
    pub sensitive: Vec<SensitiveCategory>,
    /// What the role denies.
    pub deny: Vec<DenyRule>,
}

impl RoleDef {
    /// Every action any grant of this role names.
    #[must_use]
    pub fn actions(&self) -> ActionSet {
        self.grants
            .iter()
            .fold(ActionSet::empty(), |set, g| set.union(g.actions))
    }

    /// The first grant covering `action` on `resource`.
    #[must_use]
    pub fn permits(&self, action: Action, resource: &Resource) -> bool {
        self.grants.iter().any(|g| g.permits(action, resource))
    }

    /// `true` when one of this role's denies refuses `action` on
    /// `resource`.
    #[must_use]
    pub fn denies(&self, action: Action, resource: &Resource) -> bool {
        self.deny.iter().any(|d| d.matches(action, resource))
    }

    /// The stored definition (`auth_role.definition`): everything but
    /// the id and name.
    #[must_use]
    pub fn definition_json(&self) -> Vec<u8> {
        serde_json::json!({
            "grants": self.grants.iter().map(RoleGrant::to_json).collect::<Vec<_>>(),
            "sensitive": self.sensitive.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "deny": self.deny.iter().map(DenyRule::to_json).collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes()
    }

    /// Parse a stored definition. `None` when it is malformed (unknown
    /// field, action, category or sensitive category; an action no
    /// scope grants; an empty or unmatchable selector): the role then
    /// grants nothing.
    #[must_use]
    pub fn parse(id: &str, name: &str, definition: &[u8]) -> Option<Self> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            grants: Vec<SelectorWire>,
            #[serde(default)]
            sensitive: Vec<String>,
            #[serde(default)]
            deny: Vec<SelectorWire>,
        }
        // An object only: serde would also read `[]` as an empty one.
        if !matches!(
            serde_json::from_slice(definition),
            Ok(serde_json::Value::Object(_))
        ) {
            return None;
        }
        let wire: Wire = serde_json::from_slice(definition).ok()?;
        let mut grants = Vec::with_capacity(wire.grants.len());
        for g in wire.grants {
            let wildcard = g.actions.iter().any(|a| a == "*");
            let (actions, categories, devices) = g.into_parts()?;
            // `*` is every action a scope grants; naming one no scope
            // grants refuses the definition.
            let allowed = if categories.is_some() || devices.is_some() {
                NARROWABLE
            } else {
                SCOPED
            };
            let actions = if wildcard {
                actions.intersection(allowed)
            } else if allowed.contains_all(actions) {
                actions
            } else {
                return None;
            };
            grants.push(RoleGrant {
                actions,
                categories,
                devices,
            });
        }
        let mut sensitive = Vec::with_capacity(wire.sensitive.len());
        for c in &wire.sensitive {
            let c: SensitiveCategory = c.parse().ok()?;
            if !sensitive.contains(&c) {
                sensitive.push(c);
            }
        }
        let mut deny = Vec::with_capacity(wire.deny.len());
        for d in wire.deny {
            let (actions, categories, devices) = d.into_parts()?;
            deny.push(DenyRule {
                actions,
                categories,
                devices,
            });
        }
        Some(Self {
            id: id.to_owned(),
            name: name.to_owned(),
            grants,
            sensitive,
            deny,
        })
    }
}

/// Wire form of a grant or deny: `{actions, category?, devices?}`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorWire {
    actions: Vec<String>,
    #[serde(default)]
    category: Option<Vec<String>>,
    #[serde(default)]
    devices: Option<Vec<String>>,
}

/// Parsed parts of a [`SelectorWire`].
type SelectorParts = (ActionSet, Option<Vec<DeviceCategory>>, Option<Vec<String>>);

impl SelectorWire {
    /// `None` for an unknown action or category, an empty list or a
    /// device pattern no device id can match: a selector that names
    /// nothing would silently match nothing.
    pub(crate) fn into_parts(self) -> Option<SelectorParts> {
        if self.actions.is_empty()
            || self.category.as_ref().is_some_and(Vec::is_empty)
            || self.devices.as_ref().is_some_and(|d| {
                d.is_empty() || !d.iter().all(|p| crate::state::is_device_pattern(p))
            })
        {
            return None;
        }
        let actions = ActionSet::parse(self.actions.iter().map(String::as_str)).ok()?;
        let categories = self
            .category
            .map(|c| {
                let mut out: Vec<DeviceCategory> = Vec::with_capacity(c.len());
                for c in &c {
                    let c = c.parse().ok()?;
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
                Some(out)
            })
            .map_or(Some(None), |c| c.map(Some))?;
        Some((actions, categories, self.devices))
    }
}

/// `true` for a role id: `role-` and 16 lowercase hex digits.
#[must_use]
pub fn is_role_id(id: &str) -> bool {
    id.strip_prefix("role-").is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `true` for a role name: 1–32 of `a-z`, `0-9`, `-`, `_`, starting
/// with a letter, and not `owner` (which names the host's owner token
/// in listings).
#[must_use]
pub fn is_role_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name != OWNER_LABEL
}

/// What listings call the owner token's standing authority. Not a
/// role and not assignable.
pub const OWNER_LABEL: &str = "owner";

fn selector_json(
    actions: ActionSet,
    categories: Option<&[DeviceCategory]>,
    devices: Option<&[String]>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("actions".into(), serde_json::json!(actions.names()));
    if let Some(c) = categories {
        obj.insert(
            "category".into(),
            serde_json::json!(c.iter().map(|c| c.as_str()).collect::<Vec<_>>()),
        );
    }
    if let Some(d) = devices {
        obj.insert("devices".into(), serde_json::json!(d));
    }
    serde_json::Value::Object(obj)
}

fn describe(
    actions: ActionSet,
    categories: Option<&[DeviceCategory]>,
    devices: Option<&[String]>,
) -> String {
    let mut s = actions.names().join(",");
    if let Some(c) = categories {
        s.push('@');
        s.push_str(&c.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(","));
    }
    if let Some(d) = devices {
        s.push('[');
        s.push_str(&d.join(" "));
        s.push(']');
    }
    s
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
        selector_json(
            self.actions,
            self.categories.as_deref(),
            self.devices.as_deref(),
        )
    }

    /// A short human form: `device.command@lock,alarm[dev-a1*]`.
    #[must_use]
    pub fn describe(&self) -> String {
        describe(
            self.actions,
            self.categories.as_deref(),
            self.devices.as_deref(),
        )
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
        for a in Action::ALL {
            assert_eq!(a.as_str().parse::<Action>(), Ok(a));
        }
        assert!("device.unlock".parse::<Action>().is_err());
        assert!(is_role_id("role-0123456789abcdef"));
        assert!(!is_role_id("role-0123"));
        assert!(is_role_name("hall-tablet_2"));
        for bad in ["", "owner", "Tablet", "2nd", "a b", &"x".repeat(33)] {
            assert!(!is_role_name(bad), "{bad}");
        }
    }

    #[test]
    fn action_set_parses_and_prints() {
        assert_eq!(ActionSet::parse(["*"]), Ok(ActionSet::ALL));
        assert_eq!(ActionSet::ALL.names(), vec!["*"]);
        let s = ActionSet::parse(["device.command", "service.call"]).unwrap();
        assert_eq!(s.names(), vec!["device.command", "service.call"]);
        assert!(ActionSet::parse(["device.command", "nope"]).is_err());
        assert_eq!(ActionSet::ALL.iter().count(), Action::ALL.len());
        assert!(SCOPED.contains_all(ActionSet::of(&[Action::DeviceRead])));
        assert!(!SCOPED.contains_all(ActionSet::of(&[Action::DeviceRead, Action::TokenManage])));
    }

    fn role(definition: &str) -> Option<RoleDef> {
        RoleDef::parse("role-0123456789abcdef", "r", definition.as_bytes())
    }

    #[test]
    fn definitions_parse_round_trip_and_refuse_what_no_scope_grants() {
        let def = role(
            r#"{"grants":[{"actions":["device.read","device.command"],"category":["light","light"],"devices":["dev-a1*"]}],
                "sensitive":["lock","lock"],
                "deny":[{"actions":["device.command"],"category":["alarm"]}]}"#,
        )
        .expect("parses");
        assert_eq!(def.grants[0].categories, Some(vec![DeviceCategory::Light]));
        assert_eq!(def.sensitive, vec![SensitiveCategory::Lock]);
        assert_eq!(
            def.grants[0].describe(),
            "device.read,device.command@light[dev-a1*]"
        );
        let again = RoleDef::parse(&def.id, &def.name, &def.definition_json()).unwrap();
        assert_eq!(again, def);
        assert_eq!(role("{}").unwrap().grants, vec![]);
        assert_eq!(
            role(r#"{"grants":[{"actions":["*"]}]}"#).unwrap().actions(),
            SCOPED
        );
        for bad in [
            r#"{"grants":[{"actions":["token.manage"]}]}"#,
            r#"{"grants":[{"actions":["service.call"]}]}"#,
            r#"{"grants":[{"actions":[]}]}"#,
            r#"{"grants":[{"actions":["device.read"],"category":[]}]}"#,
            r#"{"grants":[{"actions":["device.read"],"category":["door"]}]}"#,
            r#"{"grants":[{"actions":["device.read"],"devices":["lamp"]}]}"#,
            r#"{"sensitive":["door"]}"#,
            r#"{"deny":[{"actions":["nope"]}]}"#,
            r#"{"scopes":["*"]}"#,
        ] {
            assert!(role(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn narrowed_grants_cover_devices_and_device_pre_checks_only() {
        let g = RoleGrant {
            actions: ActionSet::of(&[
                Action::DeviceList,
                Action::DeviceRead,
                Action::DeviceCommand,
            ]),
            categories: Some(vec![DeviceCategory::Light]),
            devices: None,
        };
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
        let by_id = RoleGrant {
            categories: None,
            devices: Some(vec!["dev-a1*".into()]),
            ..g.clone()
        };
        assert!(by_id.permits(Action::DeviceRead, &device(DeviceCategory::Switch)));
        assert!(!by_id.permits(
            Action::DeviceRead,
            &Resource::device(
                "dev-ff00000000000000",
                DeviceClass::of(DeviceCategory::Light)
            )
        ));
        let open = RoleGrant {
            categories: None,
            devices: None,
            ..g
        };
        assert!(open.permits(Action::DeviceRead, &Resource::devices()));
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
