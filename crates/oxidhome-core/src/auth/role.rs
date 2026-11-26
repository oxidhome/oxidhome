//! Roles: what a token may do.
//!
//! A token holds roles by name and nothing else. A **role** is a list
//! of [`RoleGrant`]s; a grant names actions and may narrow them to
//! device categories and device ids. Four roles are built in
//! ([`builtin`]): `admin`, `member`, `guest` and `agent`. The owner
//! adds custom ones (`auth_role`, keyed by name). Access is absent
//! unless a grant gives it; there is no deny list.
//!
//! # Grants
//!
//! [`RoleGrant::actions`] names actions; `*` is every action a role can
//! hold ([`GRANTABLE`]: all but the owner's `token.manage` and
//! `policy.manage`). A grant without selectors covers every resource
//! that isn't sensitive. With a `category` and / or `devices` selector
//! it names only [`NARROWABLE`] actions (a narrowed `*` means those)
//! and covers a device whose display category or sensitive set is
//! listed (only while the device is registered: an offline device's
//! category is unknown) and whose id matches a pattern (`dev-…`,
//! literal or `prefix*`). A `category` grant also covers a camera
//! instance's blob when it lists `camera`. A narrowed grant covers the
//! pre-check on devices and blobs ([`crate::auth::Resource::PreCheck`]),
//! since the per-target check follows, and never a whole collection.
//!
//! # Sensitive categories
//!
//! A command on a `lock`, `opener` or `alarm` device, and reading a
//! camera's bytes, need a grant whose `category` names every such
//! category of the target: `{"actions": ["device.command"],
//! "category": ["lock"]}`. A grant without `category` never reaches
//! them, `*` included.

use std::str::FromStr;
use std::sync::{Arc, LazyLock};

use super::authorize::{Action, Resource, ResourceKind};
use super::category::{DeviceCategory, SensitiveCategory, SensitiveSet};

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

    /// The set holding `actions`.
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

    /// Actions in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Actions in `self` but not in `other`.
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

    /// The actions, in [`Action::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Action> {
        Action::ALL.into_iter().filter(move |a| self.contains(*a))
    }

    /// The actions' names; `["*"]` for every grantable action.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        if self == GRANTABLE {
            vec!["*"]
        } else {
            self.iter().map(Action::as_str).collect()
        }
    }
}

/// An action, category or role name the host doesn't know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} `{name}`")]
pub struct UnknownName {
    /// What was named (`action`, `role`).
    pub kind: &'static str,
    /// The name.
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

/// Every action a role can grant: all but the owner's.
pub const GRANTABLE: ActionSet =
    ActionSet::ALL.without(ActionSet::of(&[Action::TokenManage, Action::PolicyManage]));

/// The actions a grant narrowed to categories or devices may name.
pub const NARROWABLE: ActionSet = ActionSet::of(&[
    Action::DeviceList,
    Action::DeviceRead,
    Action::DeviceCommand,
    Action::BlobRead,
]);

/// One grant of a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleGrant {
    /// Actions granted.
    pub actions: ActionSet,
    /// Device categories the grant is narrowed to; `None` for every
    /// non-sensitive target. Names the sensitive categories it reaches.
    pub categories: Option<Vec<DeviceCategory>>,
    /// Device id patterns (`dev-…`, literal or `prefix*`); `None` for
    /// every device.
    pub devices: Option<Vec<String>>,
}

impl RoleGrant {
    /// `true` when the grant covers `action` on `resource`, whose
    /// sensitive categories `sensitive` it must name.
    #[must_use]
    pub fn permits(&self, action: Action, resource: &Resource, sensitive: SensitiveSet) -> bool {
        if !self.actions.contains(action) {
            return false;
        }
        let names_all = sensitive.iter().all(|s| {
            self.categories
                .as_ref()
                .is_some_and(|c| c.contains(&s.category()))
        });
        match resource {
            Resource::Device(d) => {
                let class = d.class();
                names_all
                    && self.categories.as_ref().is_none_or(|c| {
                        class.is_registered()
                            && c.iter().any(|c| {
                                *c == class.category()
                                    || c.sensitive().is_some_and(|s| class.sensitive().contains(s))
                            })
                    })
                    && self
                        .devices
                        .as_ref()
                        .is_none_or(|p| p.iter().any(|p| match_pattern(p, d.id())))
            }
            // A blob names no device; a camera instance's blob is
            // reached by a grant naming `camera`.
            Resource::Blob(b) => {
                names_all
                    && self.devices.is_none()
                    && self
                        .categories
                        .as_ref()
                        .is_none_or(|c| b.is_camera() && c.contains(&DeviceCategory::Camera))
            }
            Resource::PreCheck(ResourceKind::Device | ResourceKind::Blob) => true,
            _ => self.categories.is_none() && self.devices.is_none(),
        }
    }

    /// The grant as role-definition JSON.
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

    /// One-line form for listings: `actions[@categories][ [devices]]`.
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

/// A role: its name and grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDef {
    /// Unique name.
    pub name: String,
    /// What the role grants.
    pub grants: Vec<RoleGrant>,
}

/// One grant as stored and sent: names, not parsed values.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantWire {
    /// Action names, or `*`.
    pub actions: Vec<String>,
    /// Device categories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<Vec<String>>,
    /// Device id patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<String>>,
}

/// Why a grant was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("grant {index}: {reason}")]
pub struct GrantError {
    /// Position in the role's grant list.
    pub index: usize,
    /// What is wrong with it.
    pub reason: String,
}

impl GrantWire {
    fn parse(self) -> Result<RoleGrant, String> {
        if self.actions.is_empty() {
            return Err("names no action".into());
        }
        let narrowed = self.category.is_some() || self.devices.is_some();
        let allowed = if narrowed { NARROWABLE } else { GRANTABLE };
        let mut actions = ActionSet::empty();
        for name in &self.actions {
            actions = actions.union(if name == "*" {
                allowed
            } else {
                let action: Action = name.parse().map_err(|e: UnknownName| e.to_string())?;
                if !allowed.contains(action) {
                    return Err(if narrowed {
                        format!("`{name}` can't be narrowed to categories or devices")
                    } else {
                        format!("`{name}` is the owner's alone")
                    });
                }
                ActionSet::of(&[action])
            });
        }
        let categories = match self.category {
            None => None,
            Some(c) if c.is_empty() => return Err("`category` is empty".into()),
            Some(c) => {
                let mut out: Vec<DeviceCategory> = Vec::with_capacity(c.len());
                for name in &c {
                    let c: DeviceCategory = name.parse().map_err(|e| format!("{e}"))?;
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
                Some(out)
            }
        };
        if let Some(d) = &self.devices {
            if d.is_empty() {
                return Err("`devices` is empty".into());
            }
            if let Some(bad) = d.iter().find(|p| !crate::state::is_device_pattern(p)) {
                return Err(format!(
                    "`{bad}` is not a device id or a `dev-…*` prefix pattern"
                ));
            }
        }
        Ok(RoleGrant {
            actions,
            categories,
            devices: self.devices,
        })
    }
}

impl RoleDef {
    /// Build a role from wire grants.
    ///
    /// # Errors
    ///
    /// The first grant that doesn't parse.
    pub fn from_wire(name: &str, grants: Vec<GrantWire>) -> Result<Self, GrantError> {
        let grants = grants
            .into_iter()
            .enumerate()
            .map(|(index, g)| g.parse().map_err(|reason| GrantError { index, reason }))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            name: name.to_owned(),
            grants,
        })
    }

    /// Parse a stored definition (a JSON array of grants). `None` when
    /// it doesn't parse: the role then grants nothing.
    #[must_use]
    pub fn parse(name: &str, definition: &[u8]) -> Option<Self> {
        let wire: Vec<GrantWire> = serde_json::from_slice(definition).ok()?;
        Self::from_wire(name, wire).ok()
    }

    /// The stored form of [`Self::grants`].
    #[must_use]
    pub fn definition_json(&self) -> Vec<u8> {
        serde_json::Value::Array(self.grants.iter().map(RoleGrant::to_json).collect())
            .to_string()
            .into_bytes()
    }

    /// Every action some grant names.
    #[must_use]
    pub fn actions(&self) -> ActionSet {
        self.grants
            .iter()
            .fold(ActionSet::empty(), |set, g| set.union(g.actions))
    }

    /// `true` when a grant covers `action` on `resource`.
    #[must_use]
    pub fn permits(&self, action: Action, resource: &Resource, sensitive: SensitiveSet) -> bool {
        self.grants
            .iter()
            .any(|g| g.permits(action, resource, sensitive))
    }
}

/// `true` when `id` matches `pattern` (literal, or `prefix*`).
pub(crate) fn match_pattern(pattern: &str, id: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => pattern == id,
    }
}

/// `true` for a valid role name: 1 to 32 of `a-z0-9-_`, starting with
/// a letter, and not `owner`.
#[must_use]
pub fn is_role_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name != OWNER_LABEL
}

/// The owner is not a role; this name is refused for one.
pub const OWNER_LABEL: &str = "owner";

/// Names of the built-in roles.
pub const BUILTIN_ROLES: [&str; 4] = ["admin", "member", "guest", "agent"];

static BUILTINS: LazyLock<Vec<Arc<RoleDef>>> = LazyLock::new(|| {
    #[allow(clippy::enum_glob_use)]
    use Action::*;
    let sensitive = Some(
        SensitiveCategory::ALL
            .iter()
            .map(|c| c.category())
            .collect::<Vec<_>>(),
    );
    let role = |name: &str, actions: ActionSet, reaches_sensitive: bool| {
        let mut grants = vec![RoleGrant {
            actions,
            categories: None,
            devices: None,
        }];
        if reaches_sensitive {
            grants.push(RoleGrant {
                actions: ActionSet::of(&[DeviceCommand, BlobRead]),
                categories: sensitive.clone(),
                devices: None,
            });
        }
        Arc::new(RoleDef {
            name: name.to_owned(),
            grants,
        })
    };
    let devices = ActionSet::of(&[DeviceList, DeviceRead, DeviceCommand, EventSubscribe]);
    vec![
        role("admin", GRANTABLE, true),
        role(
            "member",
            devices.union(ActionSet::of(&[
                EventRead,
                BlobRead,
                InstanceRead,
                PluginRead,
                PluginUi,
                DashboardRead,
                DashboardWrite,
                HostStatus,
                ServiceCall,
            ])),
            true,
        ),
        role(
            "guest",
            devices.union(ActionSet::of(&[DashboardRead, PluginUi, ServiceCall])),
            false,
        ),
        role(
            "agent",
            devices.union(ActionSet::of(&[
                EventRead,
                InstanceRead,
                PluginRead,
                HostStatus,
                ServiceCall,
            ])),
            false,
        ),
    ]
});

/// The built-in role `name`, if there is one.
#[must_use]
pub fn builtin(name: &str) -> Option<Arc<RoleDef>> {
    BUILTINS.iter().find(|r| r.name == name).cloned()
}

/// Every built-in role, in [`BUILTIN_ROLES`] order.
#[must_use]
pub fn builtins() -> &'static [Arc<RoleDef>] {
    &BUILTINS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DeviceClass;

    fn grant(json: serde_json::Value) -> Result<RoleGrant, String> {
        serde_json::from_value::<GrantWire>(json).unwrap().parse()
    }

    #[test]
    fn wildcard_is_every_grantable_action_or_every_narrowable_one() {
        let g = grant(serde_json::json!({"actions": ["*"]})).unwrap();
        assert_eq!(g.actions, GRANTABLE);
        assert!(!g.actions.contains(Action::TokenManage));
        let g = grant(serde_json::json!({"actions": ["*"], "category": ["light"]})).unwrap();
        assert_eq!(g.actions, NARROWABLE);
    }

    #[test]
    fn bad_grants_are_refused() {
        for bad in [
            serde_json::json!({"actions": []}),
            serde_json::json!({"actions": ["nope"]}),
            serde_json::json!({"actions": ["token.manage"]}),
            serde_json::json!({"actions": ["host.status"], "category": ["lock"]}),
            serde_json::json!({"actions": ["device.read"], "category": []}),
            serde_json::json!({"actions": ["device.read"], "category": ["toaster"]}),
            serde_json::json!({"actions": ["device.read"], "devices": ["x*"]}),
        ] {
            assert!(grant(bad.clone()).is_err(), "{bad}");
        }
        assert!(
            serde_json::from_value::<GrantWire>(serde_json::json!({"actions": ["*"], "deny": []}))
                .is_err()
        );
    }

    #[test]
    fn sensitive_targets_need_a_grant_naming_their_category() {
        let lock = Resource::device("dev-a1", DeviceClass::of(DeviceCategory::Lock));
        let locks = [SensitiveCategory::Lock].into_iter().collect();
        let all = grant(serde_json::json!({"actions": ["*"]})).unwrap();
        assert!(!all.permits(Action::DeviceCommand, &lock, locks));
        assert!(all.permits(Action::DeviceRead, &lock, SensitiveSet::empty()));
        let g = grant(serde_json::json!({"actions": ["device.command"], "category": ["lock"]}))
            .unwrap();
        assert!(g.permits(Action::DeviceCommand, &lock, locks));
        let light = Resource::device("dev-b2", DeviceClass::of(DeviceCategory::Light));
        assert!(!g.permits(Action::DeviceCommand, &light, SensitiveSet::empty()));
        let camera_blob = Resource::blob("cam", "x", true);
        let camera = [SensitiveCategory::Camera].into_iter().collect();
        assert!(!all.permits(Action::BlobRead, &camera_blob, camera));
        let g =
            grant(serde_json::json!({"actions": ["blob.read"], "category": ["camera"]})).unwrap();
        assert!(g.permits(Action::BlobRead, &camera_blob, camera));
        assert!(!g.permits(
            Action::BlobRead,
            &Resource::blob("x", "y", false),
            SensitiveSet::empty()
        ));
    }

    #[test]
    fn narrowed_grants_cover_matching_devices_and_pre_checks_only() {
        let g =
            grant(serde_json::json!({"actions": ["device.read"], "devices": ["dev-a1*"]})).unwrap();
        let none = SensitiveSet::empty();
        assert!(g.permits(
            Action::DeviceRead,
            &Resource::device("dev-a1ff", DeviceClass::other()),
            none
        ));
        assert!(!g.permits(
            Action::DeviceRead,
            &Resource::device("dev-b2", DeviceClass::other()),
            none
        ));
        assert!(g.permits(
            Action::DeviceRead,
            &Resource::pre_check(ResourceKind::Device),
            none
        ));
        assert!(!g.permits(Action::DeviceRead, &Resource::devices(), none));
        let cat =
            grant(serde_json::json!({"actions": ["device.read"], "category": ["light"]})).unwrap();
        assert!(!cat.permits(
            Action::DeviceRead,
            &Resource::device("dev-a1", DeviceClass::unregistered()),
            none
        ));
    }

    #[test]
    fn definitions_round_trip() {
        let def = RoleDef::parse(
            "kiosk",
            br#"[{"actions":["device.read","device.command"],"category":["light"],"devices":["dev-a1*"]},{"actions":["*"]}]"#,
        )
        .unwrap();
        assert_eq!(
            RoleDef::parse("kiosk", &def.definition_json()),
            Some(def.clone())
        );
        assert_eq!(
            def.grants[0].describe(),
            "device.read,device.command@light[dev-a1*]"
        );
        assert!(RoleDef::parse("x", b"{}").is_none());
    }

    #[test]
    fn builtins_match_the_plan() {
        assert_eq!(builtins().len(), BUILTIN_ROLES.len());
        let lock = Resource::device("dev-a1", DeviceClass::of(DeviceCategory::Lock));
        let locks = [SensitiveCategory::Lock].into_iter().collect();
        for (name, sensitive) in [
            ("admin", true),
            ("member", true),
            ("guest", false),
            ("agent", false),
        ] {
            let r = builtin(name).unwrap();
            assert_eq!(
                r.permits(Action::DeviceCommand, &lock, locks),
                sensitive,
                "{name}"
            );
            assert!(!r.actions().contains(Action::TokenManage));
        }
        assert!(
            !builtin("agent")
                .unwrap()
                .actions()
                .contains(Action::BlobRead)
        );
        assert!(builtin("owner").is_none());
        assert!(!is_role_name("owner"));
    }
}
