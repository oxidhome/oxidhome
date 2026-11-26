//! Token policy blob.
//!
//! A token's policy is its scope list, optionally extended with
//! **per-tool constraints** (Phase 14.4) — an operator issuing an
//! MCP token should be able to say
//! *"this token can send commands to any device matching
//! `dev-a1b2c3d4*`, but nothing else"*, not just *"this token
//! holds `devices:command`"*.
//!
//! # Wire shape
//!
//! `parse_policy` accepts either of two JSON shapes, both
//! round-tripped from the `auth_token.scope_json` column:
//!
//! - **Scope list** — a bare array of scope strings:
//!   ```json
//!   ["logs:read", "devices:command"]
//!   ```
//!   Parses to a [`TokenPolicy`] with those scopes and
//!   **no constraints**. [`TokenPolicy::to_json`] writes this
//!   shape whenever the policy carries nothing but scopes.
//!
//! - **Extended** — an object with `scopes` + optional
//!   `constraints`:
//!   ```json
//!   {
//!     "scopes": ["devices:command"],
//!     "constraints": {
//!       "device.send_command": {
//!         "devices": ["dev-a1b2c3d4*", "dev-1122334455667788"]
//!       }
//!     }
//!   }
//!   ```
//!   `constraints` is keyed by tool name (`device.send_command`,
//!   `plugins.install`, …). Values are per-tool
//!   [`ToolConstraint`] blobs; unknown keys are preserved
//!   verbatim so a token issued for tomorrow's constraint
//!   shape doesn't force a host rebuild before it can be
//!   loaded (though nothing will consult those keys until the
//!   host learns them).
//!
//! # Enforcement is staged per key, per transport
//!
//! Constraint keys are MCP tool names, and only the MCP
//! dispatch layer will consume them once enforcement lands
//! per tool. Landing a constraint-bearing token before its
//! keys are enforced would grant it unrestricted authority
//! on that transport — the flat scope check would pass and
//! no dispatch site would consult the constraint.
//!
//! The bearer middleware (`crate::api::auth::require_token`,
//! `crate::api::connect_rpc`) therefore carries a
//! per-(key, field) allowlist (`AuthState::enforced_constraints`,
//! a `&'static [EnforcedConstraint]`). A bearer whose policy
//! names any constraint key outside the transport's set — or
//! sets a field on an enforced key that the entry doesn't
//! consume — is refused with 403 at verify time, and the
//! specific offending key (and field, on a field-level
//! refusal) is written to the audit row as
//! `<constraint-key-unenforced:{key}>` (unknown / unenforced
//! key) or `<constraint-field-unenforced:{key}:{field}>`
//! (enforced key with an unenforced field).
//!
//! In 14.4a **every transport** passes an empty slice, so
//! any constraint-bearing token is refused. Each per-tool
//! enforcement slice adds its own [`EnforcedConstraint`] to
//! the transport that consumes it, atomically with wiring
//! the dispatch-site check — 14.4b adds
//! `("device.send_command", devices)` on MCP; 14.4c adds the
//! five `plugins.*` entries with `plugins` on MCP; …
//!
//! H6 made `device.send_command` / `devices` transport-neutral:
//! REST, Connect and MCP all list [`DEVICE_COMMAND_ENFORCED`] and
//! authorize their device commands through
//! [`crate::auth::authorize()`], so the allowlist can't be bypassed by
//! switching transport.
//!
//! The constraints are applied by [`crate::auth::authorize()`]: its
//! evaluator maps each (action, resource) pair that a constraint
//! narrows to the constraint key and field. This module only parses
//! the policy and matches ids.
//!
//! See round-3 / round-4 / round-5 / round-6 P1 on PR #147
//! for the iteration history (bool → key set → (key, field)
//! set) and why each refinement matters.
//!
//! # Device IDs
//!
//! Device IDs in `OxidHome` are **opaque `dev-<16 hex>`
//! strings** — a truncated SHA-256 over `(installation_uuid,
//! instance_id, local_id)` computed by
//! [`crate::state::devices::stable_device_id`]. There is no
//! `dev-kitchen-lamp` in a real deployment; every id is 20
//! characters (the `dev-` prefix plus 16 hex).
//!
//! Because the id is a SHA truncation, its bits are
//! uniformly distributed — a prefix like `dev-a*` groups
//! roughly 1/16th of the id space at random, **not** by
//! room or plugin. The `prefix*` glob is therefore useful
//! only for whitelisting one or a handful of *specific*
//! known devices (typed short by knowing their leading
//! hex), not for semantic grouping.
//!
//! Semantic grouping (by room / plugin / capability / user
//! tag) needs a selector shape that speaks the underlying
//! `(installation_uuid, instance_id, local_id)` tuple or an
//! operator-assigned tag layer. Both are future work; 14.4a
//! ships only the opaque-id allowlist so simple "just this
//! one device" cases have a solution today.
//!
//! # Scope of 14.4a
//!
//! This module ships the schema, the parser, and the
//! [`Actor::constraint`](crate::auth::Actor::constraint)
//! accessor. **No dispatch site consults constraints yet.**
//! Wiring per-tool enforcement lands in follow-up slices
//! (14.4b: `device.send_command` device allowlist; 14.4c:
//! `plugins.*` plugin allowlists; …). Landing the shape first
//! means those follow-ups touch one call site each without
//! having to also negotiate the wire shape.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::category::SensitiveCategory;
use super::role::{DenyRule, SelectorWire, is_role_id};

/// A decoded token policy. Constructed via [`parse_policy`];
/// see the module-level doc for the accepted JSON shapes.
///
/// `scopes` mirrors the pre-14.4 flat scope list — the
/// [`crate::auth::authorize()`] evaluator matches it verbatim.
///
/// `constraints` maps a tool name to that tool's
/// [`ToolConstraint`]. A tool name with **no** entry in the
/// map is *unrestricted* for that token (subject to the
/// scope-check above); an entry with an empty `devices` /
/// `plugins` list is *deny-all* for that field. See each
/// field's docs for the precise semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenPolicy {
    /// Flat scope list — same shape as pre-14.4.
    pub scopes: Vec<String>,
    /// Per-tool constraints; key is the tool name
    /// (`device.send_command`, `plugins.install`, …).
    pub constraints: HashMap<String, ToolConstraint>,
    /// H6 slice 2: explicit sensitive-category grants. A wildcard
    /// scope never reaches a lock, opener, alarm or camera bytes; one
    /// of these does, on top of the scope and constraints the action
    /// already needs.
    pub sensitive: Vec<SensitiveGrant>,
    /// H6 slice 3: ids of owner-defined roles
    /// ([`crate::auth::RoleDef`]), resolved per request and evaluated
    /// by [`crate::auth::authorize()`]. A role deleted since grants
    /// nothing.
    pub roles: Vec<String>,
    /// H6 slice 3: the deny list. A matching [`DenyRule`] refuses the
    /// action whatever scope, role or grant permits it.
    pub deny: Vec<DenyRule>,
}

impl TokenPolicy {
    /// Serialize to the `scope_json` form: the bare scope-list array when
    /// there are no constraints, sensitive grants, roles or denies, the
    /// extended object otherwise. Round-trips through [`parse_policy`].
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        if self.constraints.is_empty()
            && self.sensitive.is_empty()
            && self.roles.is_empty()
            && self.deny.is_empty()
        {
            return serde_json::to_vec(&self.scopes).unwrap_or_default();
        }
        let mut constraints: Vec<(&String, &ToolConstraint)> = self.constraints.iter().collect();
        constraints.sort_by_key(|(k, _)| *k);
        let constraints: serde_json::Map<String, serde_json::Value> = constraints
            .into_iter()
            .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or_default()))
            .collect();
        let mut obj = serde_json::Map::new();
        obj.insert("scopes".into(), serde_json::json!(self.scopes));
        if !self.roles.is_empty() {
            obj.insert("roles".into(), serde_json::json!(self.roles));
        }
        if !self.deny.is_empty() {
            obj.insert(
                "deny".into(),
                serde_json::Value::Array(self.deny.iter().map(DenyRule::to_json).collect()),
            );
        }
        if !constraints.is_empty() {
            obj.insert("constraints".into(), serde_json::Value::Object(constraints));
        }
        if !self.sensitive.is_empty() {
            obj.insert(
                "sensitive".into(),
                serde_json::Value::Array(
                    self.sensitive.iter().map(SensitiveGrant::to_json).collect(),
                ),
            );
        }
        serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_default()
    }
}

/// One explicit sensitive-category grant on a token (H6 slice 2).
///
/// Wire shape inside the extended policy object, either a bare
/// category name or an object narrowed to devices:
///
/// ```json
/// "sensitive": ["lock", {"category": "camera", "devices": ["dev-a1b2c3d4*"]}]
/// ```
///
/// The grant is bound to its scope: it only adds the category on top
/// of what the token's scopes and 14.4 constraints already permit,
/// and a `devices` list narrows it further to those ids (same
/// literal / `prefix*` patterns as [`ToolConstraint::devices`]). A
/// device-narrowed grant never covers a resource that names no device
/// (a blob addressed by instance and name). An unknown category name
/// makes the whole policy fail to parse, which the bearer middleware
/// treats as deny-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveGrant {
    /// The category granted.
    pub category: SensitiveCategory,
    /// Device-id allowlist; `None` covers every device of the category.
    pub devices: Option<Vec<String>>,
}

impl SensitiveGrant {
    /// A grant of `category` on every device.
    #[must_use]
    pub fn all(category: SensitiveCategory) -> Self {
        Self {
            category,
            devices: None,
        }
    }

    /// Does this grant cover `category` on `device_id` (`None` when the
    /// resource names no device)?
    #[must_use]
    pub fn covers(&self, category: SensitiveCategory, device_id: Option<&str>) -> bool {
        if self.category != category {
            return false;
        }
        match (&self.devices, device_id) {
            (None, _) => true,
            (Some(patterns), Some(id)) => patterns.iter().any(|p| match_pattern(p, id)),
            (Some(_), None) => false,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match &self.devices {
            None => serde_json::Value::String(self.category.as_str().to_owned()),
            Some(devices) => serde_json::json!({
                "category": self.category.as_str(),
                "devices": devices,
            }),
        }
    }
}

/// Per-tool constraint blob. Fields are additive — a call
/// must satisfy **every** constraint that applies to its
/// tool.
///
/// # Field semantics
///
/// `Option<Vec<String>>` (not bare `Vec<String>`) so an
/// operator can distinguish *"this field is not constrained"*
/// (`None` — accept anything) from *"this field is
/// constrained to the empty set"* (`Some(vec![])` — deny
/// all). Bare `Vec::is_empty()` conflates the two.
///
/// Patterns support a single trailing `*` wildcard
/// (`dev-a1b2c3d4*`) so an operator can whitelist one or a
/// handful of specific *known* devices by their leading hex.
/// Because SHA-derived device IDs are uniformly distributed,
/// the glob does **not** group semantically by room, plugin,
/// or capability — see the module-level "Device IDs" doc.
/// Semantic grouping needs a future tuple- or tag-based
/// selector; the current wire shape can accept it without
/// breaking back-compat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConstraint {
    /// Device-id allowlist for tools that take a `device_id`
    /// argument (`device.send_command`, and future tools that
    /// address a specific device). Each entry is either a
    /// literal id or a `prefix*` glob against the opaque
    /// `dev-<16 hex>` string produced by
    /// [`crate::state::devices::stable_device_id`]. `None` =
    /// no constraint; `Some(vec![])` = deny all. See the
    /// module-level "Device IDs" doc for the rationale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<String>>,
    /// Plugin-id allowlist for tools that take a `plugin_id`
    /// argument (`plugins.show`, `plugins.stop`,
    /// `plugins.uninstall`, `plugins.start`). Same shape +
    /// semantics as [`Self::devices`].
    ///
    /// **`plugins.install` is a special case**: the tool
    /// takes a `source_dir`, not a `plugin_id` — the id is
    /// only known after the manifest is read. 14.4d landed
    /// enforcement via
    /// `installed_plugins::install_gated`, which runs the
    /// caller-supplied gate against the manifest-derived id
    /// **before** any installation side effects
    /// (the on-disk `plugins/<id>/` layout, the `plugin_installation`
    /// row, the running-instance guards). Refusing a manifest
    /// mid-install is fine; refusing it after the on-disk
    /// layout was committed would leave orphan state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugins: Option<Vec<String>>,
}

impl ToolConstraint {
    /// Return `true` when `id` satisfies the `devices`
    /// allowlist. `true` when `devices` is `None` (no
    /// constraint) — callers combine this with the flat scope
    /// check upstream.
    #[must_use]
    pub fn allows_device(&self, id: &str) -> bool {
        Self::allows(self.devices.as_deref(), id)
    }

    /// Return `true` when `id` satisfies the `plugins`
    /// allowlist. Same semantics as [`Self::allows_device`].
    #[must_use]
    pub fn allows_plugin(&self, id: &str) -> bool {
        Self::allows(self.plugins.as_deref(), id)
    }

    /// Shared matcher. `None` = unrestricted (always true).
    /// `Some(patterns)` = the id must match at least one
    /// entry — literal equality, or `prefix*` glob.
    fn allows(patterns: Option<&[String]>, id: &str) -> bool {
        let Some(patterns) = patterns else {
            return true;
        };
        patterns.iter().any(|p| match_pattern(p, id))
    }
}

/// Match `id` against one `prefix*` glob or a literal.
/// `*` may appear only at the very end; anywhere else it
/// matches literally (the wire schema doesn't advertise
/// mid-string `*` and rejecting it here keeps the match
/// semantics small).
pub(crate) fn match_pattern(pattern: &str, id: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        id.starts_with(prefix)
    } else {
        pattern == id
    }
}

// ── Wire deserialisation helpers ────────────────────────────────

/// Scope-list-or-extended envelope the JSON blob deserialises
/// into. Kept private — external callers go through
/// [`parse_policy`] which normalises the two shapes into
/// [`TokenPolicy`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PolicyWire {
    /// Bare scope-list array.
    ScopeList(Vec<String>),
    /// Extended — object with `scopes` + optional
    /// `constraints`. `deny_unknown_fields` so a typo like
    /// `"scope"` (singular) doesn't silently pin the token to
    /// an empty scope list.
    Extended(ExtendedPolicy),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtendedPolicy {
    scopes: Vec<String>,
    /// H6 slice 2 sensitive grants; see [`SensitiveGrant`].
    #[serde(default)]
    sensitive: Vec<SensitiveGrantWire>,
    /// H6 slice 3 role ids; see [`crate::auth::RoleDef`].
    #[serde(default)]
    roles: Vec<String>,
    /// H6 slice 3 deny list; see [`DenyRule`].
    #[serde(default)]
    deny: Vec<SelectorWire>,
    // Round-7 P1 on PR #147: reject duplicate JSON keys. The
    // default `HashMap` deserializer accepts them and keeps
    // the last value; once enforcement lands, a bearer with
    // `{"device.send_command":{"devices":[]},
    //   "device.send_command":{}}` would parse as
    // unrestricted, defeating a deny-all restriction the
    // operator authored. Custom visitor rejects duplicates at
    // parse time so the fail-closed contract holds.
    #[serde(default, deserialize_with = "deserialize_unique_map")]
    constraints: HashMap<String, ToolConstraint>,
}

/// Wire form of a [`SensitiveGrant`]: a bare category name or an
/// object with `category` and optional `devices`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SensitiveGrantWire {
    Name(String),
    Narrowed(NarrowedGrantWire),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NarrowedGrantWire {
    category: String,
    #[serde(default)]
    devices: Option<Vec<String>>,
}

impl SensitiveGrantWire {
    fn into_grant(self) -> Option<SensitiveGrant> {
        let (category, devices) = match self {
            SensitiveGrantWire::Name(name) => (name, None),
            SensitiveGrantWire::Narrowed(n) => (n.category, n.devices),
        };
        Some(SensitiveGrant {
            category: category.parse().ok()?,
            devices,
        })
    }
}

/// Parse stored role ids: a malformed id is `None` (the policy is then
/// unparseable). Duplicates collapse.
fn parse_roles(ids: &[String]) -> Option<Vec<String>> {
    let mut roles: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !is_role_id(id) {
            return None;
        }
        if !roles.contains(id) {
            roles.push(id.clone());
        }
    }
    Some(roles)
}

fn deserialize_unique_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, ToolConstraint>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};

    struct UniqueMapVisitor;

    impl<'de> Visitor<'de> for UniqueMapVisitor {
        type Value = HashMap<String, ToolConstraint>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of tool-name -> ToolConstraint with unique keys")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((key, value)) = access.next_entry::<String, ToolConstraint>()? {
                if let Some(prev) = map.insert(key.clone(), value) {
                    let _ = prev;
                    return Err(serde::de::Error::custom(format!(
                        "duplicate constraint key `{key}`",
                    )));
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(UniqueMapVisitor)
}

// ── Enforcement declaration ────────────────────────────────────────

/// One entry in a transport's enforced-constraint set — a
/// tool name plus the [`ToolConstraint`] fields the transport
/// actually consults at dispatch. Naming a key without
/// declaring a field would fail open on that field: the flat
/// scope check passes and no dispatch site reads it, so an
/// operator's `{"device.send_command": {"plugins": [...]}}`
/// would silently grant unrestricted device access.
///
/// Round-6 P1 on PR #147.
#[derive(Debug, Clone, Copy)]
pub struct EnforcedConstraint {
    /// Tool name — must match the `constraints` map key
    /// exactly (`device.send_command`, `plugins.install`, …).
    pub key: &'static str,
    /// `true` when the transport's dispatch site consults
    /// [`ToolConstraint::allows_device`] on this key. A
    /// bearer whose constraint carries `devices` but this
    /// flag is `false` is refused — the field would be inert.
    pub enforce_devices: bool,
    /// Same idea for [`ToolConstraint::allows_plugin`].
    pub enforce_plugins: bool,
}

impl EnforcedConstraint {
    /// Diagnose one of the actor's constraints against this
    /// enforcement declaration. Returns `Some(field_name)`
    /// when the constraint sets a field this key doesn't
    /// enforce — the offending field is what the bearer
    /// middleware surfaces in its log line + audit row.
    /// `None` means every field the operator set is consumed
    /// at dispatch.
    ///
    /// Called only when [`Self::key`] already matches the
    /// actor's constraint key; the key match is caller-side.
    #[must_use]
    pub fn first_unenforced_field(&self, constraint: &ToolConstraint) -> Option<&'static str> {
        if constraint.devices.is_some() && !self.enforce_devices {
            return Some("devices");
        }
        if constraint.plugins.is_some() && !self.enforce_plugins {
            return Some("plugins");
        }
        None
    }
}

/// The `device.send_command` / `devices` enforcement entry. Every
/// transport that can dispatch a device command (REST
/// `POST /api/v1/devices/{id}/command`, Connect
/// `DevicesService.ExecuteCommand`, MCP `device.send_command`) lists it
/// and authorizes `device.command` on the addressed device through
/// [`crate::auth::authorize()`] at its dispatch boundary (H6), so a
/// per-device allowlist cannot be sidestepped by switching transport.
pub const DEVICE_COMMAND_ENFORCED: EnforcedConstraint = EnforcedConstraint {
    key: "device.send_command",
    enforce_devices: true,
    enforce_plugins: false,
};

/// Audit sentinel recorded as `required_scope` when the
/// `device.send_command` allowlist refuses a device command.
pub const DEVICE_COMMAND_DENIED_SENTINEL: &str = "constraint:device.send_command:devices";

/// Decode the `scope_json` blob into a [`TokenPolicy`].
///
/// Returns `None` when the blob is malformed. The
/// bearer-auth middleware treats `None` as **deny-all** — a
/// malformed policy is fail-closed. See
/// `crate::api::auth::require_token` for that call site.
#[must_use]
pub fn parse_policy(blob: &[u8]) -> Option<TokenPolicy> {
    let wire: PolicyWire = serde_json::from_slice(blob).ok()?;
    Some(match wire {
        PolicyWire::ScopeList(scopes) => TokenPolicy {
            scopes,
            ..TokenPolicy::default()
        },
        PolicyWire::Extended(ext) => TokenPolicy {
            scopes: ext.scopes,
            constraints: ext.constraints,
            // An unknown category fails the whole parse (deny-all)
            // rather than silently dropping the grant.
            sensitive: ext
                .sensitive
                .into_iter()
                .map(SensitiveGrantWire::into_grant)
                .collect::<Option<Vec<_>>>()?,
            // A malformed role id, or a malformed deny
            // entry, fails the whole parse (deny-all) too.
            roles: parse_roles(&ext.roles)?,
            deny: ext
                .deny
                .into_iter()
                .map(crate::auth::role::SelectorWire::into_deny)
                .collect::<Option<Vec<_>>>()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_list_round_trips() {
        let policy = parse_policy(br#"["logs:read","devices:command"]"#).expect("parse");
        assert_eq!(policy.scopes, vec!["logs:read", "devices:command"]);
        assert!(policy.constraints.is_empty());
    }

    #[test]
    fn extended_shape_parses_with_constraints() {
        let blob = br#"{
            "scopes": ["devices:command"],
            "constraints": {
                "device.send_command": {
                    "devices": ["dev-a1b2c3d4*", "dev-1122334455667788"]
                }
            }
        }"#;
        let policy = parse_policy(blob).expect("parse");
        assert_eq!(policy.scopes, vec!["devices:command"]);
        let cx = policy
            .constraints
            .get("device.send_command")
            .expect("constraint");
        assert_eq!(
            cx.devices.as_deref(),
            Some(
                &[
                    "dev-a1b2c3d4*".to_string(),
                    "dev-1122334455667788".to_string()
                ][..]
            ),
        );
        assert!(cx.plugins.is_none());
    }

    #[test]
    fn extended_shape_without_constraints_parses() {
        let policy = parse_policy(br#"{"scopes":["*"]}"#).expect("parse");
        assert_eq!(policy.scopes, vec!["*"]);
        assert!(policy.constraints.is_empty());
    }

    #[test]
    fn malformed_shapes_reject() {
        // Not JSON.
        assert!(parse_policy(b"not json").is_none());
        // Scope element must be a string.
        assert!(parse_policy(br#"["ok", 7]"#).is_none());
        // Extended envelope missing required `scopes`.
        assert!(parse_policy(br#"{"constraints":{}}"#).is_none());
        // Unknown top-level field on the extended envelope —
        // `deny_unknown_fields` guards against a typo silently
        // pinning the token to nothing.
        assert!(parse_policy(br#"{"scope":["logs:read"]}"#).is_none());
        // A deny that could never match what it names (H6 slice 4).
        assert!(
            parse_policy(
                br#"{"scopes":["*"],"deny":[{"actions":["device.command"],"services":["acme.notify"]}]}"#
            )
            .is_none()
        );
        let p = parse_policy(
            br#"{"scopes":["*"],"deny":[{"actions":["*"],"services":["acme.notify"]}]}"#,
        )
        .expect("narrowed wildcard");
        assert_eq!(p.deny[0].actions, crate::auth::role::SERVICE_NARROWABLE);
        // A device deny naming `service.call`, which it could never match.
        assert!(
            parse_policy(
                br#"{"scopes":["*"],"deny":[{"actions":["service.call"],"category":["lock"]}]}"#,
            )
            .is_none()
        );
        // Unknown field inside a constraint blob — same
        // rationale.
        assert!(parse_policy(br#"{"scopes":[],"constraints":{"t":{"unknown":true}}}"#).is_none());
        // Non-array `devices` inside a constraint.
        assert!(parse_policy(br#"{"scopes":[],"constraints":{"t":{"devices":"x"}}}"#).is_none());
    }

    #[test]
    fn sensitive_grants_parse_and_round_trip() {
        let blob = br#"{
            "scopes": ["*"],
            "sensitive": ["lock", {"category": "camera", "devices": ["dev-a1*"]}]
        }"#;
        let policy = parse_policy(blob).expect("parse");
        assert_eq!(
            policy.sensitive,
            vec![
                SensitiveGrant::all(SensitiveCategory::Lock),
                SensitiveGrant {
                    category: SensitiveCategory::Camera,
                    devices: Some(vec!["dev-a1*".into()]),
                },
            ]
        );
        assert_eq!(parse_policy(&policy.to_json()), Some(policy.clone()));
        let lock = &policy.sensitive[0];
        assert!(lock.covers(SensitiveCategory::Lock, Some("dev-ff")));
        assert!(lock.covers(SensitiveCategory::Lock, None));
        assert!(!lock.covers(SensitiveCategory::Opener, Some("dev-ff")));
        let cam = &policy.sensitive[1];
        assert!(cam.covers(SensitiveCategory::Camera, Some("dev-a1b2")));
        assert!(!cam.covers(SensitiveCategory::Camera, Some("dev-b1b2")));
        assert!(!cam.covers(SensitiveCategory::Camera, None));
        // A scopes-only policy stays a bare array.
        let scope_list = parse_policy(br#"["devices:list"]"#).expect("parse");
        assert_eq!(scope_list.to_json(), br#"["devices:list"]"#.to_vec());
    }

    #[test]
    fn unknown_sensitive_category_rejects_the_policy() {
        assert!(parse_policy(br#"{"scopes":["*"],"sensitive":["door"]}"#).is_none());
        assert!(
            parse_policy(br#"{"scopes":["*"],"sensitive":[{"category":"lock","x":1}]}"#).is_none()
        );
        assert!(parse_policy(br#"{"scopes":["*"],"sensitive":"lock"}"#).is_none());
    }

    #[test]
    fn roles_and_deny_parse_and_round_trip() {
        let blob = br#"{
            "scopes": [],
            "roles": ["role-00000000000000a1", "role-00000000000000b2", "role-00000000000000a1"],
            "deny": [
                {"actions": ["device.command"], "category": ["lock", "alarm"]},
                {"actions": ["*"], "devices": ["dev-a1*"]}
            ]
        }"#;
        let policy = parse_policy(blob).expect("parse");
        assert_eq!(
            policy.roles,
            vec!["role-00000000000000a1", "role-00000000000000b2"]
        );
        assert_eq!(policy.deny.len(), 2);
        assert_eq!(
            policy.deny[0].categories.as_deref(),
            Some(
                &[
                    crate::auth::DeviceCategory::Lock,
                    crate::auth::DeviceCategory::Alarm
                ][..]
            )
        );
        // A device selector never matches a service: a narrowed `*` is
        // every action but `service.call`.
        assert_eq!(
            policy.deny[1].actions,
            crate::auth::ActionSet::ALL.without(crate::auth::role::SERVICE_NARROWABLE)
        );
        assert_eq!(parse_policy(&policy.to_json()), Some(policy.clone()));
        // A role-only policy keeps the object shape.
        let role_only = TokenPolicy {
            roles: vec!["role-00000000000000a1".into()],
            ..TokenPolicy::default()
        };
        assert_eq!(
            role_only.to_json(),
            br#"{"roles":["role-00000000000000a1"],"scopes":[]}"#.to_vec()
        );
    }

    #[test]
    fn bad_roles_and_denies_reject_the_policy() {
        for blob in [
            // Role names or malformed ids: a policy stores role ids.
            &br#"{"scopes":[],"roles":["monitor"]}"#[..],
            br#"{"scopes":[],"roles":["owner"]}"#,
            br#"{"scopes":[],"roles":"role-00000000000000a1"}"#,
            // Empty or unknown deny parts.
            br#"{"scopes":[],"deny":[{"actions":[]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["device.unlock"]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"category":[]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"category":["door"]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"devices":[]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"devices":[""]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"devices":["*"]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"devices":["lamp"]}]}"#,
            br#"{"scopes":[],"deny":[{"actions":["*"],"areas":["hall"]}]}"#,
            br#"{"scopes":[],"deny":[{"category":["lock"]}]}"#,
        ] {
            assert!(
                parse_policy(blob).is_none(),
                "{}",
                String::from_utf8_lossy(blob)
            );
        }
    }

    #[test]
    fn duplicate_constraint_keys_reject() {
        // Round-7 P1 on PR #147: default HashMap deserialization
        // silently keeps the last value for duplicate keys.
        // Once enforcement lands, a bearer with
        // {"device.send_command":{"devices":[]},
        //  "device.send_command":{}} would parse as
        // unrestricted and defeat the operator's deny-all —
        // the custom map visitor refuses at parse time.
        let blob = br#"{
            "scopes": ["*"],
            "constraints": {
                "device.send_command": {"devices": []},
                "device.send_command": {}
            }
        }"#;
        assert!(
            parse_policy(blob).is_none(),
            "duplicate constraint key must fail parse",
        );
    }

    #[test]
    fn constraint_allows_none_means_unrestricted() {
        let cx = ToolConstraint::default();
        assert!(cx.allows_device("dev-a1b2c3d4e5f60718"));
        assert!(cx.allows_plugin("acme.thermostat"));
    }

    #[test]
    fn constraint_allows_empty_list_means_deny_all() {
        let cx = ToolConstraint {
            devices: Some(vec![]),
            plugins: None,
        };
        assert!(!cx.allows_device("dev-anything"));
        // `plugins` is None so still unrestricted.
        assert!(cx.allows_plugin("anything"));
    }

    #[test]
    fn constraint_allows_literal_and_prefix_glob() {
        // Device IDs in OxidHome are opaque `dev-<16 hex>`
        // strings (see `crate::state::devices::stable_device_id`);
        // this test uses realistic shapes rather than the
        // human-friendly names the docs use as illustrations.
        let cx = ToolConstraint {
            devices: Some(vec![
                "dev-a1b2c3d4*".to_string(),
                "dev-1122334455667788".to_string(),
            ]),
            plugins: None,
        };
        // Prefix glob.
        assert!(cx.allows_device("dev-a1b2c3d4e5f60718"));
        assert!(cx.allows_device("dev-a1b2c3d4000000ff"));
        // Prefix boundary — `*` matches the empty tail too.
        assert!(cx.allows_device("dev-a1b2c3d4"));
        // Literal.
        assert!(cx.allows_device("dev-1122334455667788"));
        // Not covered.
        assert!(!cx.allows_device("dev-a1b2c3d3ffffffff"));
        assert!(!cx.allows_device("dev-11223344556677882"));
    }

    #[test]
    fn mid_pattern_star_is_treated_as_literal() {
        // The wire schema only advertises trailing `*`; a
        // mid-string `*` matches literally rather than being
        // silently interpreted, so an operator typing a
        // pattern they thought was a glob doesn't get an
        // unintended broader match.
        let cx = ToolConstraint {
            devices: Some(vec!["dev-a*b".to_string()]),
            plugins: None,
        };
        assert!(cx.allows_device("dev-a*b"));
        assert!(!cx.allows_device("dev-a12345b"));
    }
}
