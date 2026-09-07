//! Phase 14.4 — richer token policy blob.
//!
//! Phase 14.2a landed bearer + per-scope-string enforcement:
//! the token record stored a JSON array of scope names
//! (`["logs:read", "devices:command"]`), and each dispatch site
//! called [`crate::api::scopes::require_scope`] against the
//! bearer's scope list.
//!
//! Phase 14.4 extends that shape with **per-tool constraints**
//! — an operator issuing an MCP token should be able to say
//! *"this token can send commands to any device matching
//! `dev-a1b2c3d4*`, but nothing else"*, not just *"this token
//! holds `devices:command`"*.
//!
//! # Wire shape
//!
//! `parse_policy` accepts either of two JSON shapes, both
//! round-tripped from the `auth_token.scope_json` column:
//!
//! - **Legacy** — a bare array of scope strings:
//!   ```json
//!   ["logs:read", "devices:command"]
//!   ```
//!   Parses to a [`TokenPolicy`] with those scopes and
//!   **no constraints**. Every existing token row keeps working.
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
//! The bearer middleware ([`crate::api::auth::require_token`],
//! [`crate::api::connect_rpc`]) therefore carries a
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

/// A decoded token policy. Constructed via [`parse_policy`];
/// see the module-level doc for the accepted JSON shapes.
///
/// `scopes` mirrors the pre-14.4 flat scope list — the
/// existing [`crate::api::scopes::require_scope`] path uses
/// it verbatim.
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
    /// only known after the manifest is read. When 14.4c
    /// wires enforcement, the `plugins.install` dispatch site
    /// must parse the manifest and validate the resulting
    /// plugin id **before** any installation side effects
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
fn match_pattern(pattern: &str, id: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        id.starts_with(prefix)
    } else {
        pattern == id
    }
}

// ── Wire deserialisation helpers ────────────────────────────────

/// Legacy-or-extended envelope the JSON blob deserialises
/// into. Kept private — external callers go through
/// [`parse_policy`] which normalises the two shapes into
/// [`TokenPolicy`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PolicyWire {
    /// Legacy — bare scope-list array.
    Legacy(Vec<String>),
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

/// Decode the `scope_json` blob into a [`TokenPolicy`].
///
/// Returns `None` when the blob is malformed. The
/// bearer-auth middleware treats `None` as **deny-all** — a
/// malformed policy is fail-closed. See
/// [`crate::api::auth::require_token`] for that call site.
#[must_use]
pub fn parse_policy(blob: &[u8]) -> Option<TokenPolicy> {
    let wire: PolicyWire = serde_json::from_slice(blob).ok()?;
    Some(match wire {
        PolicyWire::Legacy(scopes) => TokenPolicy {
            scopes,
            constraints: HashMap::new(),
        },
        PolicyWire::Extended(ext) => TokenPolicy {
            scopes: ext.scopes,
            constraints: ext.constraints,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_scope_array_round_trips() {
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
        // Unknown field inside a constraint blob — same
        // rationale.
        assert!(parse_policy(br#"{"scopes":[],"constraints":{"t":{"unknown":true}}}"#).is_none());
        // Non-array `devices` inside a constraint.
        assert!(parse_policy(br#"{"scopes":[],"constraints":{"t":{"devices":"x"}}}"#).is_none());
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
