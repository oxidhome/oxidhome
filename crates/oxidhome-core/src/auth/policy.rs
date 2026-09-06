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
//! `dev-kitchen-*`, but nothing else"*, not just *"this token
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
//!         "devices": ["dev-kitchen-*", "dev-hallway-lamp"]
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
/// (`dev-kitchen-*`); this is the minimum expressive shape
/// for the common "one room's devices" and "one plugin
/// family's ids" cases. Richer glob / regex support can
/// land in a follow-up without breaking the wire shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConstraint {
    /// Device-id allowlist for tools that take a `device_id`
    /// argument (`device.send_command`, and future tools that
    /// address a specific device). Each entry is either a
    /// literal id or a `prefix*` glob. `None` = no
    /// constraint; `Some(vec![])` = deny all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<String>>,
    /// Plugin-id allowlist for tools that take a `plugin_id`
    /// argument (`plugins.show`, `plugins.stop`,
    /// `plugins.uninstall`, `plugins.start`,
    /// `plugins.install`). Same shape + semantics as
    /// [`Self::devices`].
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
    #[serde(default)]
    constraints: HashMap<String, ToolConstraint>,
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
                    "devices": ["dev-kitchen-*", "dev-hallway-lamp"]
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
            Some(&["dev-kitchen-*".to_string(), "dev-hallway-lamp".to_string()][..]),
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
    fn constraint_allows_none_means_unrestricted() {
        let cx = ToolConstraint::default();
        assert!(cx.allows_device("dev-kitchen-light"));
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
        let cx = ToolConstraint {
            devices: Some(vec![
                "dev-kitchen-*".to_string(),
                "dev-hallway-lamp".to_string(),
            ]),
            plugins: None,
        };
        // Prefix glob.
        assert!(cx.allows_device("dev-kitchen-light"));
        assert!(cx.allows_device("dev-kitchen-fan"));
        // Prefix boundary — `*` matches the empty tail too.
        assert!(cx.allows_device("dev-kitchen-"));
        // Literal.
        assert!(cx.allows_device("dev-hallway-lamp"));
        // Not covered.
        assert!(!cx.allows_device("dev-bedroom-light"));
        assert!(!cx.allows_device("dev-hallway-lamp2"));
    }

    #[test]
    fn mid_pattern_star_is_treated_as_literal() {
        // The wire schema only advertises trailing `*`; a
        // mid-string `*` matches literally rather than being
        // silently interpreted, so an operator typing a
        // pattern they thought was a glob doesn't get an
        // unintended broader match.
        let cx = ToolConstraint {
            devices: Some(vec!["dev-*-light".to_string()]),
            plugins: None,
        };
        assert!(cx.allows_device("dev-*-light"));
        assert!(!cx.allows_device("dev-kitchen-light"));
    }
}
