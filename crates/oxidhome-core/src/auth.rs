//! Actor identity for host-internal calls.
//!
//! Every command, tool invocation, and state-changing call that
//! crosses an internal boundary should carry an [`Actor`]: *who* is
//! making this call?
//!
//! **Phase 4 scope.** Introduce the type and give every
//! [`PluginState`](crate::runtime::PluginState) an
//! [`Actor::plugin(instance_id)`]. Host-call entry points (e.g.
//! `execute_command`, `on_event`) do **not** take an `Actor` parameter
//! yet — every host call from a `PluginState` is by construction a
//! plugin actor with the state's `instance_id`, so a separate field
//! would only duplicate the existing `instance_id` span data. Phase 12
//! threads `Actor` through host-call sites once non-plugin actor
//! kinds (Api / Cli / Mcp / Automation) have real callers; the other
//! variants exist now so that work doesn't need a refactor.
//!
//! Beyond identity, [`Actor`] carries the scopes the caller is
//! authorized for. The Phase-12 token table is the source of truth;
//! plugin actors get a minimal scope set derived from their manifest's
//! `[capabilities]` block.
//!
//! See `ARCHITECTURE.md` "Auth & actor identity" for the
//! cross-cutting design and `00_OVERVIEW.md` for the per-phase
//! breakdown.

use std::collections::HashMap;
use std::sync::Arc;

pub mod policy;

pub use policy::{TokenPolicy, ToolConstraint, parse_policy};

/// What kind of caller this `Actor` represents. Drives where the
/// audit log attributes the action and which scope policy the
/// `Actor.id` should resolve against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    /// In-process plugin instance. `Actor.id` is the instance id.
    Plugin,
    /// Phase 12 external HTTP/WS request. `Actor.id` is the API
    /// token id (not the secret).
    Api,
    /// Phase 12 CLI invocation. `Actor.id` is the token id the CLI
    /// authenticated with.
    Cli,
    /// Phase 14 MCP tool call. `Actor.id` is the MCP token id.
    Mcp,
    /// Phase 7 / 13 automation script. `Actor.id` is the
    /// `<scripting-plugin>/<script-name>` pair.
    Automation,
}

impl ActorKind {
    /// Stable name for log/audit emission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ActorKind::Plugin => "plugin",
            ActorKind::Api => "api",
            ActorKind::Cli => "cli",
            ActorKind::Mcp => "mcp",
            ActorKind::Automation => "automation",
        }
    }
}

/// Identity + scopes for one command-path caller. `Clone` is cheap
/// (`Arc` internally) so the actor can be threaded through nested
/// calls without copying the scope list.
#[derive(Debug, Clone)]
pub struct Actor {
    inner: Arc<ActorInner>,
}

#[derive(Debug)]
struct ActorInner {
    kind: ActorKind,
    id: String,
    scopes: Vec<String>,
    // Phase 14.4a: per-tool constraint map from the token
    // policy. `HashMap::new()` for plugin actors and for API
    // tokens that don't carry constraints (legacy scope-array
    // shape). Empty allocation is one small
    // heap word, not per-actor overhead.
    constraints: HashMap<String, policy::ToolConstraint>,
}

impl Actor {
    /// Construct an `Actor` for an in-process plugin instance.
    /// Phase 4's only constructor; the other variants ship with the
    /// phases that introduce them.
    #[must_use]
    pub fn plugin(instance_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind: ActorKind::Plugin,
                id: instance_id.into(),
                // 0.1 plugin scopes are derived from the manifest's
                // `[capabilities]` block at load time and live on the
                // loaded plugin's state, not on the actor. Leaving
                // empty here keeps the actor purely about identity;
                // gating consults the manifest directly.
                scopes: Vec::new(),
                constraints: HashMap::new(),
            }),
        }
    }

    /// Construct an `Actor` for a Phase-12 external HTTP/WS request.
    /// `token_id` is the persisted token id (not the secret); the
    /// secret only exists in the inbound `Authorization: Bearer …`
    /// header and is hashed for comparison against the store. `scopes`
    /// is the verbatim scope list from the token record — the
    /// dispatch layer checks individual entries before executing.
    #[must_use]
    pub fn api(token_id: impl Into<String>, scopes: Vec<String>) -> Self {
        Self::api_with_policy(token_id, scopes, HashMap::new())
    }

    /// Construct an `Actor` for a Phase-12 external caller that
    /// carries a Phase-14.4 [`TokenPolicy`] with per-tool
    /// constraints. Same shape as [`Self::api`] otherwise; the
    /// `constraints` map is what
    /// [`Self::constraint`] surfaces to dispatch sites.
    ///
    /// [`Self::api`] delegates here with `HashMap::new()`, so
    /// existing call sites that don't know about the policy
    /// blob keep working — they just get a no-constraint
    /// actor.
    #[must_use]
    pub fn api_with_policy(
        token_id: impl Into<String>,
        scopes: Vec<String>,
        constraints: HashMap<String, policy::ToolConstraint>,
    ) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind: ActorKind::Api,
                id: token_id.into(),
                scopes,
                constraints,
            }),
        }
    }

    /// What kind of caller this is.
    #[must_use]
    pub fn kind(&self) -> ActorKind {
        self.inner.kind
    }

    /// Stable identifier for this caller. Shape depends on `kind`:
    /// plugin instance id, token id, etc.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    /// Authorized scopes. Empty for Phase-4 plugin actors —
    /// capability decisions for those callers go through the
    /// manifest, not the actor. Phase 12 fills this in for external
    /// callers.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.inner.scopes
    }

    /// Look up the per-tool constraint for `tool_name`, if the
    /// token carried one. `None` means the tool is
    /// **unrestricted** for this actor (subject to the flat
    /// scope check upstream).
    ///
    /// Callers combine this with the flat scope check — a
    /// dispatch site first calls
    /// [`crate::api::scopes::require_scope`] to confirm the
    /// actor holds `<tool>:...`, then, if a constraint
    /// exists, checks the tool's argument shape against
    /// [`ToolConstraint::allows_device`] /
    /// [`ToolConstraint::allows_plugin`].
    ///
    /// Introduced in Phase 14.4a; enforcement lands per-tool
    /// in follow-up slices — no dispatch site consults this
    /// yet.
    #[must_use]
    pub fn constraint(&self, tool_name: &str) -> Option<&policy::ToolConstraint> {
        self.inner.constraints.get(tool_name)
    }

    /// `true` when this actor's token carried any per-tool
    /// constraint entry.
    #[must_use]
    pub fn is_constrained(&self) -> bool {
        !self.inner.constraints.is_empty()
    }

    /// Iterate the constraint keys the token carried
    /// (`device.send_command`, `plugins.install`, unknown
    /// forward-compat keys). Order is unspecified.
    ///
    /// The bearer middleware uses this to reject tokens whose
    /// constraint set contains any key the current transport
    /// does not enforce — see `AuthState.enforced_constraint_keys`
    /// in [`crate::api::auth`]. Landing a token whose keys are
    /// only *partially* enforced would fail open on the
    /// unenforced keys (the flat scope check would pass and
    /// no dispatch site consults the constraint).
    pub fn constraint_keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.inner.constraints.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_actor_carries_instance_id() {
        let a = Actor::plugin("example.simulated-switch#0");
        assert_eq!(a.kind(), ActorKind::Plugin);
        assert_eq!(a.id(), "example.simulated-switch#0");
        assert!(a.scopes().is_empty());
    }

    #[test]
    fn actor_clone_shares_inner() {
        let a = Actor::plugin("x");
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
    }

    #[test]
    fn actor_constraint_returns_none_when_no_policy() {
        // Legacy `Actor::api` — no constraints, so every
        // tool lookup returns None (unrestricted).
        let a = Actor::api("tok-abc", vec!["devices:command".into()]);
        assert!(a.constraint("device.send_command").is_none());
        assert!(a.constraint("plugins.install").is_none());
    }

    #[test]
    fn actor_constraint_surfaces_policy_map() {
        let mut constraints = HashMap::new();
        constraints.insert(
            "device.send_command".to_string(),
            policy::ToolConstraint {
                devices: Some(vec!["dev-a1b2c3d4*".into()]),
                plugins: None,
            },
        );
        let a = Actor::api_with_policy("tok-xyz", vec!["devices:command".into()], constraints);

        let cx = a
            .constraint("device.send_command")
            .expect("device.send_command constraint present");
        assert!(cx.allows_device("dev-a1b2c3d4e5f60718"));
        assert!(!cx.allows_device("dev-a1b2c3d3ffffffff"));

        // Unqueried tool name is still unrestricted.
        assert!(a.constraint("plugins.install").is_none());
    }

    #[test]
    fn actor_kind_strings() {
        assert_eq!(ActorKind::Plugin.as_str(), "plugin");
        assert_eq!(ActorKind::Api.as_str(), "api");
        assert_eq!(ActorKind::Cli.as_str(), "cli");
        assert_eq!(ActorKind::Mcp.as_str(), "mcp");
        assert_eq!(ActorKind::Automation.as_str(), "automation");
    }
}
