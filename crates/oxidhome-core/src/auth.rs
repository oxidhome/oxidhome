//! Actor identity for host-internal calls.
//!
//! Every command, tool invocation, and state-changing call that
//! crosses an internal boundary should carry an [`Actor`]: *who* is
//! making this call?
//!
//! **Phase 4 scope.** Introduce the type and give every
//! [`PluginState`](crate::runtime::PluginState) an
//! [`Actor::plugin(instance_id)`](Actor::plugin). Host-call entry points (e.g.
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
//! What happens *after* authentication — the root principal with its
//! resolved authority, call id, deadline and delegation chain that
//! follow a request into plugin dispatch — lives in
//! [`invocation::InvocationContext`] (H6). Every REST, Connect and MCP
//! token-scope check is made by [`authorize()`] against that root
//! authority; plugin manifest grants are still checked at their own
//! call sites.
//!
//! See `ARCHITECTURE.md` "Auth & actor identity" for the
//! cross-cutting design and `00_OVERVIEW.md` for the per-phase
//! breakdown.

use std::collections::HashMap;
use std::sync::Arc;

pub mod authorize;
pub mod category;
pub mod invocation;
pub mod policy;
pub mod role;
pub mod sensitive;

pub use authorize::{
    Action, AuditLevel, Authority, CONSUMES_SERVICES_GRANT, Decision, Obligations, Reason,
    Resource, ResourceKind, ServiceResource, authorize, authorize_hop,
};
pub use category::{DeviceCategory, DeviceClass, SensitiveCategory, SensitiveSet};
pub use invocation::{DelegationHop, InvocationContext, Principal, Transport};
pub use policy::{
    DEVICE_COMMAND_ENFORCED, EnforcedConstraint, SensitiveGrant, TokenPolicy, ToolConstraint,
    parse_policy,
};
pub use role::{ActionSet, DenyRule, RoleDef, RoleGrant};

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
    // H6 slice 2: explicit sensitive-category grants from the token
    // policy (or the `mcp-stdio` operator flag). Empty for plugins.
    sensitive: Vec<policy::SensitiveGrant>,
    // H6 slice 2: the token is the host-recorded owner (bootstrap or
    // `recover-admin-token`), read from `auth_token.owner`. Never set
    // from a label or from caller input.
    owner: bool,
    // H6 slice 3: the token's owner-defined roles, resolved from
    // `auth_role` for this request (a deleted role is absent), and its
    // deny list. Empty for plugins and scope-only tokens.
    roles: Vec<Arc<role::RoleDef>>,
    deny: Vec<role::DenyRule>,
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
                sensitive: Vec::new(),
                owner: false,
                roles: Vec::new(),
                deny: Vec::new(),
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
                sensitive: Vec::new(),
                owner: false,
                roles: Vec::new(),
                deny: Vec::new(),
            }),
        }
    }

    /// Construct an external `Actor` from a verified token's whole
    /// policy: scopes, 14.4 constraints, sensitive grants and deny
    /// list. `owner` is the token's host-recorded owner flag
    /// (`auth_token.owner`). The policy's role ids are not resolved
    /// here: attach their definitions with [`Self::with_roles`], or
    /// they grant nothing.
    #[must_use]
    pub fn from_token_policy(
        token_id: impl Into<String>,
        policy: policy::TokenPolicy,
        owner: bool,
    ) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind: ActorKind::Api,
                id: token_id.into(),
                scopes: policy.scopes,
                constraints: policy.constraints,
                sensitive: policy.sensitive,
                owner,
                roles: Vec::new(),
                deny: policy.deny,
            }),
        }
    }

    /// A copy of this actor with `grants` as its sensitive grants.
    /// The `mcp-stdio` session uses it for the operator's
    /// `--allow-sensitive` flag.
    #[must_use]
    pub fn with_sensitive(&self, grants: Vec<policy::SensitiveGrant>) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind: self.inner.kind,
                id: self.inner.id.clone(),
                scopes: self.inner.scopes.clone(),
                constraints: self.inner.constraints.clone(),
                sensitive: grants,
                owner: self.inner.owner,
                roles: self.inner.roles.clone(),
                deny: self.inner.deny.clone(),
            }),
        }
    }

    /// A copy of this actor holding `roles`, the current definitions
    /// of its policy's role ids (H6 slice 3).
    #[must_use]
    pub fn with_roles(&self, roles: Vec<Arc<role::RoleDef>>) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind: self.inner.kind,
                id: self.inner.id.clone(),
                scopes: self.inner.scopes.clone(),
                constraints: self.inner.constraints.clone(),
                sensitive: self.inner.sensitive.clone(),
                owner: self.inner.owner,
                roles,
                deny: self.inner.deny.clone(),
            }),
        }
    }

    /// Explicit sensitive-category grants (H6 slice 2).
    #[must_use]
    pub fn sensitive_grants(&self) -> &[policy::SensitiveGrant] {
        &self.inner.sensitive
    }

    /// Resolved owner-defined roles (H6 slice 3).
    #[must_use]
    pub fn roles(&self) -> &[Arc<role::RoleDef>] {
        &self.inner.roles
    }

    /// The deny list (H6 slice 3).
    #[must_use]
    pub fn deny_rules(&self) -> &[role::DenyRule] {
        &self.inner.deny
    }

    /// `true` when this actor's token is the host-recorded owner.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.inner.owner
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
    /// Dispatch sites don't consult this directly: the invocation's
    /// root [`authorize::Authority`] shares this actor's `Arc`, and
    /// [`authorize()`] applies the constraint.
    #[must_use]
    pub fn constraint(&self, tool_name: &str) -> Option<&policy::ToolConstraint> {
        self.inner.constraints.get(tool_name)
    }

    /// The full per-tool constraint map, keyed by tool name. The root
    /// [`Authority`] of an invocation reads this same map.
    #[must_use]
    pub fn constraints(&self) -> &HashMap<String, policy::ToolConstraint> {
        &self.inner.constraints
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
    /// The bearer middleware iterates this to reject tokens
    /// carrying any constraint the current transport does not
    /// enforce — see `AuthState::enforced_constraints`
    /// (`&[EnforcedConstraint]`) in `crate::api::auth`. Each
    /// enforced entry names a key **and** which
    /// [`ToolConstraint`] fields the dispatch site actually
    /// consults; a bearer whose policy names an unenforced
    /// key OR sets a field the entry doesn't consume would
    /// fail open on that dimension (flat scope check passes,
    /// no dispatch site reads the field), so both cases are
    /// refused.
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
        assert_eq!(a.scopes(), Vec::<String>::new());
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
