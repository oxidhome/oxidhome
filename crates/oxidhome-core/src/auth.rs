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
//! Beyond identity, [`Actor`] carries what the caller may do: for a
//! token, its owner flag and the definitions of the roles it holds.
//! Plugin actors hold no roles; their manifest grants decide.
//!
//! What happens *after* authentication — the root principal with its
//! resolved authority, call id, deadline and delegation chain that
//! follow a request into plugin dispatch — lives in
//! [`invocation::InvocationContext`] (H6). Every REST, Connect and MCP
//! permission check is made by [`authorize()`] against that root
//! authority; plugin manifest grants are still checked at their own
//! call sites.

use std::sync::Arc;

pub mod authorize;
pub mod category;
pub mod invocation;
pub mod role;
pub mod sensitive;

pub use authorize::{
    Action, Authority, CONSUMES_SERVICES_GRANT, Decision, Reason, Resource, ResourceKind,
    ServiceResource, authorize, authorize_hop,
};
pub use category::{DeviceCategory, DeviceClass, SensitiveCategory, SensitiveSet};
pub use invocation::{DelegationHop, InvocationContext, Principal, Transport};
pub use role::{ActionSet, GrantWire, RoleDef, RoleGrant};

/// What kind of caller this `Actor` represents. Drives where the
/// audit log attributes the action and which roles the
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

/// Identity and roles of one command-path caller. `Clone` is cheap
/// (`Arc` internally) so the actor can be threaded through nested
/// calls.
#[derive(Debug, Clone)]
pub struct Actor {
    inner: Arc<ActorInner>,
}

#[derive(Debug)]
struct ActorInner {
    kind: ActorKind,
    id: String,
    // The token is the host-recorded owner (bootstrap or
    // `recover-admin-token`), read from `auth_token.owner`. Never set
    // from a label or from caller input.
    owner: bool,
    // The definitions of the roles the token holds, resolved for this
    // request. Empty for plugins.
    roles: Vec<Arc<role::RoleDef>>,
}

impl Actor {
    fn new(kind: ActorKind, id: String, owner: bool, roles: Vec<Arc<role::RoleDef>>) -> Self {
        Self {
            inner: Arc::new(ActorInner {
                kind,
                id,
                owner,
                roles,
            }),
        }
    }

    /// An in-process plugin instance. It holds no roles: its manifest
    /// grants decide what it may do.
    #[must_use]
    pub fn plugin(instance_id: impl Into<String>) -> Self {
        Self::new(ActorKind::Plugin, instance_id.into(), false, Vec::new())
    }

    /// A verified API token: `token_id` is the persisted id (never the
    /// secret), `owner` its `auth_token.owner` flag, `roles` the
    /// definitions of the roles it holds.
    #[must_use]
    pub fn token(token_id: impl Into<String>, owner: bool, roles: Vec<Arc<role::RoleDef>>) -> Self {
        Self::new(ActorKind::Api, token_id.into(), owner, roles)
    }

    /// A non-owner API token holding `roles`.
    #[must_use]
    pub fn api(token_id: impl Into<String>, roles: Vec<Arc<role::RoleDef>>) -> Self {
        Self::token(token_id, false, roles)
    }

    /// The roles this actor holds.
    #[must_use]
    pub fn roles(&self) -> &[Arc<role::RoleDef>] {
        &self.inner.roles
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_actor_carries_instance_id() {
        let a = Actor::plugin("example.simulated-switch#0");
        assert_eq!(a.kind(), ActorKind::Plugin);
        assert_eq!(a.id(), "example.simulated-switch#0");
        assert!(a.roles().is_empty() && !a.is_owner());
    }

    #[test]
    fn actor_clone_shares_inner() {
        let a = Actor::plugin("x");
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.inner, &b.inner));
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
