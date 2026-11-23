//! One authorization decision point (H6 slice 2).
//!
//! Every external token-scope check goes through [`authorize`]:
//! REST and Connect handlers, MCP tools, resources and prompts, the
//! 14.4 per-token constraints, and the M7 byte-withholding check. A
//! call names *what* is being done ([`Action`], a closed enum) and *to
//! what* ([`Resource`], built by host code), and gets back a
//! [`Decision`] with a [`Reason`] for the audit ledger and the
//! [`Obligations`] that come with an allow.
//!
//! The decision is made against the root principal's resolved
//! [`Authority`] carried on the [`InvocationContext`]: its scopes and
//! its 14.4 constraints. Nothing is read from the request itself.
//!
//! # Evaluator
//!
//! The evaluator reproduces the token scope semantics exactly:
//!
//! 1. Each action maps to the one scope that has always gated it
//!    (`Action::legacy_scope`). A token holds the action when its scope
//!    list contains that scope literally or the wildcard `*`. An action
//!    no scope maps to is refused ([`Reason::NoPermit`]).
//! 2. For a few (action, resource) pairs, a 14.4 per-token constraint
//!    narrows the scope to an id allowlist: `device.send_command`
//!    (`devices`) on a device command, and `plugins.show` /
//!    `plugins.start` / `plugins.stop` / `plugins.uninstall` /
//!    `plugins.install` (`plugins`) on the matching plugin action. A
//!    constraint only applies to a resource that names its target; a
//!    collection-level check ([`Resource::Collection`], [`Resource::Host`])
//!    is the flat scope alone.
//!
//! Plugin principals are still authorized by their manifest grants at
//! their own call sites (`consumes_services`, `reads_state`,
//! `subscribes_events`); [`Action::ServiceCall`] and
//! [`Action::StateRead`] exist so the taxonomy is complete, and are
//! refused here.
//!
//! Each transport keeps its existing deny wire shape (an empty REST
//! 403, Connect `permission_denied` with `scope <label> required`, a
//! generic MCP `-32001` for tools and resources, the missing scope
//! named for prompts); [`Reason::audit_label`] is what lands in the
//! audit row's `required_scope` column.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::Actor;
use super::invocation::InvocationContext;
use super::policy::{DEVICE_COMMAND_DENIED_SENTINEL, DEVICE_COMMAND_ENFORCED, ToolConstraint};
use crate::api::scopes::{self, Scope};

/// What the caller wants to do. Closed: a new action is a host change,
/// never caller input. Names follow `kind.verb` ([`Self::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// List registered devices (`devices:list`).
    DeviceList,
    /// Read device state (`devices:read`).
    DeviceRead,
    /// Send a command to a device (`devices:command`).
    DeviceCommand,
    /// Subscribe to the live event stream (`events:tail`).
    EventSubscribe,
    /// Read event history (`events:read`).
    EventRead,
    /// Read blob payloads, including `bytes-val` in state, events and
    /// command results (`blobs:read`).
    BlobRead,
    /// List running instances (`instances:list`).
    InstanceRead,
    /// Start an instance of an installed plugin (`plugins:start`).
    InstanceStart,
    /// Stop instances of a plugin (`plugins:stop`).
    InstanceStop,
    /// Read installed plugins, their detail and schema (`plugins:list`).
    PluginRead,
    /// Install a plugin (`plugins:install`).
    PluginInstall,
    /// Remove an installed plugin (`plugins:uninstall`).
    PluginUninstall,
    /// Open a plugin's UI (`plugins:ui`).
    PluginUi,
    /// Read dashboards (`dashboards:read`).
    DashboardRead,
    /// Create, replace or delete dashboards (`dashboards:write`).
    DashboardWrite,
    /// Read host status and effective configuration (`status:read`).
    HostStatus,
    /// Read host logs (`logs:read`).
    HostLogs,
    /// Read the audit ledger (`audit:read`).
    HostAudit,
    /// Manage tokens. CLI only today; no scope grants it.
    TokenManage,
    /// Manage authorization policy. No scope grants it.
    PolicyManage,
    /// Call a plugin service. Plugin principals are authorized by
    /// `consumes_services` in the dispatcher; no scope grants it.
    ServiceCall,
    /// Read another plugin's device state. Plugin principals are
    /// authorized by `reads_state`; no scope grants it.
    StateRead,
}

impl Action {
    /// Every action, for exhaustive tests and listings.
    pub const ALL: [Action; 22] = [
        Action::DeviceList,
        Action::DeviceRead,
        Action::DeviceCommand,
        Action::EventSubscribe,
        Action::EventRead,
        Action::BlobRead,
        Action::InstanceRead,
        Action::InstanceStart,
        Action::InstanceStop,
        Action::PluginRead,
        Action::PluginInstall,
        Action::PluginUninstall,
        Action::PluginUi,
        Action::DashboardRead,
        Action::DashboardWrite,
        Action::HostStatus,
        Action::HostLogs,
        Action::HostAudit,
        Action::TokenManage,
        Action::PolicyManage,
        Action::ServiceCall,
        Action::StateRead,
    ];

    /// Stable `kind.verb` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::DeviceList => "device.list",
            Action::DeviceRead => "device.read",
            Action::DeviceCommand => "device.command",
            Action::EventSubscribe => "event.subscribe",
            Action::EventRead => "event.read",
            Action::BlobRead => "blob.read",
            Action::InstanceRead => "instance.read",
            Action::InstanceStart => "instance.start",
            Action::InstanceStop => "instance.stop",
            Action::PluginRead => "plugin.read",
            Action::PluginInstall => "plugin.install",
            Action::PluginUninstall => "plugin.uninstall",
            Action::PluginUi => "plugin.ui",
            Action::DashboardRead => "dashboard.read",
            Action::DashboardWrite => "dashboard.write",
            Action::HostStatus => "host.status",
            Action::HostLogs => "host.logs",
            Action::HostAudit => "host.audit",
            Action::TokenManage => "token.manage",
            Action::PolicyManage => "policy.manage",
            Action::ServiceCall => "service.call",
            Action::StateRead => "state.read",
        }
    }

    /// The token scope that grants this action, if any.
    #[must_use]
    pub(crate) fn legacy_scope(self) -> Option<Scope> {
        Some(match self {
            Action::DeviceList => scopes::DEVICES_LIST,
            Action::DeviceRead => scopes::DEVICES_READ,
            Action::DeviceCommand => scopes::DEVICES_COMMAND,
            Action::EventSubscribe => scopes::EVENTS_TAIL,
            Action::EventRead => scopes::EVENTS_READ,
            Action::BlobRead => scopes::BLOBS_READ,
            Action::InstanceRead => scopes::INSTANCES_LIST,
            Action::InstanceStart => scopes::PLUGINS_START,
            Action::InstanceStop => scopes::PLUGINS_STOP,
            Action::PluginRead => scopes::PLUGINS_LIST,
            Action::PluginInstall => scopes::PLUGINS_INSTALL,
            Action::PluginUninstall => scopes::PLUGINS_UNINSTALL,
            Action::PluginUi => scopes::PLUGINS_UI,
            Action::DashboardRead => scopes::DASHBOARDS_READ,
            Action::DashboardWrite => scopes::DASHBOARDS_WRITE,
            Action::HostStatus => scopes::STATUS_READ,
            Action::HostLogs => scopes::LOGS_READ,
            Action::HostAudit => scopes::AUDIT_READ,
            Action::TokenManage
            | Action::PolicyManage
            | Action::ServiceCall
            | Action::StateRead => return None,
        })
    }
}

/// Kinds of resource, for collection-level checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// Registered devices and their state.
    Device,
    /// Bus events, live or historical.
    Event,
    /// Blob payloads and `bytes-val` values.
    Blob,
    /// Plugin instances.
    Instance,
    /// Installed plugins.
    Plugin,
    /// Dashboards.
    Dashboard,
}

/// What an action targets. Built by host code from the id the call
/// addresses or from the host's own registries, never deserialized from
/// a request. Variants carry attribute structs with private fields so
/// later slices can add host-owned attributes (device category, area,
/// tags) without changing any call site's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    /// The host itself: status, configuration, logs, audit, and a plugin
    /// install before its manifest is read.
    Host,
    /// Resources of one kind in general: list endpoints, streams, route
    /// pre-checks made before the target is known, and reads not yet
    /// checked per target. Never narrowed by a per-target constraint.
    Collection(ResourceKind),
    /// One device.
    Device(DeviceResource),
    /// One installed plugin.
    Plugin(PluginResource),
    /// Instances of one plugin, or one of them.
    Instance(InstanceResource),
    /// One blob.
    Blob(BlobResource),
    /// One dashboard.
    Dashboard(DashboardResource),
}

impl Resource {
    /// One device, addressed by its host-minted `dev-…` id.
    #[must_use]
    pub fn device(id: impl Into<String>) -> Self {
        Self::Device(DeviceResource { id: id.into() })
    }

    /// One installed plugin.
    #[must_use]
    pub fn plugin(plugin_id: impl Into<String>) -> Self {
        Self::Plugin(PluginResource {
            plugin_id: plugin_id.into(),
        })
    }

    /// Instances of `plugin_id`; `instance_id` narrows to one.
    #[must_use]
    pub fn instance(plugin_id: impl Into<String>, instance_id: Option<String>) -> Self {
        Self::Instance(InstanceResource {
            plugin_id: plugin_id.into(),
            instance_id,
        })
    }

    /// One blob owned by `instance_id`.
    #[must_use]
    pub fn blob(instance_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::Blob(BlobResource {
            instance_id: instance_id.into(),
            name: name.into(),
        })
    }

    /// One dashboard.
    #[must_use]
    pub fn dashboard(id: i64) -> Self {
        Self::Dashboard(DashboardResource { id })
    }

    /// The device collection.
    #[must_use]
    pub const fn devices() -> Self {
        Self::Collection(ResourceKind::Device)
    }

    /// The event stream and history.
    #[must_use]
    pub const fn events() -> Self {
        Self::Collection(ResourceKind::Event)
    }

    /// Blob payloads in general (M7 byte withholding).
    #[must_use]
    pub const fn blobs() -> Self {
        Self::Collection(ResourceKind::Blob)
    }

    /// The instance collection.
    #[must_use]
    pub const fn instances() -> Self {
        Self::Collection(ResourceKind::Instance)
    }

    /// The installed-plugin collection.
    #[must_use]
    pub const fn plugins() -> Self {
        Self::Collection(ResourceKind::Plugin)
    }

    /// The dashboard collection.
    #[must_use]
    pub const fn dashboards() -> Self {
        Self::Collection(ResourceKind::Dashboard)
    }
}

/// Device attributes the host decides on. Today: the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceResource {
    id: String,
}

impl DeviceResource {
    /// Host-minted `dev-<16 hex>` id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Plugin attributes the host decides on. Today: the plugin id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginResource {
    plugin_id: String,
}

impl PluginResource {
    /// Plugin id.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }
}

/// Instance attributes the host decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceResource {
    plugin_id: String,
    instance_id: Option<String>,
}

impl InstanceResource {
    /// Plugin the instances belong to.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// One instance, when the call names it.
    #[must_use]
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }
}

/// Blob attributes the host decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobResource {
    instance_id: String,
    name: String,
}

impl BlobResource {
    /// Owning instance.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Blob name within the instance.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Dashboard attributes the host decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardResource {
    id: i64,
}

impl DashboardResource {
    /// Dashboard row id.
    #[must_use]
    pub fn id(&self) -> i64 {
        self.id
    }
}

/// The resolved authority of an invocation's root principal: the token
/// id plus its scopes and 14.4 constraints, as verified by the bearer
/// middleware (or the ambient grant of a local-process transport).
/// Host-only: never serialized, never in an audit row, never visible to
/// a plugin.
///
/// Host-origin work (`init`, `tick`, `on-event`) has an empty
/// authority: plugins are authorized by their manifest grants, not
/// scopes.
#[derive(Debug, Clone, Default)]
pub struct Authority {
    source: Source,
}

/// Where the policy lives. A token authority shares the verified
/// [`Actor`]'s `Arc` instead of copying its scopes and constraints, so
/// building a principal per request or per MCP read is a refcount bump.
#[derive(Debug, Clone)]
enum Source {
    Owned(Arc<AuthorityInner>),
    Actor { actor: Actor, token: bool },
}

impl Default for Source {
    fn default() -> Self {
        Self::Owned(Arc::default())
    }
}

#[derive(Debug, Default)]
struct AuthorityInner {
    token_id: Option<String>,
    scopes: Vec<String>,
    constraints: HashMap<String, ToolConstraint>,
}

impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        self.token_id() == other.token_id()
            && self.scopes() == other.scopes()
            && self.constraints() == other.constraints()
    }
}

impl Eq for Authority {}

impl Authority {
    /// No authority: every action is refused.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The authority a verified token carries. `token_id` is the
    /// credential id (`None` for a local-process grant).
    #[must_use]
    pub fn new(
        token_id: Option<String>,
        scopes: Vec<String>,
        constraints: HashMap<String, ToolConstraint>,
    ) -> Self {
        Self {
            source: Source::Owned(Arc::new(AuthorityInner {
                token_id,
                scopes,
                constraints,
            })),
        }
    }

    /// The authority of a bearer-token [`Actor`]: its id as the token
    /// id, its scopes and its constraints.
    #[must_use]
    pub fn of_token(actor: &Actor) -> Self {
        Self {
            source: Source::Actor {
                actor: actor.clone(),
                token: true,
            },
        }
    }

    /// The authority of an actor authorized by the local process
    /// boundary rather than a credential (MCP stdio): its scopes and
    /// constraints, no token id.
    #[must_use]
    pub fn of_local_process(actor: &Actor) -> Self {
        Self {
            source: Source::Actor {
                actor: actor.clone(),
                token: false,
            },
        }
    }

    /// Token that carries this authority, if any.
    #[must_use]
    pub fn token_id(&self) -> Option<&str> {
        match &self.source {
            Source::Owned(inner) => inner.token_id.as_deref(),
            Source::Actor { actor, token } => token.then(|| actor.id()),
        }
    }

    /// Resolved scope list.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        match &self.source {
            Source::Owned(inner) => &inner.scopes,
            Source::Actor { actor, .. } => actor.scopes(),
        }
    }

    /// The 14.4 constraint for `key` (a tool name), if the token
    /// carries one.
    #[must_use]
    pub fn constraint(&self, key: &str) -> Option<&ToolConstraint> {
        self.constraints().get(key)
    }

    fn constraints(&self) -> &HashMap<String, ToolConstraint> {
        match &self.source {
            Source::Owned(inner) => &inner.constraints,
            Source::Actor { actor, .. } => actor.constraints(),
        }
    }
}

/// Why a decision came out the way it did. Not `Copy`: later slices
/// add reasons that carry owned data (the deny entry that matched).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Allowed: the token holds `scope` (or the wildcard) and no
    /// constraint narrows it for this resource.
    Scope {
        /// Scope that granted the action.
        scope: &'static str,
    },
    /// Denied: the token does not hold `scope`.
    MissingScope {
        /// Scope the action needs.
        scope: &'static str,
    },
    /// Denied: the token holds the scope, but a 14.4 constraint does not
    /// cover the resource.
    Constraint {
        /// Constraint key (a tool name, e.g. `device.send_command`).
        key: &'static str,
        /// Constraint field that refused (`devices`, `plugins`).
        field: &'static str,
        /// Audit sentinel, `constraint:<key>:<field>`.
        sentinel: &'static str,
    },
    /// Denied: no scope grants this action.
    NoPermit,
}

/// Audit label for [`Reason::NoPermit`].
pub const NO_PERMIT_LABEL: &str = "no-permit";

impl Reason {
    /// The value a deny writes to the audit row's `required_scope`
    /// column: the missing scope, the constraint sentinel, or
    /// [`NO_PERMIT_LABEL`]. `None` for an allow.
    #[must_use]
    pub fn audit_label(&self) -> Option<&'static str> {
        match self {
            Reason::Scope { .. } => None,
            Reason::MissingScope { scope } => Some(*scope),
            Reason::Constraint { sentinel, .. } => Some(*sentinel),
            Reason::NoPermit => Some(NO_PERMIT_LABEL),
        }
    }
}

/// Audit level an allowed action requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLevel {
    /// The transport's ordinary per-request row.
    #[default]
    Info,
    /// A row at `warn` (sensitive allows; not produced yet).
    Warn,
}

/// A rate limit an allowed action must pass. Not produced yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Allowed calls per window.
    pub max: u32,
    /// Window length.
    pub per: Duration,
}

/// What the caller must do on top of an allow. Only `audit_level` is
/// set today, always [`AuditLevel::Info`]; `rate_limit` and
/// `require_confirmation` stay unset until sensitive categories land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Obligations {
    /// How the allow is audited.
    pub audit_level: AuditLevel,
    /// Rate limit to apply, if any.
    pub rate_limit: Option<RateLimit>,
    /// Whether the request must carry a fresh confirmation.
    pub require_confirmation: bool,
}

/// The outcome of [`authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `true` to proceed.
    pub allow: bool,
    /// Why.
    pub reason: Reason,
    /// Obligations on an allow; default on a deny.
    pub obligations: Obligations,
}

impl Decision {
    fn allow(reason: Reason) -> Self {
        Self {
            allow: true,
            reason,
            obligations: Obligations::default(),
        }
    }

    fn deny(reason: Reason) -> Self {
        Self {
            allow: false,
            reason,
            obligations: Obligations::default(),
        }
    }

    /// `Ok(self)` on an allow, `Err(audit label)` on a deny: the shape
    /// the transport adapters turn into a 403 / `permission-denied`.
    ///
    /// # Errors
    ///
    /// Returns the deny's [`Reason::audit_label`].
    pub fn into_result(self) -> Result<Self, &'static str> {
        if self.allow {
            Ok(self)
        } else {
            Err(self.reason.audit_label().unwrap_or(NO_PERMIT_LABEL))
        }
    }
}

/// Decide whether the invocation's root may perform `action` on
/// `resource`. See the module docs for the evaluator.
#[must_use]
pub fn authorize(ctx: &InvocationContext, action: Action, resource: &Resource) -> Decision {
    evaluate(ctx.root().authority(), action, resource)
}

/// The evaluator behind [`authorize`], on an [`Authority`] directly.
#[must_use]
pub(crate) fn evaluate(authority: &Authority, action: Action, resource: &Resource) -> Decision {
    let Some(scope) = action.legacy_scope() else {
        return Decision::deny(Reason::NoPermit);
    };
    if !scope.satisfied_by(authority.scopes()) {
        return Decision::deny(Reason::MissingScope {
            scope: scope.name(),
        });
    }
    if let Some(rule) = constraint_rule(action, resource)
        && let Some(cx) = authority.constraint(rule.key)
        && !rule.allows(cx)
    {
        return Decision::deny(Reason::Constraint {
            key: rule.key,
            field: rule.field.as_str(),
            sentinel: rule.sentinel,
        });
    }
    Decision::allow(Reason::Scope {
        scope: scope.name(),
    })
}

/// Which [`ToolConstraint`] field a rule consults.
#[derive(Debug, Clone, Copy)]
enum ConstraintField {
    Devices,
    Plugins,
}

impl ConstraintField {
    const fn as_str(self) -> &'static str {
        match self {
            ConstraintField::Devices => "devices",
            ConstraintField::Plugins => "plugins",
        }
    }
}

/// One 14.4 constraint that narrows an (action, resource) pair.
struct ConstraintRule<'r> {
    key: &'static str,
    field: ConstraintField,
    sentinel: &'static str,
    target: &'r str,
}

impl ConstraintRule<'_> {
    fn allows(&self, cx: &ToolConstraint) -> bool {
        match self.field {
            ConstraintField::Devices => cx.allows_device(self.target),
            ConstraintField::Plugins => cx.allows_plugin(self.target),
        }
    }
}

/// `required_scope` sentinels for the `plugins.*` constraints,
/// `constraint:<key>:plugins`.
pub const PLUGINS_SHOW_DENIED_SENTINEL: &str = "constraint:plugins.show:plugins";
/// See [`PLUGINS_SHOW_DENIED_SENTINEL`].
pub const PLUGINS_STOP_DENIED_SENTINEL: &str = "constraint:plugins.stop:plugins";
/// See [`PLUGINS_SHOW_DENIED_SENTINEL`].
pub const PLUGINS_UNINSTALL_DENIED_SENTINEL: &str = "constraint:plugins.uninstall:plugins";
/// See [`PLUGINS_SHOW_DENIED_SENTINEL`].
pub const PLUGINS_START_DENIED_SENTINEL: &str = "constraint:plugins.start:plugins";
/// See [`PLUGINS_SHOW_DENIED_SENTINEL`].
pub const PLUGINS_INSTALL_DENIED_SENTINEL: &str = "constraint:plugins.install:plugins";

/// The 14.4 constraint table. A constraint applies only to a resource
/// that names its target; the key names the tool whose argument the
/// constraint was written against.
fn constraint_rule(action: Action, resource: &Resource) -> Option<ConstraintRule<'_>> {
    let plugins = |key, sentinel, target| {
        Some(ConstraintRule {
            key,
            field: ConstraintField::Plugins,
            sentinel,
            target,
        })
    };
    match (action, resource) {
        (Action::DeviceCommand, Resource::Device(d)) => Some(ConstraintRule {
            key: DEVICE_COMMAND_ENFORCED.key,
            field: ConstraintField::Devices,
            sentinel: DEVICE_COMMAND_DENIED_SENTINEL,
            target: &d.id,
        }),
        (Action::PluginRead, Resource::Plugin(p)) => {
            plugins("plugins.show", PLUGINS_SHOW_DENIED_SENTINEL, &p.plugin_id)
        }
        (Action::InstanceStop, Resource::Instance(i)) => {
            plugins("plugins.stop", PLUGINS_STOP_DENIED_SENTINEL, &i.plugin_id)
        }
        (Action::InstanceStart, Resource::Instance(i)) => {
            plugins("plugins.start", PLUGINS_START_DENIED_SENTINEL, &i.plugin_id)
        }
        (Action::PluginUninstall, Resource::Plugin(p)) => plugins(
            "plugins.uninstall",
            PLUGINS_UNINSTALL_DENIED_SENTINEL,
            &p.plugin_id,
        ),
        (Action::PluginInstall, Resource::Plugin(p)) => plugins(
            "plugins.install",
            PLUGINS_INSTALL_DENIED_SENTINEL,
            &p.plugin_id,
        ),
        _ => None,
    }
}

#[cfg(test)]
mod parity;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ActorKind, Principal, Transport};

    fn ctx_for(actor: &Actor) -> InvocationContext {
        InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest))
    }

    #[test]
    fn action_names_are_unique_kind_verb() {
        let mut seen = std::collections::HashSet::new();
        for a in Action::ALL {
            assert!(seen.insert(a.as_str()), "duplicate {}", a.as_str());
            assert!(a.as_str().contains('.'), "{} is not kind.verb", a.as_str());
        }
    }

    #[test]
    fn host_origin_context_is_refused_everything() {
        let ctx = InvocationContext::host_origin("alpha");
        for a in Action::ALL {
            assert!(!authorize(&ctx, a, &Resource::Host).allow, "{}", a.as_str());
        }
    }

    #[test]
    fn unmapped_actions_are_refused_even_for_wildcard() {
        let ctx = ctx_for(&Actor::api("admin", vec!["*".into()]));
        for a in [
            Action::TokenManage,
            Action::PolicyManage,
            Action::ServiceCall,
            Action::StateRead,
        ] {
            let d = authorize(&ctx, a, &Resource::Host);
            assert!(!d.allow);
            assert_eq!(d.reason, Reason::NoPermit);
            assert_eq!(d.reason.audit_label(), Some(NO_PERMIT_LABEL));
        }
    }

    #[test]
    fn allow_carries_scope_and_info_audit() {
        let ctx = ctx_for(&Actor::api("t", vec!["devices:list".into()]));
        let d = authorize(&ctx, Action::DeviceList, &Resource::devices());
        assert!(d.allow);
        assert_eq!(
            d.reason,
            Reason::Scope {
                scope: "devices:list"
            }
        );
        assert_eq!(d.reason.audit_label(), None);
        assert_eq!(d.obligations, Obligations::default());
        assert_eq!(d.obligations.audit_level, AuditLevel::Info);
        assert!(d.obligations.rate_limit.is_none());
        assert!(!d.obligations.require_confirmation);
        assert!(d.into_result().is_ok());
    }

    #[test]
    fn constraint_deny_names_key_field_and_sentinel() {
        let mut constraints = HashMap::new();
        constraints.insert(
            "plugins.stop".to_string(),
            ToolConstraint {
                devices: None,
                plugins: Some(vec!["acme.*".into()]),
            },
        );
        let actor = Actor::api_with_policy("t", vec!["*".into()], constraints);
        let ctx = ctx_for(&actor);
        let d = authorize(
            &ctx,
            Action::InstanceStop,
            &Resource::instance("other.p", None),
        );
        assert_eq!(
            d.reason,
            Reason::Constraint {
                key: "plugins.stop",
                field: "plugins",
                sentinel: PLUGINS_STOP_DENIED_SENTINEL,
            }
        );
        assert_eq!(d.into_result(), Err(PLUGINS_STOP_DENIED_SENTINEL));
        // Collection-level pre-check is the flat scope alone.
        assert!(authorize(&ctx, Action::InstanceStop, &Resource::instances()).allow);
        assert!(
            authorize(
                &ctx,
                Action::InstanceStop,
                &Resource::instance("acme.lamp", Some("lamp".into())),
            )
            .allow
        );
    }

    #[test]
    fn authority_travels_with_derived_contexts() {
        let actor = Actor::api("tok-a", vec!["devices:read".into()]);
        let ctx = ctx_for(&actor).entering("alpha");
        assert_eq!(ctx.root().authority().token_id(), Some("tok-a"));
        assert_eq!(
            ctx.root().authority().scopes(),
            &["devices:read".to_string()]
        );
        assert!(authorize(&ctx, Action::DeviceRead, &Resource::devices()).allow);
    }

    #[test]
    fn local_process_authority_has_no_token_id() {
        let actor = Actor::api("mcp-stdio-parent-process", vec!["*".into()]);
        let p = Principal::local_process(ActorKind::Mcp, actor.id(), Transport::McpStdio)
            .with_authority(Authority::of_local_process(&actor));
        let ctx = InvocationContext::external(p);
        assert_eq!(ctx.root().authority().token_id(), None);
        assert!(authorize(&ctx, Action::PluginInstall, &Resource::Host).allow);
        // Without the authority a local-process principal holds nothing.
        let bare = InvocationContext::external(Principal::local_process(
            ActorKind::Mcp,
            "x",
            Transport::McpStdio,
        ));
        assert!(!authorize(&bare, Action::DeviceList, &Resource::devices()).allow);
    }
}
