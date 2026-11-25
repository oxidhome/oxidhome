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
//! [`Authority`] carried on the [`InvocationContext`]: its scopes, its
//! 14.4 constraints, its resolved roles and deny list, its sensitive
//! grants and owner flag. Nothing is read from the request itself.
//!
//! # Evaluator
//!
//! The evaluator reproduces the token scope semantics, then adds
//! owner-defined roles, the deny list and the sensitive-category rule:
//!
//! 0. **Deny list (H6 slice 3).** A [`crate::auth::DenyRule`] of the
//!    token, or a deny that comes with one of its roles, that matches
//!    the action and resource refuses it ([`Reason::Denied`], label
//!    `deny`), whatever grants it below.
//! 1. Each action maps to the one scope that has always gated it
//!    (`Action::legacy_scope`). A token holds the action when its scope
//!    list contains that scope literally or the wildcard `*`, **or**
//!    when one of its roles ([`crate::auth::RoleDef`]) has a grant for
//!    the action that covers the resource ([`Reason::Role`]). A role
//!    grant narrowed to device categories or ids covers a matching
//!    device and the device pre-check ([`Resource::PreCheck`]), never a
//!    whole collection. A token with no grant for the action is
//!    refused with the scope it lacks ([`Reason::MissingScope`]); one
//!    whose role grants the action elsewhere, with
//!    [`Reason::NoPermit`]. An action no scope maps to is refused
//!    ([`Reason::NoPermit`]).
//! 2. For a few (action, resource) pairs, a 14.4 per-token constraint
//!    narrows the scope to an id allowlist: `device.send_command`
//!    (`devices`) on a device command, and `plugins.show` /
//!    `plugins.start` / `plugins.stop` / `plugins.uninstall` /
//!    `plugins.install` (`plugins`) on the matching plugin action. A
//!    constraint only applies to a resource that names its target; a
//!    collection-level check ([`Resource::Collection`], [`Resource::Host`])
//!    is the flat scope alone.
//! 3. **Sensitive categories.** A command on a device whose class
//!    ([`DeviceClass`], host-derived) includes `lock`, `opener` or
//!    `alarm`, and `blob.read` of camera bytes (a camera device, or a
//!    blob of a camera instance), additionally need a
//!    [`SensitiveGrant`] (or a role's sensitive category) covering
//!    every such category and the device ([`Reason::MissingSensitive`],
//!    label `sensitive:<category>`).
//!    The wildcard scope never satisfies this; the owner token
//!    ([`Authority::is_owner`]) does. An allow carries
//!    [`Obligations`] — `warn` audit level, the categories, and a
//!    per-category [`RateLimit`] for non-owners — which the caller
//!    meets with [`crate::auth::sensitive::SensitiveGuard`] before it
//!    acts. Collection-level checks are never sensitive.
//! 4. [`Action::PolicyManage`] (category overrides) and
//!    [`Action::TokenManage`] (minting and listing tokens) are the
//!    owner's alone; no scope or role grants them.
//!
//! The parity tests (`parity.rs`) pin that steps 1 and 2 match the
//! checks they replaced on non-sensitive targets, list each
//! intentional departure on sensitive ones, and check sample
//! owner-defined roles against an independent oracle.
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
use super::category::{DeviceClass, SensitiveCategory, SensitiveSet};
use super::invocation::InvocationContext;
use super::policy::{
    DEVICE_COMMAND_DENIED_SENTINEL, DEVICE_COMMAND_ENFORCED, SensitiveGrant, ToolConstraint,
};
use super::role::{DenyRule, RoleDef};
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
    /// Mint and list tokens over the API. The owner's alone; no scope
    /// or role grants it.
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

    /// This action's bit in an [`crate::auth::ActionSet`].
    pub(crate) const fn bit(self) -> u32 {
        1 << (self as u32)
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
    /// Every resource of one kind: list endpoints and streams that
    /// release every item, and reads not checked per target. Never
    /// narrowed by a per-target constraint. A role grant narrowed to
    /// device categories never covers it, and a deny with a selector
    /// covers it when the kind can hold a denied device (devices,
    /// events, blobs).
    Collection(ResourceKind),
    /// A pre-check made before the target is known, which a
    /// per-target check (or a per-item filter) always follows: may the
    /// root do this to *some* resource of this kind? The scope check
    /// alone, like [`Self::Collection`]; a category-narrowed role grant
    /// covers it and a selector deny never does, since the per-target
    /// check decides.
    PreCheck(ResourceKind),
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
    /// One device, addressed by its host-minted `dev-…` id, with the
    /// class the host derived for it. Build it with
    /// [`crate::state::DeviceRegistry::resource`], which reads the
    /// class from the registry and the durable `device_meta` floor;
    /// never from caller input.
    #[must_use]
    pub fn device(id: impl Into<String>, class: DeviceClass) -> Self {
        Self::Device(DeviceResource {
            id: id.into(),
            class,
        })
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

    /// One blob owned by `instance_id`. `camera` is the host's
    /// classification of the owning instance: `true` when it has ever
    /// registered a camera-category device (blobs carry no provenance
    /// of their own, so a camera plugin's blobs are all camera blobs).
    #[must_use]
    pub fn blob(instance_id: impl Into<String>, name: impl Into<String>, camera: bool) -> Self {
        Self::Blob(BlobResource {
            instance_id: instance_id.into(),
            name: name.into(),
            camera,
        })
    }

    /// One dashboard.
    #[must_use]
    pub fn dashboard(id: i64) -> Self {
        Self::Dashboard(DashboardResource { id })
    }

    /// The pre-check for `kind`, before a per-target check.
    #[must_use]
    pub const fn pre_check(kind: ResourceKind) -> Self {
        Self::PreCheck(kind)
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

    /// Blob payloads in general. Never sensitive, so it never decides
    /// whether a camera's bytes are released; that is `blob.read` on
    /// the device or blob itself.
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

/// Device attributes the host decides on: the id and the
/// host-derived class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceResource {
    id: String,
    class: DeviceClass,
}

impl DeviceResource {
    /// Host-minted `dev-<16 hex>` id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Host-derived category and sensitive set.
    #[must_use]
    pub fn class(&self) -> DeviceClass {
        self.class
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
    camera: bool,
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

    /// `true` when the owning instance is a camera source.
    #[must_use]
    pub fn is_camera(&self) -> bool {
        self.camera
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
    sensitive: Vec<SensitiveGrant>,
    owner: bool,
    roles: Vec<Arc<RoleDef>>,
    deny: Vec<DenyRule>,
}

impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        self.token_id() == other.token_id()
            && self.scopes() == other.scopes()
            && self.constraints() == other.constraints()
            && self.sensitive_grants() == other.sensitive_grants()
            && self.owner_flag() == other.owner_flag()
            && self.roles() == other.roles()
            && self.deny_rules() == other.deny_rules()
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
                sensitive: Vec::new(),
                owner: false,
                roles: Vec::new(),
                deny: Vec::new(),
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

    /// Explicit sensitive-category grants (H6 slice 2).
    #[must_use]
    pub fn sensitive_grants(&self) -> &[SensitiveGrant] {
        match &self.source {
            Source::Owned(inner) => &inner.sensitive,
            Source::Actor { actor, .. } => actor.sensitive_grants(),
        }
    }

    /// Resolved owner-defined roles (H6 slice 3).
    #[must_use]
    pub fn roles(&self) -> &[Arc<RoleDef>] {
        match &self.source {
            Source::Owned(inner) => &inner.roles,
            Source::Actor { actor, .. } => actor.roles(),
        }
    }

    /// The token's own deny list (H6 slice 3); role denies are not
    /// included.
    #[must_use]
    pub fn deny_rules(&self) -> &[DenyRule] {
        match &self.source {
            Source::Owned(inner) => &inner.deny,
            Source::Actor { actor, .. } => actor.deny_rules(),
        }
    }

    fn owner_flag(&self) -> bool {
        match &self.source {
            Source::Owned(inner) => inner.owner,
            // A local-process grant is never the owner, whatever the
            // actor says: the owner is a token the host minted.
            Source::Actor { actor, token } => *token && actor.is_owner(),
        }
    }

    /// `true` for the owner token: the token the host recorded as the
    /// bootstrap or `recover-admin-token` admin (`auth_token.owner`),
    /// still holding the wildcard scope. The owner holds every
    /// sensitive category. A token's label is not proof, and no
    /// caller input can set this.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.owner_flag() && self.scopes().iter().any(|s| s == scopes::WILDCARD)
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
    /// Allowed: a grant of the role named `role` covers the action on
    /// this resource (H6 slice 3), and no constraint narrows it.
    Role {
        /// Name of the role whose grant decided.
        role: String,
    },
    /// Denied: an entry of the deny list matched (the token's own, or
    /// one of the role named `role`).
    Denied {
        /// The role whose deny matched; `None` for the token's own.
        role: Option<String>,
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
    /// Allowed on a sensitive resource: the token holds `scope` (or a
    /// role grant) and either an explicit grant for every sensitive
    /// category the resource falls under, or is the owner.
    Sensitive {
        /// Scope that granted the action, or [`ROLE_LABEL`] when a
        /// role grant did.
        scope: &'static str,
        /// The sensitive categories the resource falls under.
        categories: SensitiveSet,
        /// `true` when the owner token's standing grant decided.
        owner: bool,
    },
    /// Denied: the token holds the scope, but no explicit grant covers
    /// `category` on this resource. A wildcard scope never does.
    MissingSensitive {
        /// The first category without a grant.
        category: SensitiveCategory,
    },
    /// Allowed: an owner-only host action (`policy.manage`,
    /// `token.manage`).
    Owner,
}

/// Audit label for [`Reason::NoPermit`].
pub const NO_PERMIT_LABEL: &str = "no-permit";

/// Audit label for [`Reason::Denied`].
pub const DENIED_LABEL: &str = "deny";

/// What [`Reason::Sensitive`] names as the grant when a role decided.
pub const ROLE_LABEL: &str = "role";

impl Reason {
    /// The value a deny writes to the audit row's `required_scope`
    /// column: the missing scope, the constraint sentinel, or
    /// [`NO_PERMIT_LABEL`]. `None` for an allow.
    #[must_use]
    pub fn audit_label(&self) -> Option<&'static str> {
        match self {
            Reason::Scope { .. }
            | Reason::Role { .. }
            | Reason::Sensitive { .. }
            | Reason::Owner => None,
            Reason::Denied { .. } => Some(DENIED_LABEL),
            Reason::MissingScope { scope } => Some(*scope),
            Reason::Constraint { sentinel, .. } => Some(*sentinel),
            Reason::NoPermit => Some(NO_PERMIT_LABEL),
            Reason::MissingSensitive { category } => Some(category.deny_label()),
        }
    }
}

/// Audit level an allowed action requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLevel {
    /// The transport's ordinary per-request row.
    #[default]
    Info,
    /// An extra row at `warn`, written before the action runs:
    /// every allowed sensitive action.
    Warn,
}

/// A rate limit an allowed action must pass, per principal and per
/// sensitive category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Allowed calls per window.
    pub max: u32,
    /// Window length.
    pub per: Duration,
}

impl RateLimit {
    /// The limit for one sensitive category: 10 commands per 10
    /// minutes for locks, openers and alarms; 120 camera byte releases
    /// per 10 minutes.
    #[must_use]
    pub const fn for_category(category: SensitiveCategory) -> Self {
        Self {
            max: if category.guards_commands() { 10 } else { 120 },
            per: Duration::from_mins(10),
        }
    }
}

/// What the caller must do on top of an allow. A sensitive allow sets
/// `audit_level` to [`AuditLevel::Warn`] and names its `sensitive`
/// categories; a non-owner sensitive allow also carries a
/// `rate_limit` (the owner is not rate limited). Confirmation is not
/// produced yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Obligations {
    /// How the allow is audited.
    pub audit_level: AuditLevel,
    /// Rate limit to apply, if any: each category in `sensitive` is
    /// charged against its own [`RateLimit::for_category`] bucket.
    pub rate_limit: Option<RateLimit>,
    /// The sensitive categories this allow touched.
    pub sensitive: SensitiveSet,
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
    if let Some(reason) = denied_by(authority, action, resource) {
        return Decision::deny(reason);
    }
    let Some(scope) = action.legacy_scope() else {
        // Owner-only host actions: no scope or role grants them, so a
        // wildcard admin token can't either.
        if matches!(action, Action::PolicyManage | Action::TokenManage) && authority.is_owner() {
            return Decision::allow(Reason::Owner);
        }
        return Decision::deny(Reason::NoPermit);
    };
    let granted = if scope.satisfied_by(authority.scopes()) {
        Reason::Scope {
            scope: scope.name(),
        }
    } else if let Some(role) = authority
        .roles()
        .iter()
        .find(|r| r.permits(action, resource))
    {
        Reason::Role {
            role: role.name.clone(),
        }
    } else if authority
        .roles()
        .iter()
        .any(|r| r.actions().contains(action))
    {
        // A role grants the action, but not on this resource.
        return Decision::deny(Reason::NoPermit);
    } else {
        return Decision::deny(Reason::MissingScope {
            scope: scope.name(),
        });
    };
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
    let (categories, device_id) = sensitive_requirement(action, resource);
    if categories.is_empty() {
        return Decision::allow(granted);
    }
    let owner = authority.is_owner();
    if !owner {
        for category in categories.iter() {
            let granted = authority
                .sensitive_grants()
                .iter()
                .any(|g| g.covers(category, device_id))
                || authority
                    .roles()
                    .iter()
                    .any(|r| r.sensitive.contains(&category));
            if !granted {
                return Decision::deny(Reason::MissingSensitive { category });
            }
        }
    }
    let rate_limit = (!owner).then(|| {
        categories
            .iter()
            .map(RateLimit::for_category)
            .min_by_key(|r| r.max)
            .unwrap_or(RateLimit::for_category(SensitiveCategory::Lock))
    });
    Decision {
        allow: true,
        reason: Reason::Sensitive {
            scope: match granted {
                Reason::Role { .. } => ROLE_LABEL,
                _ => scope.name(),
            },
            categories,
            owner,
        },
        obligations: Obligations {
            audit_level: AuditLevel::Warn,
            rate_limit,
            sensitive: categories,
            require_confirmation: false,
        },
    }
}

/// [`Reason::Denied`] when a deny entry refuses `action` on `resource`:
/// the token's own deny list first, then its roles'.
fn denied_by(authority: &Authority, action: Action, resource: &Resource) -> Option<Reason> {
    if authority
        .deny_rules()
        .iter()
        .any(|d| d.matches(action, resource))
    {
        return Some(Reason::Denied { role: None });
    }
    authority
        .roles()
        .iter()
        .find(|r| r.denies(action, resource))
        .map(|r| Reason::Denied {
            role: Some(r.name.clone()),
        })
}

/// The sensitive categories `action` on `resource` needs a grant for,
/// and the device the resource names (for device-narrowed grants).
/// Commands on a lock, opener or alarm; `blob.read` on a camera's
/// bytes or a camera instance's blob. Collection-level checks are
/// never sensitive: they are pre-checks, and the per-target check
/// that follows decides.
fn sensitive_requirement(action: Action, resource: &Resource) -> (SensitiveSet, Option<&str>) {
    match (action, resource) {
        (Action::DeviceCommand, Resource::Device(d)) => (
            d.class
                .sensitive()
                .iter()
                .filter(|c| c.guards_commands())
                .collect(),
            Some(d.id.as_str()),
        ),
        (Action::BlobRead, Resource::Device(d)) if d.class.is_camera() => (
            [SensitiveCategory::Camera].into_iter().collect(),
            Some(d.id.as_str()),
        ),
        (Action::BlobRead, Resource::Blob(b)) if b.camera => {
            ([SensitiveCategory::Camera].into_iter().collect(), None)
        }
        _ => (SensitiveSet::empty(), None),
    }
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
