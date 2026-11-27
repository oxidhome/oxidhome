//! One authorization decision point.
//!
//! Every external permission check goes through [`authorize`]: REST
//! and Connect handlers, MCP tools, resources and prompts, and the M7
//! byte-withholding check. A call names *what* is being done
//! ([`Action`], a closed enum) and *to what* ([`Resource`], built by
//! host code), and gets back a [`Decision`].
//!
//! The decision is made against the root principal's [`Authority`]
//! carried on the [`InvocationContext`]: its owner flag and its roles.
//! Nothing is read from the request itself.
//!
//! # Evaluator
//!
//! - The **owner token** ([`Authority::is_owner`]) may do everything,
//!   and alone holds [`Action::TokenManage`] and [`Action::PolicyManage`].
//! - Anyone else needs a role grant that covers the action on the
//!   resource ([`crate::auth::RoleGrant::permits`]); otherwise the
//!   action is refused ([`Reason::NoPermit`], labelled with the action
//!   name). There is no deny list: access is absent unless granted.
//! - **Sensitive categories.** A command on a device whose class
//!   ([`DeviceClass`], host-derived) includes `lock`, `opener` or
//!   `alarm`, and `blob.read` of camera bytes (a camera device, or a
//!   blob of a camera instance), need a grant whose `category` names
//!   every such category. An allow on one carries the categories in
//!   [`Decision::sensitive`]; the caller writes a `warn` audit row
//!   ([`crate::auth::sensitive::record`]) before it acts.
//!
//! # Delegated hops
//!
//! A `call-service` hop is decided by [`authorize_hop`]:
//! `allow = permit(calling plugin) ∧ permit(root)`. The calling
//! plugin's permit is its `consumes_services` grant (requested ∩
//! granted), which the dispatcher matches and passes in. When the root
//! is external it must also hold [`Action::ServiceCall`], so a narrow
//! token can't have a script use the script's broader grants on its
//! behalf. Host-rooted work (`init`, `tick`, `on-event`) has the plugin
//! as its root: only the plugin's grant applies.
//!
//! Plugin principals are otherwise authorized by their manifest grants
//! at their own call sites (`reads_state`, `subscribes_events`).

use std::sync::Arc;

use super::Actor;
use super::category::{DeviceClass, SensitiveCategory, SensitiveSet};
use super::invocation::InvocationContext;
use super::role::RoleDef;

/// What the caller wants to do. Closed: a new action is a host change,
/// never caller input. Names follow `kind.verb` ([`Self::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// List registered devices.
    DeviceList,
    /// Read device state.
    DeviceRead,
    /// Send a command to a device.
    DeviceCommand,
    /// Subscribe to the live event stream.
    EventSubscribe,
    /// Read event history.
    EventRead,
    /// Read blob payloads, including `bytes-val` in state, events and
    /// command results.
    BlobRead,
    /// List running instances.
    InstanceRead,
    /// Start an instance of an installed plugin.
    InstanceStart,
    /// Stop instances of a plugin.
    InstanceStop,
    /// Read installed plugins, their detail and schema.
    PluginRead,
    /// Install a plugin.
    PluginInstall,
    /// Remove an installed plugin.
    PluginUninstall,
    /// Open a plugin's UI.
    PluginUi,
    /// Read dashboards.
    DashboardRead,
    /// Create, replace or delete dashboards.
    DashboardWrite,
    /// Read host status and effective configuration.
    HostStatus,
    /// Read host logs.
    HostLogs,
    /// Read the audit ledger.
    HostAudit,
    /// Call a plugin service through a delegated hop. Checked for the
    /// root of every hop ([`authorize_hop`]), on top of the calling
    /// plugin's `consumes_services` grant.
    ServiceCall,
    /// Mint and list tokens. The owner's alone.
    TokenManage,
    /// Manage roles, device categories and plugin grants. The owner's
    /// alone.
    PolicyManage,
}

impl Action {
    /// Every action, for exhaustive tests and listings.
    pub const ALL: [Action; 21] = [
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
        Action::ServiceCall,
        Action::TokenManage,
        Action::PolicyManage,
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
            Action::ServiceCall => "service.call",
            Action::TokenManage => "token.manage",
            Action::PolicyManage => "policy.manage",
        }
    }

    /// This action's bit in an [`crate::auth::ActionSet`].
    pub(crate) const fn bit(self) -> u32 {
        1 << (self as u32)
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
    /// Plugin services.
    Service,
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
    /// release every item, and reads not checked per target. A role
    /// grant narrowed to categories or devices never covers it.
    Collection(ResourceKind),
    /// A pre-check made before the target is known, which a
    /// per-target check (or a per-item filter) always follows: may the
    /// root do this to *some* resource of this kind? A narrowed role
    /// grant covers it for devices and blobs, since the per-target
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
    /// One command of one plugin service: the target of a delegated
    /// `call-service` hop.
    Service(ServiceResource),
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

    /// One command of a registered service, from the service
    /// registry's owner tuple (never from what the caller passed
    /// beyond the host-minted service id and the command name).
    #[must_use]
    pub fn service(
        plugin_id: impl Into<String>,
        instance_id: impl Into<String>,
        local_id: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self::Service(ServiceResource {
            plugin_id: plugin_id.into(),
            instance_id: instance_id.into(),
            local_id: local_id.into(),
            command: command.into(),
        })
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

/// Service attributes the host decides on: the owner and the
/// immutable `local-id` (not the renamable `name`), and the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceResource {
    plugin_id: String,
    instance_id: String,
    local_id: String,
    command: String,
}

impl ServiceResource {
    /// Plugin that owns the service.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Instance that registered the service.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// The service's immutable `local-id`.
    #[must_use]
    pub fn local_id(&self) -> &str {
        &self.local_id
    }

    /// The command called.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
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

/// The resolved authority of an invocation's root principal: the
/// verified token's owner flag and roles (or the roles a local-process
/// transport runs with). Host-only: never serialized, never in an audit
/// row, never visible to a plugin.
///
/// Host-origin work (`init`, `tick`, `on-event`) has no authority:
/// plugins are authorized by their manifest grants.
#[derive(Debug, Clone, Default)]
pub struct Authority {
    actor: Option<Actor>,
    token: bool,
}

impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        self.token_id() == other.token_id()
            && self.is_owner() == other.is_owner()
            && self.roles() == other.roles()
    }
}

impl Eq for Authority {}

impl Authority {
    /// No authority: every action is refused.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The authority of a bearer-token [`Actor`]. Shares the actor's
    /// `Arc`, so building one per request is a refcount bump.
    #[must_use]
    pub fn of_token(actor: &Actor) -> Self {
        Self {
            actor: Some(actor.clone()),
            token: true,
        }
    }

    /// The authority of an actor authorized by the local process
    /// boundary rather than a credential (MCP stdio): its roles, no
    /// token id, never the owner.
    #[must_use]
    pub fn of_local_process(actor: &Actor) -> Self {
        Self {
            actor: Some(actor.clone()),
            token: false,
        }
    }

    /// Token that carries this authority, if any.
    #[must_use]
    pub fn token_id(&self) -> Option<&str> {
        self.actor.as_ref().filter(|_| self.token).map(Actor::id)
    }

    /// The roles the principal holds.
    #[must_use]
    pub fn roles(&self) -> &[Arc<RoleDef>] {
        self.actor.as_ref().map_or(&[], Actor::roles)
    }

    /// `true` for the owner token: the token the host recorded as the
    /// bootstrap or `recover-admin-token` admin (`auth_token.owner`).
    /// A local-process grant is never the owner, and no caller input
    /// can set this.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.token && self.actor.as_ref().is_some_and(Actor::is_owner)
    }
}

/// Why a decision came out the way it did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Allowed: a grant of the role named `role` covers the action.
    Role {
        /// Name of the role whose grant decided.
        role: String,
    },
    /// Allowed: the owner token.
    Owner,
    /// Denied: no grant covers `action` on this resource.
    NoPermit {
        /// The refused action.
        action: Action,
    },
    /// Allowed: a hop of host-rooted work, which the calling plugin's
    /// own manifest grant `grant` decides alone.
    PluginGrant {
        /// The manifest grant (`consumes_services`).
        grant: &'static str,
    },
    /// Denied: the calling plugin's manifest grant `grant` does not
    /// cover the hop. Its label is the grant's name.
    MissingPluginGrant {
        /// The manifest grant (`consumes_services`).
        grant: &'static str,
    },
}

impl Reason {
    /// The value a deny writes to the audit row's `required_scope`
    /// column: the refused action's name, or the missing plugin
    /// grant's. `None` for an allow.
    #[must_use]
    pub fn audit_label(&self) -> Option<&'static str> {
        match self {
            Reason::Role { .. } | Reason::Owner | Reason::PluginGrant { .. } => None,
            Reason::NoPermit { action } => Some(action.as_str()),
            Reason::MissingPluginGrant { grant } => Some(grant),
        }
    }
}

/// The outcome of [`authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `true` to proceed.
    pub allow: bool,
    /// Why.
    pub reason: Reason,
    /// On an allow, the sensitive categories the action touches; the
    /// caller writes a `warn` audit row for them before it acts.
    pub sensitive: SensitiveSet,
}

impl Decision {
    fn deny(reason: Reason) -> Self {
        Self {
            allow: false,
            reason,
            sensitive: SensitiveSet::empty(),
        }
    }

    fn allow(reason: Reason, sensitive: SensitiveSet) -> Self {
        Self {
            allow: true,
            reason,
            sensitive,
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
            Err(self.reason.audit_label().unwrap_or("no-permit"))
        }
    }
}

/// Decide whether the invocation's root may perform `action` on
/// `resource`. See the module docs for the evaluator.
#[must_use]
pub fn authorize(ctx: &InvocationContext, action: Action, resource: &Resource) -> Decision {
    evaluate(ctx.root().authority(), action, resource)
}

/// Manifest grant name of a plugin's service-call permit.
pub const CONSUMES_SERVICES_GRANT: &str = "consumes_services";

/// Decide a delegated hop: `ctx` is the callee's context (the hop
/// already on its chain), `plugin_permit` whether the calling plugin's
/// own manifest grant (`plugin_grant`, e.g. [`CONSUMES_SERVICES_GRANT`])
/// covers the hop. The plugin's grant is checked first; an external
/// root must then itself be allowed `action` on `resource`, while a
/// host-rooted hop is decided by the plugin's grant alone.
#[must_use]
pub fn authorize_hop(
    ctx: &InvocationContext,
    action: Action,
    resource: &Resource,
    plugin_grant: &'static str,
    plugin_permit: bool,
) -> Decision {
    if !plugin_permit {
        return Decision::deny(Reason::MissingPluginGrant {
            grant: plugin_grant,
        });
    }
    if ctx.root().is_external() {
        return authorize(ctx, action, resource);
    }
    Decision::allow(
        Reason::PluginGrant {
            grant: plugin_grant,
        },
        SensitiveSet::empty(),
    )
}

/// The evaluator behind [`authorize`], on an [`Authority`] directly.
#[must_use]
pub(crate) fn evaluate(authority: &Authority, action: Action, resource: &Resource) -> Decision {
    let sensitive = sensitive_requirement(action, resource);
    if authority.is_owner() {
        return Decision::allow(Reason::Owner, sensitive);
    }
    // The owner's alone, whatever a role holds: parsing refuses them,
    // and this keeps a role built in code from granting them either.
    if !super::role::GRANTABLE.contains(action) {
        return Decision::deny(Reason::NoPermit { action });
    }
    match authority
        .roles()
        .iter()
        .find(|r| r.permits(action, resource, sensitive))
    {
        Some(role) => Decision::allow(
            Reason::Role {
                role: role.name.clone(),
            },
            sensitive,
        ),
        None => Decision::deny(Reason::NoPermit { action }),
    }
}

/// The sensitive categories `action` on `resource` touches: commands on
/// a lock, opener or alarm; `blob.read` of a camera's bytes or a camera
/// instance's blob. Collections and pre-checks never are: the
/// per-target check that follows decides.
fn sensitive_requirement(action: Action, resource: &Resource) -> SensitiveSet {
    match (action, resource) {
        (Action::DeviceCommand, Resource::Device(d)) => d
            .class()
            .sensitive()
            .iter()
            .filter(|c| c.guards_commands())
            .collect(),
        (Action::BlobRead, Resource::Device(d)) if d.class().is_camera() => {
            [SensitiveCategory::Camera].into_iter().collect()
        }
        (Action::BlobRead, Resource::Blob(b)) if b.is_camera() => {
            [SensitiveCategory::Camera].into_iter().collect()
        }
        _ => SensitiveSet::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::role::builtin;
    use crate::auth::{ActorKind, DeviceCategory, Principal, Transport};

    fn ctx_for(actor: &Actor) -> InvocationContext {
        InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest))
    }

    fn role(json: &str) -> Arc<RoleDef> {
        Arc::new(RoleDef::parse("r", json.as_bytes()).expect("role parses"))
    }

    #[test]
    fn action_names_are_unique_kind_verb() {
        let mut seen = std::collections::HashSet::new();
        for a in Action::ALL {
            assert!(seen.insert(a.as_str()), "duplicate {}", a.as_str());
            assert!(a.as_str().contains('.'), "{} is not kind.verb", a.as_str());
            assert_eq!(a.as_str().parse::<Action>(), Ok(a));
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
    fn only_the_owner_manages_tokens_and_policy() {
        let admin = ctx_for(&Actor::api("tok-a", vec![builtin("admin").unwrap()]));
        let owner = ctx_for(&Actor::token("tok-o", true, Vec::new()));
        for a in [Action::TokenManage, Action::PolicyManage] {
            let d = authorize(&admin, a, &Resource::Host);
            assert!(!d.allow);
            assert_eq!(d.reason.audit_label(), Some(a.as_str()));
            assert_eq!(authorize(&owner, a, &Resource::Host).reason, Reason::Owner);
        }
        // Not even a role built in code with every action.
        let all = Arc::new(RoleDef {
            name: "all".into(),
            grants: vec![crate::auth::RoleGrant {
                actions: crate::auth::ActionSet::ALL,
                categories: None,
                devices: None,
            }],
        });
        let all = ctx_for(&Actor::api("tok-all", vec![all]));
        for a in [Action::TokenManage, Action::PolicyManage] {
            assert!(!authorize(&all, a, &Resource::Host).allow);
        }
        assert!(authorize(&all, Action::HostStatus, &Resource::Host).allow);
    }

    #[test]
    fn a_role_grant_decides_and_a_missing_one_names_the_action() {
        let ctx = ctx_for(&Actor::api(
            "tok",
            vec![role(r#"[{"actions":["host.logs"]}]"#)],
        ));
        assert_eq!(
            authorize(&ctx, Action::HostLogs, &Resource::Host).reason,
            Reason::Role { role: "r".into() }
        );
        assert_eq!(
            authorize(&ctx, Action::HostAudit, &Resource::Host).into_result(),
            Err("host.audit")
        );
    }

    #[test]
    fn sensitive_allows_carry_their_categories() {
        let lock = Resource::device("dev-a1", DeviceClass::of(DeviceCategory::Lock));
        let ctx = ctx_for(&Actor::api("tok", vec![builtin("member").unwrap()]));
        let d = authorize(&ctx, Action::DeviceCommand, &lock);
        assert!(d.allow);
        assert!(d.sensitive.contains(SensitiveCategory::Lock));
        let guest = ctx_for(&Actor::api("tok", vec![builtin("guest").unwrap()]));
        assert!(!authorize(&guest, Action::DeviceCommand, &lock).allow);
        assert!(authorize(&guest, Action::DeviceRead, &lock).allow);
        let owner = ctx_for(&Actor::token("tok-o", true, Vec::new()));
        assert!(
            !authorize(&owner, Action::DeviceCommand, &lock)
                .sensitive
                .is_empty()
        );
    }

    #[test]
    fn a_local_process_authority_is_never_the_owner() {
        let actor = Actor::token("stdio", true, Vec::new());
        let ctx = InvocationContext::external(
            Principal::local_process(ActorKind::Mcp, "stdio", Transport::McpStdio)
                .with_authority(Authority::of_local_process(&actor)),
        );
        assert!(!authorize(&ctx, Action::HostStatus, &Resource::Host).allow);
    }

    #[test]
    fn hops_need_the_plugin_grant_and_an_external_roots_permit() {
        let svc = Resource::service("acme.notify", "n", "notify", "send");
        let host = InvocationContext::host_origin("alpha");
        assert!(
            authorize_hop(
                &host,
                Action::ServiceCall,
                &svc,
                CONSUMES_SERVICES_GRANT,
                true
            )
            .allow
        );
        assert!(
            !authorize_hop(
                &host,
                Action::ServiceCall,
                &svc,
                CONSUMES_SERVICES_GRANT,
                false
            )
            .allow
        );
        let narrow = ctx_for(&Actor::api(
            "tok",
            vec![role(r#"[{"actions":["device.command"]}]"#)],
        ));
        assert_eq!(
            authorize_hop(
                &narrow,
                Action::ServiceCall,
                &svc,
                CONSUMES_SERVICES_GRANT,
                true
            )
            .into_result(),
            Err("service.call")
        );
        let guest = ctx_for(&Actor::api("tok", vec![builtin("guest").unwrap()]));
        assert!(
            authorize_hop(
                &guest,
                Action::ServiceCall,
                &svc,
                CONSUMES_SERVICES_GRANT,
                true
            )
            .allow
        );
    }
}
