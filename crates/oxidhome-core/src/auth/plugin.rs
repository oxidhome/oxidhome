//! Plugin principals in the authorization engine (H6 slice 5).
//!
//! A plugin instance acting through a host import is a principal like
//! a token. Its permits are compiled from its effective manifest
//! grants; the owner can give its plugin a deny list
//! ([`crate::state::PluginDenyStore`]). [`authorize_plugin`] decides,
//! for every action a plugin takes:
//!
//! `allow = no deny on the chain ∧ permit(acting plugin) ∧ permit(root)`
//!
//! - **Denies.** The owner's deny list for the acting plugin and for
//!   every plugin that made a `call-service` hop on the way to it
//!   ([`crate::auth::DelegationHop::caller_plugin`]). A plugin that
//!   may not touch the alarm can't launder the call through a second
//!   plugin. A deny matches as a token's does ([`DenyRule::matches`]);
//!   a plugin deny list may name only [`PLUGIN_ACTIONS`].
//! - **The acting plugin's permit**, from its manifest grants
//!   (requested ∩ granted, C5):
//!
//!   | Action | Resource | Grant |
//!   |--------|----------|-------|
//!   | `service.call` | [`Resource::Service`] | `consumes_services`: one requested and one granted selector match all five axes (H10) |
//!   | `state.read` | [`Resource::State`] | `reads_state`: a selector matches the owner plugin, capability and device |
//!   | `blob.read` | [`Resource::State`] | `reads_state` with `bytes = true` (the entry's `bytes-val` fields) |
//!   | `event.subscribe` | any | `subscribes_events` |
//!
//! - **The root's permit**, when the invocation is rooted at an
//!   external principal: [`authorize`] on the token-facing equivalent
//!   (`service.call` as is; `state.read` as `device.read` and bytes as
//!   `blob.read` on the entry's device; `event.subscribe` as
//!   `event.read` on the whole event stream). Host-rooted work
//!   (`init`, `tick`, `on-event`) is the plugin's own.
//!
//! Not in the engine, as manifest-only checks: `network`,
//! `declares_devices` / `declares_services`, quotas,
//! `script_sandboxes` and `reads_event_bytes`. A plugin's own state
//! entries are its own data and are not asked about here
//! (`runtime::state_read`). Host-mediated device commands between
//! plugins don't exist yet, so `device.command` is not a plugin action.

use std::borrow::Cow;

use oxidhome_manifest::{ServiceGrant, StateGrant};

use super::authorize::{Action, Decision, Reason, Resource, ResourceKind, authorize};
use super::invocation::InvocationContext;
use super::role::{ActionSet, DenyRule};
use crate::state::PluginDenyStore;

/// The actions a plugin takes through host imports, and so the only
/// ones a plugin deny list may name. A plugin deny's `*` means these.
pub const PLUGIN_ACTIONS: ActionSet = ActionSet::of(&[
    Action::ServiceCall,
    Action::StateRead,
    Action::BlobRead,
    Action::EventSubscribe,
]);

/// Manifest grant name of a plugin's service-call permit.
pub const CONSUMES_SERVICES_GRANT: &str = "consumes_services";
/// Manifest grant name of a plugin's state-read permit.
pub const READS_STATE_GRANT: &str = "reads_state";
/// What permits a plugin the `bytes-val` fields of a state entry.
pub const READS_STATE_BYTES_GRANT: &str = "reads_state.bytes";
/// Manifest grant name of a plugin's event-bus permit.
pub const SUBSCRIBES_EVENTS_GRANT: &str = "subscribes_events";

/// A plugin instance as a principal: its identity, its effective grants
/// and the owner's deny lists. Borrowed from the instance's state for
/// one decision.
#[derive(Debug, Clone, Copy)]
pub struct PluginPrincipal<'a> {
    /// The plugin's id.
    pub plugin_id: &'a str,
    /// The acting instance (a sandbox child is its own instance).
    pub instance_id: &'a str,
    /// `consumes_services` as the manifest requests it.
    pub requested_services: &'a [ServiceGrant],
    /// `consumes_services` as the operator granted it. A call needs a
    /// matching selector in both lists.
    pub granted_services: &'a [ServiceGrant],
    /// Effective `reads_state` selectors.
    pub reads_state: &'a [StateGrant],
    /// Effective `subscribes_events`.
    pub subscribes_events: bool,
    /// The owner's deny lists, for this plugin and the chain's.
    pub denies: &'a PluginDenyStore,
}

/// Decide whether `plugin`, acting within `ctx`, may perform `action`
/// on `resource`. See the module docs.
///
/// An allow may carry [`crate::auth::Obligations`] from the root's
/// decision (a sensitive target); a caller that can't meet them must
/// treat the allow as a deny.
#[must_use]
pub fn authorize_plugin(
    ctx: &InvocationContext,
    plugin: &PluginPrincipal<'_>,
    action: Action,
    resource: &Resource,
) -> Decision {
    if let Some(reason) = chain_denied(ctx, plugin, action, resource) {
        return Decision::deny(reason);
    }
    let grant = match plugin_permit(plugin, action, resource) {
        Ok(grant) => grant,
        Err(reason) => return Decision::deny(reason),
    };
    if ctx.root().is_external() {
        let (action, resource) = root_equivalent(action, resource);
        return authorize(ctx, action, &resource);
    }
    Decision::allow(Reason::PluginGrant { grant })
}

/// [`Reason::PluginDenied`] for the first of `plugins` whose deny
/// list refuses `action` on `resource`, read from one snapshot of the
/// lists. For checks made outside a decision, such as filtering what
/// an event subscription delivers.
#[must_use]
pub fn denied_by<'a>(
    denies: &PluginDenyStore,
    plugins: impl IntoIterator<Item = &'a str>,
    action: Action,
    resource: &Resource,
) -> Option<Reason> {
    denies
        .first_refusing(plugins, |d| d.matches(action, resource))
        .map(|id| Reason::PluginDenied {
            plugin: id.to_owned(),
        })
}

/// The acting plugin's list, then each caller's on the chain.
fn chain_denied(
    ctx: &InvocationContext,
    plugin: &PluginPrincipal<'_>,
    action: Action,
    resource: &Resource,
) -> Option<Reason> {
    denied_by(
        plugin.denies,
        std::iter::once(plugin.plugin_id)
            .chain(ctx.chain().iter().map(|h| h.caller_plugin.as_str())),
        action,
        resource,
    )
}

/// The acting plugin's own permit: the grant that covers `action` on
/// `resource`, or the reason it is refused.
fn plugin_permit(
    plugin: &PluginPrincipal<'_>,
    action: Action,
    resource: &Resource,
) -> Result<&'static str, Reason> {
    let missing = |grant| Reason::MissingPluginGrant { grant };
    match (action, resource) {
        (Action::ServiceCall, Resource::Service(s)) => {
            let covers = |grants: &[ServiceGrant]| {
                crate::state::any_grant_matches(
                    grants,
                    plugin.instance_id,
                    s.plugin_id(),
                    s.instance_id(),
                    s.local_id(),
                    s.command(),
                )
            };
            (covers(plugin.requested_services) && covers(plugin.granted_services))
                .then_some(CONSUMES_SERVICES_GRANT)
                .ok_or(missing(CONSUMES_SERVICES_GRANT))
        }
        (Action::StateRead | Action::BlobRead, Resource::State(s)) => {
            let bytes = action == Action::BlobRead;
            let grant = if bytes {
                READS_STATE_BYTES_GRANT
            } else {
                READS_STATE_GRANT
            };
            plugin
                .reads_state
                .iter()
                .any(|g| {
                    (!bytes || g.bytes)
                        && g.matches(s.owner_plugin(), s.device().id(), s.capability())
                })
                .then_some(grant)
                .ok_or(missing(grant))
        }
        (Action::EventSubscribe, _) => plugin
            .subscribes_events
            .then_some(SUBSCRIBES_EVENTS_GRANT)
            .ok_or(missing(SUBSCRIBES_EVENTS_GRANT)),
        (Action::ServiceCall, _) => Err(missing(CONSUMES_SERVICES_GRANT)),
        (Action::StateRead, _) => Err(missing(READS_STATE_GRANT)),
        (Action::BlobRead, _) => Err(missing(READS_STATE_BYTES_GRANT)),
        _ => Err(Reason::NoPermit),
    }
}

/// What the root of an external invocation must hold for a plugin to
/// take `action` on `resource` on its behalf: the token-facing action
/// on the resource a token can address.
fn root_equivalent(action: Action, resource: &Resource) -> (Action, Cow<'_, Resource>) {
    match (action, resource) {
        (Action::StateRead, Resource::State(s)) => (
            Action::DeviceRead,
            Cow::Owned(Resource::Device(s.device().clone())),
        ),
        (Action::BlobRead, Resource::State(s)) => (
            Action::BlobRead,
            Cow::Owned(Resource::Device(s.device().clone())),
        ),
        // A subscription outlives the request: it releases every
        // event its filter matches from then on.
        (Action::EventSubscribe, _) => (
            Action::EventRead,
            Cow::Owned(Resource::Collection(ResourceKind::Event)),
        ),
        _ => (action, Cow::Borrowed(resource)),
    }
}

/// A deny entry restricted to [`PLUGIN_ACTIONS`], or `None` when it
/// names another action explicitly (`names` are the entry's action
/// names as written) or covers no plugin action at all.
#[must_use]
pub fn restrict_to_plugin_actions(names: &[String], rule: DenyRule) -> Option<DenyRule> {
    let explicit = ActionSet::parse(names.iter().map(String::as_str).filter(|n| *n != "*")).ok()?;
    if !PLUGIN_ACTIONS.contains_all(explicit) {
        return None;
    }
    let actions = rule.actions.intersection(PLUGIN_ACTIONS);
    (!actions.is_empty()).then_some(DenyRule { actions, ..rule })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        Actor, ActorKind, DelegationHop, DeviceCategory, DeviceClass, Principal, Transport,
    };

    fn bouncer() -> Resource {
        Resource::service("example.bouncer", "alpha", "bouncer", "kick")
    }

    fn grant() -> ServiceGrant {
        ServiceGrant {
            plugin: "example.bouncer".into(),
            instance: "*".into(),
            service: "bouncer".into(),
            commands: vec!["kick".into()],
            caller_instance: "*".into(),
        }
    }

    fn plugin<'a>(
        denies: &'a PluginDenyStore,
        services: &'a [ServiceGrant],
        reads: &'a [StateGrant],
    ) -> PluginPrincipal<'a> {
        PluginPrincipal {
            plugin_id: "example.caller",
            instance_id: "caller",
            requested_services: services,
            granted_services: services,
            reads_state: reads,
            subscribes_events: true,
            denies,
        }
    }

    fn ctx_for(actor: &Actor) -> InvocationContext {
        InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest))
    }

    fn deny(actions: &[Action], categories: Option<Vec<DeviceCategory>>) -> DenyRule {
        DenyRule {
            actions: ActionSet::of(actions),
            categories,
            devices: None,
            services: None,
        }
    }

    /// A hop needs the plugin's grant and, for an external root, the
    /// root's own `service.call`; host-rooted work is the plugin's
    /// alone.
    #[test]
    fn hops_need_the_plugin_grant_and_the_roots_permit() {
        let denies = PluginDenyStore::detached();
        let grants = [grant()];
        let with = plugin(&denies, &grants, &[]);
        let without = plugin(&denies, &[], &[]);
        let hop = |ctx: &InvocationContext, p: &PluginPrincipal<'_>| {
            authorize_plugin(ctx, p, Action::ServiceCall, &bouncer())
        };
        let host = InvocationContext::host_origin("caller");
        let d = hop(&host, &with);
        assert!(d.allow);
        assert_eq!(
            d.reason,
            Reason::PluginGrant {
                grant: CONSUMES_SERVICES_GRANT
            }
        );
        let reaction = InvocationContext::reacting_to("caller", "call-x");
        assert!(hop(&reaction, &with).allow);
        let d = hop(&host, &without);
        assert_eq!(d.reason.audit_label(), Some(CONSUMES_SERVICES_GRANT));

        let narrow = ctx_for(&Actor::api("t", vec!["devices:command".into()]));
        let d = hop(&narrow, &with);
        assert!(!d.allow);
        assert_eq!(d.reason.audit_label(), Some("services:call"));
        // The plugin's grant is asked first, whoever the root is.
        let admin = ctx_for(&Actor::api("t", vec!["*".into()]));
        assert_eq!(
            hop(&admin, &without).reason.audit_label(),
            Some(CONSUMES_SERVICES_GRANT)
        );
        let d = hop(&admin, &with);
        assert!(d.allow);
        assert_eq!(d.obligations, crate::auth::Obligations::default());
        let scoped = ctx_for(&Actor::api("t", vec!["services:call".into()]));
        assert!(hop(&scoped, &with).allow);

        // Requested and granted must both cover the call.
        let requested_only = PluginPrincipal {
            granted_services: &[],
            ..with
        };
        assert!(!hop(&host, &requested_only).allow);
    }

    /// The owner's deny list for the acting plugin, or for any plugin
    /// that made a hop on the way, refuses the action whatever grants
    /// it: the owner token rooting the call included.
    #[test]
    fn chain_denies_refuse_whatever_grants() {
        let denies = PluginDenyStore::detached();
        let grants = [grant()];
        let p = plugin(&denies, &grants, &[]);
        let owner = ctx_for(&Actor::api("t", vec!["*".into()]));
        assert!(authorize_plugin(&owner, &p, Action::ServiceCall, &bouncer()).allow);

        denies
            .set(
                "example.caller",
                vec![DenyRule {
                    services: Some(vec!["example.bouncer".into()]),
                    ..deny(&[Action::ServiceCall], None)
                }],
            )
            .expect("set");
        let d = authorize_plugin(&owner, &p, Action::ServiceCall, &bouncer());
        assert_eq!(
            d.reason,
            Reason::PluginDenied {
                plugin: "example.caller".into()
            }
        );
        assert_eq!(d.reason.audit_label(), Some("plugin-deny"));
        let other = Resource::service("example.notify", "n", "notify", "send");
        let notify = [ServiceGrant {
            plugin: "example.notify".into(),
            service: "notify".into(),
            commands: vec!["*".into()],
            ..grant()
        }];
        let p2 = plugin(&denies, &notify, &[]);
        assert!(authorize_plugin(&owner, &p2, Action::ServiceCall, &other).allow);

        // An upstream caller's deny travels down the chain.
        denies.set("example.caller", Vec::new()).expect("reset");
        denies
            .set("example.upstream", vec![deny(&[Action::ServiceCall], None)])
            .expect("set");
        let chained = owner.delegate(DelegationHop {
            caller_instance: "up".into(),
            caller_plugin: "example.upstream".into(),
            target_plugin: "example.caller".into(),
            target_instance: "caller".into(),
            target_service: "svc".into(),
        });
        assert_eq!(
            authorize_plugin(&chained, &p, Action::ServiceCall, &bouncer()).reason,
            Reason::PluginDenied {
                plugin: "example.upstream".into()
            }
        );
        // Not on this chain: no effect.
        assert!(authorize_plugin(&owner, &p, Action::ServiceCall, &bouncer()).allow);
    }

    fn lock_state() -> Resource {
        Resource::state(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Lock),
            "example.lock",
            "lock",
        )
    }

    fn read_all(bytes: bool) -> StateGrant {
        StateGrant {
            plugin: "*".into(),
            capabilities: vec!["*".into()],
            devices: vec!["*".into()],
            bytes,
        }
    }

    /// State reads: `reads_state` for the entry, `bytes = true` for its
    /// bytes; an external root also needs `device.read` (and
    /// `blob.read`) on the device; a category deny hides the entry.
    #[test]
    fn state_reads_follow_the_grant_the_root_and_the_denies() {
        let denies = PluginDenyStore::detached();
        let reads = [read_all(false)];
        let p = plugin(&denies, &[], &reads);
        let host = InvocationContext::host_origin("caller");
        assert!(authorize_plugin(&host, &p, Action::StateRead, &lock_state()).allow);
        let d = authorize_plugin(&host, &p, Action::BlobRead, &lock_state());
        assert_eq!(d.reason.audit_label(), Some(READS_STATE_BYTES_GRANT));
        let none = plugin(&denies, &[], &[]);
        let d = authorize_plugin(&host, &none, Action::StateRead, &lock_state());
        assert_eq!(d.reason.audit_label(), Some(READS_STATE_GRANT));

        // A token rooting the read needs `devices:read`.
        let narrow = ctx_for(&Actor::api("t", vec!["devices:command".into()]));
        let d = authorize_plugin(&narrow, &p, Action::StateRead, &lock_state());
        assert_eq!(d.reason.audit_label(), Some("devices:read"));
        let reader = ctx_for(&Actor::api("t", vec!["devices:read".into()]));
        assert!(authorize_plugin(&reader, &p, Action::StateRead, &lock_state()).allow);
        let bytes = [read_all(true)];
        let pb = plugin(&denies, &[], &bytes);
        let d = authorize_plugin(&reader, &pb, Action::BlobRead, &lock_state());
        assert_eq!(d.reason.audit_label(), Some("blobs:read"));

        denies
            .set(
                "example.caller",
                vec![deny(&[Action::StateRead], Some(vec![DeviceCategory::Lock]))],
            )
            .expect("set");
        assert!(!authorize_plugin(&host, &p, Action::StateRead, &lock_state()).allow);
        let light = Resource::state(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light),
            "example.lock",
            "switch",
        );
        assert!(authorize_plugin(&host, &p, Action::StateRead, &light).allow);
    }

    /// `event.subscribe` needs `subscribes_events`, and from an
    /// external root `event.read`; a deny without a selector refuses
    /// it, a category deny only filters what is delivered.
    #[test]
    fn subscriptions_need_the_flag_and_the_roots_event_read() {
        let denies = PluginDenyStore::detached();
        let p = plugin(&denies, &[], &[]);
        let pre = Resource::pre_check(ResourceKind::Event);
        let host = InvocationContext::host_origin("caller");
        assert!(authorize_plugin(&host, &p, Action::EventSubscribe, &pre).allow);
        let off = PluginPrincipal {
            subscribes_events: false,
            ..p
        };
        assert_eq!(
            authorize_plugin(&host, &off, Action::EventSubscribe, &pre)
                .reason
                .audit_label(),
            Some(SUBSCRIBES_EVENTS_GRANT)
        );
        let narrow = ctx_for(&Actor::api("t", vec!["devices:command".into()]));
        assert_eq!(
            authorize_plugin(&narrow, &p, Action::EventSubscribe, &pre)
                .reason
                .audit_label(),
            Some("events:read")
        );
        denies
            .set(
                "example.caller",
                vec![deny(
                    &[Action::EventSubscribe],
                    Some(vec![DeviceCategory::Alarm]),
                )],
            )
            .expect("set");
        assert!(authorize_plugin(&host, &p, Action::EventSubscribe, &pre).allow);
        let alarm = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Alarm),
        );
        assert!(denied_by(&denies, ["example.caller"], Action::EventSubscribe, &alarm).is_some());
        denies
            .set(
                "example.caller",
                vec![deny(&[Action::EventSubscribe], None)],
            )
            .expect("set");
        assert!(!authorize_plugin(&host, &p, Action::EventSubscribe, &pre).allow);
    }

    #[test]
    fn plugin_deny_lists_name_plugin_actions_only() {
        let rule = deny(&Action::ALL, None);
        let all = restrict_to_plugin_actions(&["*".into()], rule.clone()).expect("narrowed");
        assert_eq!(all.actions, PLUGIN_ACTIONS);
        assert!(restrict_to_plugin_actions(&["device.command".into()], rule.clone()).is_none());
        let host = deny(&[Action::HostLogs], None);
        assert!(restrict_to_plugin_actions(&["*".into()], host).is_none());
        let one =
            restrict_to_plugin_actions(&["state.read".into()], deny(&[Action::StateRead], None))
                .expect("plugin action");
        assert_eq!(one.actions, ActionSet::of(&[Action::StateRead]));
    }
}
