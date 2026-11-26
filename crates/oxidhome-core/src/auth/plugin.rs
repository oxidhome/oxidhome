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
//! - **Denies.** The owner's global deny list (`*`, every plugin),
//!   the list for the acting plugin and the list for every plugin
//!   that made a `call-service` hop on the way to it
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
//!   | `blob.read` | [`Resource::State`] | `reads_state` with `bytes = true` (the entry's `bytes-val` fields); camera bytes also `sensitive = ["camera"]` on that grant |
//!   | `blob.read` | [`Resource::Device`] or [`Resource::Blob`] (an event's `bytes-val` fields, [`event_bytes_permit`]) | `reads_event_bytes`; camera bytes also `sensitive_event_bytes = ["camera"]` |
//!   | `event.subscribe` | any | `subscribes_events` |
//!
//!   Camera bytes are sensitive (H6 slice 5b): no `*` selector covers
//!   them, only a grant that names `camera` (refused as
//!   [`Reason::MissingSensitive`], label `sensitive:camera`). The
//!   owner approves such grants at install. A plugin's own sensitive
//!   grant carries no obligation; a token root's does, and a plugin
//!   read can't meet it, so the bytes are withheld.
//!
//! - **The root's permit**, when the invocation is rooted at an
//!   external principal: [`authorize`] on the token-facing equivalent
//!   (`service.call` as is; `state.read` as `device.read` and bytes as
//!   `blob.read` on the entry's device; `event.subscribe` as
//!   `event.read` on the whole event stream). Host-rooted work
//!   (`init`, `tick`, `on-event`) is the plugin's own.
//!
//! Not in the engine, as manifest-only checks: `network`,
//! `declares_devices` / `declares_services`, quotas and
//! `script_sandboxes`. A plugin's own state
//! entries are its own data and are not asked about here
//! (`runtime::state_read`). Host-mediated device commands between
//! plugins don't exist yet, so `device.command` is not a plugin action.

use std::borrow::Cow;

use oxidhome_manifest::{ServiceGrant, StateGrant};

use super::authorize::{Action, Decision, Reason, Resource, ResourceKind, authorize};
use super::category::SensitiveCategory;
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
/// What permits a plugin the `bytes-val` fields of recorded events
/// (`read-events`).
pub const READS_EVENT_BYTES_GRANT: &str = "reads_event_bytes";
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
    /// Effective `reads_event_bytes`.
    pub reads_event_bytes: bool,
    /// Effective `sensitive_event_bytes` names `camera`.
    pub camera_event_bytes: bool,
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

/// The global list, the acting plugin's, then each caller's on the
/// chain.
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
        (Action::StateRead, Resource::State(s)) => plugin
            .reads_state
            .iter()
            .any(|g| g.matches(s.owner_plugin(), s.device().id(), s.capability()))
            .then_some(READS_STATE_GRANT)
            .ok_or(missing(READS_STATE_GRANT)),
        (Action::BlobRead, Resource::State(s)) => {
            let mut with_bytes = plugin.reads_state.iter().filter(|g| {
                g.bytes && g.matches(s.owner_plugin(), s.device().id(), s.capability())
            });
            if !is_camera_bytes(resource) {
                return with_bytes
                    .next()
                    .map(|_| READS_STATE_BYTES_GRANT)
                    .ok_or(missing(READS_STATE_BYTES_GRANT));
            }
            let mut any = false;
            for g in with_bytes {
                if g.sensitive
                    .iter()
                    .any(|c| c == SensitiveCategory::Camera.as_str())
                {
                    return Ok(READS_STATE_BYTES_GRANT);
                }
                any = true;
            }
            Err(if any {
                Reason::MissingSensitive {
                    category: SensitiveCategory::Camera,
                }
            } else {
                missing(READS_STATE_BYTES_GRANT)
            })
        }
        (Action::BlobRead, Resource::Device(_) | Resource::Blob(_)) => event_bytes_permit(
            plugin.reads_event_bytes,
            plugin.camera_event_bytes,
            resource,
        ),
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

/// A plugin's permit to read the `bytes-val` fields of a recorded
/// event, whose bytes are `resource` (the event's device, or its
/// source's blobs): `reads_event_bytes`, and for camera bytes the
/// `camera` sensitive grant (`camera_grant`, from
/// `sensitive_event_bytes`). Plain inputs, so a history scan can
/// decide it off the plugin's state.
///
/// # Errors
///
/// [`Reason::MissingPluginGrant`] labelled `reads_event_bytes`, or
/// [`Reason::MissingSensitive`] for camera bytes without the grant.
pub fn event_bytes_permit(
    reads_event_bytes: bool,
    camera_grant: bool,
    resource: &Resource,
) -> Result<&'static str, Reason> {
    if !reads_event_bytes {
        return Err(Reason::MissingPluginGrant {
            grant: READS_EVENT_BYTES_GRANT,
        });
    }
    live_event_bytes_permit(camera_grant, resource).map(|()| READS_EVENT_BYTES_GRANT)
}

/// Whether a plugin may receive the bytes `resource` of an event
/// delivered live (`on-event`, which needs no `reads_event_bytes`):
/// camera bytes need the `camera` sensitive grant (`camera_grant`).
///
/// # Errors
///
/// [`Reason::MissingSensitive`] for camera bytes without the grant.
pub fn live_event_bytes_permit(camera_grant: bool, resource: &Resource) -> Result<(), Reason> {
    if is_camera_bytes(resource) && !camera_grant {
        return Err(Reason::MissingSensitive {
            category: SensitiveCategory::Camera,
        });
    }
    Ok(())
}

/// `true` when reading `resource`'s bytes reads camera bytes: a camera
/// device's (or a camera-source instance's, whose class says so), or a
/// camera-source instance's blobs. Only an explicit `camera` sensitive
/// grant covers them; no `*` selector does.
fn is_camera_bytes(resource: &Resource) -> bool {
    match resource {
        Resource::Device(d) => d.class().is_camera(),
        Resource::State(s) => s.device().class().is_camera(),
        Resource::Blob(b) => b.is_camera(),
        _ => false,
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
            reads_event_bytes: false,
            camera_event_bytes: false,
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
            sensitive: Vec::new(),
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
            reads_event_bytes: false,
            camera_event_bytes: false,
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

    /// An event's bytes need `reads_event_bytes`, like a state entry's
    /// need `reads_state.bytes`; an external root also needs
    /// `blob.read` on them.
    #[test]
    fn event_bytes_need_reads_event_bytes() {
        let denies = PluginDenyStore::detached();
        let p = plugin(&denies, &[], &[]);
        let host = InvocationContext::host_origin("caller");
        let lamp = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light),
        );
        let blob = Resource::blob("src", "", false);
        for bytes in [&lamp, &blob] {
            let d = authorize_plugin(&host, &p, Action::BlobRead, bytes);
            assert_eq!(d.reason.audit_label(), Some(READS_EVENT_BYTES_GRANT));
        }
        let with = PluginPrincipal {
            reads_event_bytes: true,
            ..p
        };
        let d = authorize_plugin(&host, &with, Action::BlobRead, &lamp);
        assert_eq!(
            d.reason,
            Reason::PluginGrant {
                grant: READS_EVENT_BYTES_GRANT
            }
        );
        let narrow = ctx_for(&Actor::api("t", vec!["events:read".into()]));
        let d = authorize_plugin(&narrow, &with, Action::BlobRead, &lamp);
        assert_eq!(d.reason.audit_label(), Some("blobs:read"));
    }

    /// Camera bytes are sensitive for plugins too: no `*` grant
    /// covers them, only one naming `camera`; the label is
    /// `sensitive:camera`. Reading the entry itself isn't sensitive.
    #[test]
    fn camera_bytes_need_a_camera_grant() {
        let denies = PluginDenyStore::detached();
        let cam = Resource::state(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Camera),
            "example.cam",
            "camera",
        );
        let host = InvocationContext::host_origin("caller");
        let wildcard = [read_all(true)];
        let p = plugin(&denies, &[], &wildcard);
        assert!(authorize_plugin(&host, &p, Action::StateRead, &cam).allow);
        let d = authorize_plugin(&host, &p, Action::BlobRead, &cam);
        assert_eq!(d.reason.audit_label(), Some("sensitive:camera"));
        assert!(authorize_plugin(&host, &p, Action::BlobRead, &lock_state()).allow);
        let granted = [
            read_all(true),
            StateGrant {
                sensitive: vec!["camera".into()],
                ..read_all(true)
            },
        ];
        let p = plugin(&denies, &[], &granted);
        let d = authorize_plugin(&host, &p, Action::BlobRead, &cam);
        assert!(d.allow);
        assert_eq!(d.obligations, crate::auth::Obligations::default());
        // A token root's camera allow carries an obligation, which the
        // caller can't meet; a token without the camera grant is
        // refused.
        let owner = ctx_for(&Actor::api("t", vec!["*".into()]));
        let d = authorize_plugin(&owner, &p, Action::BlobRead, &cam);
        assert_eq!(d.reason.audit_label(), Some("sensitive:camera"));

        // Event bytes: `reads_event_bytes`, then the camera grant.
        let cam_device = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Camera),
        );
        let cam_blob = Resource::blob("src", "", true);
        let events = PluginPrincipal {
            reads_event_bytes: true,
            ..plugin(&denies, &[], &[])
        };
        for bytes in [&cam_device, &cam_blob] {
            let d = authorize_plugin(&host, &events, Action::BlobRead, bytes);
            assert_eq!(d.reason.audit_label(), Some("sensitive:camera"));
            let with = PluginPrincipal {
                camera_event_bytes: true,
                ..events
            };
            assert!(authorize_plugin(&host, &with, Action::BlobRead, bytes).allow);
            assert!(live_event_bytes_permit(false, bytes).is_err());
            assert!(live_event_bytes_permit(true, bytes).is_ok());
        }
        assert!(live_event_bytes_permit(false, &Resource::blob("src", "", false)).is_ok());
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
