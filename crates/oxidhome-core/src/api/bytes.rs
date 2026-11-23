//! Who may see raw `bytes-val` payloads (M7, H6 slice 2).
//!
//! Camera snapshots, audio clips and inference frames ride device
//! state, events and command results as `bytes-val`. Every read
//! surface (REST, Connect, MCP; snapshots, change feeds, history,
//! live tails, command replies) builds one [`BytesGate`] per request or
//! stream and asks it per value's source. A value the gate refuses is
//! replaced by the withheld marker ([`crate::redact::withhold_bytes`]).
//!
//! The decision is [`authorize()`] of `blob.read` on the source:
//!
//! - the root must hold `blob.read` (the `blobs:read` scope or the
//!   wildcard), as before;
//! - bytes from a **camera source** are sensitive: the source device is
//!   a camera, or its owning instance has ever registered a camera
//!   (blobs and bytes carry no provenance of their own, so everything a
//!   camera plugin emits is treated as camera bytes). These need an
//!   explicit `camera` grant; a wildcard scope doesn't reach them.
//!
//! The decision is taken per value against the current device
//! registry, so a long-lived stream follows reclassification. The
//! obligations of a camera release (rate limit, `warn` audit row) are
//! met once per gate: on the first camera value the gate would
//! release. If the principal's camera allowance is used up, the gate
//! withholds every camera value for the rest of the request or
//! stream. The `warn` row is written off the request path and
//! best-effort: a read releases no physical effect, and failing the
//! whole stream on an audit hiccup would be worse than a missed row
//! (the failure is logged at error).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::Engine;
use crate::auth::sensitive::{ObligationError, SensitiveGuard};
use crate::auth::{Action, InvocationContext, Resource, SensitiveCategory, authorize};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};
use crate::runtime::{CommandOutcome, CommandReport};
use crate::state::DeviceRegistry;

/// Per-request (or per-stream) byte-release decision.
pub(crate) struct BytesGate {
    ctx: InvocationContext,
    devices: Arc<DeviceRegistry>,
    guard: Arc<SensitiveGuard>,
    /// The root holds `blob.read` at all (the pre-check).
    general: bool,
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    /// `instance_is_camera` answers, so a page of entries from one
    /// instance scans the registry once.
    camera_instances: HashMap<String, bool>,
    camera: CameraRelease,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum CameraRelease {
    /// No camera value released yet: the next one meets the
    /// obligations.
    #[default]
    NotYet,
    /// Obligations met; release camera values the decision allows.
    Released,
    /// Rate limited: withhold every camera value.
    Refused,
}

impl BytesGate {
    /// A gate for `ctx`'s root against `engine`'s registry.
    pub(crate) fn new(ctx: &InvocationContext, engine: &Engine) -> Self {
        Self {
            ctx: ctx.clone(),
            devices: engine.devices(),
            guard: engine.sensitive(),
            general: authorize(ctx, Action::BlobRead, &Resource::blobs()).allow,
            state: Mutex::new(GateState::default()),
        }
    }

    /// A gate that releases nothing (no invocation context).
    pub(crate) fn deny_all(engine: &Engine) -> Self {
        let ctx = InvocationContext::external(crate::auth::Principal::token(
            crate::auth::ActorKind::Api,
            &crate::auth::Actor::api("", Vec::new()),
            crate::auth::Transport::Rest,
        ));
        Self {
            general: false,
            ..Self::new(&ctx, engine)
        }
    }

    /// `true` when the root holds `blob.read` at all. Only for sizing
    /// pages (an upper bound); never to release a value.
    pub(crate) fn general(&self) -> bool {
        self.general
    }

    /// May bytes from `device` (registered by `owner_instance`) be
    /// released? Either may be unknown: a custom event names no device,
    /// a historical row may name an instance that's gone.
    pub(crate) fn allows(&self, device: Option<&str>, owner_instance: Option<&str>) -> bool {
        if !self.general {
            return false;
        }
        let owner = owner_instance
            .map(str::to_owned)
            .or_else(|| device.and_then(|d| self.devices.get_owner(&d.to_owned())));
        let camera_source = owner.as_deref().is_some_and(|i| self.instance_is_camera(i));
        let resource = match device {
            Some(id) => {
                let mut class = self.devices.class_of(id);
                if camera_source {
                    class = class.raised(crate::auth::DeviceCategory::Camera);
                }
                Resource::device(id, class)
            }
            None => Resource::blob(owner.clone().unwrap_or_default(), "", camera_source),
        };
        let decision = authorize(&self.ctx, Action::BlobRead, &resource);
        if !decision.allow {
            return false;
        }
        if decision.obligations.sensitive.is_empty() {
            return true;
        }
        self.camera_release(&decision, device.or(owner.as_deref()).unwrap_or(""))
    }

    /// May `kvs` from `device` / `owner_instance` go out with their
    /// bytes? `true` without asking when they carry none, so a
    /// byte-free value never meets camera obligations.
    pub(crate) fn release_kvs(
        &self,
        device: Option<&str>,
        owner_instance: Option<&str>,
        kvs: &[KeyValue],
    ) -> bool {
        !kvs.iter().any(|kv| matches!(kv.value, Value::BytesVal(_)))
            || self.allows(device, owner_instance)
    }

    /// [`Self::release_kvs`] for a projected state entry.
    pub(crate) fn release_state(&self, state: &crate::state::DeviceState) -> bool {
        self.release_kvs(
            Some(&state.device_id),
            Some(&state.owner_instance),
            &state.fields,
        )
    }

    /// [`Self::release_kvs`] for an event (only `state-changed`
    /// payloads carry bytes).
    pub(crate) fn release_event(&self, event: &Event) -> bool {
        match &event.payload {
            EventPayload::StateChanged(sc) => self.release_kvs(
                event.device.as_deref(),
                Some(&event.origin_instance_id),
                &sc.fields,
            ),
            _ => true,
        }
    }

    /// [`Self::release_kvs`] for a command's `completed` readout from
    /// `device`.
    pub(crate) fn release_report(&self, device: &str, report: &CommandReport) -> bool {
        match &report.outcome {
            CommandOutcome::Completed { state: Some(kvs) } => {
                self.release_kvs(Some(device), None, kvs)
            }
            _ => true,
        }
    }

    fn instance_is_camera(&self, instance: &str) -> bool {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(&known) = st.camera_instances.get(instance) {
            return known;
        }
        let camera = self.devices.instance_is_camera(instance);
        st.camera_instances.insert(instance.to_owned(), camera);
        camera
    }

    fn camera_release(&self, decision: &crate::auth::Decision, target: &str) -> bool {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match st.camera {
            CameraRelease::Released => return true,
            CameraRelease::Refused => return false,
            CameraRelease::NotYet => {}
        }
        if decision.obligations.rate_limit.is_some() {
            let principal = self.ctx.root().audit_token_id().to_owned();
            if let Err(ObligationError::RateLimited { .. }) = self
                .guard
                .charge(&principal, decision.obligations.sensitive)
            {
                st.camera = CameraRelease::Refused;
                return false;
            }
        }
        st.camera = CameraRelease::Released;
        drop(st);
        let guard = Arc::clone(&self.guard);
        let ctx = self.ctx.clone();
        let target = target.to_owned();
        let decision = decision.clone();
        let write = move || {
            if let Err(err) = guard.record(&ctx, Action::BlobRead, &target, &decision) {
                tracing::error!(
                    target: "auth.sensitive",
                    error = %err,
                    category = SensitiveCategory::Camera.as_str(),
                    "recording a camera byte release failed",
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            Err(_) => write(),
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Actor, ActorKind, Principal, SensitiveGrant, TokenPolicy, Transport};
    use crate::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec;
    use crate::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;

    fn info(local: &str, caps: Vec<CapabilitySpec>) -> DeviceInfo {
        DeviceInfo {
            local_id: local.into(),
            name: local.into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: caps,
            initial_state: Vec::new(),
            metadata: Vec::new(),
        }
    }

    fn ctx(scopes: &[&str], sensitive: Vec<SensitiveGrant>) -> InvocationContext {
        let actor = Actor::from_token_policy(
            "tok",
            TokenPolicy {
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                sensitive,
                ..TokenPolicy::default()
            },
            false,
        );
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
    }

    #[tokio::test]
    async fn camera_bytes_follow_the_decision() {
        let engine = Engine::new().expect("engine");
        let cam = engine.devices().register(
            "u",
            "cam-inst".into(),
            info("c", vec![CapabilitySpec::VideoStream]),
        );
        let bell = engine.devices().register(
            "u",
            "cam-inst".into(),
            info("b", vec![CapabilitySpec::Button]),
        );
        let lamp = engine.devices().register(
            "u",
            "lamp-inst".into(),
            info("l", vec![CapabilitySpec::Switch]),
        );

        // Wildcard: lamp bytes yes, camera (and the camera plugin's
        // other devices) no.
        let gate = BytesGate::new(&ctx(&["*"], vec![]), &engine);
        assert!(gate.allows(Some(&lamp), None));
        assert!(!gate.allows(Some(&cam), None));
        assert!(!gate.allows(Some(&bell), None));
        assert!(!gate.allows(None, Some("cam-inst")));
        assert!(gate.allows(None, Some("lamp-inst")));

        // No blobs:read at all: nothing.
        let gate = BytesGate::new(&ctx(&["devices:read"], vec![]), &engine);
        assert!(!gate.allows(Some(&lamp), None));

        // Explicit camera grant: released.
        let gate = BytesGate::new(
            &ctx(
                &["blobs:read"],
                vec![SensitiveGrant::all(SensitiveCategory::Camera)],
            ),
            &engine,
        );
        assert!(gate.allows(Some(&cam), None));
        assert!(gate.allows(Some(&bell), None));
        assert!(gate.allows(None, Some("cam-inst")));

        // A grant narrowed to the camera device covers it, not the bell.
        let gate = BytesGate::new(
            &ctx(
                &["blobs:read"],
                vec![SensitiveGrant {
                    category: SensitiveCategory::Camera,
                    devices: Some(vec![cam.clone()]),
                }],
            ),
            &engine,
        );
        assert!(gate.allows(Some(&cam), None));
        assert!(!gate.allows(Some(&bell), None));
    }
}
