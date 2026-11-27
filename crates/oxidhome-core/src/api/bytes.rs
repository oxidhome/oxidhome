//! Who may see raw `bytes-val` payloads (M7).
//!
//! Camera snapshots, audio clips and inference frames ride device
//! state, events and command results as `bytes-val`. Every read
//! surface (REST, Connect, MCP; snapshots, change feeds, history,
//! live tails, command replies) builds one [`BytesGate`] per request or
//! stream and asks it per value's source. A value the gate refuses is
//! replaced by the withheld marker ([`crate::redact::withhold_bytes`]).
//!
//! The decision is [`authorize()`] of `blob.read` on the source. Bytes
//! from a **camera source** are sensitive: the source device is a
//! camera, or its owning instance has ever registered a camera (blobs
//! and bytes carry no provenance of their own, so everything a camera
//! plugin emits is treated as camera bytes). They need a role grant
//! naming `camera`.
//!
//! The decision is taken per value against the current device
//! registry, so a long-lived stream follows reclassification. A camera
//! release is recorded once per gate, on the first camera value it
//! releases, with a `warn` audit row written off the request path and
//! best-effort: a read releases no physical effect, and failing the
//! whole stream on an audit hiccup would be worse than a missed row
//! (the failure is logged at error).

use std::sync::{Arc, Mutex, PoisonError};

use crate::Engine;
use crate::auth::{Action, Decision, InvocationContext, Resource, SensitiveCategory, authorize};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};
use crate::runtime::{CommandOutcome, CommandReport};
use crate::state::{AuditLog, DeviceRegistry};

/// Per-request (or per-stream) byte-release decisions.
pub(crate) struct BytesGate {
    ctx: InvocationContext,
    devices: Arc<DeviceRegistry>,
    audit: Arc<AuditLog>,
    /// The pre-check: may the root read any bytes at all?
    general: bool,
    /// Record the camera release only once [`Self::settle`] says the
    /// response was delivered.
    deferred: bool,
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    /// A camera value was released (and recorded, or pending).
    camera_released: bool,
    /// A deferred gate's release, recorded on [`BytesGate::settle`].
    pending: Option<(Decision, String)>,
}

impl BytesGate {
    /// A gate for `ctx`'s root.
    pub(crate) fn new(ctx: &InvocationContext, engine: &Engine) -> Self {
        Self {
            ctx: ctx.clone(),
            devices: engine.devices(),
            audit: engine.audit_log(),
            // A pre-check: every value is decided per source below.
            general: authorize(
                ctx,
                Action::BlobRead,
                &Resource::pre_check(crate::auth::ResourceKind::Blob),
            )
            .allow,
            deferred: false,
            state: Mutex::new(GateState::default()),
        }
    }

    /// A gate whose camera release is recorded only once
    /// [`Self::settle`] reports the response delivered: for a
    /// response that may still be refused after it is built (an MCP
    /// body over its size cap).
    pub(crate) fn deferred(ctx: &InvocationContext, engine: &Engine) -> Self {
        let mut gate = Self::new(ctx, engine);
        gate.deferred = true;
        gate
    }

    /// Settle a deferred gate: record its camera release if the
    /// response was `delivered`, else forget it.
    pub(crate) fn settle(&self, delivered: bool) {
        let pending = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .take();
        if let Some((decision, target)) = pending
            && delivered
        {
            self.record_release(decision, target);
        }
    }

    /// A gate that releases nothing.
    pub(crate) fn deny_all(engine: &Engine) -> Self {
        let mut gate = Self::new(&InvocationContext::host_origin(""), engine);
        gate.general = false;
        gate
    }

    /// `true` when the root may read bytes from some source: the
    /// pre-check.
    pub(crate) fn general(&self) -> bool {
        self.general
    }

    /// Whether bytes from `device` (or, for a blob, from
    /// `owner_instance`) are released.
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
                    class = class.with_camera_bytes();
                }
                Resource::device(id, class)
            }
            None => Resource::blob(owner.clone().unwrap_or_default(), "", camera_source),
        };
        let decision = authorize(&self.ctx, Action::BlobRead, &resource);
        if !decision.allow {
            return false;
        }
        if !decision.sensitive.is_empty() {
            self.camera_release(decision, device.or(owner.as_deref()).unwrap_or(""));
        }
        true
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
    /// `device`, owned by `owner_instance` at dispatch.
    pub(crate) fn release_report(
        &self,
        device: &str,
        owner_instance: &str,
        report: &CommandReport,
    ) -> bool {
        match &report.outcome {
            CommandOutcome::Completed { state: Some(kvs) } => {
                self.release_kvs(Some(device), Some(owner_instance), kvs)
            }
            _ => true,
        }
    }

    /// Asked afresh for every byte-bearing value (not cached), so an
    /// open stream sees an instance become a camera source.
    fn instance_is_camera(&self, instance: &str) -> bool {
        self.devices.instance_is_camera(instance)
    }

    /// Record the first camera release of this gate.
    fn camera_release(&self, decision: Decision, target: &str) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if std::mem::replace(&mut st.camera_released, true) {
            return;
        }
        if self.deferred {
            st.pending = Some((decision, target.to_owned()));
            return;
        }
        drop(st);
        self.record_release(decision, target.to_owned());
    }

    /// Write the `warn` row of a camera release, off the request path.
    fn record_release(&self, decision: Decision, target: String) {
        let audit = Arc::clone(&self.audit);
        let ctx = self.ctx.clone();
        let write = move || {
            if let Err(err) =
                crate::auth::sensitive::record(&audit, &ctx, Action::BlobRead, &target, &decision)
            {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Actor, ActorKind, Principal, RoleDef, Transport};
    use crate::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec;
    use crate::host_impl::plugin::oxidhome::plugin::devices::DeviceInfo;
    use std::sync::Arc;

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

    fn ctx(grants: &str) -> InvocationContext {
        let role = RoleDef::parse("r", grants.as_bytes()).expect("role");
        let actor = Actor::api("tok", vec![Arc::new(role)]);
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
    }

    const ALL: &str = r#"[{"actions":["*"]}]"#;
    const CAMERA: &str = r#"[{"actions":["blob.read"],"category":["camera"]}]"#;

    /// A deferred gate records a camera release only once settled as
    /// delivered.
    #[test]
    fn a_deferred_release_counts_only_when_delivered() {
        use crate::state::AuditQuery;
        let engine = Engine::new().expect("engine");
        let cam = engine.devices().register(
            "u",
            "cam-inst".into(),
            info("c", vec![CapabilitySpec::VideoStream]),
        );
        let viewer = ctx(CAMERA);
        let warn = || {
            engine
                .audit_log()
                .query(
                    &AuditQuery {
                        level: Some("warn".into()),
                        ..AuditQuery::default()
                    },
                    10,
                )
                .unwrap()
                .len()
        };
        for _ in 0..3 {
            let gate = BytesGate::deferred(&viewer, &engine);
            assert!(gate.allows(Some(&cam), None));
            gate.settle(false);
        }
        assert_eq!(warn(), 0);
        let gate = BytesGate::deferred(&viewer, &engine);
        assert!(gate.allows(Some(&cam), None));
        gate.settle(true);
        assert_eq!(warn(), 1);
    }

    /// An open gate (a tail) sees an instance become a camera source:
    /// the next byte value from a sibling device is withheld.
    #[tokio::test]
    async fn an_open_gate_follows_a_new_camera() {
        let engine = Engine::new().expect("engine");
        let bell =
            engine
                .devices()
                .register("u", "inst".into(), info("b", vec![CapabilitySpec::Button]));
        let gate = BytesGate::new(&ctx(ALL), &engine);
        assert!(gate.allows(Some(&bell), None));
        engine.devices().register(
            "u",
            "inst".into(),
            info("c", vec![CapabilitySpec::VideoStream]),
        );
        assert!(!gate.allows(Some(&bell), None));
        assert!(!gate.allows(None, Some("inst")));
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

        // `*`: lamp bytes yes, camera (and the camera plugin's other
        // devices) no.
        let gate = BytesGate::new(&ctx(ALL), &engine);
        assert!(gate.allows(Some(&lamp), None));
        assert!(!gate.allows(Some(&cam), None));
        assert!(!gate.allows(Some(&bell), None));
        assert!(!gate.allows(None, Some("cam-inst")));
        assert!(gate.allows(None, Some("lamp-inst")));

        // No blob.read at all: nothing.
        let gate = BytesGate::new(&ctx(r#"[{"actions":["device.read"]}]"#), &engine);
        assert!(!gate.allows(Some(&lamp), None));

        // A grant naming camera: released.
        let gate = BytesGate::new(&ctx(CAMERA), &engine);
        assert!(gate.allows(Some(&cam), None));
        assert!(gate.allows(Some(&bell), None));
        assert!(gate.allows(None, Some("cam-inst")));

        // A grant narrowed to the camera device covers it, not the bell.
        let gate = BytesGate::new(
            &ctx(&format!(
                r#"[{{"actions":["blob.read"],"category":["camera"],"devices":["{cam}"]}}]"#
            )),
            &engine,
        );
        assert!(gate.allows(Some(&cam), None));
        assert!(!gate.allows(Some(&bell), None));
    }
}
