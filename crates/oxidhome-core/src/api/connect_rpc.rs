//! Connect RPC handler wiring.
//!
//! Builds a [`connectrpc::Router`] populated with `OxidHome`'s Connect
//! services and exposes it as an axum-compatible `tower::Service`
//! via [`connectrpc::Router::into_axum_service`]. The existing JSON
//! `/api/v1/*` axum router mounts this service as a `fallback_service`
//! so both protocols share one listener:
//!
//! - JSON paths (`/api/v1/*`) continue to land on the handlers in
//!   [`super::server`].
//! - Connect paths (`POST /oxidhome.v1.HealthService/Check` etc.) fall
//!   through to the Connect router.
//!
//! **Auth + audit shape.** axum's `.layer(...)` on the outer
//! `build_router` covers the explicit `/api/v1/*` routes but does
//! **not** wrap what a caller passes to `.fallback_service(...)`.
//! Connect therefore carries its own wrapper middleware — installed
//! by [`axum_service`] on the sub-router the JSON side mounts as
//! fallback (see [`connect_auth_middleware`], added in 15-b). It
//! authenticates every non-anonymous request against the same
//! [`TokenStore`](crate::state::TokenStore) the JSON `require_token`
//! uses, stamps the [`Actor`](crate::auth::Actor) and its
//! [`InvocationContext`] into `req.extensions_mut()` (forwarded
//! into [`RequestContext::extensions()`] by the Connect dispatcher),
//! and records one row per authenticated request in the C3 audit
//! ledger via [`crate::api::auth::finalize_audit`]. The
//! `Health.Check` path is on the anonymous allow-list so liveness
//! probes still work without credentials.
//!
//! Per-RPC authorization happens inside each handler via
//! [`require_connect`], which asks [`crate::auth::authorize()`] — the
//! same decision the JSON handlers' `require` uses. Handlers record
//! their outcome (the deny's audit label on `permission_denied`, or
//! the synthesized HTTP
//! status of any other [`ConnectError`] via [`rpc_err`]) into a
//! [`HandlerOutcomeSlot`] request-extension the middleware reads
//! back — that's what keeps the audit row's decision classification
//! and `required_scope` field correct across all transports,
//! including gRPC / gRPC-Web where RPC errors ride at HTTP 200
//! with the status in trailers rather than on the response status.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response as AxumResponse;
use connectrpc::{
    ConnectError, Encodable, RequestContext, Response, Router as ConnectRouter, ServiceRequest,
    ServiceResult,
};
use oxidhome_proto::connect::oxidhome::v1::{
    DevicesServiceExt, EventsServiceExt, HealthServiceExt, InstancesServiceExt, LogsServiceExt,
    PluginsServiceExt, TokensServiceExt,
};
use oxidhome_proto::proto::oxidhome::v1::{
    Button as ProtoButton, ButtonKind as ProtoButtonKind, CheckRequest, CheckResponse,
    CommandOutcome as ProtoCommandOutcome, CursorExpired as ProtoCursorExpired,
    CustomEvent as ProtoCustomEvent, Device, DeviceStateEntry as ProtoDeviceStateEntry,
    DeviceStateSnapshot as ProtoDeviceStateSnapshot, Event as ProtoEvent,
    ExecuteCommandError as ProtoCmdError, ExecuteCommandRequest, ExecuteCommandResponse,
    GetDeviceStateRequest, GetDeviceStateResponse, Inference as ProtoInference,
    InstallPluginRequest, InstallPluginResponse, Instance, KeyValue as ProtoKeyValue,
    Lagged as ProtoLagged, ListDeviceStateChangesRequest, ListDeviceStateChangesResponse,
    ListDeviceStateRequest, ListDeviceStateResponse, ListDevicesRequest, ListDevicesResponse,
    ListInstancesRequest, ListInstancesResponse, ListPluginsRequest, ListPluginsResponse,
    LogEvent as ProtoLogEvent, LogField as ProtoLogField, LogLevel as ProtoLogLevel,
    LogValue as ProtoLogValue, Plugin as ProtoPlugin, QueryLogsRequest, QueryLogsResponse,
    StartPluginRequest, StartPluginResponse, StateChanged as ProtoStateChanged,
    StateQuality as ProtoStateQuality, StopPluginRequest, StopPluginResponse, TailEventsRequest,
    TailEventsResponse, UninstallPluginRequest, UninstallPluginResponse, Value as ProtoValue,
    event as proto_event, execute_command_error, execute_command_response, log_value,
    tail_events_response, value,
};
use oxidhome_proto::proto::oxidhome::v1::{
    CreateTokenRequest, CreateTokenResponse, ListTokensRequest, ListTokensResponse,
    Token as ProtoToken,
};

use crate::Engine;
use crate::auth::{Action, InvocationContext, Resource, ResourceKind, authorize};
use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent as WitButtonEvent;
use crate::host_impl::plugin::oxidhome::plugin::devices::Command;
use crate::host_impl::plugin::oxidhome::plugin::events::{Event as WitEvent, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};
use crate::runtime::{CommandOutcome, CommandReport};
use crate::state::{
    HistoricalLogEvent, InstallError, LogLevel, LogQuery, LogValue, TokenError, UninstallError,
};

use super::auth::{
    AuthState, actor_from_record, extract_bearer, finalize_audit, record_anonymous_probe,
};
use super::bytes::BytesGate;
use super::scopes::{ScopeDenied, require};

/// The device pre-check: a per-device decision always follows.
const DEVICE_PRE_CHECK: Resource = Resource::pre_check(ResourceKind::Device);

/// `HealthService` implementation. Anonymous; reads only the
/// in-memory event-log mirror health (H3) and device-state flush
/// health (H2), never the database.
struct OxidHomeHealth {
    engine: Engine,
}

impl oxidhome_proto::connect::oxidhome::v1::HealthService for OxidHomeHealth {
    async fn check<'a>(
        &'a self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CheckRequest>,
    ) -> ServiceResult<impl Encodable<CheckResponse> + Send + use<'a>> {
        // The version comes from `oxidhome-core`'s `Cargo.toml` —
        // the daemon binary lives in this same crate, so a workspace
        // bump moves both in lockstep.
        // `..Default::default()` swallows buffa's `__buffa_unknown_fields`
        // marker (its forward-compat slot for round-tripping unknown
        // proto fields). Setting the schema's named fields covers
        // the contract.
        //
        // H3 follow-up: mirror `/readyz`'s `event_log` signal. The
        // status stays "ok" while degraded, same as `/readyz` stays
        // 200: control still works, only history is missing rows.
        let event_log = if self.engine.event_log().health().degraded {
            "degraded"
        } else {
            "ok"
        };
        // H2: the device-state projection's flush health, the same way.
        let device_state = if self.engine.device_state().flush_health().degraded {
            "degraded"
        } else {
            "ok"
        };
        Response::ok(CheckResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            event_log: event_log.into(),
            device_state: device_state.into(),
            ..Default::default()
        })
    }
}

// ── Scope-check + outcome-record helpers ────────────────────────

/// What a Connect handler recorded as it returned. Serves the
/// middleware's audit classifier — see [`connect_auth_middleware`].
#[derive(Debug, Clone)]
struct HandlerOutcome {
    /// Synthesized HTTP status for the audit row. `ConnectError::http_status()`
    /// on the error path (403 for `PermissionDenied`, 404 for `NotFound`,
    /// 409 for `AlreadyExists`, 422 for `InvalidArgument`, etc.). This is
    /// what the audit classifier consumes rather than
    /// `response.status()`, because gRPC and gRPC-Web RPC errors ride at
    /// HTTP 200 with the status in trailers/body — see finding #1 on
    /// the PR #67 review.
    ///
    /// `None` when this outcome was recorded by
    /// [`record_domain_outcome`] — the RPC itself succeeded (HTTP
    /// 200 / gRPC OK) and carries a device command's outcome.
    /// See the module doc + [`super::auth::DomainOutcome`] for why
    /// authorization and execution outcomes must not share the
    /// same audit field.
    status: Option<axum::http::StatusCode>,
    /// The deny's audit label (missing scope or constraint
    /// sentinel), if this outcome was a `PermissionDenied` recorded by
    /// [`require_connect`]. Middleware populates the `required_scope`
    /// audit field from this — mirrors the JSON side's `DeniedScope`
    /// smuggle.
    denied_scope: Option<&'static str>,
    /// H5: the dispatched device command's id and explicit outcome.
    /// Populated by [`record_domain_outcome`]; the middleware forwards
    /// it to the audit ledger's command / execution columns (F4).
    command: Option<super::auth::DomainOutcome>,
}

/// Request-scoped smuggling channel from Connect handlers to the
/// [`connect_auth_middleware`]. The middleware installs an empty
/// slot on `req.extensions_mut()` before running the handler;
/// handlers write to it on the error path via
/// [`require_connect`] (for authorization denials) or [`rpc_err`]
/// (for every other `ConnectError`); the middleware reads it after
/// the handler returns.
///
/// **Why a request-side slot instead of reading the response status:**
/// The Connect response type — `Response<ConnectRpcBody>` — carries
/// the RPC outcome in transport-shaped places (HTTP status for
/// Connect unary, `grpc-status` trailers for gRPC / gRPC-Web,
/// `EndStreamResponse` envelope for Connect streaming). By the time
/// the response reaches the axum middleware it's just
/// `AxumResponse<Body>` — the middleware can only see HTTP status,
/// which is 200 for every gRPC / gRPC-Web error. Recording the
/// outcome pre-return preserves the classification cleanly across
/// every transport without the middleware having to parse trailer
/// frames out of the body.
#[derive(Clone, Default)]
struct HandlerOutcomeSlot(Arc<Mutex<Option<HandlerOutcome>>>);

impl HandlerOutcomeSlot {
    fn take(&self) -> Option<HandlerOutcome> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn set(&self, outcome: HandlerOutcome) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
    }
}

/// M7 / H6 slice 2: the request's [`BytesGate`]. Without the
/// invocation context (a pipeline bug) the gate releases nothing.
fn ctx_bytes_gate(ctx: &RequestContext, engine: &Engine) -> BytesGate {
    match ctx.extensions().get::<InvocationContext>() {
        Some(invocation) => BytesGate::new(invocation, engine),
        None => BytesGate::deny_all(engine),
    }
}

/// Wrap a [`ConnectError`] on the error-return site so the audit
/// row picks up the outcome. Idiomatic use — at every `return Err(...)`
/// inside a Connect handler that isn't a scope denial:
///
/// ```ignore
/// return Err(rpc_err(&ctx, ConnectError::not_found("device x")));
/// ```
///
/// [`require_connect`] does the equivalent for authorization denials
/// via the same slot; no double-record and no ambiguity.
#[must_use]
fn rpc_err(ctx: &RequestContext, err: ConnectError) -> ConnectError {
    if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
        slot.set(HandlerOutcome {
            status: Some(err.http_status()),
            denied_scope: None,
            command: None,
        });
    }
    err
}

/// Handler-side authorization for Connect RPCs. Mirrors the JSON
/// [`require`] but returns a [`ConnectError::permission_denied`]
/// instead of a `ScopeDenied` axum response, and records the deny's
/// audit label on the request's [`HandlerOutcomeSlot`] so the
/// middleware populates `required_scope` on the audit row (same
/// field shape as the JSON `DeniedScope` extension smuggle).
///
/// The [`InvocationContext`] is read out of `ctx.extensions()`. Its
/// presence is a contract with the middleware (which stamps it during
/// auth); missing it is an internal bug rather than a client error →
/// `ConnectError::internal`, not `Unauthenticated`.
fn require_connect(
    ctx: &RequestContext,
    action: Action,
    resource: &Resource,
) -> Result<crate::auth::Decision, ConnectError> {
    // If the middleware failed to stamp the context into extensions,
    // wrap the internal error through `rpc_err` too — otherwise a
    // gRPC / gRPC-Web caller of a scoped RPC in a broken pipeline
    // would audit as `allow` on an HTTP 200 wire response. Defense
    // in depth for the same class of bug PR #74 review flagged on
    // `query_logs`.
    let invocation = ctx.extensions().get::<InvocationContext>().ok_or_else(|| {
        rpc_err(
            ctx,
            ConnectError::internal("connect handler ran without an invocation context"),
        )
    })?;
    let denied = match require(invocation, action, resource) {
        Ok(decision) => return Ok(decision),
        Err(denied) => denied,
    };
    {
        let ScopeDenied { required } = denied;
        if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
            slot.set(HandlerOutcome {
                status: Some(axum::http::StatusCode::FORBIDDEN),
                denied_scope: Some(required),
                command: None,
            });
        }
        Err(ConnectError::permission_denied(format!(
            "scope {required} required"
        )))
    }
}

/// H6 slice 2: the error for a sensitive action whose obligations
/// weren't met — `resource_exhausted` when rate limited, `internal`
/// when the `warn` audit row couldn't be written.
fn obligation_err(
    ctx: &RequestContext,
    err: &crate::auth::sensitive::ObligationError,
) -> ConnectError {
    use crate::auth::sensitive::ObligationError;
    let e = match err {
        ObligationError::RateLimited { .. } => ConnectError::resource_exhausted(err.to_string()),
        ObligationError::Audit(_) | ObligationError::Join(_) => {
            tracing::error!(target: "auth.sensitive", error = %err, "sensitive action refused");
            ConnectError::internal("sensitive action refused")
        }
    };
    rpc_err(ctx, e)
}

// ── Read-service implementations (Instances / Devices / Plugins / Logs) ──

/// One `Engine` clone per handler struct — clone is cheap
/// (Arc-backed) and each service registered on the same
/// [`ConnectRouter`] takes its own owned copy.
struct OxidHomeInstances {
    engine: Engine,
}

impl oxidhome_proto::connect::oxidhome::v1::InstancesService for OxidHomeInstances {
    async fn list_instances<'a>(
        &'a self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListInstancesRequest>,
    ) -> ServiceResult<impl Encodable<ListInstancesResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::InstanceRead, &Resource::instances())?;
        let instances = self
            .engine
            .instances()
            .list()
            .into_iter()
            .map(|handle| Instance {
                instance_id: handle.instance_id().to_string(),
                plugin_id: handle.plugin_id().to_string(),
                state: format!("{:?}", handle.state()),
                // M7: masked config view; empty until first load.
                config_json: handle
                    .config_view()
                    .map_or_else(String::new, |v| v.to_string()),
                parent_instance_id: handle.parent_instance_id().map(str::to_owned),
                sandbox_local_id: handle.sandbox_local_id().map(str::to_owned),
                ..Default::default()
            })
            .collect();
        Response::ok(ListInstancesResponse {
            instances,
            ..Default::default()
        })
    }
}

struct OxidHomeDevices {
    engine: Engine,
}

impl oxidhome_proto::connect::oxidhome::v1::DevicesService for OxidHomeDevices {
    async fn list_devices<'a>(
        &'a self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListDevicesRequest>,
    ) -> ServiceResult<impl Encodable<ListDevicesResponse> + Send + use<'a>> {
        // Pre-check, then one decision per device: a role narrowed to
        // device categories (H6 slice 3) lists only its devices.
        require_connect(&ctx, Action::DeviceList, &DEVICE_PRE_CHECK)?;
        let invocation = ctx.extensions().get::<InvocationContext>();
        let devices = self
            .engine
            .devices()
            .list()
            .into_iter()
            .filter_map(|meta| {
                // One read, so `category` and `sensitive` agree.
                let class = self.engine.devices().class_of_meta(&meta);
                let listed = invocation.is_some_and(|i| {
                    authorize(
                        i,
                        Action::DeviceList,
                        &Resource::device(meta.id.as_str(), class),
                    )
                    .allow
                });
                listed.then(|| Device {
                    device_id: meta.id.clone(),
                    owner_instance: meta.owner_instance.clone(),
                    name: meta.info.name.clone(),
                    category: class.category().as_str().to_owned(),
                    sensitive: class
                        .sensitive()
                        .iter()
                        .map(|c| c.as_str().to_owned())
                        .collect(),
                    ..Default::default()
                })
            })
            .collect();
        Response::ok(ListDevicesResponse {
            devices,
            ..Default::default()
        })
    }

    async fn execute_command<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExecuteCommandRequest>,
    ) -> ServiceResult<impl Encodable<ExecuteCommandResponse> + Send + use<'a>> {
        // Pre-check before the request is copied, then H6:
        // `device.command` on the addressed device — the token's
        // per-device allowlist, role and deny list, shared with REST
        // and MCP — before the lookup so a refused token can't probe
        // ids.
        require_connect(&ctx, Action::DeviceCommand, &DEVICE_PRE_CHECK)?;
        let req = request.to_owned_message();
        let decision = require_connect(
            &ctx,
            Action::DeviceCommand,
            &self.engine.devices().resource(&req.device_id),
        )?;
        let invocation = ctx
            .extensions()
            .get::<crate::auth::InvocationContext>()
            .cloned()
            .ok_or_else(|| {
                rpc_err(
                    &ctx,
                    ConnectError::internal("connect handler ran without an invocation context"),
                )
            })?;

        // Resolve device → owning instance via the same
        // `get_owner` primitive the JSON side uses (single read-
        // lock + map lookup, mirrors `ServiceRegistry::get_owner`).
        // Unknown device *and* non-running owner both collapse to
        // NotFound so a probing caller can't distinguish the two
        // cases — same no-enumeration-leak property as the JSON
        // handler.
        let owner = self
            .engine
            .devices()
            .get_owner(&req.device_id)
            .ok_or_else(|| rpc_err(&ctx, ConnectError::not_found("device not found")))?;
        let handle = self
            .engine
            .instances()
            .get(&owner)
            .ok_or_else(|| rpc_err(&ctx, ConnectError::not_found("device not found")))?;

        // H6 slice 2: rate limit and `warn` row before a sensitive
        // command runs.
        self.engine
            .sensitive()
            .discharge_blocking(
                &invocation,
                Action::DeviceCommand,
                &req.device_id,
                &decision,
            )
            .await
            .map_err(|e| obligation_err(&ctx, &e))?;
        let gate = BytesGate::new(&invocation, &self.engine);

        // The supervisor handle mints `id` (H5).
        let cmd = Command {
            id: String::new(),
            capability: req.capability,
            action: req.action,
            args: req.args.into_iter().map(proto_key_value_to_wit).collect(),
        };
        // H5: a client `Connect-Timeout-Ms` / `grpc-timeout` earlier
        // than the invocation deadline bounds dispatch too, so a
        // command still queued when the client gives up is `timed_out`
        // and never runs.
        let invocation = match ctx.deadline() {
            Some(rpc) => {
                let rpc = tokio::time::Instant::from_std(rpc);
                let deadline = invocation.deadline().map_or(rpc, |d| d.min(rpc));
                invocation.with_deadline(Some(deadline))
            }
            None => invocation,
        };
        let report = handle
            .execute_command_admitted(
                invocation,
                req.device_id.clone(),
                cmd,
                decision.obligations.sensitive,
            )
            .await;
        // F4 + H5: every routed command is an RPC success carrying
        // its explicit outcome. Record the command id and outcome on
        // the slot so the middleware audits them next to the
        // authorization decision. Mirrors the JSON side's
        // `DomainOutcome` response-extension smuggle.
        record_domain_outcome(&ctx, &report);
        let blobs = gate.release_report(&req.device_id, &owner, &report);
        Response::ok(command_report_to_proto(report, blobs))
    }

    async fn get_device_state<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetDeviceStateRequest>,
    ) -> ServiceResult<impl Encodable<GetDeviceStateResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::DeviceRead, &DEVICE_PRE_CHECK)?;
        let device_id = request.to_owned_message().device_id;
        // Host-minted ids are short; don't copy a huge one under the
        // projection lock. The target check below decides for the
        // device (a role narrowed to categories, a deny list).
        if device_id.len() > MAX_DEVICE_ID_LEN {
            return Err(rpc_err(
                &ctx,
                ConnectError::invalid_argument("`device_id` is too long"),
            ));
        }
        require_connect(
            &ctx,
            Action::DeviceRead,
            &self.engine.devices().resource(&device_id),
        )?;
        let gate = ctx_bytes_gate(&ctx, &self.engine);
        let (epoch, revision, mut entries) = self
            .engine
            .device_state()
            .snapshot_device_with_revision(&device_id);
        // The device may have been re-registered since the check: the
        // snapshot answers to its current class.
        let current = self.engine.devices().resource(&device_id);
        let allowed = ctx
            .extensions()
            .get::<InvocationContext>()
            .is_some_and(|i| authorize(i, Action::DeviceRead, &current).allow);
        if !allowed {
            require_connect(&ctx, Action::DeviceRead, &current)?;
        }
        entries.sort_by(|a, b| a.capability.cmp(&b.capability));
        Response::ok(GetDeviceStateResponse {
            state: device_snapshot_to_proto(device_id, &entries, &epoch, revision, &gate).into(),
            ..Default::default()
        })
    }

    async fn list_device_state<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListDeviceStateRequest>,
    ) -> ServiceResult<impl Encodable<ListDeviceStateResponse> + Send + use<'a>> {
        use super::server::{
            DEFAULT_ALL_DEVICES_STATE_LIMIT, MAX_ALL_DEVICES_STATE_LIMIT,
            MAX_ALL_DEVICES_STATE_SCAN, MAX_STATE_PAGE_WIRE_BYTES,
        };
        require_connect(&ctx, Action::DeviceRead, &Resource::devices())?;
        let gate = ctx_bytes_gate(&ctx, &self.engine);
        let blobs = gate.general();
        let req = request.to_owned_message();
        let limit = match usize::try_from(req.limit).unwrap_or(usize::MAX) {
            0 => DEFAULT_ALL_DEVICES_STATE_LIMIT,
            n => n.min(MAX_ALL_DEVICES_STATE_LIMIT),
        };
        let store = self.engine.device_state();
        // Same pin protocol as REST: the cursor is verified before any
        // of its fields are trusted.
        let pinned = if req.cursor.is_empty() {
            None
        } else {
            match store.verify_cursor(&req.cursor) {
                Ok((_, revision, after)) => Some((revision, after)),
                Err(crate::state::CursorError::Bad) => {
                    return Err(rpc_err(
                        &ctx,
                        ConnectError::invalid_argument(
                            "invalid `cursor`: pass the previous page's `next_cursor` verbatim",
                        ),
                    ));
                }
                Err(crate::state::CursorError::EpochChanged) => {
                    return Err(rpc_err(
                        &ctx,
                        ConnectError::aborted(
                            "the cursor is from an earlier daemon process or store epoch; \
                             restart the resync without a cursor",
                        ),
                    ));
                }
            }
        };
        let page = store.snapshot_page_capped(
            pinned.as_ref().map(|(_, after)| after.as_str()),
            limit,
            MAX_STATE_PAGE_WIRE_BYTES,
            crate::state::PageSizing::Wire { blobs },
            MAX_ALL_DEVICES_STATE_SCAN,
            // Same as REST: a continuation page leaves out entries
            // newer than the pinned revision.
            |e| pinned.as_ref().is_none_or(|(r, _)| e.global_revision <= *r),
        );
        let revision = pinned.as_ref().map_or(page.revision, |(r, _)| *r);
        let devices: Vec<ProtoDeviceStateSnapshot> = page
            .devices
            .iter()
            .map(|caps| {
                let id = caps
                    .first()
                    .map_or_else(String::new, |c| c.device_id.clone());
                device_snapshot_to_proto(id, caps, &page.epoch, revision, &gate)
            })
            .collect();
        let next_cursor = page
            .resume_after
            .map_or_else(String::new, |after| store.issue_cursor(revision, &after));
        Response::ok(ListDeviceStateResponse {
            epoch: page.epoch,
            revision,
            devices,
            next_cursor,
            truncated: page.truncated,
            ..Default::default()
        })
    }

    async fn list_device_state_changes<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListDeviceStateChangesRequest>,
    ) -> ServiceResult<impl Encodable<ListDeviceStateChangesResponse> + Send + use<'a>> {
        use super::server::{
            DEFAULT_STATE_CHANGES_LIMIT, MAX_STATE_CHANGES_LIMIT, MAX_STATE_PAGE_WIRE_BYTES,
        };
        require_connect(&ctx, Action::DeviceRead, &Resource::devices())?;
        let gate = ctx_bytes_gate(&ctx, &self.engine);
        let blobs = gate.general();
        let req = request.to_owned_message();
        let limit = match usize::try_from(req.limit).unwrap_or(usize::MAX) {
            0 => DEFAULT_STATE_CHANGES_LIMIT,
            n => n.min(MAX_STATE_CHANGES_LIMIT),
        };
        let page = self.engine.device_state().deltas_since_capped(
            req.since_revision,
            limit,
            MAX_STATE_PAGE_WIRE_BYTES,
            crate::state::PageSizing::Wire { blobs },
        );
        Response::ok(ListDeviceStateChangesResponse {
            epoch: page.epoch,
            current_revision: page.current_revision,
            changes: page
                .entries
                .iter()
                .map(|e| device_state_to_proto(e, &gate))
                .collect(),
            reset_required: page.reset_required,
            truncated: page.truncated,
            ..Default::default()
        })
    }
}

/// F4 + H5 helper — stamps the [`HandlerOutcomeSlot`] with the
/// dispatched command's id and explicit outcome. The middleware writes
/// them into the audit ledger's command / execution columns *without*
/// touching the transport status or the authorization decision. See
/// [`super::auth::DomainOutcome`] for why authorization and execution
/// outcomes are kept as distinct audit fields.
/// Longest device id `GetDeviceState` looks up (host-minted ids are
/// 20 bytes).
const MAX_DEVICE_ID_LEN: usize = 256;

fn record_domain_outcome(ctx: &RequestContext, report: &CommandReport) {
    if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
        slot.set(HandlerOutcome {
            status: None,
            denied_scope: None,
            command: Some(super::auth::DomainOutcome::from_report(report)),
        });
    }
}

/// Convert an incoming proto [`ProtoValue`] to the WIT `value`
/// variant the plugin expects. Mirrors the JSON side's
/// `From<WireValue> for Value` — same six-way variant projection.
/// A missing / `None` inner `kind` (proto3 default for a message
/// with an unset `oneof`) maps to the empty JSON payload, which
/// the plugin can pattern-match if it accepts arbitrary shapes.
fn proto_key_value_to_wit(kv: ProtoKeyValue) -> KeyValue {
    let value = match kv.value.into_option().and_then(|v| v.kind) {
        Some(value::Kind::BoolVal(b)) => Value::BoolVal(b),
        Some(value::Kind::IntVal(i)) => Value::IntVal(i),
        Some(value::Kind::FloatVal(f)) => Value::FloatVal(f),
        Some(value::Kind::StringVal(s)) => Value::StringVal(s),
        Some(value::Kind::BytesVal(b)) => Value::BytesVal(b),
        Some(value::Kind::JsonVal(j)) => Value::JsonVal(j),
        None => Value::JsonVal(String::new()),
    };
    KeyValue { key: kv.key, value }
}

/// H2: one projected entry on the wire. `bytes_val` fields the
/// caller's [`BytesGate`] doesn't release are withheld (M7).
fn device_state_to_proto(
    state: &crate::state::DeviceState,
    gate: &BytesGate,
) -> ProtoDeviceStateEntry {
    let mut fields = state.fields.clone();
    if !gate.release_state(state) {
        crate::redact::withhold_bytes_in_kvs(&mut fields);
    }
    ProtoDeviceStateEntry {
        device_id: state.device_id.clone(),
        capability: state.capability.clone(),
        fields: fields
            .into_iter()
            .map(|kv| ProtoKeyValue {
                key: kv.key,
                value: wit_value_to_proto(kv.value).into(),
                ..Default::default()
            })
            .collect(),
        global_revision: state.global_revision,
        received_ms: state.received_ms,
        observed_ms: state.observed_ms,
        source_generation: state.source_generation,
        quality: match state.quality {
            crate::state::StateQuality::Fresh => ProtoStateQuality::Fresh,
            crate::state::StateQuality::Stale => ProtoStateQuality::Stale,
        }
        .into(),
        ..Default::default()
    }
}

/// H2: one device's entries (sorted by capability) as a snapshot.
fn device_snapshot_to_proto(
    device_id: String,
    entries: &[std::sync::Arc<crate::state::DeviceState>],
    epoch: &str,
    revision: u64,
    gate: &BytesGate,
) -> ProtoDeviceStateSnapshot {
    ProtoDeviceStateSnapshot {
        device_id,
        epoch: epoch.to_owned(),
        revision,
        capabilities: entries
            .iter()
            .map(|e| device_state_to_proto(e, gate))
            .collect(),
        ..Default::default()
    }
}

fn wit_value_to_proto(value: Value) -> ProtoValue {
    let kind = match value {
        Value::BoolVal(b) => value::Kind::BoolVal(b),
        Value::IntVal(i) => value::Kind::IntVal(i),
        Value::FloatVal(f) => value::Kind::FloatVal(f),
        Value::StringVal(s) => value::Kind::StringVal(s),
        Value::BytesVal(b) => value::Kind::BytesVal(b),
        Value::JsonVal(j) => value::Kind::JsonVal(j),
    };
    ProtoValue {
        kind: Some(kind),
        ..Default::default()
    }
}

/// M7: `blobs` is the caller's [`BytesGate`] answer for the device;
/// without it returned `bytes-val` state is withheld.
fn command_report_to_proto(mut report: CommandReport, blobs: bool) -> ExecuteCommandResponse {
    if !blobs {
        report.withhold_bytes();
    }
    let command_outcome = match &report.outcome {
        CommandOutcome::Accepted => ProtoCommandOutcome::Accepted,
        CommandOutcome::Completed { .. } => ProtoCommandOutcome::Completed,
        CommandOutcome::Rejected { .. } => ProtoCommandOutcome::Rejected,
        CommandOutcome::TimedOut { .. } => ProtoCommandOutcome::TimedOut,
        CommandOutcome::Unknown { .. } => ProtoCommandOutcome::Unknown,
    };
    let outcome = match report.outcome {
        CommandOutcome::Completed { state: None } => {
            execute_command_response::Outcome::Ok(Box::<execute_command_response::Ok>::default())
        }
        CommandOutcome::Completed { state: Some(kvs) } => {
            execute_command_response::Outcome::OkWithState(Box::new(
                execute_command_response::OkWithState {
                    state: kvs
                        .into_iter()
                        .map(|kv| ProtoKeyValue {
                            key: kv.key,
                            value: wit_value_to_proto(kv.value).into(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                },
            ))
        }
        CommandOutcome::Rejected { error } => {
            execute_command_response::Outcome::Err(Box::new(wit_error_to_proto(error)))
        }
        CommandOutcome::Accepted => execute_command_response::Outcome::Accepted(Box::default()),
        CommandOutcome::TimedOut { message } => execute_command_response::Outcome::TimedOut(
            Box::new(execute_command_response::TimedOut {
                message,
                ..Default::default()
            }),
        ),
        CommandOutcome::Unknown { message } => execute_command_response::Outcome::OutcomeUnknown(
            Box::new(execute_command_response::OutcomeUnknown {
                message,
                ..Default::default()
            }),
        ),
    };
    ExecuteCommandResponse {
        command_id: report.command_id,
        command_outcome: command_outcome.into(),
        outcome: Some(outcome),
        ..Default::default()
    }
}

fn wit_error_to_proto(err: WitError) -> ProtoCmdError {
    let kind = match err {
        WitError::NotFound(m) => execute_command_error::Kind::NotFound(m),
        WitError::PermissionDenied(m) => execute_command_error::Kind::PermissionDenied(m),
        WitError::InvalidArgument(m) => execute_command_error::Kind::InvalidArgument(m),
        WitError::Unavailable(m) => execute_command_error::Kind::Unavailable(m),
        WitError::Internal(m) => execute_command_error::Kind::Internal(m),
    };
    ProtoCmdError {
        kind: Some(kind),
        ..Default::default()
    }
}

struct OxidHomePlugins {
    engine: Engine,
}

impl oxidhome_proto::connect::oxidhome::v1::PluginsService for OxidHomePlugins {
    async fn list_plugins<'a>(
        &'a self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListPluginsRequest>,
    ) -> ServiceResult<impl Encodable<ListPluginsResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::PluginRead, &Resource::plugins())?;
        // Mirrors the JSON `list_plugins` aggregation: installed
        // rows first (with `installed = true` + `version`), then
        // running-but-not-installed rows from the dev argv path.
        let mut by_plugin: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for handle in self.engine.instances().list() {
            *by_plugin.entry(handle.plugin_id().to_string()).or_default() += 1;
        }
        let mut plugins: Vec<ProtoPlugin> = Vec::new();
        for installed in self.engine.installed_plugins().list() {
            let id = installed.plugin_id.to_string();
            let count = by_plugin.remove(&id).unwrap_or(0);
            plugins.push(ProtoPlugin {
                plugin_id: id,
                installed: true,
                version: Some(installed.version),
                instance_count: count,
                ..Default::default()
            });
        }
        for (plugin_id, instance_count) in by_plugin {
            plugins.push(ProtoPlugin {
                plugin_id,
                installed: false,
                version: None,
                instance_count,
                ..Default::default()
            });
        }
        plugins.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
        Response::ok(ListPluginsResponse {
            plugins,
            ..Default::default()
        })
    }

    async fn install_plugin<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, InstallPluginRequest>,
    ) -> ServiceResult<impl Encodable<InstallPluginResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::PluginInstall, &Resource::Host)?;
        let req = request.to_owned_message();
        let installed_registry = self.engine.installed_plugins();
        let source_dir = std::path::PathBuf::from(req.source_dir);
        let installed = tokio::task::spawn_blocking(move || {
            installed_registry.install(&source_dir)
        })
        .await
        .map_err(|err| {
            tracing::error!(target: "api.plugins", error = %err, "install spawn_blocking failed");
            rpc_err(&ctx, ConnectError::internal("install task join failed"))
        })?
        .map_err(|err| rpc_err(&ctx, install_error_to_connect(err)))?;
        Response::ok(InstallPluginResponse {
            plugin_id: installed.plugin_id.to_string(),
            version: installed.version,
            installed_path: installed.path.display().to_string(),
            ..Default::default()
        })
    }

    async fn start_plugin<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StartPluginRequest>,
    ) -> ServiceResult<impl Encodable<StartPluginResponse> + Send + use<'a>> {
        require_connect(
            &ctx,
            Action::InstanceStart,
            &Resource::pre_check(ResourceKind::Instance),
        )?;
        let req = request.to_owned_message();
        require_connect(
            &ctx,
            Action::InstanceStart,
            &Resource::instance(req.plugin_id.as_str(), req.instance_id.clone()),
        )?;
        // H2 round-2 F1: serialize against a concurrent uninstall
        // for the same plugin_id. Held for the full start-through-
        // reach-Running window so no uninstall can slip in between
        // the registry lookup below and the supervisor's registry
        // read at instantiate time. See F1 comment in
        // `server.rs::start_plugin_instance`.
        let lifecycle_lock = self.engine.plugin_lifecycle_lock(&req.plugin_id);
        let _guard = lifecycle_lock.lock().await;
        let installed = self
            .engine
            .installed_plugins()
            .get(&req.plugin_id)
            .ok_or_else(|| rpc_err(&ctx, ConnectError::not_found("plugin not installed")))?;
        let instance_id = req.instance_id.unwrap_or_else(|| req.plugin_id.clone());
        // Follow-up review H1: reject caller-supplied `instance_id`s
        // that aren't safe as FS segments before they reach the
        // blob store's path construction. Mirrors the JSON side's
        // check in `api::server::start_plugin_instance`.
        if !crate::runtime::is_operator_instance_id(&instance_id) {
            return Err(rpc_err(
                &ctx,
                ConnectError::invalid_argument(format!(
                    "instance_id {instance_id:?} is unsafe for use as a filesystem segment \
                     or uses the reserved `~`"
                )),
            ));
        }
        // `config_overrides_json` is optional; empty / absent
        // means "use manifest defaults."
        let overrides = match req.config_overrides_json.as_deref() {
            None | Some("") => None,
            Some(json) => match serde_json::from_str::<toml::Value>(json) {
                Ok(v) => Some(v),
                Err(err) => {
                    return Err(rpc_err(
                        &ctx,
                        ConnectError::invalid_argument(format!("config_overrides_json: {err}")),
                    ));
                }
            },
        };
        // H11 round-2 F1: `start_installed_instance` pins the
        // load-time identity to the `installation_uuid` observed
        // under the lifecycle lock so the loader refuses to fall
        // back to synthetic-identity + manifest-requested caps
        // if the registry row disappears between here and the
        // supervisor's re-read.
        let handle = self
            .engine
            .start_installed_instance(
                installed.path.clone(),
                &instance_id,
                overrides,
                std::sync::Arc::clone(&installed.installation_uuid),
            )
            .await
            .map_err(|err| {
                tracing::error!(target: "api.plugins", error = %err, "start_installed_instance failed");
                rpc_err(
                    &ctx,
                    ConnectError::internal(format!("start_installed_instance failed: {err}")),
                )
            })?;
        handle.wait_for_running().await.map_err(|err| {
            tracing::error!(target: "api.plugins", error = %err, "wait_for_running failed");
            rpc_err(
                &ctx,
                ConnectError::internal(format!("wait_for_running failed: {err}")),
            )
        })?;
        Response::ok(StartPluginResponse {
            plugin_id: req.plugin_id,
            instance_id,
            state: format!("{:?}", handle.state()),
            ..Default::default()
        })
    }

    async fn stop_plugin<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StopPluginRequest>,
    ) -> ServiceResult<impl Encodable<StopPluginResponse> + Send + use<'a>> {
        require_connect(
            &ctx,
            Action::InstanceStop,
            &Resource::pre_check(ResourceKind::Instance),
        )?;
        let req = request.to_owned_message();
        require_connect(
            &ctx,
            Action::InstanceStop,
            &Resource::instance(req.plugin_id.as_str(), req.instance_id.clone()),
        )?;
        // Same shape as the JSON handler: stop every match at once and
        // wait for each to be reaped (sandboxes included), bounded.
        let handles = self
            .engine
            .instances()
            .list()
            .into_iter()
            .filter(|handle| {
                handle.plugin_id() == req.plugin_id
                    && req
                        .instance_id
                        .as_ref()
                        .is_none_or(|want| handle.instance_id() == want)
            })
            .collect();
        let report = crate::runtime::stop_and_wait_reaped(handles, crate::STOP_WAIT_LIMIT).await;
        if !report.still_stopping.is_empty() {
            return Err(rpc_err(
                &ctx,
                ConnectError::deadline_exceeded(format!(
                    "instances still stopping after {} s (they finish in the background): \
                     {:?}; stopped: {:?}",
                    crate::STOP_WAIT_LIMIT.as_secs(),
                    report.still_stopping,
                    report.stopped,
                )),
            ));
        }
        Response::ok(StopPluginResponse {
            stopped_ids: report.stopped,
            ..Default::default()
        })
    }

    async fn uninstall_plugin<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UninstallPluginRequest>,
    ) -> ServiceResult<impl Encodable<UninstallPluginResponse> + Send + use<'a>> {
        require_connect(
            &ctx,
            Action::PluginUninstall,
            &Resource::pre_check(ResourceKind::Plugin),
        )?;
        let req = request.to_owned_message();
        require_connect(
            &ctx,
            Action::PluginUninstall,
            &Resource::plugin(req.plugin_id.as_str()),
        )?;
        // H2 round-2 F1 + H3 round-2 F1: hold the per-plugin_id
        // lifecycle lock across the running-instances check +
        // the compose uninstall, and MOVE the guard into the
        // `spawn_blocking` closure so a cancelled Connect
        // handler can't drop the guard while the detached
        // uninstall task is still running. See F1 comment in
        // `server.rs::uninstall_plugin` for the race that shape
        // closes.
        let lifecycle_lock = self.engine.plugin_lifecycle_lock(&req.plugin_id);
        let guard = lifecycle_lock.lock_owned().await;
        // Refuse if any instance of the plugin is running. Same
        // fail-closed shape the JSON handler enforces — operator
        // stops first. FAILED_PRECONDITION is the Connect-side
        // equivalent of the JSON 409 code.
        let running: Vec<String> = self
            .engine
            .instances()
            .list()
            .into_iter()
            .filter(|h| h.plugin_id() == req.plugin_id)
            .map(|h| h.instance_id().to_string())
            .collect();
        if !running.is_empty() {
            return Err(rpc_err(
                &ctx,
                ConnectError::failed_precondition(format!(
                    "plugin instances still running: {running:?}"
                )),
            ));
        }
        // H2: `Engine::uninstall_plugin` composes per-install
        // KV/blob purge + registry tombstone (in that order —
        // see H2 round-2 F2) so a reinstall of the same
        // `plugin_id` doesn't inherit the previous install's
        // state.
        let engine = self.engine.clone();
        let id_for_blocking = req.plugin_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            engine.uninstall_plugin(&id_for_blocking)
        })
        .await
        .map_err(|err| {
            tracing::error!(target: "api.plugins", error = %err, "uninstall spawn_blocking failed");
            rpc_err(&ctx, ConnectError::internal("uninstall task join failed"))
        })?;
        result.map_err(|err| rpc_err(&ctx, uninstall_error_to_connect(err)))?;
        Response::ok(UninstallPluginResponse {
            plugin_id: req.plugin_id,
            ..Default::default()
        })
    }
}

/// Map an install-side registry error to a Connect-spec error
/// code. Same shape mapping the JSON `PluginLifecycleError` uses
/// — kept in one place so the audit / client experience stays
/// consistent across surfaces.
fn install_error_to_connect(err: InstallError) -> ConnectError {
    match err {
        InstallError::NoPluginsRoot => {
            ConnectError::unavailable("plugin install requires a state-dir-backed engine")
        }
        InstallError::SourceMissing(path) => ConnectError::not_found(format!(
            "source dir missing or has no manifest.toml: {}",
            path.display()
        )),
        InstallError::InvalidSource { reason, .. } => {
            ConnectError::invalid_argument(format!("source_dir {reason}"))
        }
        InstallError::AlreadyInstalled { plugin_id } => {
            ConnectError::already_exists(format!("plugin {plugin_id} is already installed"))
        }
        InstallError::BadManifest { path, reason } => {
            ConnectError::invalid_argument(format!("manifest at {}: {reason}", path.display()))
        }
        InstallError::Io(err) => {
            tracing::error!(target: "api.plugins", error = %err, "install io error");
            ConnectError::internal("install io error")
        }
        InstallError::Persistence(err) => {
            tracing::error!(target: "api.plugins", error = %err, "install persistence error");
            ConnectError::internal("install persistence error")
        }
    }
}

fn uninstall_error_to_connect(err: UninstallError) -> ConnectError {
    match err {
        UninstallError::NoPluginsRoot => {
            ConnectError::unavailable("plugin uninstall requires a state-dir-backed engine")
        }
        UninstallError::NotInstalled(id) => {
            ConnectError::not_found(format!("plugin {id} is not installed"))
        }
        UninstallError::Io(err) => {
            tracing::error!(target: "api.plugins", error = %err, "uninstall io error");
            ConnectError::internal("uninstall io error")
        }
        UninstallError::Persistence(err) => {
            tracing::error!(target: "api.plugins", error = %err, "uninstall persistence error");
            ConnectError::internal("uninstall persistence error")
        }
    }
}

struct OxidHomeLogs {
    engine: Engine,
}

/// Default `limit` when the caller omits one. Matches
/// [`super::server::LOGS_QUERY_DEFAULT_LIMIT`](server) on the JSON
/// side — the two protocols return the same page size for the same
/// request shape.
const LOGS_QUERY_DEFAULT_LIMIT: u32 = 100;
/// Upper bound on a single query's `limit`. Same guardrail as the
/// JSON side (see `LOGS_QUERY_MAX_LIMIT` on the JSON handler).
const LOGS_QUERY_MAX_LIMIT: u32 = 1_000;

impl oxidhome_proto::connect::oxidhome::v1::LogsService for OxidHomeLogs {
    async fn query_logs<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, QueryLogsRequest>,
    ) -> ServiceResult<impl Encodable<QueryLogsResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::HostLogs, &Resource::Host)?;
        // `request` is a `ServiceRequest` view; its zero-copy field
        // accessors either return owned copies or `&str` slices, both
        // fine for a synchronous read.
        let req = request.to_owned_message();
        let limit = req
            .limit
            .unwrap_or(LOGS_QUERY_DEFAULT_LIMIT)
            .clamp(1, LOGS_QUERY_MAX_LIMIT);
        // `min_level` handling: `LOG_LEVEL_UNSPECIFIED` is the
        // proto3 default sentinel and means "no filter" (a client
        // that omits the field gets it back as Unspecified). A wire
        // value that doesn't map to any known variant is instead a
        // client bug — silently treating `Unknown(999)` as "no
        // filter" would broaden a client's intended query in a way
        // they can't observe. Reject those with `invalid_argument`.
        let min_level = match req.min_level {
            None | Some(oxidhome_proto::runtime::EnumValue::Known(ProtoLogLevel::Unspecified)) => {
                None
            }
            Some(oxidhome_proto::runtime::EnumValue::Known(known)) => {
                proto_log_level_to_host(known)
            }
            Some(oxidhome_proto::runtime::EnumValue::Unknown(v)) => {
                return Err(rpc_err(
                    &ctx,
                    ConnectError::invalid_argument(format!(
                        "min_level: unknown log-level value {v}"
                    )),
                ));
            }
        };
        let query = LogQuery {
            since_ms: req.since_ms,
            until_ms: req.until_ms,
            min_level,
            instance_id: req.instance_id,
            plugin_id: req.plugin_id,
            device_id: req.device_id,
            target: req.target,
            target_prefix: req.target_prefix,
            span_path_prefix: req.span_path_prefix,
        };
        let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
        let rows = self
            .engine
            .log_store()
            .query(&query, limit_usize)
            .map_err(|err| {
                tracing::error!(target: "api.logs", error = %err, "logs query failed");
                rpc_err(&ctx, ConnectError::internal("logs query failed"))
            })?;
        let logs = rows.into_iter().map(historical_to_proto).collect();
        Response::ok(QueryLogsResponse {
            logs,
            ..Default::default()
        })
    }
}

fn proto_log_level_to_host(level: ProtoLogLevel) -> Option<LogLevel> {
    match level {
        ProtoLogLevel::Trace => Some(LogLevel::Trace),
        ProtoLogLevel::Debug => Some(LogLevel::Debug),
        ProtoLogLevel::Info => Some(LogLevel::Info),
        ProtoLogLevel::Warn => Some(LogLevel::Warn),
        ProtoLogLevel::Error => Some(LogLevel::Error),
        // Proto3 default sentinel — treat as "no minimum" so a
        // client that omits `min_level` (proto3 default = 0) doesn't
        // accidentally filter to nothing.
        ProtoLogLevel::Unspecified => None,
    }
}

fn host_log_level_to_proto(level: LogLevel) -> ProtoLogLevel {
    match level {
        LogLevel::Trace => ProtoLogLevel::Trace,
        LogLevel::Debug => ProtoLogLevel::Debug,
        LogLevel::Info => ProtoLogLevel::Info,
        LogLevel::Warn => ProtoLogLevel::Warn,
        LogLevel::Error => ProtoLogLevel::Error,
    }
}

fn historical_to_proto(row: HistoricalLogEvent) -> ProtoLogEvent {
    ProtoLogEvent {
        id: row.id,
        ts_unix_ms: row.ts_unix_ms,
        level: host_log_level_to_proto(row.level).into(),
        instance_id: row.instance_id,
        plugin_id: row.plugin_id,
        device_id: row.device_id,
        target: row.target,
        span_path: row.span_path,
        message: row.message,
        fields: row
            .fields
            .into_iter()
            .map(|(key, value)| ProtoLogField {
                key,
                value: log_value_to_proto(value).into(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn log_value_to_proto(value: LogValue) -> ProtoLogValue {
    let inner = match value {
        LogValue::Bool(b) => log_value::Value::BoolVal(b),
        LogValue::Int(i) => log_value::Value::IntVal(i),
        LogValue::UInt(u) => log_value::Value::UintVal(u),
        LogValue::Float(f) => log_value::Value::FloatVal(f),
        LogValue::String(s) => log_value::Value::StringVal(s),
        LogValue::Debug(s) => log_value::Value::DebugVal(s),
    };
    ProtoLogValue {
        value: Some(inner),
        ..Default::default()
    }
}

// ── Events.TailEvents (server-streaming) ────────────────────────

struct OxidHomeEvents {
    engine: Engine,
}

impl oxidhome_proto::connect::oxidhome::v1::EventsService for OxidHomeEvents {
    async fn tail_events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, TailEventsRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<impl Encodable<TailEventsResponse> + Send + use<>>>
    {
        // Auth + scope check runs BEFORE the stream is established
        // — a denied caller sees a clean Connect error, no wasted
        // stream setup, and the audit row lands with the right
        // decision via the outcome slot. A cursor replays history,
        // so it also needs `events:read`.
        require_connect(&ctx, Action::EventSubscribe, &Resource::events())?;
        let after_id = request.to_owned_message().after_id;
        if after_id.is_some() {
            require_connect(&ctx, Action::EventRead, &Resource::events())?;
        }

        // Subscribe *before* returning the stream so the caller
        // doesn't miss an event that fires between `stream_ok`
        // returning and the future being polled for the first
        // time. H4: `EventTail` owns the history-to-live handoff
        // for `after_id` and the lag / cursor-expired notices; see
        // `crate::state::event_tail`.
        let tail = crate::state::EventTail::open(
            &self.engine.events(),
            self.engine.event_log(),
            after_id,
            "connect-tail",
        )
        .await
        .map_err(|err| {
            tracing::error!(target: "api.events", error = %err, "connect events tail open failed");
            rpc_err(&ctx, ConnectError::unavailable("event history unavailable"))
        })?;
        let resume_after_id = tail.resume_after_id();
        // The tail (and its `SubscriberToken`) lives in the unfold
        // state, so the bus slot is freed when the stream ends.
        // M7: live and replayed events alike withhold `bytes-val`
        // payloads unless the caller holds `blobs:read`.
        let gate = std::sync::Arc::new(ctx_bytes_gate(&ctx, &self.engine));
        let response_stream = futures_util::stream::unfold(Some(tail), move |tail| {
            let gate = std::sync::Arc::clone(&gate);
            async move {
                use crate::state::TailItem;
                let mut tail = tail?;
                let body = match tail.next().await {
                    Ok(Some(TailItem::Event(event))) => {
                        tail_events_response::Body::Event(Box::new(wit_event_to_proto(
                            std::sync::Arc::unwrap_or_clone(event),
                            &gate,
                        )))
                    }
                    Ok(Some(TailItem::Lagged {
                        skipped,
                        resume_after_id,
                    })) => tail_events_response::Body::Lagged(Box::new(ProtoLagged {
                        skipped,
                        resume_after_id,
                        ..Default::default()
                    })),
                    Ok(Some(TailItem::CursorExpired(expired))) => {
                        tail_events_response::Body::CursorExpired(Box::new(ProtoCursorExpired {
                            after_id: expired.after_id,
                            oldest_id: expired.oldest_id,
                            head_id: expired.head_id,
                            ..Default::default()
                        }))
                    }
                    // Bus gone (engine shutting down), or the
                    // stream already sent `CursorExpired`.
                    Ok(None) => return None,
                    Err(err) => {
                        tracing::error!(target: "api.events", error = %err, "connect events tail stopped");
                        return Some((
                            Err(ConnectError::unavailable("event history unavailable")),
                            None,
                        ));
                    }
                };
                Some((
                    Ok(TailEventsResponse {
                        body: Some(body),
                        ..Default::default()
                    }),
                    Some(tail),
                ))
            }
        });
        // H4: acknowledge an accepted cursor, so a client can tell a
        // resumed stream from a server that ignored `after_id`.
        let response = Response::stream(response_stream);
        Ok(match resume_after_id {
            Some(id) => response.with_header(super::server::RESUME_AFTER_ID_HEADER, id),
            None => response,
        })
    }
}

/// M7: `bytes-val` state-change fields the subscriber's [`BytesGate`]
/// doesn't release are withheld.
fn wit_event_to_proto(mut event: WitEvent, gate: &BytesGate) -> ProtoEvent {
    if !gate.release_event(&event) {
        crate::redact::withhold_bytes_in_event(&mut event.payload);
    }
    let payload = match event.payload {
        EventPayload::StateChanged(sc) => Some(proto_event::Payload::StateChanged(Box::new(
            ProtoStateChanged {
                capability: sc.capability,
                // Full state-change record — capability + the
                // partial-state fields. PR #75 review flagged the
                // earlier `capability`-only shape as silently
                // dropping the actual changed values; the WIT
                // record carries them and Connect clients have no
                // other RPC to fetch device state from.
                fields: sc.fields.into_iter().map(wit_key_value_to_proto).collect(),
                ..Default::default()
            },
        ))),
        EventPayload::Button(button) => {
            let (kind, delta) = match button {
                WitButtonEvent::Pressed => (ProtoButtonKind::Pressed, 0.0),
                WitButtonEvent::Released => (ProtoButtonKind::Released, 0.0),
                WitButtonEvent::SinglePress => (ProtoButtonKind::SinglePress, 0.0),
                WitButtonEvent::DoublePress => (ProtoButtonKind::DoublePress, 0.0),
                WitButtonEvent::LongPress => (ProtoButtonKind::LongPress, 0.0),
                WitButtonEvent::Rotated(d) => (ProtoButtonKind::Rotated, d),
            };
            Some(proto_event::Payload::Button(Box::new(ProtoButton {
                kind: kind.into(),
                delta,
                ..Default::default()
            })))
        }
        EventPayload::Inference(i) => {
            Some(proto_event::Payload::Inference(Box::new(ProtoInference {
                model: i.model,
                payload: i.payload,
                // WIT `unix-ms` is `u64`; proto field is `uint64`.
                // Direct assignment — the previous `cast_signed` on
                // an `int64` field wrapped large timestamps to
                // negative on the wire.
                frame_timestamp_ms: i.frame_timestamp,
                ..Default::default()
            })))
        }
        EventPayload::Custom(c) => Some(proto_event::Payload::Custom(Box::new(ProtoCustomEvent {
            topic: c.topic,
            payload: c.payload,
            ..Default::default()
        }))),
    };
    ProtoEvent {
        device_id: event.device,
        // Plugin-supplied timestamp; `uint64` on the proto matches
        // the WIT `unix-ms` type. Preserves values above `i64::MAX`
        // that the earlier `int64` encoding would have wrapped
        // negative.
        timestamp_ms: event.timestamp,
        // Host-populated origin (C2b). Set on publish by
        // `PluginState::publish_event` from the caller's manifest
        // and instance id, so a Connect subscriber can trust these
        // as the immutable event source.
        origin_plugin_id: event.origin_plugin_id,
        origin_instance_id: event.origin_instance_id,
        // H5 round-2: durable `event_log` row id stamped on the
        // WIT event at publish time. Proto3 `uint64` has no
        // "absent" state, so we send `0` for events published via
        // code paths that don't hit the durable log — matches the
        // proto3 default and the field's docstring.
        row_id: event.row_id.unwrap_or(0),
        payload,
        ..Default::default()
    }
}

/// Convert a WIT `key-value` (as used inside `StateChanged.fields`)
/// to the proto `KeyValue` message shared with `Devices.ExecuteCommand`.
/// Reuses the existing `wit_value_to_proto` variant projection.
fn wit_key_value_to_proto(kv: KeyValue) -> ProtoKeyValue {
    ProtoKeyValue {
        key: kv.key,
        value: wit_value_to_proto(kv.value).into(),
        ..Default::default()
    }
}

/// H6 slice 3: `TokensService`, mirroring `POST` / `GET /api/v1/tokens`.
/// Both RPCs need `token.manage`: the owner token only.
struct OxidHomeTokens {
    engine: Engine,
}

fn proto_token(s: super::token_admin::TokenSummary) -> ProtoToken {
    ProtoToken {
        token_id: s.token_id,
        label: s.label,
        owner: s.owner,
        revoked: s.revoked,
        roles: s.roles,
        scopes: s.scopes,
        sensitive: s.sensitive,
        deny: s.deny,
        created_ms: s.created_ms,
        last_used_ms: s.last_used_ms,
        policy_valid: s.policy_valid,
        ..Default::default()
    }
}

impl oxidhome_proto::connect::oxidhome::v1::TokensService for OxidHomeTokens {
    async fn create_token<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateTokenRequest>,
    ) -> ServiceResult<impl Encodable<CreateTokenResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::TokenManage, &Resource::Host)?;
        let req = request.to_owned_message();
        let none_if_empty = |v: Vec<String>| (!v.is_empty()).then_some(v);
        let mint = super::token_admin::MintRequest {
            label: req.label,
            roles: req.roles,
            scopes: req.scopes,
            sensitive: req.sensitive,
            deny: req
                .deny
                .into_iter()
                .map(|d| super::token_admin::DenySpec {
                    actions: d.actions,
                    category: none_if_empty(d.category),
                    devices: none_if_empty(d.devices),
                })
                .collect(),
        };
        let tokens = self.engine.auth_tokens();
        let audit = self.engine.audit_log();
        let call_id = ctx
            .extensions()
            .get::<InvocationContext>()
            .map(|i| i.call_id().to_owned());
        let minted = tokio::task::spawn_blocking(move || {
            super::token_admin::mint(&tokens, &audit, "connect", "api", call_id.as_deref(), &mint)
        })
        .await
        .map_err(|e| rpc_err(&ctx, ConnectError::internal(e.to_string())))?
        .map_err(|err| match err {
            super::token_admin::MintError::Invalid(msg) => {
                rpc_err(&ctx, ConnectError::invalid_argument(msg))
            }
            super::token_admin::MintError::Store(msg) => {
                tracing::error!(target: "api.tokens", error = %msg, "minting a token failed");
                rpc_err(&ctx, ConnectError::internal("storing the token failed"))
            }
        })?;
        Response::ok(CreateTokenResponse {
            secret: minted.secret,
            token: proto_token(minted.summary).into(),
            ..Default::default()
        })
    }

    async fn list_tokens<'a>(
        &'a self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListTokensRequest>,
    ) -> ServiceResult<impl Encodable<ListTokensResponse> + Send + use<'a>> {
        require_connect(&ctx, Action::TokenManage, &Resource::Host)?;
        let tokens = self.engine.auth_tokens();
        let list = tokio::task::spawn_blocking(move || super::token_admin::summaries(&tokens))
            .await
            .map_err(|e| rpc_err(&ctx, ConnectError::internal(e.to_string())))?
            .map_err(|err| {
                tracing::error!(target: "api.tokens", error = %err, "listing tokens failed");
                rpc_err(&ctx, ConnectError::internal("listing tokens failed"))
            })?;
        Response::ok(ListTokensResponse {
            tokens: list.into_iter().map(proto_token).collect(),
            ..Default::default()
        })
    }
}

/// Build the Connect router with every `OxidHome` service registered.
/// The caller mounts it on the axum app via
/// [`connectrpc::Router::into_axum_service`].
#[must_use]
pub fn router(engine: Engine) -> ConnectRouter {
    let router = ConnectRouter::new();
    let router = Arc::new(OxidHomeHealth {
        engine: engine.clone(),
    })
    .register(router);
    let router = Arc::new(OxidHomeInstances {
        engine: engine.clone(),
    })
    .register(router);
    let router = Arc::new(OxidHomeDevices {
        engine: engine.clone(),
    })
    .register(router);
    let router = Arc::new(OxidHomePlugins {
        engine: engine.clone(),
    })
    .register(router);
    let router = Arc::new(OxidHomeTokens {
        engine: engine.clone(),
    })
    .register(router);
    let router = Arc::new(OxidHomeLogs {
        engine: engine.clone(),
    })
    .register(router);
    Arc::new(OxidHomeEvents { engine }).register(router)
}

// ── Auth + audit middleware ─────────────────────────────────────

/// Connect paths that don't require a bearer token. Mirrors the
/// `PUBLIC_PATHS` constant on the JSON side; `Health.Check` lives
/// here so anonymous liveness probes (k8s, load balancers, the
/// upcoming CLI's startup ping) can hit it without credentials.
///
/// Adding a new entry is a deliberate decision — every other
/// Connect path defaults to "requires a verified token." A future
/// authorization check happens inside each handler via
/// [`require_connect`]; the middleware here only
/// enforces authentication and emits the audit row.
///
/// Linear scan is fine at one entry. If the list grows past a
/// handful (anonymous discovery endpoint, `/readyz` mirror, …),
/// swap to a `HashSet<&'static str>` or compile-time `match`.
const ANONYMOUS_CONNECT_PATHS: &[&str] = &["/oxidhome.v1.HealthService/Check"];

/// Build the Connect surface as an `axum::Router` wrapped with the
/// Connect-side auth + audit middleware. Returned by the API
/// [`super::server::build_router`] as the `fallback_service` so any
/// path not matched by the JSON `/api/v1/*` routes lands here.
///
/// **Why a separate middleware from the JSON `require_token`:**
/// Connect requires a specific error wire format
/// (`{"code": "unauthenticated", "message": "..."}` JSON body, HTTP
/// 401) — the JSON middleware's plain-text 401 + `WWW-Authenticate:
/// Bearer` is correct for the JSON surface but would confuse a
/// Connect client. This middleware shares the **same audit emit
/// helper** and the **same `TokenStore::verify`** as the JSON path
/// so a token issued via the CLI works on both surfaces and the
/// C3 audit ledger sees uniform rows regardless of which
/// transport served the request.
pub fn axum_service(engine: Engine) -> axum::Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
        audit_log: engine.audit_log(),
        // H6: `DevicesService.ExecuteCommand` applies the
        // `device.send_command` per-device allowlist through
        // `crate::auth::authorize`, same as REST and MCP. Every other
        // constraint key is still refused here.
        enforced_constraints: &[crate::auth::DEVICE_COMMAND_ENFORCED],
        transport: crate::auth::Transport::Connect,
    };
    let inner = router(engine).into_axum_service();
    axum::Router::new()
        .fallback_service(inner)
        .layer(from_fn_with_state(auth_state, connect_auth_middleware))
}

/// axum `from_fn_with_state` middleware. Wraps every Connect call:
///
/// 1. Allow-listed path → pass through, no audit (anonymous probe).
/// 2. Otherwise extract bearer → verify → stamp the
///    [`Actor`](crate::auth::Actor) and its [`InvocationContext`] into
///    `req.extensions_mut()` (the Connect dispatcher forwards
///    `req.extensions()` into [`RequestContext::extensions()`], so
///    a handler reads the context via
///    `ctx.extensions().get::<InvocationContext>()`).
/// 3. After the handler runs, finalize one audit-ledger row via
///    [`crate::api::auth::finalize_audit`] — same shape and same
///    ledger the JSON middleware uses.
//
// Reads linearly top-to-bottom (allow-list → extract → verify →
// intent → run → finalize). Splitting for `too_many_lines` would
// hurt more than it'd help.
#[allow(clippy::too_many_lines)]
async fn connect_auth_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> AxumResponse {
    // Allow-list check FIRST, against a borrowed `&str` — anonymous
    // probes (Health.Check, the hot path for orchestrators) shouldn't
    // pay for a `String` allocation they'll never use.
    if ANONYMOUS_CONNECT_PATHS
        .iter()
        .any(|p| *p == req.uri().path())
    {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    let Some(bearer) = extract_bearer(&req).map(str::to_owned) else {
        // No `Authorization` header — record an anonymous probe (no
        // fingerprint, nothing was presented) then respond with the
        // Connect-native "unauthenticated" shape.
        record_anonymous_probe(&state.audit_log, &method, &path, 401, None).await;
        return connect_error_response(
            ConnectError::unauthenticated("unauthenticated"),
            req.headers(),
        );
    };
    let outcome_slot = HandlerOutcomeSlot::default();
    let (token_id, actor_kind, invocation) = match state.tokens.verify(&bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            // Round-3 P1 on PR #147: same reasoning as
            // [`crate::api::auth::require_token`] — a
            // constraint-bearing token has no meaning on
            // Connect-RPC, so refusing it here prevents the
            // MCP-only restriction from being bypassed via an
            // equivalent Connect RPC.
            if let Some(refusal) =
                super::auth::first_constraint_refusal(&actor, state.enforced_constraints)
            {
                let sentinel = refusal.audit_sentinel();
                tracing::warn!(
                    target: "api.auth",
                    token_id = %actor.id(),
                    refusal = %refusal.as_display(),
                    "token carries a constraint Connect-RPC does not enforce; refusing (14.4a)",
                );
                // Round-4 P2 / round-6 P2 on PR #147:
                // authenticated denial with the specific
                // offending key (and field, on a field-level
                // refusal) in `required_scope`.
                let entry = crate::state::AuditEntry {
                    id: 0,
                    intent_ms: 0,
                    finalized_ms: None,
                    token_id: actor.id().to_string(),
                    actor_kind: actor.kind().as_str().to_string(),
                    method: method.clone(),
                    path: path.clone(),
                    status: axum::http::StatusCode::FORBIDDEN.as_u16(),
                    decision: "deny".into(),
                    required_scope: Some(sentinel),
                    execution_outcome: None,
                    domain_error: None,
                    credential_fp: None,
                    call_id: None,
                    invocation: None,
                    command_id: None,
                    command_outcome: None,

                    level: None,
                };
                super::auth::record_authenticated_denial(&state.audit_log, None, entry).await;
                return connect_error_response(
                    ConnectError::permission_denied(
                        "token carries a constraint this transport does not enforce",
                    ),
                    req.headers(),
                );
            }
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            // H6: one invocation per authenticated RPC; see the JSON
            // middleware.
            let invocation = crate::auth::InvocationContext::external(
                crate::auth::Principal::token(actor.kind(), &actor, state.transport),
            );
            req.extensions_mut().insert(invocation.clone());
            req.extensions_mut().insert(actor);
            // Give the handler a way to smuggle back its outcome
            // (scope-deny name + a synthesized HTTP status for the
            // audit classifier). See the `HandlerOutcomeSlot`
            // docstring for why we can't just read the response
            // status on gRPC / gRPC-Web transports.
            req.extensions_mut().insert(outcome_slot.clone());
            (token_id, actor_kind, invocation)
        }
        Err(TokenError::Malformed | TokenError::Unknown | TokenError::Revoked) => {
            let fp = crate::state::credential_fingerprint(&bearer);
            record_anonymous_probe(&state.audit_log, &method, &path, 401, Some(fp)).await;
            return connect_error_response(
                ConnectError::unauthenticated("unauthenticated"),
                req.headers(),
            );
        }
        Err(TokenError::Sqlite(err)) => {
            tracing::error!(target: "api.auth", error = %err, "token verify failed");
            return connect_error_response(ConnectError::internal("internal error"), req.headers());
        }
    };

    // (F1) Pre-audit intent — same shape as the JSON middleware.
    // Fail-closed on ledger error.
    let intent = crate::state::AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.clone(),
        actor_kind: actor_kind.clone(),
        method: method.clone(),
        path: path.clone(),
        status: 0,
        decision: "pending".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
        call_id: Some(invocation.call_id().to_owned()),
        invocation: Some(invocation.audit_json()),
        command_id: None,
        command_outcome: None,

        level: None,
    };
    let audit_id = {
        let al = Arc::clone(&state.audit_log);
        match tokio::task::spawn_blocking(move || al.record_intent(&intent)).await {
            Ok(Ok(id)) => id,
            Ok(Err(err)) => {
                eprintln!(
                    "oxidhome audit_log: connect record_intent failed; refusing request: {err}",
                );
                tracing::error!(
                    target: "api.audit",
                    error = %err,
                    token_id = %token_id,
                    method = %method,
                    path = %path,
                    "audit-ledger intent write failed — refusing request",
                );
                return connect_error_response(
                    ConnectError::internal("internal error"),
                    req.headers(),
                );
            }
            Err(join_err) => {
                eprintln!(
                    "oxidhome audit_log: connect record_intent join failed; refusing request: {join_err}",
                );
                return connect_error_response(
                    ConnectError::internal("internal error"),
                    req.headers(),
                );
            }
        }
    };

    let response = next.run(req).await;
    // `HandlerOutcomeSlot` is `Arc`-shared with the request; `take()`
    // on our clone reads whatever the handler wrote before the
    // request was consumed. `None` on happy paths → we fall back to
    // `response.status()`, which is correct for Connect unary and
    // for `Ok` outcomes across every transport.
    //
    // **Transport-independent decision classification.** gRPC and
    // gRPC-Web render RPC errors as HTTP 200 with `grpc-status` in
    // trailers/body, so `response.status()` alone would mis-audit
    // handler-returned errors as `decision=allow` on those
    // transports. `HandlerOutcomeSlot` sidesteps that by having the
    // handler record its outcome at return time (see [`rpc_err`]
    // and [`require_connect`]) — the middleware then trusts
    // that record over the wire-shaped HTTP status.
    //
    // Residual gap: framing / dispatch errors that reject BEFORE
    // any handler runs (bad `Content-Type`, unknown method,
    // malformed proto) leave the slot empty. On gRPC / gRPC-Web
    // those still audit as `allow`. Rare in practice (client
    // protocol misuse); a peek-at-trailers pass is deferred until
    // a real gap appears.
    let outcome = outcome_slot.take();
    // Authorization / transport status. `outcome.status` is `Some`
    // for handler-returned errors (`rpc_err` / scope-deny), and
    // `None` for successful RPCs — including the F4 case where
    // `record_domain_outcome` stamped a `domain_error` but no
    // synthesized status. Falling back to `response.status()` on
    // `None` handles both a normal 200 and any handler that didn't
    // touch the slot.
    let audit_status = outcome
        .as_ref()
        .and_then(|o| o.status)
        .unwrap_or_else(|| response.status());
    let denied_scope = outcome.as_ref().and_then(|o| o.denied_scope);
    // F4 + H5: a dispatched command's id and outcome. Lives on the
    // same slot but is orthogonal to the transport status — see
    // `super::auth::DomainOutcome` for the split. The JSON side
    // smuggles the same information through a `DomainOutcome`
    // response extension.
    let domain_outcome = outcome.and_then(|o| o.command);
    finalize_audit(
        &state.audit_log,
        audit_id,
        &token_id,
        &method,
        &path,
        audit_status,
        denied_scope,
        domain_outcome,
    )
    .await;
    response
}

/// Build an HTTP response from a [`ConnectError`], **matching the
/// caller's transport.**
///
/// The Connect spec pairs each transport with a distinct error
/// shape:
/// - Connect unary (`application/proto`, `application/json`, or
///   absent) → non-200 HTTP status + JSON body `{"code","message"}`.
/// - Connect streaming (`application/connect+{proto,json}`) →
///   HTTP 200 with the error inside an `EndStreamResponse` envelope.
/// - gRPC / gRPC-Web (`application/grpc*`) → HTTP 200 with
///   `grpc-status` + `grpc-message` trailers (HTTP/2 trailers for
///   gRPC, encoded in the body for gRPC-Web).
///
/// `ConnectError::into_http_response(request_headers)` (available
/// since connectrpc 0.7) inspects the inbound `Content-Type` via
/// `Protocol::detect` and picks the right shape. Hand-rolling the
/// JSON 401 shape (as this used to) worked for a curl-JSON client
/// but caused a transport/protocol failure at gRPC / gRPC-Web
/// clients that expect status-in-trailers — flagged in the
/// PR #50 review.
fn connect_error_response(err: ConnectError, req_headers: &HeaderMap) -> AxumResponse {
    let (parts, body) = err.into_http_response(req_headers).into_parts();
    AxumResponse::from_parts(parts, Body::new(body))
}

#[cfg(test)]
mod command_report_tests {
    use super::*;

    /// M7 + H5: Connect withholds a `completed` report's `bytes-val`
    /// state from a caller without `blobs:read`.
    #[test]
    fn command_report_withholds_bytes_without_blobs_read() {
        let report = || CommandReport {
            command_id: "cmd-00000000000000000000000000000001".into(),
            outcome: CommandOutcome::Completed {
                state: Some(vec![KeyValue {
                    key: "frame".into(),
                    value: Value::BytesVal(vec![1, 2, 3]),
                }]),
            },
        };
        let state_value = |resp: ExecuteCommandResponse| match resp.outcome {
            Some(execute_command_response::Outcome::OkWithState(s)) => {
                s.state[0].value.clone().into_option().expect("value").kind
            }
            other => panic!("unexpected outcome {other:?}"),
        };
        let narrow = state_value(command_report_to_proto(report(), false));
        let full = state_value(command_report_to_proto(report(), true));
        assert_eq!(full, Some(value::Kind::BytesVal(vec![1, 2, 3])));
        assert_ne!(narrow, full);
    }
}
