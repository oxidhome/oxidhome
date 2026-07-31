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
//! uses, stamps an [`Actor`] into `req.extensions_mut()` (forwarded
//! into [`RequestContext::extensions()`] by the Connect dispatcher),
//! and records one row per authenticated request in the C3 audit
//! ledger via [`crate::api::auth::finalize_audit`]. The
//! `Health.Check` path is on the anonymous allow-list so liveness
//! probes still work without credentials.
//!
//! Per-RPC scope enforcement happens inside each handler via
//! [`require_scope_connect`], mirroring the JSON handler-side
//! `require_scope` pattern. Handlers record their outcome (the
//! denied scope on `permission_denied`, or the synthesized HTTP
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
    PluginsServiceExt,
};
use oxidhome_proto::proto::oxidhome::v1::{
    Button as ProtoButton, ButtonKind as ProtoButtonKind, CheckRequest, CheckResponse,
    CustomEvent as ProtoCustomEvent, Device, Event as ProtoEvent,
    ExecuteCommandError as ProtoCmdError, ExecuteCommandRequest, ExecuteCommandResponse,
    Inference as ProtoInference, InstallPluginRequest, InstallPluginResponse, Instance,
    KeyValue as ProtoKeyValue, Lagged as ProtoLagged, ListDevicesRequest, ListDevicesResponse,
    ListInstancesRequest, ListInstancesResponse, ListPluginsRequest, ListPluginsResponse,
    LogEvent as ProtoLogEvent, LogField as ProtoLogField, LogLevel as ProtoLogLevel,
    LogValue as ProtoLogValue, Plugin as ProtoPlugin, QueryLogsRequest, QueryLogsResponse,
    StartPluginRequest, StartPluginResponse, StateChanged as ProtoStateChanged, StopPluginRequest,
    StopPluginResponse, TailEventsRequest, TailEventsResponse, UninstallPluginRequest,
    UninstallPluginResponse, Value as ProtoValue, event as proto_event, execute_command_error,
    execute_command_response, log_value, tail_events_response, value,
};

use crate::Engine;
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent as WitButtonEvent;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event as WitEvent, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};
use crate::state::{
    HistoricalLogEvent, InstallError, LogLevel, LogQuery, LogValue, TokenError, UninstallError,
};

use super::auth::{
    AuthState, actor_from_record, extract_bearer, finalize_audit, record_anonymous_probe,
};
use super::scopes::{
    DEVICES_COMMAND, DEVICES_LIST, EVENTS_TAIL, INSTANCES_LIST, LOGS_READ, PLUGINS_INSTALL,
    PLUGINS_LIST, PLUGINS_START, PLUGINS_STOP, PLUGINS_UNINSTALL, Scope, ScopeDenied,
    require_scope,
};

/// `HealthService` implementation. Anonymous — no engine state is
/// needed today; carries no fields. A future `Health.PluginRollup`
/// RPC would take an `Engine` here.
struct OxidHomeHealth;

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
        Response::ok(CheckResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        })
    }
}

// ── Scope-check + outcome-record helpers ────────────────────────

/// What a Connect handler recorded as it returned. Serves the
/// middleware's audit classifier — see [`connect_auth_middleware`].
#[derive(Debug, Clone, Copy)]
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
    /// 200 / gRPC OK) but the plugin returned `CommandResult::Err`.
    /// See the module doc + [`super::auth::DomainOutcome`] for why
    /// authorization and execution outcomes must not share the
    /// same audit field.
    status: Option<axum::http::StatusCode>,
    /// The missing scope, if this outcome was a
    /// `PermissionDenied` recorded by [`require_scope_connect`].
    /// Middleware populates the `required_scope` audit field from
    /// this — mirrors the JSON side's `DeniedScope` smuggle.
    denied_scope: Option<Scope>,
    /// The plugin's WIT error kind for a `CommandResult::Err` on
    /// an authorized RPC. Populated by [`record_domain_outcome`];
    /// the middleware forwards it to the audit ledger's
    /// `domain_error` column (F4).
    domain_error: Option<&'static str>,
}

/// Request-scoped smuggling channel from Connect handlers to the
/// [`connect_auth_middleware`]. The middleware installs an empty
/// slot on `req.extensions_mut()` before running the handler;
/// handlers write to it on the error path via
/// [`require_scope_connect`] (for scope denials) or [`rpc_err`]
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

/// Wrap a [`ConnectError`] on the error-return site so the audit
/// row picks up the outcome. Idiomatic use — at every `return Err(...)`
/// inside a Connect handler that isn't a scope denial:
///
/// ```ignore
/// return Err(rpc_err(&ctx, ConnectError::not_found("device x")));
/// ```
///
/// [`require_scope_connect`] does the equivalent for scope denials
/// via the same slot; no double-record and no ambiguity.
#[must_use]
fn rpc_err(ctx: &RequestContext, err: ConnectError) -> ConnectError {
    if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
        slot.set(HandlerOutcome {
            status: Some(err.http_status()),
            denied_scope: None,
            domain_error: None,
        });
    }
    err
}

/// Handler-side scope check for Connect RPCs. Mirrors the JSON
/// [`require_scope`] but returns a [`ConnectError::permission_denied`]
/// instead of a `ScopeDenied` axum response, and records the
/// missing scope on the request's [`HandlerOutcomeSlot`] so the
/// middleware populates `required_scope` on the audit row (same
/// field shape as the JSON `DeniedScope` extension smuggle).
///
/// The `Actor` is read out of `ctx.extensions()`. Its presence is a
/// contract with the middleware (which stamps it during auth);
/// missing it is an internal bug rather than a client error →
/// `ConnectError::internal`, not `Unauthenticated`.
fn require_scope_connect(ctx: &RequestContext, required: Scope) -> Result<(), ConnectError> {
    // If the middleware failed to stamp `Actor` into extensions,
    // wrap the internal error through `rpc_err` too — otherwise a
    // gRPC / gRPC-Web caller of a scoped RPC in a broken pipeline
    // would audit as `allow` on an HTTP 200 wire response. Defense
    // in depth for the same class of bug PR #74 review flagged on
    // `query_logs`.
    let actor = ctx.extensions().get::<Actor>().ok_or_else(|| {
        rpc_err(
            ctx,
            ConnectError::internal("connect handler ran without an Actor extension"),
        )
    })?;
    if let Err(ScopeDenied { required }) = require_scope(actor, required) {
        if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
            slot.set(HandlerOutcome {
                status: Some(axum::http::StatusCode::FORBIDDEN),
                denied_scope: Some(Scope::new(required)),
                domain_error: None,
            });
        }
        return Err(ConnectError::permission_denied(format!(
            "scope {required} required"
        )));
    }
    Ok(())
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
        require_scope_connect(&ctx, INSTANCES_LIST)?;
        let instances = self
            .engine
            .instances()
            .list()
            .into_iter()
            .map(|handle| Instance {
                instance_id: handle.instance_id().to_string(),
                plugin_id: handle.plugin_id().to_string(),
                state: format!("{:?}", handle.state()),
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
        require_scope_connect(&ctx, DEVICES_LIST)?;
        let devices = self
            .engine
            .devices()
            .list()
            .into_iter()
            .map(|meta| Device {
                device_id: meta.id.clone(),
                owner_instance: meta.owner_instance.clone(),
                name: meta.info.name.clone(),
                ..Default::default()
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
        require_scope_connect(&ctx, DEVICES_COMMAND)?;
        let req = request.to_owned_message();

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

        let cmd = Command {
            capability: req.capability,
            action: req.action,
            args: req.args.into_iter().map(proto_key_value_to_wit).collect(),
        };
        let result = handle
            .execute_command(req.device_id.clone(), cmd)
            .await
            .map_err(|err| {
                tracing::error!(target: "api.devices", error = %err, "device command dispatch failed");
                rpc_err(&ctx, ConnectError::internal("device command dispatch failed"))
            })?;
        // F4: the RPC succeeded (wire response is HTTP 200 / gRPC
        // OK / Connect Ok) but a `CommandResult::Err` payload is a
        // domain failure. Record it on the outcome slot so the
        // middleware audits with a synthesized status instead of a
        // spurious `allow`. Mirrors the JSON side's `DomainOutcome`
        // response-extension smuggle.
        if let CommandResult::Err(ref err) = result {
            record_domain_outcome(&ctx, err);
        }
        Response::ok(command_result_to_proto(result))
    }
}

/// F4 helper — stamps the [`HandlerOutcomeSlot`] with the *domain*
/// error kind for a WIT failure carried inside an otherwise-
/// successful RPC response. The middleware reads
/// `domain_error` off the slot and writes it into the audit ledger's
/// `execution_outcome` / `domain_error` columns — *without* touching
/// the transport status or the authorization decision. See
/// [`super::auth::DomainOutcome`] for why authorization and
/// execution outcomes are kept as distinct audit fields.
fn record_domain_outcome(ctx: &RequestContext, err: &WitError) {
    if let Some(slot) = ctx.extensions().get::<HandlerOutcomeSlot>() {
        slot.set(HandlerOutcome {
            status: None,
            denied_scope: None,
            domain_error: Some(super::auth::wit_error_kind(err)),
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

fn command_result_to_proto(result: CommandResult) -> ExecuteCommandResponse {
    let outcome = match result {
        CommandResult::Ok => {
            execute_command_response::Outcome::Ok(Box::<execute_command_response::Ok>::default())
        }
        CommandResult::OkWithState(kvs) => execute_command_response::Outcome::OkWithState(
            Box::new(execute_command_response::OkWithState {
                state: kvs
                    .into_iter()
                    .map(|kv| ProtoKeyValue {
                        key: kv.key,
                        value: wit_value_to_proto(kv.value).into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
        ),
        CommandResult::Err(err) => {
            execute_command_response::Outcome::Err(Box::new(wit_error_to_proto(err)))
        }
    };
    ExecuteCommandResponse {
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
        require_scope_connect(&ctx, PLUGINS_LIST)?;
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
        require_scope_connect(&ctx, PLUGINS_INSTALL)?;
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
        require_scope_connect(&ctx, PLUGINS_START)?;
        let req = request.to_owned_message();
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
        if !crate::state::is_safe_instance_id(&instance_id) {
            return Err(rpc_err(
                &ctx,
                ConnectError::invalid_argument(format!(
                    "instance_id {instance_id:?} is unsafe for use as a filesystem segment"
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
        let handle = self
            .engine
            .start_instance(installed.path.clone(), &instance_id, overrides)
            .await
            .map_err(|err| {
                tracing::error!(target: "api.plugins", error = %err, "start_instance failed");
                rpc_err(
                    &ctx,
                    ConnectError::internal(format!("start_instance failed: {err}")),
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
        require_scope_connect(&ctx, PLUGINS_STOP)?;
        let req = request.to_owned_message();
        let mut stopped_ids = Vec::new();
        let registry = self.engine.instances();
        for handle in registry.list() {
            if handle.plugin_id() != req.plugin_id {
                continue;
            }
            if let Some(want) = &req.instance_id
                && handle.instance_id() != want
            {
                continue;
            }
            let id = handle.instance_id().to_string();
            if let Err(err) = handle.stop().await {
                tracing::warn!(
                    instance_id = %id,
                    error = %err,
                    "stop instance failed; continuing with siblings",
                );
                continue;
            }
            let _ = handle.wait_terminal().await;
            wait_for_registry_clear(&registry, &id).await;
            stopped_ids.push(id);
        }
        Response::ok(StopPluginResponse {
            stopped_ids,
            ..Default::default()
        })
    }

    async fn uninstall_plugin<'a>(
        &'a self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UninstallPluginRequest>,
    ) -> ServiceResult<impl Encodable<UninstallPluginResponse> + Send + use<'a>> {
        require_scope_connect(&ctx, PLUGINS_UNINSTALL)?;
        let req = request.to_owned_message();
        // H2 round-2 F1: hold the per-plugin_id lifecycle lock
        // across the running-instances check + the compose
        // uninstall. Mirrors `server.rs::uninstall_plugin`'s
        // JSON path. Without it, a concurrent start could
        // register a fresh supervisor between the check and the
        // tombstone.
        let lifecycle_lock = self.engine.plugin_lifecycle_lock(&req.plugin_id);
        let _guard = lifecycle_lock.lock().await;
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
        let result =
            tokio::task::spawn_blocking(move || engine.uninstall_plugin(&id_for_blocking))
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

/// Bounded poll for the instance registry to clear after a
/// supervisor reaches terminal — copied from the JSON side for the
/// same reason (the reaper task lags `wait_terminal`; a follow-up
/// uninstall would see the ghost). See the JSON `server.rs` for
/// the full rationale.
async fn wait_for_registry_clear(registry: &crate::InstanceRegistry, instance_id: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while registry.get(instance_id).is_some() {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                instance_id = %instance_id,
                "instance registry didn't clear after 5s — reaper task lagging?",
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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
        require_scope_connect(&ctx, LOGS_READ)?;
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
        _request: ServiceRequest<'_, TailEventsRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<impl Encodable<TailEventsResponse> + Send + use<>>>
    {
        // Auth + scope check runs BEFORE the stream is established
        // — a denied caller sees a clean Connect error, no wasted
        // stream setup, and the audit row lands with the right
        // decision via the outcome slot.
        require_scope_connect(&ctx, EVENTS_TAIL)?;

        // Subscribe *before* returning the stream so the caller
        // doesn't miss an event that fires between `stream_ok`
        // returning and the future being polled for the first
        // time.
        //
        // C2e: per-subscriber mpsc queue with SUBSCRIBER_CAPACITY
        // slots. A slow gRPC / Connect client whose queue fills
        // drops events *for itself only* (the bus emits a
        // per-subscriber warn log). The wire protocol no longer
        // needs a Lagged body variant because there's no shared
        // ring for other subscribers to be evicted from — but the
        // variant stays in the proto for backwards compat.
        let subscription = self.engine.events().subscribe_labeled(
            crate::host_impl::plugin::oxidhome::plugin::events::EventFilter {
                device: None,
                topic: None,
            },
            "connect-tail",
        );
        // Keep the whole `EventSubscription` (not just its
        // receiver) alive in the unfold state, so its
        // `SubscriberToken` drops when the stream ends and the
        // subscription slot on the bus is freed.
        //
        // Follow-up review H4 round-2 F1: the mpsc now delivers
        // `Event { event, skipped_before }` in one slot. When
        // `skipped_before > 0` we yield the `Lagged` wire frame
        // first, then buffer the event for the next iteration —
        // clients still see the pre-C2e "Lagged then Event"
        // ordering on the wire without the two-slot mpsc pressure
        // that starved fresh events under a tight consumer.
        let response_stream = futures_util::stream::unfold(
            (subscription, None::<std::sync::Arc<WitEvent>>),
            |(mut subscription, buffered_event)| async move {
                use crate::state::SubscriberMessage;
                if let Some(event) = buffered_event {
                    let body = tail_events_response::Body::Event(Box::new(wit_event_to_proto(
                        std::sync::Arc::unwrap_or_clone(event),
                    )));
                    return Some((
                        Ok(TailEventsResponse {
                            body: Some(body),
                            ..Default::default()
                        }),
                        (subscription, None),
                    ));
                }
                match subscription.receiver.recv().await {
                    Some(SubscriberMessage::Event {
                        event,
                        skipped_before: 0,
                    }) => {
                        let body = tail_events_response::Body::Event(Box::new(wit_event_to_proto(
                            std::sync::Arc::unwrap_or_clone(event),
                        )));
                        Some((
                            Ok(TailEventsResponse {
                                body: Some(body),
                                ..Default::default()
                            }),
                            (subscription, None),
                        ))
                    }
                    Some(SubscriberMessage::Event {
                        event,
                        skipped_before,
                    }) => {
                        // Yield the Lagged wire frame now; hold
                        // the event for the next tick.
                        let body = tail_events_response::Body::Lagged(Box::new(ProtoLagged {
                            skipped: skipped_before,
                            ..Default::default()
                        }));
                        Some((
                            Ok(TailEventsResponse {
                                body: Some(body),
                                ..Default::default()
                            }),
                            (subscription, Some(event)),
                        ))
                    }
                    // Channel closed — publisher gone (engine
                    // shutting down). End the stream cleanly.
                    None => None,
                }
            },
        );
        Response::stream_ok(response_stream)
    }
}

fn wit_event_to_proto(event: WitEvent) -> ProtoEvent {
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

/// Build the Connect router with every `OxidHome` service registered.
/// The caller mounts it on the axum app via
/// [`connectrpc::Router::into_axum_service`].
#[must_use]
pub fn router(engine: Engine) -> ConnectRouter {
    let router = ConnectRouter::new();
    let router = Arc::new(OxidHomeHealth).register(router);
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
/// scope check happens inside each handler via
/// [`super::scopes::require_scope`]; the middleware here only
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
    };
    let inner = router(engine).into_axum_service();
    axum::Router::new()
        .fallback_service(inner)
        .layer(from_fn_with_state(auth_state, connect_auth_middleware))
}

/// axum `from_fn_with_state` middleware. Wraps every Connect call:
///
/// 1. Allow-listed path → pass through, no audit (anonymous probe).
/// 2. Otherwise extract bearer → verify → stamp [`Actor`] into
///    `req.extensions_mut()` (the Connect dispatcher forwards
///    `req.extensions()` into [`RequestContext::extensions()`], so
///    a future scoped handler reads it via
///    `ctx.extensions().get::<Actor>()`).
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
    let (token_id, actor_kind) = match state.tokens.verify(&bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            req.extensions_mut().insert(actor);
            // Give the handler a way to smuggle back its outcome
            // (scope-deny name + a synthesized HTTP status for the
            // audit classifier). See the `HandlerOutcomeSlot`
            // docstring for why we can't just read the response
            // status on gRPC / gRPC-Web transports.
            req.extensions_mut().insert(outcome_slot.clone());
            (token_id, actor_kind)
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
    // and [`require_scope_connect`]) — the middleware then trusts
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
        .and_then(|o| o.status)
        .unwrap_or_else(|| response.status());
    let denied_scope = outcome.and_then(|o| o.denied_scope).map(Scope::name);
    // F4: execution outcome (`CommandResult::Err` kind). Lives on
    // the same slot but is orthogonal to the transport status —
    // see `super::auth::DomainOutcome` for the split. The JSON
    // side smuggles the same information through a
    // `DomainOutcome` response extension.
    let domain_outcome = outcome
        .and_then(|o| o.domain_error)
        .map(|domain_error| super::auth::DomainOutcome { domain_error });
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
