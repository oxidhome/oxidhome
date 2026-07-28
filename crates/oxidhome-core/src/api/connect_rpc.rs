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
//! **Auth status (load-bearing for the migration):** axum's
//! [`Router::fallback_service`] is registered *after* the
//! `require_token` `.layer(...)` and is therefore **not** wrapped
//! by it. Every Connect path is currently served **unauthenticated
//! and unaudited.** That's correct today — `Health.Check` is an
//! anonymous liveness probe by design — but it is a strict
//! prerequisite for migrating any of the existing scoped JSON
//! endpoints (`instances:list`, `devices:command`, `plugins:*`)
//! onto the Connect surface: doing so without first wiring a
//! Connect-side auth + scope + audit interceptor would expose
//! those endpoints unauthenticated. The `connectrpc` runtime
//! supports tower-style interceptors for exactly this; that
//! interceptor (with `Health.Check` allow-listed) lands as the
//! first slice of the next phase, before any authenticated
//! service joins this router.

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
    DevicesServiceExt, HealthServiceExt, InstancesServiceExt, LogsServiceExt, PluginsServiceExt,
};
use oxidhome_proto::proto::oxidhome::v1::{
    CheckRequest, CheckResponse, Device, Instance, ListDevicesRequest, ListDevicesResponse,
    ListInstancesRequest, ListInstancesResponse, ListPluginsRequest, ListPluginsResponse,
    LogEvent as ProtoLogEvent, LogField as ProtoLogField, LogLevel as ProtoLogLevel,
    LogValue as ProtoLogValue, Plugin as ProtoPlugin, QueryLogsRequest, QueryLogsResponse,
    log_value,
};

use crate::Engine;
use crate::auth::Actor;
use crate::state::{HistoricalLogEvent, LogLevel, LogQuery, LogValue, TokenError};

use super::auth::{AuthState, actor_from_record, emit_audit, extract_bearer};
use super::scopes::{
    DEVICES_LIST, INSTANCES_LIST, LOGS_READ, PLUGINS_LIST, Scope, ScopeDenied, require_scope,
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

// ── Scope-check helper ──────────────────────────────────────────

/// Request-scoped smuggling channel for the scope name a handler
/// denied on. The middleware inserts an `Arc<Mutex<Option<Scope>>>`
/// into `req.extensions_mut()` before running the handler; the
/// handler's `require_scope_connect` call writes the failing scope
/// name to it; the middleware reads it back after the handler
/// returns to populate the `required_scope` field on the audit row.
///
/// Same purpose as the JSON side's `DeniedScope` response-extension
/// smuggle, but Connect responses are constructed by the connectrpc
/// dispatcher (not the handler), so the request-extension +
/// interior-mutability shape is what actually reaches the middleware
/// on both success and failure paths.
#[derive(Clone, Default)]
struct DeniedScopeSlot(Arc<Mutex<Option<Scope>>>);

impl DeniedScopeSlot {
    fn take(&self) -> Option<Scope> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn set(&self, scope: Scope) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(scope);
    }
}

/// Handler-side scope check for Connect RPCs. Mirrors the JSON
/// [`require_scope`] but returns a [`ConnectError::permission_denied`]
/// instead of a `ScopeDenied` axum response, and records the
/// missing scope on the request's [`DeniedScopeSlot`] so the
/// middleware can put it on the audit row (same field shape as
/// the JSON `DeniedScope` extension smuggle).
///
/// The `Actor` is read out of `ctx.extensions()`. Its presence is a
/// contract with the middleware (which stamps it during auth);
/// missing it is an internal bug rather than a client error →
/// `ConnectError::internal`, not `Unauthenticated`.
fn require_scope_connect(ctx: &RequestContext, required: Scope) -> Result<(), ConnectError> {
    let actor = ctx
        .extensions()
        .get::<Actor>()
        .ok_or_else(|| ConnectError::internal("connect handler ran without an Actor extension"))?;
    if let Err(ScopeDenied { required }) = require_scope(actor, required) {
        if let Some(slot) = ctx.extensions().get::<DeniedScopeSlot>() {
            slot.set(Scope::new(required));
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
        let query = LogQuery {
            since_ms: req.since_ms,
            until_ms: req.until_ms,
            min_level: req
                .min_level
                .and_then(|ev| ev.as_known())
                .and_then(proto_log_level_to_host),
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
                ConnectError::internal("logs query failed")
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
    Arc::new(OxidHomeLogs { engine }).register(router)
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
/// audit-row shape stays uniform (`api.audit` tracing target, same
/// fields).
pub fn axum_service(engine: Engine) -> axum::Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
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
/// 3. After the handler runs, emit one `api.audit` event with the
///    same field shape the JSON middleware uses.
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

    let Some(bearer) = extract_bearer(&req) else {
        // Collapse missing / malformed / unknown / revoked into one
        // opaque message — matches the JSON `require_token`'s "can't
        // probe shape, validity, or revocation" stance from
        // 12-API-a so a Connect client can't tell the four cases
        // apart either.
        return connect_error_response(
            ConnectError::unauthenticated("unauthenticated"),
            req.headers(),
        );
    };
    let denied_scope_slot = DeniedScopeSlot::default();
    let (token_id, actor_kind, method) = match state.tokens.verify(bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            // Snapshot the strings we'll need post-handler for the
            // audit row *before* moving `actor` onto the request
            // extension — same pattern as `require_token`.
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            let method = req.method().to_string();
            req.extensions_mut().insert(actor);
            // Give the handler a way to smuggle back the failing
            // scope name if `require_scope_connect` denies — mirrors
            // the JSON side's `DeniedScope` response-extension trick.
            req.extensions_mut().insert(denied_scope_slot.clone());
            (token_id, actor_kind, method)
        }
        Err(TokenError::Malformed | TokenError::Unknown | TokenError::Revoked) => {
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

    let response = next.run(req).await;
    // `DeniedScopeSlot` is `Arc`-shared with what the request now
    // owned; `take()` on our clone reads whatever the handler wrote
    // before the request was consumed. `None` on happy paths → the
    // audit row's `required_scope` field stays empty (same shape as
    // the JSON side's allow rows).
    let denied_scope = denied_scope_slot.take().map(Scope::name);
    emit_audit(
        &token_id,
        &actor_kind,
        &method,
        &path,
        response.status(),
        denied_scope,
    );
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
