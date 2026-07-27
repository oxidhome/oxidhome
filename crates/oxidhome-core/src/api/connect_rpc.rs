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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response as AxumResponse;
use connectrpc::{
    ConnectError, Encodable, RequestContext, Response, Router as ConnectRouter, ServiceRequest,
    ServiceResult,
};
use oxidhome_proto::connect::oxidhome::v1::HealthServiceExt;
use oxidhome_proto::proto::oxidhome::v1::{CheckRequest, CheckResponse};

use crate::Engine;
use crate::state::TokenError;

use super::auth::{AuthState, actor_from_record, emit_audit, extract_bearer};

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

/// Build the Connect router with every `OxidHome` service registered.
/// The caller mounts it on the axum app via
/// [`connectrpc::Router::into_axum_service`].
///
/// `_engine` is unused today — `Health.Check` is anonymous and stateless
/// — but the parameter is in place so the next slice's
/// `Instances.List` / `Devices.List` / `Plugins.Install` services can
/// reach the engine without churning this signature on every PR.
#[must_use]
pub fn router(_engine: Engine) -> ConnectRouter {
    Arc::new(OxidHomeHealth).register(ConnectRouter::new())
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
    // 15-c onward will smuggle a Connect-side `DeniedScope` back via
    // response extensions (mirroring the JSON pattern) so the audit
    // can record which scope tripped. For now there are no scoped
    // Connect endpoints, so `required_scope` is always `None`.
    emit_audit(
        &token_id,
        &actor_kind,
        &method,
        &path,
        response.status(),
        None,
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
