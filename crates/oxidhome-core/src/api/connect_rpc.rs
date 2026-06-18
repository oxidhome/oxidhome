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

use connectrpc::{
    Encodable, RequestContext, Response, Router as ConnectRouter, ServiceRequest, ServiceResult,
};
use oxidhome_proto::connect::oxidhome::v1::HealthServiceExt;
use oxidhome_proto::proto::oxidhome::v1::{CheckRequest, CheckResponse};

use crate::Engine;

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
