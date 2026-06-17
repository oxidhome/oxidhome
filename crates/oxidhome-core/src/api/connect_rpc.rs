//! Connect RPC handler wiring.
//!
//! Builds a [`connectrpc::Router`] populated with `OxidHome`'s Connect
//! services and exposes it as an axum-compatible `tower::Service`
//! via [`connectrpc::Router::into_axum_service`]. The existing JSON
//! `/api/v1/*` axum router mounts this service as a `fallback_service`
//! so both protocols share one listener:
//!
//! - JSON paths (`/api/v1/health`, …) continue to land on the
//!   handlers in [`super::server`].
//! - Connect paths (`POST /oxidhome.v1.HealthService/Check` etc.) fall
//!   through to the Connect router.
//!
//! The split is invisible to a JSON client and the Connect surface
//! reuses the same axum middleware (auth, audit) once a Connect
//! endpoint requires authentication — the only Connect endpoint
//! today is `Health.Check`, which is anonymous, so it lands
//! *outside* the auth middleware (same as the JSON
//! `/api/v1/health`).

use std::sync::Arc;

use connectrpc::{
    Encodable, RequestContext, Response, Router as ConnectRouter, ServiceRequest, ServiceResult,
};
use oxidhome_proto::connect::oxidhome::v1::HealthServiceExt;
use oxidhome_proto::proto::oxidhome::v1::{CheckRequest, CheckResponse};

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
        // Same shape as the JSON `/api/v1/health` handler. The
        // version comes from `oxidhome-core`'s `Cargo.toml` so the
        // two endpoints can't drift on a workspace bump.
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
#[must_use]
pub fn router() -> ConnectRouter {
    Arc::new(OxidHomeHealth).register(ConnectRouter::new())
}
