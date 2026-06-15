//! Axum server + router.
//!
//! [`serve`] takes an [`Engine`] and an [`ApiConfig`], builds the
//! router, binds the listener, and runs forever. Integration tests
//! call [`build_router`] directly to drive routes via `tower::Service`
//! without binding a TCP port.

use std::net::SocketAddr;

use axum::{
    Extension, Json, Router, extract::State, http::StatusCode, middleware::from_fn_with_state,
    routing::get,
};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::Engine;
use crate::auth::Actor;

use super::auth::{AuthState, require_token};

/// Listener configuration. Defaults to `127.0.0.1:0` (random
/// loopback port — what tests use). Daemon callers set `bind` to
/// a concrete address from the host config.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind: SocketAddr,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }
}

/// Build the API router. Public for integration tests; the
/// `serve(...)` entry point that production callers use lives below.
pub fn build_router(engine: Engine) -> Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
    };
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/instances", get(list_instances))
        .layer(from_fn_with_state(auth_state.clone(), require_token))
        .with_state(ApiState { engine })
}

/// Run the API server until the future is dropped.
///
/// Returns the bound [`SocketAddr`] once the listener is up; the
/// future keeps running until the caller drops it. The daemon's
/// `main.rs` will hold this future inside a `tokio::select!` against
/// a shutdown signal in a follow-up PR; for this slice the test
/// harness drives it via `tokio::spawn` + a oneshot abort.
///
/// # Errors
///
/// - `TcpListener::bind` failure (port in use, permission denied).
/// - `axum::serve` errors (rare; mostly accept-loop failures).
pub async fn serve(engine: Engine, config: ApiConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    let actual = listener.local_addr()?;
    tracing::info!(addr = %actual, "oxidhome API listening");
    axum::serve(listener, build_router(engine))
        .await
        .map_err(anyhow::Error::from)
}

/// Router state — the live [`Engine`] every authenticated handler
/// reaches its `engine.devices()` / `instances()` / etc. through.
/// Clone is cheap (Engine is `Arc`-backed internally).
#[derive(Clone)]
struct ApiState {
    engine: Engine,
}

// ── Handlers ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    version: &'static str,
}

/// Anonymous liveness probe. Lives outside [`PUBLIC_PATHS`] only
/// nominally — the route is wired before the middleware via the
/// path-match in `require_token`.
async fn health() -> (StatusCode, Json<HealthBody>) {
    (
        StatusCode::OK,
        Json(HealthBody {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

#[derive(Serialize)]
struct InstancesBody {
    instances: Vec<InstanceSummary>,
}

#[derive(Serialize)]
struct InstanceSummary {
    instance_id: String,
    /// `Debug` repr of the current [`InstanceState`](crate::InstanceState).
    /// The richer shape (plus `plugin_id`, `state_changed_at`, etc.)
    /// lands in 12-API-b once `InstanceHandle` grows the matching
    /// accessors — keeping this skeleton dependency-free.
    state: String,
}

/// Authenticated `GET /api/v1/instances`. Returns every supervised
/// instance under the engine with its current lifecycle state. The
/// scope-policy enforcement layer (12-API-b) will gate this on a
/// `instances:list` scope; this slice authenticates only.
async fn list_instances(
    Extension(_actor): Extension<Actor>,
    State(state): State<ApiState>,
) -> Json<InstancesBody> {
    let mut instances = Vec::new();
    for handle in state.engine.instances().list() {
        instances.push(InstanceSummary {
            instance_id: handle.instance_id().to_string(),
            state: format!("{:?}", handle.state()),
        });
    }
    Json(InstancesBody { instances })
}
