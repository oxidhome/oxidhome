//! Axum server + router.
//!
//! [`serve`] takes an [`Engine`] and an [`ApiConfig`], builds the
//! router, binds the listener, and runs forever. Integration tests
//! call [`build_router`] directly to drive routes via `tower::Service`
//! without binding a TCP port.

use std::net::SocketAddr;
use std::sync::Arc;

use std::collections::HashMap;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State, WebSocketUpgrade, ws::WebSocket},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::Engine;
use crate::auth::{Action, InvocationContext, Resource};
use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent;
use crate::host_impl::plugin::oxidhome::plugin::devices::Command;
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};
use crate::runtime::{CommandOutcome, CommandReport};
use crate::state::{
    AuditQuery, EventLogError, EventQuery, HistoricalEvent, HistoricalLogEvent, InstallError,
    LogLevel, LogQuery, LogStore, LogValue, TopicMatch, UninstallError,
};

use super::auth::{AuthState, require_token};
use super::scopes::{ScopeDenied, can_read_blobs, require};
use super::ui_ticket;

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
///
/// The router serves **two protocols on one listener**:
///
/// - JSON `/api/v1/*` — every existing handler.
/// - Connect-RPC `/oxidhome.v1.{Service}/{Method}` — mounted as a
///   `fallback_service` so any path not matched by the JSON routes
///   above falls through to the Connect dispatcher (this is where
///   `HealthService.Check` and the rest of the migrating surface
///   live). See `super::connect_rpc` for the registered services.
pub fn build_router(engine: Engine) -> Router {
    let auth_state = AuthState {
        tokens: engine.auth_tokens(),
        audit_log: engine.audit_log(),
        // H6: `POST /api/v1/devices/{id}/command` applies the
        // `device.send_command` per-device allowlist through the
        // shared `crate::auth::authorize` decision, same as Connect
        // and MCP. Every other constraint key is still refused here.
        // See [`AuthState::enforced_constraints`] docs.
        enforced_constraints: &[crate::auth::DEVICE_COMMAND_ENFORCED],
        transport: crate::auth::Transport::Rest,
    };
    let connect_service = super::connect_rpc::axum_service(engine.clone());
    // The authenticated cluster — every JSON handler except the
    // anonymous `/readyz` probe wears the `require_token` layer.
    let authenticated: Router<ApiState> = Router::new()
        .route("/api/v1/instances", get(list_instances))
        .route("/api/v1/devices", get(list_devices))
        .route(
            "/api/v1/devices/state/changes",
            get(query_device_state_changes),
        )
        .route("/api/v1/devices/state", get(get_all_device_state))
        .route("/api/v1/devices/{device_id}/state", get(get_device_state))
        .route("/api/v1/devices/{device_id}/command", post(send_command))
        .route("/api/v1/plugins", get(list_plugins).post(install_plugin))
        .route(
            "/api/v1/plugins/{plugin_id}",
            axum::routing::delete(uninstall_plugin),
        )
        .route(
            "/api/v1/plugins/{plugin_id}/start",
            post(start_plugin_instance),
        )
        .route(
            "/api/v1/plugins/{plugin_id}/stop",
            post(stop_plugin_instances),
        )
        // Phase 13 slice 2: schema-driven UI. Returns the
        // installed manifest's `config` schema (Phase 4)
        // and `[ui]` section (Phase 13 slice 1) so the
        // shell can render config forms and load declared
        // UI assets without a custom panel per plugin.
        // Gated on `plugins:list` — same read-only role
        // that lists installed plugins can see their
        // schemas.
        .route("/api/v1/plugins/{plugin_id}/schema", get(get_plugin_schema))
        // Phase 13 slice 3: dashboard CRUD. Layout bytes
        // are opaque to the host; the shell owns the
        // serialization contract.
        .route(
            "/api/v1/dashboards",
            get(list_dashboards).post(create_dashboard),
        )
        .route(
            "/api/v1/dashboards/{id}",
            get(get_dashboard)
                .put(update_dashboard)
                .delete(delete_dashboard),
        )
        .route("/api/v1/events/tail", get(tail_events))
        .route("/api/v1/events", get(query_events))
        .route("/api/v1/logs", get(query_logs))
        .route("/api/v1/audit", get(query_audit))
        .route("/api/v1/config", get(get_config))
        // C6: bearer-gated JSON endpoint that mints a
        // short-lived HMAC ticket and returns the wrapper
        // URL for the dashboard to hand off as an iframe
        // `src`. `/ui` itself sits on the ticket-gated
        // router below — browsers can't attach the parent's
        // `Authorization` header to a subresource nav or a
        // top-level document nav, so requiring bearer on
        // the wrapper would 401 every legitimate browser
        // flow. Gated on `plugins:ui`.
        .route(
            "/api/v1/plugins/{plugin_id}/ui-session",
            post(post_plugin_ui_session),
        )
        .layer(from_fn_with_state(auth_state.clone(), require_token));

    // `/readyz` mounts **outside** the authenticated router (PR-#83
    // review, F2). The pre-fix shape short-circuited a
    // `PUBLIC_PATHS` path-string comparison inside the auth
    // middleware, which also matched POST/PUT/DELETE on the same
    // path — invisible today because axum returns 405 for
    // unregistered methods, but a future handler on that path
    // would silently become anonymous. Physical separation via
    // router mounting means only the GET registered here is
    // publicly reachable; any other method returns 405, and any
    // route added to `authenticated` above requires auth by
    // construction.
    let public: Router<ApiState> = Router::new().route("/api/v1/readyz", get(readyz));

    // C6: `/ui` and `/ui/frame` mount on their own router
    // with **no bearer layer** — browsers can't attach the
    // parent page's `Authorization` header to iframe
    // subresource navigations OR top-level document
    // navigations, so both authenticate via the HMAC
    // ticket in `?tk=…` (verified inside each handler).
    // Physical separation from `authenticated` means an
    // accidental route add on this router can't inherit
    // bearer-gated scopes, and ticket verification is the
    // only auth check that can grant access to plugin UI
    // content. `POST /ui-session` above (bearer-gated)
    // is the only path that mints these tickets.
    let ticket_gated: Router<ApiState> = Router::new()
        .route("/api/v1/plugins/{plugin_id}/ui", get(get_plugin_ui))
        .route(
            "/api/v1/plugins/{plugin_id}/ui/frame",
            get(get_plugin_ui_frame),
        );

    // Phase 14.1 — mount the MCP streamable-HTTP endpoint on the
    // same listener as REST/Connect. `rmcp`'s
    // `StreamableHttpService` is a `tower::Service` nested at
    // [`super::mcp::MCP_ENDPOINT`]; auth (14.4) will wrap the
    // nested router in our bearer layer once the token-scope
    // policy shape is stable.
    let mcp = super::mcp::mount_routes(&engine);

    public
        .merge(authenticated)
        .merge(ticket_gated)
        .fallback_service(connect_service)
        .with_state(ApiState { engine })
        .merge(mcp)
}

/// `GET /api/v1/config` — the daemon's effective configuration, the
/// same redacted body as the MCP `oxidhome://config` resource. Gated on
/// `status:read`: operational metadata next to the status surface, no
/// secrets.
async fn get_config(
    Extension(ctx): Extension<InvocationContext>,
) -> Result<Json<serde_json::Value>, ScopeDenied> {
    require(&ctx, Action::HostStatus, &Resource::Host)?;
    Ok(Json(super::mcp::config_json()))
}

/// `GET /api/v1/readyz` — anonymous JSON readiness probe. Same body
/// shape as the Connect `HealthService.Check` RPC
/// (`{"status": "ok", "version": "<crate-version>"}`) so an
/// orchestrator that doesn't speak Connect (systemd's
/// `ExecStartPost`, docker's `HEALTHCHECK`, k8s's `httpGet`
/// probe) can assert the daemon is ready with a plain HTTP GET.
///
/// **Readiness contract** (PR-#83 review, F1). This does more than
/// echo `200 OK` — it consults the shared `SQLite` handle via
/// [`Engine::db_ping`] before responding. Every persistent sub-
/// store (audit ledger, token store, KV, blob index, event log,
/// log store) hangs off that connection, so a failed ping means
/// the daemon can't serve authenticated requests — including the
/// fail-closed audit path — and the probe returns `503 Service
/// Unavailable` with `{"status": "not_ready"}`. An orchestrator
/// pointed at this endpoint pulls the daemon out of load-balancer
/// rotation on DB failure instead of routing traffic to a shell.
///
/// H3: `event_log` reports the durable event mirror as `"ok"` or
/// `"degraded"`. A degraded mirror keeps the probe at 200 — live
/// device control and event delivery still work, only history is
/// missing rows — so an orchestrator doesn't restart a daemon whose
/// disk is full. Details are on the authenticated MCP
/// `oxidhome://status` resource.
///
/// H2: `device_state` reports the durable device-state projection the
/// same way: `"degraded"` while its flushes fail (live state is
/// unaffected; a crash would lose the unflushed changes), still 200.
async fn readyz(State(state): State<ApiState>) -> Response {
    let device_state = if state.engine.device_state().flush_health().degraded {
        "degraded"
    } else {
        "ok"
    };
    let event_log = if state.engine.event_log().health().degraded {
        "degraded"
    } else {
        "ok"
    };
    // H3: the ping waits on the shared connection mutex, which a hung
    // write (the case the event-log mirror's deadline exists for) can
    // hold indefinitely. Ping off the async workers, bound the wait,
    // and cap outstanding pings — a timed-out ping keeps its slot
    // until its blocking thread returns — so anonymous probes against
    // a hung database can't park tokio workers or fill the blocking
    // pool. An unresponsive database reads as not ready.
    let ping = match READYZ_PING_SLOTS.try_acquire() {
        Ok(permit) => {
            let engine = state.engine.clone();
            let ping = tokio::time::timeout(
                READYZ_PING_TIMEOUT,
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    engine.db_ping()
                }),
            )
            .await;
            match ping {
                Ok(Ok(result)) => result.map_err(|e| e.to_string()),
                Ok(Err(join)) => Err(format!("ping task failed: {join}")),
                Err(_) => Err(format!(
                    "no answer within {}ms",
                    READYZ_PING_TIMEOUT.as_millis()
                )),
            }
        }
        Err(_) => Err("earlier pings are still waiting on the database".to_owned()),
    };
    match ping {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadyzBody {
                status: "ok",
                version: env!("CARGO_PKG_VERSION"),
                event_log,
                device_state,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(target: "api.readyz", error = %err, "db ping failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyzBody {
                    status: "not_ready",
                    version: env!("CARGO_PKG_VERSION"),
                    event_log,
                    device_state,
                }),
            )
                .into_response()
        }
    }
}

/// Upper bound on the `/readyz` database ping (H3).
const READYZ_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Outstanding `/readyz` database pings (H3).
static READYZ_PING_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

#[derive(Serialize)]
struct ReadyzBody {
    status: &'static str,
    version: &'static str,
    event_log: &'static str,
    device_state: &'static str,
}

/// Bind a TCP listener at the configured address.
///
/// Split out from [`serve`] so the daemon can log the resolved
/// address (`listener.local_addr()`) *before* moving into the
/// accept loop, and so integration tests can drive a real
/// `127.0.0.1:0` listener through a `tokio::spawn`ed [`serve`]
/// without losing the ephemeral port.
///
/// # Errors
///
/// - `TcpListener::bind` failure (port in use, permission denied).
pub async fn bind(config: ApiConfig) -> anyhow::Result<TcpListener> {
    TcpListener::bind(config.bind)
        .await
        .map_err(anyhow::Error::from)
}

/// Run the API accept loop on `listener` until the future is dropped.
///
/// The daemon's `main.rs` holds this future inside a `tokio::select!`
/// against `tokio::signal::ctrl_c` (and SIGTERM on Unix). The test
/// harness drives it via `tokio::spawn` + `abort()` on drop.
///
/// # Errors
///
/// - `axum::serve` errors (rare; mostly accept-loop failures).
pub async fn serve(engine: Engine, listener: TcpListener) -> anyhow::Result<()> {
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
struct InstancesBody {
    instances: Vec<InstanceSummary>,
}

#[derive(Serialize)]
struct InstanceSummary {
    instance_id: String,
    /// Manifest-resolved plugin id (e.g. `example.simulated-switch`).
    /// 12-API-d wired this onto `InstanceHandle`; before that the
    /// API only carried `instance_id` here.
    plugin_id: String,
    /// `Debug` repr of the current [`InstanceState`](crate::InstanceState).
    /// A structured projection (with `state_changed_at` etc.) is a
    /// follow-up once a UI/CLI consumer asks for it.
    state: String,
    /// M7: the resolved config as [`crate::redact::masked_config_view`]
    /// renders it — `type = "secret"` fields appear as
    /// `{"secret": true, "set": …, "value": "***" | null}`, never in
    /// plaintext. `null` until the instance's first successful load.
    config: Option<serde_json::Value>,
    /// ADR-0001: for a script sandbox, the instance that started it;
    /// `null` otherwise.
    parent_instance_id: Option<String>,
    /// ADR-0001: for a script sandbox, its `local-id` within the
    /// parent; `null` otherwise.
    sandbox_local_id: Option<String>,
}

/// Authenticated `GET /api/v1/instances`. Returns every supervised
/// instance under the engine with its current lifecycle state. Gated
/// on the `instances:list` scope; the admin / wildcard token
/// satisfies it via [`crate::api::scopes::WILDCARD`].
async fn list_instances(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
) -> Result<Json<InstancesBody>, ScopeDenied> {
    require(&ctx, Action::InstanceRead, &Resource::instances())?;
    let mut instances = Vec::new();
    for handle in state.engine.instances().list() {
        instances.push(InstanceSummary {
            instance_id: handle.instance_id().to_string(),
            plugin_id: handle.plugin_id().to_string(),
            state: format!("{:?}", handle.state()),
            config: handle.config_view(),
            parent_instance_id: handle.parent_instance_id().map(str::to_owned),
            sandbox_local_id: handle.sandbox_local_id().map(str::to_owned),
        });
    }
    Ok(Json(InstancesBody { instances }))
}

#[derive(Serialize)]
struct DevicesBody {
    devices: Vec<DeviceSummary>,
}

#[derive(Serialize)]
struct DeviceSummary {
    device_id: String,
    /// Owning plugin instance id (the host's routing key for
    /// `execute-command`).
    owner_instance: String,
    /// Human-readable name from the registration `DeviceInfo`.
    name: String,
}

/// Authenticated `GET /api/v1/devices`. Lists every device any
/// supervised instance has registered with the host. Gated on the
/// `devices:list` scope.
///
/// Returns a flat snapshot suitable for the CLI's `device list`
/// table — `device_id`, `owner_instance`, `name`. Capability /
/// state-vector projection lands in a later slice once we have a
/// concrete UI/CLI consumer.
async fn list_devices(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
) -> Result<Json<DevicesBody>, ScopeDenied> {
    require(&ctx, Action::DeviceList, &Resource::devices())?;
    let devices = state
        .engine
        .devices()
        .list()
        .into_iter()
        .map(|meta| DeviceSummary {
            device_id: meta.id.clone(),
            owner_instance: meta.owner_instance.clone(),
            name: meta.info.name.clone(),
        })
        .collect();
    Ok(Json(DevicesBody { devices }))
}

// ── Device state (H9 host-owned projection) ──────────────────────

/// JSON snapshot of one device's current per-capability state.
/// Returned by `GET /api/v1/devices/{device_id}/state`. `revision`
/// is the store-wide monotonic value at the moment of the read
/// (read atomically with `capabilities` under one lock — no entry
/// in the response has `global_revision > revision`). Callers pair
/// `{revision, capabilities}` with a subsequent
/// `GET /api/v1/devices/state/changes?since_revision=<revision>`
/// call to observe the **latest per-slot value** for slots that
/// changed after the snapshot. See the `state/changes` docs for
/// the coalescing semantics — this is a materialized-state view,
/// not an append-only event stream.
#[derive(Serialize)]
struct DeviceStateSnapshot {
    device_id: String,
    /// H9 round-6 finding 1: opaque store epoch. Clients
    /// persist this alongside `revision`; a subsequent response
    /// carrying a different `epoch` means the projection was
    /// discarded (H2: it survives a restart), the previously-held
    /// `revision` cursor is invalid, and the client should
    /// resync by re-fetching this endpoint. Round-7 finding 2:
    /// serialized as a string (128-bit OS-random nonce, hex)
    /// so JavaScript clients can compare it losslessly.
    epoch: String,
    /// Store-wide monotonic revision at read time. Even if this
    /// device has no observed state yet (empty `capabilities`),
    /// the revision is meaningful for driving the `changes`
    /// cursor forward.
    revision: u64,
    capabilities: Vec<DeviceStateEntry>,
}

/// One entry in the snapshot or changes response — same shape both
/// places so a client's decoder is reusable.
#[derive(Serialize)]
struct DeviceStateEntry {
    device_id: String,
    capability: String,
    fields: Vec<WireKeyValue>,
    /// Store-wide revision at write time. Compare with the
    /// caller's cursor to decide which entries are new — this
    /// is the **only** ordering axis. H9 round-9 finding 1
    /// removed the per-key `entry_revision`: preserving it
    /// across stale-cap eviction would either grow the store
    /// unboundedly with tombstones or force a global epoch
    /// rotation on every eviction — a `DoS` vector where one
    /// plugin churning unique `local_id`s could trigger a
    /// process-wide resync for every API client.
    global_revision: u64,
    /// Host wall-clock (ms since epoch) when the update was
    /// applied. Trusted for ordering; `observed_ms` isn't.
    received_ms: i64,
    /// Plugin-supplied observed-at timestamp (from
    /// `event.timestamp`). Informational — the plugin's clock,
    /// not the host's.
    observed_ms: u64,
    /// Supervisor generation of the owning instance at write time.
    /// Bumps on each restart; a jump means a re-init sequence.
    source_generation: u64,
    /// `"fresh"` while the owning instance is alive; `"stale"`
    /// after it stops. Safety-critical consumers filter on this.
    quality: crate::state::StateQuality,
}

impl DeviceStateSnapshot {
    /// One device's retained entries (non-empty, sorted by
    /// capability) as a wire snapshot.
    fn from_entries(
        caps: &[Arc<crate::state::DeviceState>],
        epoch: &str,
        revision: u64,
        blobs: bool,
    ) -> Self {
        Self {
            device_id: caps
                .first()
                .map_or_else(String::new, |c| c.device_id.clone()),
            epoch: epoch.to_owned(),
            revision,
            capabilities: caps
                .iter()
                .map(|c| DeviceStateEntry::from_state(c, blobs))
                .collect(),
        }
    }
}

impl DeviceStateEntry {
    /// `blobs` is [`can_read_blobs`] for the caller: without it, every
    /// `bytes-val` field is withheld (M7).
    fn from_state(state: &crate::state::DeviceState, blobs: bool) -> Self {
        Self {
            device_id: state.device_id.clone(),
            capability: state.capability.clone(),
            fields: state
                .fields
                .iter()
                .cloned()
                .map(|kv| WireKeyValue::from_wit(kv, blobs))
                .collect(),
            global_revision: state.global_revision,
            received_ms: state.received_ms,
            observed_ms: state.observed_ms,
            source_generation: state.source_generation,
            quality: state.quality,
        }
    }
}

/// H9 `GET /api/v1/devices/{device_id}/state`. Returns the current
/// state of every capability observed on `device_id`. `capabilities`
/// is empty when the device has never published a `state-changed`
/// and had no `initial_state` on registration — the response still
/// carries the current store-wide `revision` so the client can
/// drive the changes cursor forward.
///
/// **Not owner-scoped** — the state projection is a host-owned
/// aggregate meant for API / UI / MCP consumers, not the plugin
/// world. Gated on `devices:read`.
///
/// # Errors
/// - `403` scope check failed.
async fn get_device_state(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceStateSnapshot>, ScopeDenied> {
    require(
        &ctx,
        Action::DeviceRead,
        &Resource::device(device_id.as_str()),
    )?;
    let blobs = can_read_blobs(&ctx);
    // H9 round-3 finding 3: read `revision` and `entries` **under
    // one lock**. The pre-fix shape called `current_revision()`
    // then `snapshot_device()` in two separate lock acquires, so
    // a writer in between could commit an entry with
    // `global_revision > revision` — the response then carried a
    // per-entry revision above the top-level one, contradicting
    // the documented `M ≤ N` invariant.
    let (epoch, revision, entries) = state
        .engine
        .device_state()
        .snapshot_device_with_revision(&device_id);
    let mut capabilities: Vec<DeviceStateEntry> = entries
        .iter()
        .map(|s| DeviceStateEntry::from_state(s, blobs))
        .collect();
    // Deterministic ordering so a client can eyeball snapshots.
    capabilities.sort_by(|a, b| a.capability.cmp(&b.capability));
    Ok(Json(DeviceStateSnapshot {
        device_id,
        epoch,
        revision,
        capabilities,
    }))
}

/// Query params for `GET /api/v1/devices/state` (H9 round-11
/// finding 1, revised again in round-13 finding 1).
/// Pagination is by *device* — a device's capabilities all
/// land on the same page so per-device snapshots stay
/// atomic — and by **server-issued cursor** carrying epoch +
/// pinned revision + `after_device_id`, so a client can't
/// omit or forge the pin.
///
/// Protocol:
/// - First page: no `cursor` param. Response includes
///   `next_cursor` (opaque string) if more pages exist.
/// - Continuation: pass the previous `next_cursor` back
///   verbatim; the server decodes epoch + pinned revision +
///   `after_device_id`, verifies the epoch still matches the
///   store's current epoch (409 if not — restart resync),
///   and echoes the pinned revision as `revision` in the
///   response.
/// - After the final page (`next_cursor` absent), the client
///   uses the response's `revision` as its next
///   `since_revision` for `/state/changes`. Every write that
///   landed mid-pagination — including writes to devices
///   already paged past, or new devices sorting behind the
///   cursor — has `global_revision > pinned_revision` and
///   surfaces on that cursor poll.
///
/// The old round-11/12 shape (flat `after_device_id` +
/// `pinned_revision` params) let a client omit the pin on
/// continuation (falling back to current revision — the
/// original lost-update race) or supply a stale pin on page
/// one (skipping updates). The opaque cursor closes both
/// holes: page one refuses to accept a cursor, continuation
/// requires one, and only the server ever constructs one.
#[derive(Deserialize)]
struct AllDevicesStateParams {
    /// Opaque continuation cursor from the previous page's
    /// `next_cursor`. Do not parse or fabricate — the format
    /// is a private server contract that may change.
    /// Rejected on the first-page request (no cursor) with
    /// 400 if malformed, 409 if its epoch has since changed.
    #[serde(default)]
    cursor: Option<String>,
    /// Cap on distinct devices in the response. Absent / 0 ⇒
    /// default of 128. Capped at
    /// [`MAX_ALL_DEVICES_STATE_LIMIT`].
    #[serde(default)]
    limit: Option<usize>,
}

// H9 round-14 finding 3: cursor issue/verify moved into
// `DeviceStateStore` — [`DeviceStateStore::issue_cursor`] and
// [`DeviceStateStore::verify_cursor`]. Format is
// `<epoch>.<pinned_revision>.<after_device_id>.<hmac>`
// where `hmac` is HMAC-SHA256-128 keyed on a per-process
// secret. The round-13 in-handler `DecodedCursor` was
// forgeable — a client could construct any cursor from
// scratch (the epoch is publicly visible) and mutate the
// revision or device id to skip pages or recreate the
// round-12 lost-update race.

/// Default page size for `GET /api/v1/devices/state` — chosen
/// to comfortably carry a household-sized deployment in one
/// round-trip while capping the worst-case response body.
/// H9 round-16 finding 2: reduced from 128 to 64.
pub(crate) const DEFAULT_ALL_DEVICES_STATE_LIMIT: usize = 64;
/// Hard ceiling for the same endpoint — a caller can't push
/// the page past this even if they explicitly ask.
/// H9 round-16 finding 2: reduced from 512 to 256.
pub(crate) const MAX_ALL_DEVICES_STATE_LIMIT: usize = 256;
/// Byte budget of one device-state snapshot or changes page (REST
/// and Connect), measured as an upper bound on the encoded size
/// ([`crate::state::PageSizing::Wire`]: JSON escaping and the REST
/// byte-array encoding included). The entry-count caps alone can't
/// bound the body: a 16 KiB slot of control characters encodes to
/// about 96 KiB of JSON. Half of Connect's default 4 MiB receive
/// limit, so the page envelope and a client's own framing still fit.
/// A page stops before the device (snapshot) or entry (changes) that
/// would cross it and says so with `truncated`; the first one is
/// always sent, and a device within the per-device caps
/// (`MAX_CAPABILITIES_PER_DEVICE` slots of `MAX_BYTES_PER_SLOT`)
/// encodes to under 4 MiB even at the escaping worst case.
pub(crate) const MAX_STATE_PAGE_WIRE_BYTES: usize = 2 * 1024 * 1024;

/// H2: entries one snapshot page looks at. A continuation page skips
/// entries newer than its pin, so without a budget a page could walk
/// the rest of the store under the read lock; past it the page ends
/// early (possibly empty) with a `next_cursor`.
pub(crate) const MAX_ALL_DEVICES_STATE_SCAN: usize = 16_384;

/// Body of `GET /api/v1/devices/state`. Same shape as
/// [`DeviceStateSnapshot`] but returns entries across every
/// device — the resync primitive a client falls back on after
/// `reset_required` (H9 round-10 finding 2).
#[derive(Serialize)]
struct AllDevicesStateSnapshot {
    /// See [`DeviceStateSnapshot::epoch`].
    epoch: String,
    /// Resync anchor. On the first page, this is the store's
    /// `current_revision` at read time. On subsequent pages
    /// (`pinned_revision` set), the server echoes the pinned
    /// value so all pages of one resync agree. After
    /// pagination completes, the client uses this as its
    /// next `since_revision` cursor for `/state/changes`.
    /// (H9 round-12 finding 1: this pin is the guarantee
    /// that writes landing mid-pagination — including to
    /// devices already paged past — are picked up on the
    /// next cursor poll.)
    revision: u64,
    /// Devices in this page, ordered by `device_id`.
    devices: Vec<DeviceStateSnapshot>,
    /// H9 round-13 finding 1: opaque continuation cursor —
    /// `None` on the final page. The client passes this
    /// back verbatim as `?cursor=<value>` on the next
    /// request. Encodes epoch + pinned revision + last
    /// device id; server-verified on the way back in, so a
    /// client can't omit the pin or forge a stale one.
    next_cursor: Option<String>,
    /// The page holds fewer than `limit` devices because it hit the
    /// byte budget ([`MAX_STATE_PAGE_WIRE_BYTES`]) or the scan
    /// budget; `next_cursor` is set. Always present.
    truncated: bool,
}

/// Handler-local error type covering scope denial, malformed
/// cursor, and epoch drift. See [`get_all_device_state`].
enum AllDevicesStateError {
    Scope(ScopeDenied),
    BadCursor,
    EpochChanged,
}

impl IntoResponse for AllDevicesStateError {
    fn into_response(self) -> Response {
        match self {
            Self::Scope(s) => s.into_response(),
            Self::BadCursor => (
                StatusCode::BAD_REQUEST,
                "invalid `cursor` — expected the opaque value returned as \
                 `next_cursor` on the previous page",
            )
                .into_response(),
            Self::EpochChanged => (
                StatusCode::CONFLICT,
                "store `epoch` has changed since the cursor was issued \
                 (daemon restart); restart the resync from an unpinned request",
            )
                .into_response(),
        }
    }
}

impl From<ScopeDenied> for AllDevicesStateError {
    fn from(value: ScopeDenied) -> Self {
        Self::Scope(value)
    }
}

/// H9 round-10 finding 2 / round-11 finding 1 / round-13
/// finding 1: `GET /api/v1/devices/state`. Paginated atomic
/// full-store snapshot for `reset_required` recovery. When
/// [`StateChangesBody::reset_required`] is `true` (cursor
/// beyond current revision after a daemon restart, or below
/// the store's stale-eviction watermark), the caller has no
/// way to know which per-device snapshots to fetch — device
/// enumeration lives behind the separate `devices:list` scope
/// and the reset itself may have dropped device IDs from the
/// client's cache. This endpoint is the resync path, gated on
/// `devices:read`, read under one lock so `revision` + entries
/// within one page are consistent, and paginated with a
/// server-issued opaque cursor so cross-page consistency
/// (the pin protocol) is enforced instead of documented.
///
/// # Errors
/// - `400` cursor is malformed.
/// - `403` scope check failed.
/// - `409` cursor's epoch no longer matches the store's
///   current epoch — restart the resync from an unpinned
///   request.
#[allow(clippy::too_many_lines)]
async fn get_all_device_state(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Query(params): Query<AllDevicesStateParams>,
) -> Result<Json<AllDevicesStateSnapshot>, AllDevicesStateError> {
    require(&ctx, Action::DeviceRead, &Resource::devices())?;
    let blobs = can_read_blobs(&ctx);
    let limit = params
        .limit
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_ALL_DEVICES_STATE_LIMIT)
        .min(MAX_ALL_DEVICES_STATE_LIMIT);
    // H9 round-14 finding 3: verify the cursor's HMAC before
    // trusting *any* of its fields (the round-13 plain-text
    // cursor was forgeable). Bad shape / MAC → 400; MAC
    // verifies but the store's epoch has rotated → 409.
    let cursor_fields = match params.cursor.as_deref() {
        Some(raw) => match state.engine.device_state().verify_cursor(raw) {
            Ok(triple) => Some(triple),
            Err(crate::state::CursorError::Bad) => {
                return Err(AllDevicesStateError::BadCursor);
            }
            Err(crate::state::CursorError::EpochChanged) => {
                return Err(AllDevicesStateError::EpochChanged);
            }
        },
        None => None,
    };
    // H2: grouping and the count / byte caps live in the store
    // (shared with Connect and the plugin `list-state` import). Caps
    // are applied on the raw `Arc` entries; only the retained ones are
    // converted to wire values (H9 round-18/19).
    // H2: a continuation page leaves out entries newer than the pinned
    // revision. The client picks them up from `/state/changes` since
    // that revision, so a slot written mid-resync and then lost in a
    // crash is never in the client's snapshot with nothing to retract
    // it (the restored store accepts the pinned cursor).
    let pinned = cursor_fields.as_ref().map(|(_, r, _)| *r);
    let page = state.engine.device_state().snapshot_page_capped(
        cursor_fields.as_ref().map(|(_, _, did)| did.as_str()),
        limit,
        MAX_STATE_PAGE_WIRE_BYTES,
        crate::state::PageSizing::Wire { blobs },
        MAX_ALL_DEVICES_STATE_SCAN,
        |e| pinned.is_none_or(|r| e.global_revision <= r),
    );
    let epoch = page.epoch;
    // On page one (no cursor), report the store's current
    // revision; on continuation, echo the pinned revision
    // from the (verified) cursor so all pages of one resync
    // agree.
    let revision = match cursor_fields.as_ref() {
        Some((_, r, _)) => *r,
        None => page.revision,
    };
    let devices: Vec<DeviceStateSnapshot> = page
        .devices
        .into_iter()
        .map(|caps| DeviceStateSnapshot::from_entries(&caps, &epoch, revision, blobs))
        .collect();
    let next_cursor = page
        .resume_after
        .map(|after| state.engine.device_state().issue_cursor(revision, &after));
    Ok(Json(AllDevicesStateSnapshot {
        epoch,
        revision,
        devices,
        next_cursor,
        truncated: page.truncated,
    }))
}

/// `GET /api/v1/devices/state/changes` query params. Cursor-based
/// catch-up over the H9 state projection.
///
/// **Materialized view, not an append-only stream.** The projection
/// stores one entry per `(device_id, capability)`; a slot that
/// updates multiple times between polls is **coalesced** to the
/// latest value at read time, and the intermediate `global_revision`
/// values do not appear in any `state/changes` response. A caller
/// that needs every historical transition reads the full event log
/// (`GET /api/v1/events`) instead — the projection is the "current
/// value per slot" view. Consequence: `current_revision` can exceed
/// the highest `global_revision` in `changes` even when nothing has
/// been dropped.
#[derive(Deserialize)]
struct StateChangesParams {
    /// Return only entries with `global_revision > since_revision`.
    /// Absent ⇒ start from the beginning (revision 0), useful for
    /// the initial full-history sync.
    #[serde(default)]
    since_revision: Option<u64>,
    /// Cap on returned entries. Absent / 0 ⇒ default of 256.
    /// The store returns the earliest deltas first so the caller
    /// can page forward: take the highest `global_revision` in the
    /// response as the next call's `since_revision`.
    #[serde(default)]
    limit: Option<usize>,
}

/// JSON body for `GET /api/v1/devices/state/changes`.
/// `current_revision` is the store-wide value at read time (read
/// atomically with `changes` under one lock — no entry in the
/// response has `global_revision > current_revision`). Callers
/// advance their cursor by taking the highest `global_revision` in
/// `changes`; the response reflects each slot's coalesced latest
/// value, not its history (see [`StateChangesParams`]). Empty
/// `changes` with `current_revision > since_revision` just means
/// every changed slot's latest value is within the current page —
/// advance and re-poll.
///
/// H9 round-6 finding 1: `epoch` is the store's opaque nonce; a
/// client that persists the last-seen epoch and observes a change
/// knows the projection was discarded and its cursor is invalid.
/// `reset_required` covers the cases the epoch can't (H2: the
/// epoch survives restarts): a cursor above the current revision,
/// below the eviction watermark, or inside a revision range a boot
/// skipped because its writes may not have been flushed.
#[derive(Serialize)]
struct StateChangesBody {
    /// See [`DeviceStateSnapshot::epoch`] — 128-bit OS-random
    /// nonce, string-encoded (round-7 finding 2).
    epoch: String,
    current_revision: u64,
    changes: Vec<DeviceStateEntry>,
    /// True when the caller's cursor is invalid — it's beyond the
    /// store's current revision, inside a revision range a boot
    /// skipped (H2: changes lost before they were flushed), or below
    /// the store's `evicted_through_revision` watermark (an
    /// evicted stale slot may have been the client's last
    /// chance to observe a `Fresh → Stale` flip). Recovery:
    /// fetch `GET /api/v1/devices/state` for an atomic
    /// all-device snapshot (H9 round-10 finding 2), take the
    /// returned `revision` as the new cursor, and resume
    /// polling. Serialized unconditionally so a client can
    /// `if body.reset_required { ... }` without checking for
    /// absence.
    reset_required: bool,
    /// The byte budget ([`MAX_STATE_PAGE_WIRE_BYTES`]) cut the page
    /// short: more changes follow even though `changes` holds fewer
    /// than `limit` entries. Advance the cursor as usual and poll
    /// again. Always present.
    truncated: bool,
}

/// Default page size for `state/changes`. Chosen to comfortably
/// carry the initial-sync case (a few dozen devices × a few
/// capabilities each) in one round-trip, while capping the
/// worst-case JSON body for a caller that forgets to send `limit`.
pub(crate) const DEFAULT_STATE_CHANGES_LIMIT: usize = 256;
/// Hard ceiling — a caller can't push the page past this even if
/// they explicitly ask.
pub(crate) const MAX_STATE_CHANGES_LIMIT: usize = 1024;

/// H9 `GET /api/v1/devices/state/changes`. Cursor-based catch-up.
/// See [`StateChangesParams`] for the parameter shapes and the
/// paging rule.
///
/// # Errors
/// - `403` scope check failed.
async fn query_device_state_changes(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Query(params): Query<StateChangesParams>,
) -> Result<Json<StateChangesBody>, ScopeDenied> {
    require(&ctx, Action::DeviceRead, &Resource::devices())?;
    let blobs = can_read_blobs(&ctx);
    let limit = params
        .limit
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_STATE_CHANGES_LIMIT)
        .min(MAX_STATE_CHANGES_LIMIT);
    let since = params.since_revision.unwrap_or(0);
    // H9 round-3 finding 3: read `current_revision` and `deltas`
    // **under one lock** — see the sibling comment on
    // `get_device_state` for the invariant.
    // H9 round-6 finding 1: the store now returns a `DeltaPage`
    // carrying `epoch` + `reset_required` so the client can
    // detect a daemon restart and resync.
    let page = state.engine.device_state().deltas_since_capped(
        since,
        limit,
        MAX_STATE_PAGE_WIRE_BYTES,
        crate::state::PageSizing::Wire { blobs },
    );
    let changes: Vec<DeviceStateEntry> = page
        .entries
        .iter()
        .map(|s| DeviceStateEntry::from_state(s, blobs))
        .collect();
    Ok(Json(StateChangesBody {
        epoch: page.epoch,
        current_revision: page.current_revision,
        changes,
        reset_required: page.reset_required,
        truncated: page.truncated,
    }))
}

// ── Device command (write path) ──────────────────────────────────

/// `POST /api/v1/devices/{device_id}/command` body.
#[derive(Deserialize)]
struct CommandBody {
    /// Capability key — `"switch"`, `"dimmer"`, etc. — that the
    /// plugin's `execute-command` matches on alongside `action`.
    capability: String,
    /// Action verb — `"set"`, `"toggle"`, `"increment"`, … — the
    /// plugin's command dispatch interprets.
    action: String,
    /// `key=value` arguments. Each `value` is the JSON-tagged
    /// [`WireValue`] enum (mirrors the WIT `value` variant so the
    /// CLI / UI can pass typed payloads without losing precision).
    #[serde(default)]
    args: Vec<WireKeyValue>,
}

/// JSON wire mirror of the WIT `key-value` record. The on-wire
/// `value` is the tagged-JSON [`WireValue`] below. `Serialize` is
/// derived alongside `Deserialize` so the same shape can round-
/// trip in both directions — the H5 review round-2 P1 F3 fix
/// reuses this in `WireEventPayload::StateChanged.fields` for
/// history + tail wire projection.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WireKeyValue {
    pub(crate) key: String,
    pub(crate) value: WireValue,
}

/// JSON wire mirror of the WIT `value` variant — same tag/content
/// shape as the storage encoding so a future API <-> persisted
/// record migration is a pure-Rust transform. Round-trippable in
/// **both directions**: clients deserialize into [`Value`] via
/// `From<WireValue>`, and the API serializes responses into
/// [`WireValue`] via `From<Value>` so the input `{t,v}` shape on
/// command args matches the `{t,v}` shape on the
/// `OkWithState` state map. Drop the round-trip and a client
/// can't tell `Int(5)` from `Float(5.0)`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "t", content = "v")]
pub(crate) enum WireValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(String),
}

impl From<WireValue> for Value {
    fn from(v: WireValue) -> Self {
        match v {
            WireValue::Bool(b) => Value::BoolVal(b),
            WireValue::Int(i) => Value::IntVal(i),
            WireValue::Float(f) => Value::FloatVal(f),
            WireValue::String(s) => Value::StringVal(s),
            WireValue::Bytes(b) => Value::BytesVal(b),
            WireValue::Json(j) => Value::JsonVal(j),
        }
    }
}

impl From<Value> for WireValue {
    fn from(v: Value) -> Self {
        match v {
            Value::BoolVal(b) => WireValue::Bool(b),
            Value::IntVal(i) => WireValue::Int(i),
            Value::FloatVal(f) => WireValue::Float(f),
            Value::StringVal(s) => WireValue::String(s),
            Value::BytesVal(b) => WireValue::Bytes(b),
            Value::JsonVal(j) => WireValue::Json(j),
        }
    }
}

/// Wire shape of a device-command result (H5): the host-minted
/// `command_id` plus the explicit `outcome`. Shared by REST and MCP.
///
/// - `completed` carries `state` (a `{key: WireValue}` map) when the
///   plugin returned its post-command state. [`WireValue`] is tagged,
///   so the round-trip stays lossless (int vs float, JSON vs string).
/// - `rejected` carries the [`WitError`] as a tagged `{kind, message}`.
/// - `timed_out` and `outcome_unknown` carry a human-readable
///   `message`.
/// - `retry_safe` is `true` only when the host knows the command had
///   no effect (`rejected`, `timed_out`).
#[derive(Serialize)]
pub(crate) struct WireCommandReport {
    pub(crate) command_id: String,
    pub(crate) outcome: &'static str,
    pub(crate) retry_safe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<HashMap<String, WireValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<WireWitError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

impl WireCommandReport {
    /// Without `blobs` (the caller's [`can_read_blobs`]), returned
    /// `bytes-val` state is withheld (M7).
    pub(crate) fn from_report(mut report: CommandReport, blobs: bool) -> Self {
        if !blobs {
            report.withhold_bytes();
        }
        let outcome = report.outcome.as_str();
        let retry_safe = report.outcome.is_retry_safe();
        let (state, error, message) = match report.outcome {
            CommandOutcome::Accepted => (None, None, None),
            CommandOutcome::Completed { state } => (
                state.map(|kvs| {
                    kvs.into_iter()
                        .map(|kv| (kv.key, kv.value.into()))
                        .collect()
                }),
                None,
                None,
            ),
            CommandOutcome::Rejected { error } => (None, Some(error.into()), None),
            CommandOutcome::TimedOut { message } | CommandOutcome::Unknown { message } => {
                (None, None, Some(message))
            }
        };
        Self {
            command_id: report.command_id,
            outcome,
            retry_safe,
            state,
            error,
            message,
        }
    }
}

/// H5 REST status for a device-command outcome. Every outcome carries
/// the same JSON body; the status lets a generic HTTP client tell them
/// apart without reading it:
///
/// - `completed` → `200 OK`
/// - `accepted` → `202 Accepted`
/// - `rejected` → `422 Unprocessable Content` (nothing happened; fix and retry)
/// - `timed_out` → `504 Gateway Timeout` (nothing happened; retry is safe)
/// - `outcome_unknown` → `502 Bad Gateway` (may have happened; read the
///   device state before retrying)
pub(crate) fn command_outcome_status(outcome: &CommandOutcome) -> StatusCode {
    match outcome {
        CommandOutcome::Completed { .. } => StatusCode::OK,
        CommandOutcome::Accepted => StatusCode::ACCEPTED,
        CommandOutcome::Rejected { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        CommandOutcome::TimedOut { .. } => StatusCode::GATEWAY_TIMEOUT,
        CommandOutcome::Unknown { .. } => StatusCode::BAD_GATEWAY,
    }
}

/// Wire mirror of the WIT `error` variant. Same shape clients can
/// already see on other endpoints' error responses.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WireWitError {
    NotFound { message: String },
    InvalidArgument { message: String },
    PermissionDenied { message: String },
    Unavailable { message: String },
    Internal { message: String },
}

impl From<WitError> for WireWitError {
    fn from(e: WitError) -> Self {
        match e {
            WitError::NotFound(m) => WireWitError::NotFound { message: m },
            WitError::InvalidArgument(m) => WireWitError::InvalidArgument { message: m },
            WitError::PermissionDenied(m) => WireWitError::PermissionDenied { message: m },
            WitError::Unavailable(m) => WireWitError::Unavailable { message: m },
            WitError::Internal(m) => WireWitError::Internal { message: m },
        }
    }
}

/// `POST /api/v1/devices/{device_id}/command` — route a command
/// through the owning plugin instance's `execute-command` export
/// and return the result.
///
/// **Sensitive.** Gated on the `devices:command` scope: this is
/// the write-side device endpoint that can physically actuate
/// locks, garage doors, alarms, etc. The dedicated C3 audit
/// ledger records every authenticated request; `GET /api/v1/audit`
/// (scoped on `audit:read`) surfaces the trail — filter by
/// `path=/api/v1/devices/.../command` for command-dispatch rows.
///
/// **Response shape (H5).** Every command the host routed to the
/// owning instance gets a host-minted `command_id` and an explicit
/// `outcome` in a [`WireCommandReport`] body; the HTTP status follows
/// the outcome (see [`command_outcome_status`]): `200` completed, `202`
/// accepted, `422` rejected, `504` timed out, `502` outcome unknown.
/// Requests that never reach dispatch keep their usual statuses:
/// - `404 not_found` — no device with that id, or its owning
///   instance isn't currently running. Indistinguishable from
///   "wrong id" so a probing caller can't enumerate device ids.
/// - `403` — scope check failed, or the token's `device.send_command`
///   allowlist does not cover `device_id` (audited with
///   `required_scope = "constraint:device.send_command:devices"`).
///
/// The plugin runs under the request's [`InvocationContext`] (H6), so
/// any `call-service` it makes is audited against this token. The
/// audit row records `command_id` and `command_outcome`, with
/// `decision = "allow"` whatever the outcome status.
async fn send_command(
    Extension(invocation): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(device_id): Path<String>,
    Json(body): Json<CommandBody>,
) -> Result<axum::response::Response, CommandError> {
    // H6: `device.command` on the addressed device — the scope and the
    // token's per-device allowlist, shared with Connect and MCP.
    // Before the lookup so a refused token can't probe device ids.
    require(
        &invocation,
        Action::DeviceCommand,
        &Resource::device(device_id.as_str()),
    )
    .map_err(CommandError::Scope)?;

    // Resolve device → owning instance via the registry's
    // cross-instance owner-only lookup (mirrors the dispatcher's
    // `ServiceRegistry::get_owner` shape). The previous
    // `list().into_iter().find(...)` was O(n) + Vec-alloc per
    // command; this is one read-lock + map lookup.
    let owner = state
        .engine
        .devices()
        .get_owner(&device_id)
        .ok_or(CommandError::NotFound)?;
    let handle = state
        .engine
        .instances()
        .get(&owner)
        .ok_or(CommandError::NotFound)?;

    // Build the WIT command. JSON `value` shapes map to typed
    // `Value` variants via the `From<WireValue>` impl. The supervisor
    // handle mints `id` (H5).
    let cmd = Command {
        id: String::new(),
        capability: body.capability,
        action: body.action,
        args: body
            .args
            .into_iter()
            .map(|kv| KeyValue {
                key: kv.key,
                value: kv.value.into(),
            })
            .collect(),
    };

    let blobs = can_read_blobs(&invocation);
    let report = handle.execute_command_in(invocation, device_id, cmd).await;

    // F4 + H5: the authorization decision stays `allow` whatever the
    // command outcome; the outcome and command id ride to the audit
    // middleware on a response extension.
    let status = command_outcome_status(&report.outcome);
    let domain_outcome = crate::api::auth::DomainOutcome::from_report(&report);
    let mut response =
        (status, Json(WireCommandReport::from_report(report, blobs))).into_response();
    response.extensions_mut().insert(domain_outcome);
    Ok(response)
}

enum CommandError {
    Scope(ScopeDenied),
    NotFound,
}

impl IntoResponse for CommandError {
    fn into_response(self) -> axum::response::Response {
        match self {
            CommandError::Scope(s) => s.into_response(),
            CommandError::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
        }
    }
}

// ── Plugins (aggregate by plugin_id) ─────────────────────────────

#[derive(Serialize)]
struct PluginsBody {
    plugins: Vec<PluginSummary>,
}

#[derive(Serialize)]
struct PluginSummary {
    plugin_id: String,
    /// `true` if `<state_dir>/plugins/<plugin_id>/` is present on
    /// disk. A row with `installed = false` means there's a
    /// running instance whose plugin id isn't in the installed
    /// registry — typically the dev-time argv-driven start path
    /// in the daemon, not an actual install.
    installed: bool,
    /// Semver from the installed manifest, or `null` for the
    /// running-but-not-installed case above.
    version: Option<String>,
    /// How many supervised instances are currently registered for
    /// this plugin. Zero is valid for installed-but-stopped plugins;
    /// it's how the CLI distinguishes "ready to start" from
    /// "actively running".
    instance_count: u32,
}

/// `GET /api/v1/plugins` — list of every plugin known to the host:
/// every entry in the installed-plugin registry plus any
/// running-but-uninstalled instances (the dev-time argv path).
/// `instance_count` is aggregated from
/// [`InstanceRegistry::list`] by `plugin_id`. Gated on
/// `plugins:list`. Sorted by plugin id for stable CLI output.
async fn list_plugins(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
) -> Result<Json<PluginsBody>, ScopeDenied> {
    require(&ctx, Action::PluginRead, &Resource::plugins())?;
    // First, count running instances by plugin id.
    let mut by_plugin: HashMap<String, u32> = HashMap::new();
    for handle in state.engine.instances().list() {
        *by_plugin.entry(handle.plugin_id().to_string()).or_default() += 1;
    }
    // Then merge in installed plugins; an installed-but-stopped
    // plugin lands as `instance_count = 0` (the typical CLI
    // listing on a fresh boot — install endpoints don't auto-start).
    let mut plugins: Vec<PluginSummary> = Vec::new();
    for installed in state.engine.installed_plugins().list() {
        let id = installed.plugin_id.to_string();
        // `remove` doubles as "found?" — every installed id
        // disappears from `by_plugin` here, so the leftover-loop
        // below sees only running-but-not-installed entries
        // without needing a separate seen-set.
        let count = by_plugin.remove(&id).unwrap_or(0);
        plugins.push(PluginSummary {
            plugin_id: id,
            installed: true,
            version: Some(installed.version),
            instance_count: count,
        });
    }
    // Whatever's left in `by_plugin` is running-but-not-installed
    // (the dev-time argv flow).
    for (plugin_id, instance_count) in by_plugin {
        plugins.push(PluginSummary {
            plugin_id,
            installed: false,
            version: None,
            instance_count,
        });
    }
    plugins.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
    Ok(Json(PluginsBody { plugins }))
}

/// Phase 13 slice 2: JSON body for
/// `GET /api/v1/plugins/{plugin_id}/schema`. Returns the
/// installed manifest's `config` schema and the `[ui]`
/// section verbatim — same shape the manifest already
/// deserializes, so the shell's default renderer can
/// treat this endpoint as the source of truth without
/// re-parsing TOML.
///
/// `ui: null` means the plugin didn't declare `[ui]`; the
/// shell then falls back to the host's default config
/// renderer only.
#[derive(Serialize)]
struct PluginSchemaBody {
    plugin_id: String,
    version: String,
    config: std::collections::BTreeMap<String, oxidhome_manifest::ConfigField>,
    ui: Option<oxidhome_manifest::UiSection>,
}

/// Phase 13 slice 2:
/// `GET /api/v1/plugins/{plugin_id}/schema` — returns the
/// installed manifest's `config` block and `[ui]` section
/// so a UI shell can render declarative config forms and
/// know which plugin-shipped assets are declared.
///
/// Reads the manifest + wasm + declared UI assets on
/// demand and recomputes the content digest, then refuses
/// to serve any response whose bytes disagree with the
/// installation's persisted `content_digest`. Not hot-path:
/// called once per plugin selection in the dashboard, not
/// per render.
///
/// # Errors
/// - `403` scope check failed.
/// - `404` no such installed plugin (dev-only in-memory
///   plugins aren't reachable — they have no on-disk
///   manifest).
/// - `409` on-disk package bytes have drifted from the
///   installation's persisted digest (round-8 F1) — the
///   caller must reinstall via the API to re-issue the
///   grant + digest before the schema endpoint returns
///   again.
/// - `500` on-disk manifest is missing / unparseable /
///   package IO failed — surfaces as `Internal` because
///   the installer guarantees a valid manifest, so an
///   unreadable one is a host-side integrity failure.
async fn get_plugin_schema(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
) -> Result<Json<PluginSchemaBody>, PluginSchemaError> {
    require(
        &ctx,
        Action::PluginRead,
        &Resource::plugin(plugin_id.as_str()),
    )?;
    // Round-2 F4 + round-9 F1: hold the per-plugin
    // lifecycle lock across the registry lookup + the
    // package re-read + the digest verification. Without it,
    // a concurrent uninstall + reinstall between the two
    // visits could return a mixed view — the old row's
    // `version` alongside the new installation's `config` /
    // `ui` — or a transient 500 if the on-disk
    // `manifest.toml` momentarily disappears during the
    // reinstall's copy phase.
    //
    // Round-9 F1: use `lock_owned()` and move the guard INTO
    // the `spawn_blocking` closure, then return it back with
    // the result. A borrowed `_guard` on the handler frame
    // would drop the moment the client cancels the request
    // (tokio drops the handler future) — but `spawn_blocking`
    // detaches and keeps running unbounded reads of the
    // installed wasm + UI assets. Repeated cancelled
    // requests would then race those reads concurrently for
    // the same `plugin_id`, defeating the per-plugin
    // serialization and pinning the blocking-thread pool /
    // heap. Owned guard + return-with-result keeps the
    // lock live for the duration of the actual work, even
    // when the caller has walked away.
    let lifecycle = state.engine.plugin_lifecycle_lock(&plugin_id);
    let guard = lifecycle.lock_owned().await;
    let Some(installed) = state.engine.installed_plugins().get(&plugin_id) else {
        return Err(PluginSchemaError::NotFound);
    };
    let plugin_dir = installed.path.clone();
    let (result, guard) = tokio::task::spawn_blocking(move || {
        let result = crate::state::recompute_digest_and_manifest(&plugin_dir);
        (result, guard)
    })
    .await
    .map_err(|err| PluginSchemaError::Internal(err.into()))?;
    let _guard = guard;
    let (digest, manifest) = result.map_err(PluginSchemaError::Internal)?;
    if digest != *installed.content_digest {
        return Err(PluginSchemaError::DigestMismatch {
            plugin_id: (*installed.plugin_id).to_string(),
            stored: installed.content_digest.to_string(),
            current: digest,
        });
    }
    Ok(Json(PluginSchemaBody {
        plugin_id: (*installed.plugin_id).to_string(),
        version: installed.version,
        config: manifest.config,
        ui: manifest.ui,
    }))
}

/// Phase 13 slice 2: handler-local error type for the
/// schema endpoint. `Internal` covers both "manifest file
/// vanished" (registry says installed, disk disagrees —
/// a host-side integrity failure the operator needs to
/// see logged) and "`spawn_blocking` panicked".
/// `DigestMismatch` (round-8 F1) is separate so operators
/// can tell "someone modified the package on disk since
/// install" apart from generic 500s and act on it
/// (reinstall via the API).
enum PluginSchemaError {
    Scope(ScopeDenied),
    NotFound,
    DigestMismatch {
        plugin_id: String,
        stored: String,
        current: String,
    },
    Internal(anyhow::Error),
}

impl From<ScopeDenied> for PluginSchemaError {
    fn from(value: ScopeDenied) -> Self {
        Self::Scope(value)
    }
}

impl IntoResponse for PluginSchemaError {
    fn into_response(self) -> Response {
        match self {
            Self::Scope(s) => s.into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            Self::DigestMismatch {
                plugin_id,
                stored,
                current,
            } => {
                tracing::error!(
                    target: "api.plugins.schema",
                    plugin_id = %plugin_id,
                    stored_digest = %stored,
                    current_digest = %current,
                    "installed package bytes have drifted from the persisted digest; refusing to serve schema"
                );
                (
                    StatusCode::CONFLICT,
                    "installed package contents have been modified since install; reinstall via the API to re-issue the grant + digest",
                )
                    .into_response()
            }
            Self::Internal(err) => {
                tracing::error!(target: "api.plugins.schema", error = %err, "manifest re-read failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

// ── Plugin lifecycle (install / start / stop / uninstall) ────────

/// `POST /api/v1/plugins` body. `source_dir` is an absolute path
/// (no `..` components) on the daemon-local filesystem the operator
/// already staged; the daemon copies it into
/// `<state_dir>/plugins/<plugin_id>/`. A remote-fetch /
/// multipart-upload variant is a follow-up that layers on top.
#[derive(Deserialize)]
struct InstallBody {
    source_dir: std::path::PathBuf,
}

#[derive(Serialize)]
struct InstalledRow {
    plugin_id: String,
    version: String,
    installed_path: String,
}

/// `POST /api/v1/plugins` — install. Reads
/// `<source_dir>/manifest.toml` to extract the canonical plugin id,
/// then recursively copies `source_dir` into
/// `<state_dir>/plugins/<plugin_id>/`. Gated on `plugins:install`
/// (sensitive — installs new code on the host).
///
/// Does **not** start the plugin: the operator follows up with
/// `POST /api/v1/plugins/{plugin_id}/start`. Auto-start on install
/// would surprise an operator who wanted to inspect the staged
/// install before letting it run.
async fn install_plugin(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Json(body): Json<InstallBody>,
) -> Result<Json<InstalledRow>, PluginLifecycleError> {
    require(&ctx, Action::PluginInstall, &Resource::Host)?;
    // The registry's install is sync (filesystem + manifest read
    // is fast enough not to need tokio::fs). Wrap in `spawn_blocking`
    // so a slow disk doesn't stall the axum runtime; a `cp -r` of a
    // 10 MB wasm + manifest is sub-100 ms on the slowest hardware
    // but the API thread shouldn't own it either way.
    let installed_registry = state.engine.installed_plugins();
    let source = body.source_dir;
    let installed = tokio::task::spawn_blocking(move || installed_registry.install(&source))
        .await
        .map_err(|err| PluginLifecycleError::Internal(err.into()))??;
    Ok(Json(InstalledRow {
        plugin_id: installed.plugin_id.to_string(),
        version: installed.version,
        installed_path: installed.path.display().to_string(),
    }))
}

#[derive(Deserialize, Default)]
struct StartBody {
    /// Defaults to `plugin_id` if omitted — matches the dev
    /// argv-driven path where the instance id is implicit.
    #[serde(default)]
    instance_id: Option<String>,
    /// Per-instance config overrides (the same TOML-shaped JSON
    /// blob the supervisor accepts via `start_instance`'s
    /// `overrides` parameter).
    #[serde(default)]
    config_overrides: Option<toml::Value>,
}

#[derive(Serialize)]
struct StartedRow {
    plugin_id: String,
    instance_id: String,
    state: String,
}

/// `POST /api/v1/plugins/{plugin_id}/start` — start a supervised
/// instance of an installed plugin. Returns once the instance
/// reaches `Running` (or fails to). Gated on `plugins:start`.
async fn start_plugin_instance(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    body: Option<Json<StartBody>>,
) -> Result<Json<StartedRow>, PluginLifecycleError> {
    let body = body.map_or_default(|Json(b)| b);
    require(&ctx, Action::InstanceStart, &Resource::instances())?;
    require(
        &ctx,
        Action::InstanceStart,
        &Resource::instance(plugin_id.as_str(), body.instance_id.clone()),
    )?;
    let instance_id = body
        .instance_id
        .clone()
        .unwrap_or_else(|| plugin_id.clone());
    // Follow-up review H1: reject caller-supplied `instance_id`s
    // that aren't safe as FS segments before they reach the KV /
    // blob store (which use the id directly in `<blobs_root>/
    // <instance_id>/...`). Absolute paths would replace the root
    // under `Path::join`, `..` escapes it, `\0` truncates on
    // POSIX. Also rejected: empty and leading-`.` which collide
    // with the blob-store `.tmp` staging convention.
    if !crate::runtime::is_operator_instance_id(&instance_id) {
        return Err(PluginLifecycleError::BadInstanceId(instance_id));
    }
    // H2 round-2 F1: serialize against a concurrent uninstall
    // for the same plugin_id. Without this lock, uninstall's
    // running-instances check could pass while start is
    // mid-supervisor-registration, and uninstall could then
    // yank the registry row + FS from under the fresh instance
    // — leaving it running on a synthetic uuid + manifest-
    // requested capabilities (loader dev fallback) instead of
    // the persisted grant.
    let lifecycle_lock = state.engine.plugin_lifecycle_lock(&plugin_id);
    let _guard = lifecycle_lock.lock().await;
    let installed = state
        .engine
        .installed_plugins()
        .get(&plugin_id)
        .ok_or(PluginLifecycleError::NotFound)?;
    // H11 round-2 F1: `start_installed_instance` pins the
    // load-time identity to the `installation_uuid` observed under
    // the lifecycle lock. The loader fails closed if the registry
    // row named by that uuid disappears between now and the
    // supervisor's re-read (concurrent uninstall race) — never
    // falls back to synthetic identity + manifest-requested
    // capabilities.
    let handle = state
        .engine
        .start_installed_instance(
            installed.path.clone(),
            &instance_id,
            body.config_overrides,
            std::sync::Arc::clone(&installed.installation_uuid),
        )
        .await
        .map_err(PluginLifecycleError::Start)?;
    handle
        .wait_for_running()
        .await
        .map_err(PluginLifecycleError::Start)?;
    Ok(Json(StartedRow {
        plugin_id,
        instance_id,
        state: format!("{:?}", handle.state()),
    }))
}

#[derive(Deserialize, Default)]
struct StopBody {
    /// If provided, only this instance is stopped. If omitted,
    /// every supervised instance of `plugin_id` is stopped.
    #[serde(default)]
    instance_id: Option<String>,
}

#[derive(Serialize)]
struct StoppedRow {
    stopped: Vec<String>,
}

/// `POST /api/v1/plugins/{plugin_id}/stop` — stop one or all
/// running instances of `plugin_id`. Gated on `plugins:stop`.
/// Returns the list of `instance_id`s actually stopped (empty
/// if none were running, which is success — idempotent).
///
/// Every matching instance is asked to stop at once, and the handler
/// waits until each has been reaped: out of the instance registry,
/// and for a scripting plugin's instance, its sandboxes too, so a
/// follow-up uninstall doesn't see a leftover. The wait is bounded by
/// [`crate::STOP_WAIT_LIMIT`]; past it the answer is `504` with
/// `{"error": "stop_timed_out", "stopped": [...], "stopping": [...]}`,
/// and the `stopping` instances finish stopping in the background.
async fn stop_plugin_instances(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    body: Option<Json<StopBody>>,
) -> Result<Json<StoppedRow>, PluginLifecycleError> {
    let body = body.map_or_default(|Json(b)| b);
    require(&ctx, Action::InstanceStop, &Resource::instances())?;
    require(
        &ctx,
        Action::InstanceStop,
        &Resource::instance(plugin_id.as_str(), body.instance_id.clone()),
    )?;
    let handles = state
        .engine
        .instances()
        .list()
        .into_iter()
        .filter(|handle| {
            handle.plugin_id() == plugin_id
                && body
                    .instance_id
                    .as_ref()
                    .is_none_or(|want| handle.instance_id() == want)
        })
        .collect();
    let report = crate::runtime::stop_and_wait_reaped(handles, crate::STOP_WAIT_LIMIT).await;
    if !report.still_stopping.is_empty() {
        return Err(PluginLifecycleError::StopTimedOut {
            stopped: report.stopped,
            stopping: report.still_stopping,
        });
    }
    Ok(Json(StoppedRow {
        stopped: report.stopped,
    }))
}

#[derive(Serialize)]
struct UninstalledRow {
    plugin_id: String,
}

/// `DELETE /api/v1/plugins/{plugin_id}` — remove the installed
/// plugin's directory recursively. Refuses if any supervised
/// instance of the plugin is still running (`409 Conflict`); the
/// operator must `POST .../stop` first. Gated on
/// `plugins:uninstall` (sensitive).
async fn uninstall_plugin(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
) -> Result<Json<UninstalledRow>, PluginLifecycleError> {
    require(
        &ctx,
        Action::PluginUninstall,
        &Resource::plugin(plugin_id.as_str()),
    )?;
    // H2 round-2 F1 + H3 round-2 F1: hold the per-plugin_id
    // lifecycle lock across the running-instances check + the
    // compose uninstall, and — crucially — MOVE the guard into
    // the `spawn_blocking` closure so the uninstall task itself
    // owns the reservation until every FS + SQL step finishes.
    //
    // A borrowed guard on the handler frame would be dropped if
    // the HTTP handler was cancelled mid-uninstall (client
    // disconnect, axum shutdown); the `spawn_blocking` task
    // keeps running detached and can still be racing a
    // concurrent `start_plugin_instance` that has since
    // re-acquired the mutex. Owning the guard for the whole
    // blocking closure keeps the reservation alive until the
    // real work completes, cancellation or not.
    let lifecycle_lock = state.engine.plugin_lifecycle_lock(&plugin_id);
    let guard = lifecycle_lock.lock_owned().await;
    let running: Vec<String> = state
        .engine
        .instances()
        .list()
        .into_iter()
        .filter(|h| h.plugin_id() == plugin_id)
        .map(|h| h.instance_id().to_string())
        .collect();
    if !running.is_empty() {
        return Err(PluginLifecycleError::InstancesRunning(running));
    }
    // H2: `Engine::uninstall_plugin` composes per-install
    // KV/blob purge + registry tombstone (in that order — see
    // H2 round-2 F2) so a subsequent reinstall of the same
    // `plugin_id` starts with an empty per-instance keyspace.
    let engine = state.engine.clone();
    let id_for_blocking = plugin_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        engine.uninstall_plugin(&id_for_blocking)
    })
    .await
    .map_err(|err| PluginLifecycleError::Internal(err.into()))?;
    result?;
    Ok(Json(UninstalledRow { plugin_id }))
}

/// Mapped error taxonomy for the install / start / stop /
/// uninstall handlers. Each variant lands on a distinct HTTP
/// status so a caller can tell "plugin not installed" from
/// "instances still running" from "transient IO error".
enum PluginLifecycleError {
    Scope(ScopeDenied),
    /// Plugin not installed (start, uninstall) or — for install —
    /// the source dir doesn't exist.
    NotFound,
    /// `<plugins_root>/<plugin_id>/` already exists (install).
    AlreadyInstalled(String),
    /// One or more instances of the plugin are still running
    /// (uninstall). Carries the offending instance ids so the
    /// caller can `POST .../stop` and retry.
    InstancesRunning(Vec<String>),
    /// 400-class manifest / source-dir validation error from the
    /// install path.
    BadInstall(String),
    /// Follow-up review H1: caller-supplied `instance_id` failed
    /// the FS-segment safety check (empty, path traversal,
    /// absolute path, contains a NUL). Rejected with 400 before
    /// the id ever reaches `start_instance` / the KV/blob store.
    BadInstanceId(String),
    /// Internal failure that doesn't fit the buckets above. 500.
    Internal(anyhow::Error),
    /// `start_instance` or `wait_for_running` returned Err — the
    /// supervisor either failed to load the plugin or it crashed
    /// before reaching Running. 500.
    Start(anyhow::Error),
    /// In-memory engines have no plugins root. 503.
    NoPluginsRoot,
    /// Stop: some instances weren't reaped within
    /// [`crate::STOP_WAIT_LIMIT`]. 504; they keep stopping.
    StopTimedOut {
        stopped: Vec<String>,
        stopping: Vec<String>,
    },
}

impl From<ScopeDenied> for PluginLifecycleError {
    fn from(s: ScopeDenied) -> Self {
        Self::Scope(s)
    }
}

impl From<InstallError> for PluginLifecycleError {
    fn from(err: InstallError) -> Self {
        match err {
            InstallError::NoPluginsRoot => Self::NoPluginsRoot,
            InstallError::SourceMissing(_) => Self::NotFound,
            InstallError::AlreadyInstalled { plugin_id } => Self::AlreadyInstalled(plugin_id),
            InstallError::InvalidSource { reason, .. } => {
                Self::BadInstall(format!("source_dir {reason}"))
            }
            InstallError::BadManifest { reason, .. } => Self::BadInstall(reason),
            InstallError::Io(err) => Self::Internal(err.into()),
            // C1b: the `plugin_installation` INSERT failed. Surface
            // as `Internal` — the operator sees 500 + a log entry;
            // the FS side effect was rolled back by
            // `InstalledPluginRegistry::install`.
            InstallError::Persistence(err) => Self::Internal(err.into()),
        }
    }
}

impl From<UninstallError> for PluginLifecycleError {
    fn from(err: UninstallError) -> Self {
        match err {
            UninstallError::NoPluginsRoot => Self::NoPluginsRoot,
            UninstallError::NotInstalled(_) => Self::NotFound,
            UninstallError::Io(err) => Self::Internal(err.into()),
            // C1b: tombstone UPDATE failed. Surface as `Internal`;
            // the FS is untouched (tombstone happens *before* the
            // `remove_dir_all`), so the operator can retry.
            UninstallError::Persistence(err) => Self::Internal(err.into()),
        }
    }
}

impl IntoResponse for PluginLifecycleError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Scope(s) => s.into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            Self::AlreadyInstalled(id) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "already_installed", "plugin_id": id})),
            )
                .into_response(),
            Self::InstancesRunning(ids) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "instances_running", "instance_ids": ids})),
            )
                .into_response(),
            Self::BadInstall(reason) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "bad_install", "reason": reason})),
            )
                .into_response(),
            Self::BadInstanceId(id) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "bad_instance_id",
                    "reason": format!(
                        "instance_id {id:?} is unsafe for use as a filesystem segment, \
                         or contains `{}` (reserved for script sandboxes)",
                        crate::runtime::SANDBOX_SEPARATOR,
                    ),
                })),
            )
                .into_response(),
            Self::Internal(err) => {
                tracing::error!(target: "api.plugins", error = %err, "plugin lifecycle internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            Self::Start(err) => {
                tracing::error!(target: "api.plugins", error = %err, "plugin start failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "start_failed", "reason": err.to_string()})),
                )
                    .into_response()
            }
            Self::NoPluginsRoot => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "no_plugins_root"})),
            )
                .into_response(),
            Self::StopTimedOut { stopped, stopping } => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "stop_timed_out",
                    "reason": format!(
                        "instances still stopping after {} s; they finish in the background",
                        crate::STOP_WAIT_LIMIT.as_secs(),
                    ),
                    "stopped": stopped,
                    "stopping": stopping,
                })),
            )
                .into_response(),
        }
    }
}

// ── Plugin UI (sandboxed iframe wrapper + ticketed frame) ────────

/// C6 round-2 finding 1: `POST /api/v1/plugins/{plugin_id}/ui-session`
/// — bearer-gated JSON endpoint that mints a short-lived
/// HMAC ticket and returns the wrapper URL for the
/// dashboard to hand off as an iframe `src`. This is the
/// only path that mints tickets; both `/ui` and
/// `/ui/frame` verify them.
///
/// The dashboard flow:
/// 1. Dashboard (holds bearer) `POST`s here and reads
///    `{"url": ".../ui?tk=<t>", "expires_ms": …}`.
/// 2. Dashboard renders `<iframe src=<url>>` (or opens
///    `window.open(url)`) — no bearer in the request the
///    browser makes, because it can't attach one to an
///    iframe / top-level navigation.
/// 3. `/ui` verifies the ticket, returns the sandboxed
///    wrapper HTML which embeds the same ticket into the
///    inner `<iframe sandbox src=".../ui/frame?tk=<t>">`.
/// 4. `/ui/frame` verifies the ticket again and serves
///    the plugin's UI assets.
///
/// # Errors
/// - `403` scope check failed.
/// - `404` no such installed plugin.
async fn post_plugin_ui_session(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
) -> Result<Response, PluginUiError> {
    require(
        &ctx,
        Action::PluginUi,
        &Resource::plugin(plugin_id.as_str()),
    )?;
    let Some(installed) = state.engine.installed_plugins().get(&plugin_id) else {
        return Err(PluginUiError::NotFound);
    };
    let secret = state.engine.ui_ticket_secret();
    let now = std::time::SystemTime::now();
    let ticket = ui_ticket::issue(&secret, &plugin_id, &installed.installation_uuid, now);
    let url = format!(
        "/api/v1/plugins/{}/ui?tk={}",
        percent_encode_path_segment(&plugin_id),
        percent_encode_query_value(&ticket),
    );
    let expires_ms = now
        .checked_add(ui_ticket::TICKET_TTL)
        .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let mut response = Json(UiSessionBody { url, expires_ms }).into_response();
    // Round-3 finding 2: the session response body carries
    // a freshly-minted ticket. HTTP caches must not store
    // it (RFC 9111) — a shared proxy that replayed this
    // body would hand every subsequent caller a
    // still-valid ticket authorising the plugin UI.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Serialize)]
struct UiSessionBody {
    /// Ticketed URL the dashboard hands to the browser as
    /// an iframe `src` (or `window.open` argument).
    url: String,
    /// Absolute Unix-epoch expiry (milliseconds) — clients
    /// can pre-emptively refresh before this deadline.
    expires_ms: u64,
}

/// C6 round-2 finding 1: `GET /api/v1/plugins/{plugin_id}/ui`
/// — sandboxed-iframe wrapper page. Ticket-gated (no
/// bearer possible from a browser document navigation),
/// verifies `?tk=…` against the per-process secret and the
/// current installation's UUID. The wrapper embeds the
/// same ticket into an inner `<iframe sandbox>` targeting
/// the frame endpoint; the sandbox list omits
/// `allow-same-origin` so the browser assigns each iframe
/// a fresh opaque origin — distinct from the daemon's and
/// from every other plugin's iframe.
///
/// The wrapper's inline broker JS creates a fresh
/// `MessageChannel` per iframe and transfers `port2` on
/// the `oxidhome:init` handshake. All subsequent host↔
/// plugin IPC flows on that port — an origin-based
/// `postMessage` filter would be wrong here (opaque-origin
/// senders all report `origin: "null"`), and per-port
/// binding makes cross-plugin dispatch impossible by
/// construction.
///
/// CSP: `default-src 'none'; frame-src 'self'; script-src
/// 'unsafe-inline'` — inline broker JS is host-controlled,
/// nothing else can load.
///
/// # Errors
/// - `400` ticket missing or malformed.
/// - `401` ticket well-formed but expired.
/// - `404` no such installed plugin, or the ticket is
///   bound to a different `plugin_id` / `installation_uuid`
///   (round-2 finding 2 — an uninstall + reinstall race
///   under the same id fails closed here).
async fn get_plugin_ui(
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    ticket: TicketQuery,
) -> Result<Response, PluginUiError> {
    // Round-3 finding 1: verify the ticket FIRST — any
    // garbage ticket returns 400 uniformly, so an
    // unauthenticated caller can't use `?tk=garbage` to
    // distinguish installed from unknown plugins.
    let Some(ticket_raw) = ticket.tk else {
        return Err(PluginUiError::TicketBad);
    };
    let secret = state.engine.ui_ticket_secret();
    let decoded = match ui_ticket::verify(&secret, &ticket_raw, std::time::SystemTime::now()) {
        Ok(d) => d,
        Err(ui_ticket::TicketError::Bad) => return Err(PluginUiError::TicketBad),
        Err(ui_ticket::TicketError::Expired) => return Err(PluginUiError::TicketExpired),
    };
    // MAC verified. Now compare decoded claims against
    // the URL path + current registry entry. Every branch
    // below surfaces as 404 — same shape as "no such
    // plugin" — so a valid-MAC-but-wrong-target ticket
    // can't be used to enumerate installed ids either.
    if decoded.plugin_id != plugin_id {
        return Err(PluginUiError::NotFound);
    }
    let Some(installed) = state.engine.installed_plugins().get(&plugin_id) else {
        return Err(PluginUiError::NotFound);
    };
    if decoded.installation_uuid != *installed.installation_uuid {
        return Err(PluginUiError::NotFound);
    }
    let src = format!(
        "/api/v1/plugins/{}/ui/frame?tk={}",
        percent_encode_path_segment(&plugin_id),
        percent_encode_query_value(&ticket_raw),
    );
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>plugin ui</title>
</head>
<body>
<iframe
  id="oxidhome-plugin-frame"
  sandbox="allow-scripts allow-forms"
  src="{src_attr}"
  style="border:0;width:100%;height:100vh"
></iframe>
<script>
  // C6 typed postMessage broker. Bound to the iframe's
  // *exact* MessagePort object, transferred at load time;
  // NOT to event.origin (opaque-origin iframes all report
  // origin: "null", so origin can't disambiguate plugins).
  (function () {{
    var iframe = document.getElementById("oxidhome-plugin-frame");
    iframe.addEventListener("load", function () {{
      var channel = new MessageChannel();
      // port1 stays with the host page; port2 is transferred
      // to the sandboxed iframe. All subsequent host <->
      // plugin traffic flows on this dedicated pair — each
      // plugin's iframe holds its own port and cannot reach
      // any other plugin's channel.
      channel.port1.onmessage = function (event) {{
        // TODO(phase-13): route typed message envelopes to
        // the per-plugin capability dispatcher. First-cut
        // shape: {{"type": "state.snapshot" | ..., "req": <id>, ...}}.
        // Every message is bound to `iframe.contentWindow` by
        // *arriving on this specific port*, so per-plugin
        // capability enforcement is trivial: port ⇒ plugin.
      }};
      iframe.contentWindow.postMessage(
        {{ type: "oxidhome:init", plugin_id: "{plugin_js}" }},
        "*",
        [channel.port2],
      );
    }});
  }})();
</script>
</body>
</html>
"#,
        src_attr = html_escape(&src),
        plugin_js = js_string_escape(&plugin_id),
    );
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'none'; frame-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
        ),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("SAMEORIGIN"),
    );
    // Round-3 finding 2: ticket-authenticated responses
    // MUST NOT be cached. HTTP intermediaries would
    // otherwise serve stored 200 (or heuristically
    // cacheable 501) responses past the ticket's expiry
    // or after an uninstall + reinstall rotates the
    // installation UUID (RFC 9111).
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// C6: iframe destination. Loaded by the wrapper page above
/// as a sandboxed subresource → browsers don't propagate
/// the parent's `Authorization` header, so authentication
/// is via the same HMAC ticket in `?tk=…`. Round-2
/// finding 2: verifies the ticket's baked-in
/// `installation_uuid` against the current registry entry
/// so an uninstall + reinstall under the same
/// `plugin_id` doesn't let an old ticket authorise the
/// replacement package.
///
/// Stub in the first cut — real UI assets land in Phase 13.
///
/// # Errors
/// - `400` ticket missing or malformed.
/// - `401` ticket well-formed but expired.
/// - `404` unknown plugin, or ticket bound to a different
///   `plugin_id` / `installation_uuid`.
/// - `501` plugin exists + ticket valid; UI assets not yet
///   implemented.
async fn get_plugin_ui_frame(
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    ticket: TicketQuery,
) -> Result<Response, PluginUiError> {
    // Round-3 finding 1: same verify-before-lookup order
    // as `/ui`.
    let Some(ticket_raw) = ticket.tk else {
        return Err(PluginUiError::TicketBad);
    };
    let secret = state.engine.ui_ticket_secret();
    let decoded = match ui_ticket::verify(&secret, &ticket_raw, std::time::SystemTime::now()) {
        Ok(d) => d,
        Err(ui_ticket::TicketError::Bad) => return Err(PluginUiError::TicketBad),
        Err(ui_ticket::TicketError::Expired) => return Err(PluginUiError::TicketExpired),
    };
    if decoded.plugin_id != plugin_id {
        return Err(PluginUiError::NotFound);
    }
    let Some(installed) = state.engine.installed_plugins().get(&plugin_id) else {
        return Err(PluginUiError::NotFound);
    };
    if decoded.installation_uuid != *installed.installation_uuid {
        return Err(PluginUiError::NotFound);
    }
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        "plugin UI assets are a Phase 13 follow-up",
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("SAMEORIGIN"),
    );
    // Round-3 finding 2: ticket-authenticated responses
    // MUST NOT be cached. HTTP intermediaries would
    // otherwise serve stored 200 (or heuristically
    // cacheable 501) responses past the ticket's expiry
    // or after an uninstall + reinstall rotates the
    // installation UUID (RFC 9111).
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// C6 round-4 finding 2: custom extractor for the ticket
/// query param that bounds the raw query string length
/// **before** allocating or URL-decoding. Pre-fix,
/// `Query<TicketParams>` ran serde deserialization first
/// — an unauthenticated request could ship a `tk=…` value
/// up to the HTTP request-head limit (hyper defaults are
/// KiB-scale) and force an owned `String` allocation plus
/// percent-decoding, all before our `MAX_TICKET_LEN` check
/// on the frame endpoint. Bounding at
/// `parts.uri.query()` — a borrowed `&str` slice into the
/// pre-parsed URI, no alloc — moves the size cap ahead of
/// any attacker-controlled allocation.
///
/// The bound (`MAX_UI_QUERY_LEN`) is
/// `MAX_TICKET_LEN + "tk=".len()` so a valid ticket
/// always fits and any query longer than that is
/// rejected wholesale.
struct TicketQuery {
    tk: Option<String>,
}

const MAX_UI_QUERY_LEN: usize = ui_ticket::MAX_TICKET_LEN + b"tk=".len();

impl<S> axum::extract::FromRequestParts<S> for TicketQuery
where
    S: Send + Sync,
{
    type Rejection = PluginUiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or("");
        if query.len() > MAX_UI_QUERY_LEN {
            return Err(PluginUiError::TicketBad);
        }
        // Query is bounded — safe to parse now. Ticket
        // chars are all URL-safe (`~`, digits, hex, hyphens,
        // dots) so no percent-decoding is expected; if the
        // caller sends a percent-encoded ticket the raw
        // bytes will fail HMAC verify, which is the correct
        // outcome (`Bad`).
        let mut tk: Option<String> = None;
        for pair in query.split('&') {
            let Some(value) = pair.strip_prefix("tk=") else {
                continue;
            };
            // Last-`tk` wins, matching serde_urlencoded's
            // Option<T> shape.
            tk = Some(value.to_string());
        }
        Ok(Self { tk })
    }
}

/// C6: handler-local error type for the two UI endpoints.
enum PluginUiError {
    Scope(ScopeDenied),
    NotFound,
    TicketBad,
    TicketExpired,
}

impl From<ScopeDenied> for PluginUiError {
    fn from(value: ScopeDenied) -> Self {
        Self::Scope(value)
    }
}

impl IntoResponse for PluginUiError {
    fn into_response(self) -> Response {
        let mut response = match self {
            // Round-3 finding 2: scope-denied responses go
            // through the shared 403 shape without our
            // Cache-Control stamp — they aren't
            // ticket-authenticated and don't leak
            // anything cacheable-across-request either.
            Self::Scope(s) => return s.into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            // Round-3 finding 3: recovery is `POST
            // /api/v1/plugins/{id}/ui-session` (bearer + the
            // `plugins:ui` scope) — `/ui` no longer mints
            // tickets, it consumes them.
            Self::TicketBad => (
                StatusCode::BAD_REQUEST,
                "invalid or missing `tk` — POST /api/v1/plugins/{plugin_id}/ui-session to mint a fresh ticket",
            )
                .into_response(),
            Self::TicketExpired => (
                StatusCode::UNAUTHORIZED,
                "ticket expired — POST /api/v1/plugins/{plugin_id}/ui-session to mint a fresh one",
            )
                .into_response(),
        };
        // Round-3 finding 2: error responses are cacheable
        // by default too (RFC 9110 marks 404 as
        // heuristically cacheable, and 501 explicitly so).
        // Stamp `no-store` uniformly so a shared proxy
        // can't replay a stale ticket-error response past
        // the failure that produced it.
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }
}

/// C6: percent-encode a value destined for a URL path
/// segment (`plugin_id` in the iframe `src`). Encodes every
/// byte outside the RFC 3986 "unreserved" set — the
/// manifest validator restricts `plugin_id` to `[a-z0-9.-]+`
/// which are all unreserved, but defence-in-depth: a future
/// relaxation shouldn't let a `plugin_id` smuggle URL syntax
/// (`?`, `#`, `/`, `..`) into the wrapper page's iframe src.
fn percent_encode_path_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if is_url_unreserved(b) {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// C6: percent-encode a value destined for a URL query
/// value (the ticket in `?tk=…`). Same encoding as
/// `percent_encode_path_segment` — the ticket format uses
/// `~` (unreserved) and hex digits, but we don't want to
/// bake that assumption into the wrapper page's HTML.
fn percent_encode_query_value(input: &str) -> String {
    percent_encode_path_segment(input)
}

/// RFC 3986 §2.3 unreserved characters: `A-Z a-z 0-9 - . _ ~`.
fn is_url_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// C6: HTML-attribute-value escape — the src attribute
/// lives inside double quotes, so `&`, `<`, `>`, `"`, and
/// `'` all need entity encoding. Percent-encoded `plugin_id`
/// / ticket already avoid the special ASCII, but the
/// escape is here so a template edit that drops
/// percent-encoding doesn't silently open an injection.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// C6: JS-string-literal escape for the `plugin_id` embedded
/// as `"..."` in the broker init. Escapes `\`, quotes,
/// newlines, and `</` (which would prematurely close the
/// `<script>` block if a `plugin_id` ever contained it).
fn js_string_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            other => out.push(other),
        }
    }
    out
}

// ── Events tail (WebSocket) ──────────────────────────────────────

/// `GET /api/v1/events/tail[?after_id=N]` — WebSocket upgrade that
/// streams every bus event to the client as a JSON text frame. Gated
/// on `events:tail`; `after_id` also needs `events:read`, since it
/// replays history. Filter parameters (`--filter device=…`, topic
/// prefix) are a follow-up; v1 streams everything and lets the
/// client filter.
///
/// Frames (H4; see [`crate::state::EventTail`] and ARCHITECTURE.md
/// "Event delivery"):
///
/// - an event ([`WireEvent`]), with `id` when it is in history;
/// - `{"lagged": N, "resume_after_id": ID}` — the subscriber queue
///   dropped `N` events; `ID` (absent if no event with an id was
///   delivered yet) is the cursor to reopen with. A stream opened
///   with `after_id` re-reads dropped recorded events from history
///   itself;
/// - `{"cursor_expired": {"after_id", "oldest_id", "head_id"}}` —
///   the cursor can't be resumed without a gap; the server then
///   closes the socket. Reopen with `after_id = head_id`, then
///   rebuild device state from the state snapshot and its revision
///   cursor.
///
/// With `after_id` the stream delivers every history row with
/// `id > after_id` exactly once and in id order, then continues live;
/// an accepted cursor is acknowledged by the `oxidhome-resume-after-id`
/// header on the 101.
///
/// **Ordering note.** Axum runs extractors in declaration order; a
/// non-WS request rejects at `WebSocketUpgrade` with **426
/// Upgrade Required** (no `OnUpgrade` in request extensions)
/// *before* the scope check runs. That's a deliberate
/// information-leak property: a probing caller without
/// `events:tail` and without a proper WS handshake gets the same
/// 426 a wrong-method probe would, so they can't distinguish
/// "scope missing" from "wrong shape". Real WS handshakes (the
/// only ones operators actually send) reach the handler body and
/// get the 403 they should.
///
/// **Audit consequence.** A non-WS probe (426) never reaches the
/// handler body, so `emit_audit` doesn't run — non-WS requests to
/// this path leave no audit row. Real WS handshakes (success or
/// scope-deny) are audited normally. This is the same shape as
/// the `WWW-Authenticate: Bearer` 401 from `require_token`: failed
/// extractor → no audit because there's no authenticated request
/// to record. Documenting so a future audit-completeness audit
/// doesn't read it as a gap.
async fn tail_events(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    upgrade: WebSocketUpgrade,
    Query(params): Query<TailParams>,
) -> Result<axum::response::Response, ScopeDenied> {
    require(&ctx, Action::EventSubscribe, &Resource::events())?;
    if params.after_id.is_some() {
        require(&ctx, Action::EventRead, &Resource::events())?;
    }
    // H5 review P1 F1: subscribe to the bus BEFORE the 101 upgrade
    // response goes back to the client, so a client that saw 101
    // and then queried `GET /api/v1/events` can't lose an event
    // published in between. `EventTail::open` subscribes (and, with
    // a cursor, resolves it against history) before returning.
    let tail = match crate::state::EventTail::open(
        &state.engine.events(),
        state.engine.event_log(),
        params.after_id,
        "http-tail",
    )
    .await
    {
        Ok(tail) => tail,
        Err(err) => {
            tracing::error!(target: "api.events", error = %err, "events tail open failed");
            return Ok(
                (StatusCode::SERVICE_UNAVAILABLE, "event history unavailable").into_response(),
            );
        }
    };
    let resume_after_id = tail.resume_after_id();
    // M7: live and replayed events alike withhold `bytes-val`
    // payloads unless the caller holds `blobs:read`.
    let blobs = can_read_blobs(&ctx);
    let mut response = upgrade.on_upgrade(move |socket| tail_events_loop(socket, tail, blobs));
    if let Some(id) = resume_after_id {
        response
            .headers_mut()
            .insert(RESUME_AFTER_ID_HEADER, axum::http::HeaderValue::from(id));
    }
    Ok(response)
}

/// H4: response header acknowledging an accepted `after_id` on the
/// event tails (WebSocket 101 and Connect `TailEvents`), carrying the
/// resolved cursor. Absent on live-only streams, on expired cursors
/// (whose stream carries only `cursor_expired`), and on servers that
/// predate cursor resume.
pub(crate) const RESUME_AFTER_ID_HEADER: &str = "oxidhome-resume-after-id";

/// Query string for `GET /api/v1/events/tail`.
#[derive(Deserialize)]
struct TailParams {
    /// H4 resume cursor: replay history rows with `id > after_id`,
    /// then continue live. `0` starts at the oldest retained row.
    after_id: Option<u64>,
}

/// One [`crate::state::EventTail::next`] step that owns the tail, so
/// the WebSocket loop can keep the same step running across client
/// frames.
async fn tail_step(
    mut tail: crate::state::EventTail,
) -> (
    crate::state::EventTail,
    Result<Option<crate::state::TailItem>, crate::state::TailError>,
) {
    let item = tail.next().await;
    (tail, item)
}

async fn tail_events_loop(mut socket: WebSocket, tail: crate::state::EventTail, blobs: bool) {
    use crate::state::TailItem;
    use axum::extract::ws::{CloseFrame, Message};
    // C2e: per-subscriber mpsc queue. The tail ends when the bus
    // drops (engine shutdown). Drops due to a slow WebSocket happen
    // *for this subscriber only*.
    //
    // The pending step survives client frames: a Ping must not
    // restart a history read that is already running.
    let mut step = Box::pin(tail_step(tail));
    loop {
        // Select between the tail (events to push) and the socket
        // (client frames + disconnects). Polling `socket.recv()`
        // is what makes axum drive the WS control frames —
        // auto-Pong on client Ping, Close handling — and what
        // notices a client disconnect *promptly* on quiet event
        // buses rather than waiting for the next publish to find
        // a dead send target.
        tokio::select! {
            (tail, item) = &mut step => {
                step = Box::pin(tail_step(tail));
                let text = match item {
                    Ok(Some(TailItem::Event(event))) => {
                        match serde_json::to_string(&WireEvent::from_host(&event, blobs)) {
                            Ok(text) => text,
                            Err(_) => continue,
                        }
                    }
                    Ok(Some(TailItem::Lagged { skipped, resume_after_id })) => {
                        let mut frame = serde_json::json!({ "lagged": skipped });
                        if let Some(id) = resume_after_id {
                            frame["resume_after_id"] = id.into();
                        }
                        frame.to_string()
                    }
                    Ok(Some(TailItem::CursorExpired(expired))) => {
                        let frame = serde_json::json!({ "cursor_expired": expired });
                        if socket.send(Message::Text(frame.to_string().into())).await.is_ok() {
                            let _ = socket
                                .send(Message::Close(Some(CloseFrame {
                                    code: axum::extract::ws::close_code::NORMAL,
                                    reason: "cursor_expired".into(),
                                })))
                                .await;
                        }
                        break;
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::error!(target: "api.events", error = %err, "events tail stopped");
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: axum::extract::ws::close_code::ERROR,
                                reason: "event history unavailable".into(),
                            })))
                            .await;
                        break;
                    }
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            client = socket.recv() => match client {
                // Client gone (None) or socket error → exit. Close
                // frame is the polite version of the same thing.
                None
                | Some(Err(_) | Ok(Message::Close(_))) => break,
                // Other client frames (Text, Binary, Pong) are
                // ignored; the WS protocol forbids text from the
                // client on this endpoint anyway. `Ping` is
                // handled automatically by axum's WebSocket
                // implementation as part of `recv()` polling.
                Some(Ok(_)) => {}
            },
        }
    }
}

/// JSON wire shape for an event over the WS / future history reads.
/// Deliberately decoupled from the WIT bindgen type (so the WIT
/// regenerates without breaking external clients) and from the
/// `event_log` storage shape (which is private to that module).
#[derive(Serialize)]
pub(crate) struct WireEvent {
    /// H5: the durable `event_log` row id assigned when this event
    /// was persisted. Tail clients use this to reconcile against a
    /// later `GET /api/v1/events` history query across a reconnect.
    /// Absent when the event is not in history: the event-log
    /// mirror was degraded (H3; history gets a `host.event_log.gap`
    /// marker on recovery) or the event came from a host-side
    /// simulator / test harness. Clients don't advance their cursor
    /// on an event without `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    device_id: Option<String>,
    /// Plugin-claimed `unix-ms`. The host's receive-time isn't
    /// available on the live bus (only the durable `event_log`
    /// tracks it); a tailing client treats this as best-effort.
    timestamp_ms: u64,
    /// Capability name for `StateChanged` / `"button"` /
    /// `"inference"` for those variants, or the custom-event topic
    /// for `Custom`. Mirrors `EventBus::subscribe`'s topic match.
    topic: String,
    /// Plugin id of the publisher — host-populated on publish
    /// (architecture-review C2b), immutable. Lets a subscriber
    /// distinguish legitimate events from forgeries without having
    /// to trust the payload.
    origin_plugin_id: String,
    /// Instance id of the publishing plugin instance. Same host-
    /// populated / immutable contract as `origin_plugin_id`.
    origin_instance_id: String,
    payload: WireEventPayload,
}

/// H5 review round-2 P1 F3: wire projection has parity with the
/// WIT `event-payload` record — `StateChanged` carries the
/// changed `fields` (not just the capability tag) so a client
/// tailing / replaying history can actually observe brightness /
/// switch-state / temperature changes; `Inference` carries the
/// `frame_timestamp` when present. The pre-fix projection kept
/// only the capability tag and the raw `Inference.model` /
/// `Inference.payload`, so history reads of state-change events
/// were effectively empty and tail readers couldn't distinguish
/// two `StateChanged("switch")` publishes with different values.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WireEventPayload {
    StateChanged {
        capability: String,
        /// Partial-state key/value pairs the plugin supplied
        /// with the change. Mirrors WIT `state-change.fields`.
        /// Empty when the plugin published a capability-only
        /// change (rare, but legal).
        fields: Vec<WireKeyValue>,
    },
    Button {
        /// One of `"pressed"` / `"released"` / `"single_press"`
        /// / `"double_press"` / `"long_press"` / `"rotated"`.
        /// Matches the WIT `button-event` variant 1:1.
        variant: &'static str,
        /// Rotational delta (positive = clockwise), only set on
        /// the `"rotated"` variant per the WIT comment on
        /// `button-event::rotated`. `None` for the discrete
        /// press/release variants.
        #[serde(skip_serializing_if = "Option::is_none")]
        delta: Option<f64>,
    },
    Inference {
        model: String,
        payload: String,
        /// H5 review round-2 P1 F3: source-frame timestamp the
        /// inference tap saw (matches WIT
        /// `inference-result.frame-timestamp`). `None` when
        /// the plugin published without one — some inference
        /// pipelines don't have a well-defined frame time.
        #[serde(skip_serializing_if = "Option::is_none")]
        frame_timestamp_ms: Option<u64>,
    },
    Custom {
        topic: String,
        payload: String,
    },
}

impl WireKeyValue {
    /// H5 review round-2 P1 F3: build a wire `KeyValue` from the
    /// WIT record — reuses the existing `Value → WireValue`
    /// conversion so a single value decoder covers both storage
    /// and event surfaces.
    ///
    /// M7: without `blobs` (the caller's [`can_read_blobs`]) a
    /// `bytes-val` is replaced by the withheld marker.
    fn from_wit(mut kv: KeyValue, blobs: bool) -> Self {
        if !blobs {
            crate::redact::withhold_bytes(&mut kv.value);
        }
        Self {
            key: kv.key,
            value: WireValue::from(kv.value),
        }
    }
}

impl WireEvent {
    fn from_host(event: &Event, blobs: bool) -> Self {
        let id = event.row_id;
        let (topic, payload) = match &event.payload {
            EventPayload::StateChanged(sc) => (
                sc.capability.clone(),
                WireEventPayload::StateChanged {
                    capability: sc.capability.clone(),
                    fields: sc
                        .fields
                        .iter()
                        .cloned()
                        .map(|kv| WireKeyValue::from_wit(kv, blobs))
                        .collect(),
                },
            ),
            EventPayload::Button(b) => {
                let (variant, delta) = match *b {
                    ButtonEvent::Pressed => ("pressed", None),
                    ButtonEvent::Released => ("released", None),
                    ButtonEvent::SinglePress => ("single_press", None),
                    ButtonEvent::DoublePress => ("double_press", None),
                    ButtonEvent::LongPress => ("long_press", None),
                    ButtonEvent::Rotated(d) => ("rotated", Some(d)),
                };
                (
                    "button".to_string(),
                    WireEventPayload::Button { variant, delta },
                )
            }
            EventPayload::Inference(i) => (
                "inference".to_string(),
                WireEventPayload::Inference {
                    model: i.model.clone(),
                    payload: i.payload.clone(),
                    frame_timestamp_ms: i.frame_timestamp,
                },
            ),
            EventPayload::Custom(c) => (
                c.topic.clone(),
                WireEventPayload::Custom {
                    topic: c.topic.clone(),
                    payload: c.payload.clone(),
                },
            ),
        };
        Self {
            id,
            device_id: event.device.clone(),
            timestamp_ms: event.timestamp,
            topic,
            origin_plugin_id: event.origin_plugin_id.clone(),
            origin_instance_id: event.origin_instance_id.clone(),
            payload,
        }
    }
}

// ── Logs query ───────────────────────────────────────────────────

/// Query-string parameters for `GET /api/v1/logs`. All fields are
/// optional and AND-combined (same semantics as
/// [`LogQuery`](crate::state::LogQuery)). `limit` defaults to 100;
/// the handler clamps it to a sane maximum.
#[derive(Deserialize, Default)]
struct LogsParams {
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    min_level: Option<LogLevel>,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    target: Option<String>,
    target_prefix: Option<String>,
    span_path_prefix: Option<String>,
    /// Maximum rows to return. Clamped to `LOGS_QUERY_MAX_LIMIT`;
    /// 0 / missing defaults to `LOGS_QUERY_DEFAULT_LIMIT`.
    limit: Option<u32>,
}

/// Default `limit` when the caller omits one. Matches what
/// `oxidhome logs query` (Phase 12-CLI) will default to.
const LOGS_QUERY_DEFAULT_LIMIT: u32 = 100;

/// Upper bound on a single query's `limit` — guards a misbehaving
/// client from pulling the whole log table in one shot, which
/// would pin the `SQLite` read mutex (and the request thread)
/// for a long time on a busy host. The CLI streams in chunks
/// rather than asking for more than this in a single call.
const LOGS_QUERY_MAX_LIMIT: u32 = 1_000;

/// `GET /api/v1/logs?…` — historical log query against the
/// `LogStore` `SQLite` table. Gated on `logs:read`. Returns rows
/// newest-first (the store's native order).
async fn query_logs(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Query(params): Query<LogsParams>,
) -> Result<Json<LogsBody>, LogsError> {
    require(&ctx, Action::HostLogs, &Resource::Host).map_err(LogsError::Scope)?;
    let limit = params
        .limit
        .unwrap_or(LOGS_QUERY_DEFAULT_LIMIT)
        .clamp(1, LOGS_QUERY_MAX_LIMIT);
    let query = LogQuery {
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        min_level: params.min_level,
        instance_id: params.instance_id,
        plugin_id: params.plugin_id,
        device_id: params.device_id,
        target: params.target,
        target_prefix: params.target_prefix,
        span_path_prefix: params.span_path_prefix,
    };
    let rows =
        run_logs_query(&state.engine.log_store(), &query, limit).map_err(LogsError::Storage)?;
    let logs = rows.into_iter().map(WireLogEvent::from_row).collect();
    Ok(Json(LogsBody { logs }))
}

fn run_logs_query(
    store: &LogStore,
    query: &LogQuery,
    limit: u32,
) -> Result<Vec<HistoricalLogEvent>, crate::state::LogStoreError> {
    // `LogStore::query` takes `usize`; `usize::from(u32)` is only
    // defined on 64+-bit targets. The handler clamps `limit` to
    // `LOGS_QUERY_MAX_LIMIT` (1_000) so any reasonable `usize`
    // width (≥16 bits) holds it; `try_from` keeps it explicit.
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    store.query(query, limit)
}

/// Composite error for `query_logs` so a 403 (scope) and a 500
/// (storage) flow through the same `?` chain without a custom
/// trait juggling.
enum LogsError {
    Scope(ScopeDenied),
    Storage(crate::state::LogStoreError),
}

impl IntoResponse for LogsError {
    fn into_response(self) -> axum::response::Response {
        match self {
            LogsError::Scope(s) => s.into_response(),
            LogsError::Storage(err) => {
                tracing::error!(target: "api.logs", error = %err, "logs query failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

#[derive(Serialize)]
struct LogsBody {
    logs: Vec<WireLogEvent>,
}

#[derive(Serialize)]
struct WireLogEvent {
    id: u64,
    ts_unix_ms: i64,
    level: LogLevel,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    device_id: Option<String>,
    target: String,
    span_path: Option<String>,
    message: String,
    /// Structured fields as `[ [key, JSON-tagged-value], ... ]`.
    /// Tag shape matches the host-side [`LogValue`] enum's serde
    /// repr — clients can deserialize back into the same enum.
    fields: Vec<(String, LogValue)>,
}

impl WireLogEvent {
    fn from_row(row: HistoricalLogEvent) -> Self {
        Self {
            id: row.id,
            ts_unix_ms: row.ts_unix_ms,
            level: row.level,
            instance_id: row.instance_id,
            plugin_id: row.plugin_id,
            device_id: row.device_id,
            target: row.target,
            span_path: row.span_path,
            message: row.message,
            fields: row.fields,
        }
    }
}

// ── Events query (H5) ────────────────────────────────────────────
//
// Historical query against the durable `event_log` table. Pairs
// with the `GET /api/v1/events/tail` live stream: a client can
// reconcile a live tail's `id` field (H5 addition) against a bounded
// historical query without gaps across a reconnect.

/// Query-string parameters for `GET /api/v1/events`. Every field is
/// optional and AND-combined (same semantics as
/// [`crate::state::EventQuery`]). `limit` defaults to 100, clamped
/// to [`EVENTS_QUERY_MAX_LIMIT`]. `topic` uses exact match; use
/// `topic_prefix` for custom-event prefix scans (e.g.
/// `automation.` → every `automation.morning`, `automation.evening`).
#[derive(Deserialize, Default)]
struct EventsParams {
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    device_id: Option<String>,
    instance_id: Option<String>,
    plugin_id: Option<String>,
    topic: Option<String>,
    topic_prefix: Option<String>,
    /// H5 review round-2 P1 F2: durable-id cursor. Return only
    /// rows with `id > after_id`. A tail client that saved the
    /// last seen event id resumes from here — the id is a
    /// monotonic `INTEGER PRIMARY KEY`, so this is safe even
    /// when many events land in the same millisecond. H4: a
    /// cursor whose next row was pruned (or that is ahead of
    /// history) returns `410 Gone` with a `cursor_expired` body;
    /// `0` never expires.
    after_id: Option<u64>,
    /// Complements `after_id`: return only rows with
    /// `id < before_id`. Used to walk backwards through history
    /// for pagination — the caller passes the lowest id
    /// returned by the previous batch.
    before_id: Option<u64>,
    limit: Option<u32>,
}

const EVENTS_QUERY_DEFAULT_LIMIT: u32 = 100;
const EVENTS_QUERY_MAX_LIMIT: u32 = 1_000;

/// `GET /api/v1/events` reads allowed on the blocking pool at once;
/// more answer `503`.
const EVENTS_QUERY_INFLIGHT: usize = 8;
static EVENTS_QUERY_SLOTS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(EVENTS_QUERY_INFLIGHT)));

/// `GET /api/v1/events?…` — historical event query against the
/// `EventLog` `SQLite` table. Gated on `events:read`. Returns rows
/// in descending `id` order (highest first). Under normal
/// operation this is "newest first" since id is a monotonic
/// AUTOINCREMENT (migration 16); under wall-clock skew id
/// still walks stably where `received_ms` would not. Each
/// row carries the same `id` a live tail message includes,
/// so a client that saved the last-seen tail id can resume
/// from `since_ms` or reconcile against `id`.
async fn query_events(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Query(params): Query<EventsParams>,
) -> Result<Json<EventsBody>, EventsError> {
    require(&ctx, Action::EventRead, &Resource::events()).map_err(EventsError::Scope)?;
    let limit = params
        .limit
        .unwrap_or(EVENTS_QUERY_DEFAULT_LIMIT)
        .clamp(1, EVENTS_QUERY_MAX_LIMIT);
    // `topic` (exact) and `topic_prefix` are mutually exclusive —
    // if both are set, prefer prefix (broader) and emit a
    // `tracing::warn` so an operator watching the log can spot
    // the ambiguous client. The comment used to claim the
    // ambiguity was logged; PR #103 review noted the log was
    // missing.
    let topic = match (params.topic, params.topic_prefix) {
        (topic_exact, Some(p)) => {
            if let Some(exact) = &topic_exact {
                tracing::warn!(
                    target: "api.events",
                    topic_exact = %exact,
                    topic_prefix = %p,
                    "GET /api/v1/events: both `topic` and `topic_prefix` supplied — using `topic_prefix`",
                );
            }
            Some((p, TopicMatch::Prefix))
        }
        (Some(t), None) => Some((t, TopicMatch::Exact)),
        (None, None) => None,
    };
    let query = EventQuery {
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        device_id: params.device_id,
        instance_id: params.instance_id,
        plugin_id: params.plugin_id,
        topic,
        after_id: params.after_id,
        before_id: params.before_id,
        order: crate::state::EventOrder::Desc,
    };
    // H4: the query and the `after_id` check share one connection
    // lock, so a pruned (or future) cursor is reported, not skipped.
    // Off the async workers: both hold the shared database mutex.
    // At most `EVENTS_QUERY_INFLIGHT` reads queued on the blocking
    // pool; the permit moves into the closure, so a cancelled request
    // still holds it until its read finishes.
    let permit = Arc::clone(&EVENTS_QUERY_SLOTS)
        .try_acquire_owned()
        .map_err(|_| EventsError::Busy)?;
    let event_log = state.engine.event_log();
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let rows = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        event_log.query_after_cursor(&query, limit)
    })
    .await
    .map_err(|_| EventsError::Join)?
    .map_err(EventsError::Storage)?
    .map_err(EventsError::CursorExpired)?;
    let events = rows
        .into_iter()
        .map(|row| WireHistoricalEvent::from_row(row, can_read_blobs(&ctx)))
        .collect();
    Ok(Json(EventsBody { events }))
}

enum EventsError {
    Scope(ScopeDenied),
    Storage(EventLogError),
    Join,
    Busy,
    CursorExpired(crate::state::CursorExpired),
}

impl IntoResponse for EventsError {
    fn into_response(self) -> axum::response::Response {
        match self {
            EventsError::Scope(s) => s.into_response(),
            EventsError::Storage(err) => {
                tracing::error!(target: "api.events", error = %err, "events query failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            EventsError::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "event history busy; retry shortly",
            )
                .into_response(),
            EventsError::Join => {
                tracing::error!(target: "api.events", "events query task failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            // Same body as the tail's `cursor_expired` frame.
            EventsError::CursorExpired(expired) => (
                StatusCode::GONE,
                Json(serde_json::json!({ "cursor_expired": expired })),
            )
                .into_response(),
        }
    }
}

#[derive(Serialize)]
struct EventsBody {
    events: Vec<WireHistoricalEvent>,
}

/// JSON wire shape for a historical event row. Carries the same
/// payload variant tags [`WireEvent`] uses so a client can decode
/// tail messages + history rows with one code path — the extra
/// fields (`received_ms`, `payload_ms`, `instance_id`, `plugin_id`)
/// are the host-owned metadata the durable log tracks that the
/// live wire shape doesn't.
#[derive(Serialize)]
pub(crate) struct WireHistoricalEvent {
    id: u64,
    received_ms: i64,
    payload_ms: u64,
    device_id: Option<String>,
    instance_id: String,
    plugin_id: String,
    topic: String,
    payload: WireEventPayload,
}

impl WireHistoricalEvent {
    pub(crate) fn from_row(row: HistoricalEvent, blobs: bool) -> Self {
        // Build a scratch `Event` so `WireEvent::from_host`'s
        // payload-projection logic can be reused. The event's
        // `origin_*` / `timestamp` fields are populated from
        // the corresponding host-attributed columns on `row`
        // (`plugin_id`, `instance_id`, `payload_ms`) so the
        // wire projection sees the same identity + timestamp
        // shape it would for a live tail event.
        let ev = Event {
            device: row.device_id.clone(),
            timestamp: row.payload_ms,
            origin_plugin_id: row.plugin_id.clone(),
            origin_instance_id: row.instance_id.clone(),
            row_id: Some(row.id),
            payload: row.payload,
        };
        // Reuse the tail-side payload projection so a single
        // client codec handles both live tail + history reads.
        let wire = WireEvent::from_host(&ev, blobs);
        Self {
            id: row.id,
            received_ms: row.received_ms,
            payload_ms: row.payload_ms,
            device_id: wire.device_id,
            instance_id: row.instance_id,
            plugin_id: row.plugin_id,
            topic: row.topic,
            payload: wire.payload,
        }
    }
}

// ── Audit query ──────────────────────────────────────────────────
//
// The C3 dedicated audit ledger (`AuditLog`) is the forensic source
// of truth for every authenticated API request. Pre-C3-followup
// operators queried the ledger indirectly through the `LogStore`
// via `/api/v1/logs?target_prefix=api.audit` (a tracing mirror the
// middleware emitted alongside the ledger insert), and that mirror
// is now gone — the ledger is the sole audit source. This endpoint
// is its query surface.

/// Query-string parameters for `GET /api/v1/audit`. All fields are
/// optional and AND-combined ([`AuditQuery`] semantics). `limit`
/// defaults to 100; the handler clamps it to a sane maximum.
#[derive(Deserialize, Default)]
struct AuditParams {
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    token_id: Option<String>,
    decision: Option<String>,
    /// Exact `path` match — the forensic drill-down for a
    /// specific endpoint, e.g.
    /// `path=/api/v1/devices/dev-abc/command`.
    path: Option<String>,
    /// Exact `call_id` match (H6) — the entry point's row plus every
    /// delegated `call-service` hop it caused.
    call_id: Option<String>,
    /// Cursor for lossless pagination. Opaque `"<intent_ms>:<id>"`
    /// string returned as `next_cursor` on the previous page.
    /// Callers should not construct it by hand — pass the previous
    /// response's `next_cursor` verbatim.
    before: Option<String>,
    limit: Option<u32>,
}

const AUDIT_QUERY_DEFAULT_LIMIT: u32 = 100;
const AUDIT_QUERY_MAX_LIMIT: u32 = 1_000;

/// `GET /api/v1/audit?…` — historical audit query against the
/// dedicated C3 `audit_event` `SQLite` table. Gated on
/// `audit:read`. Returns rows newest-first with a `next_cursor`
/// for lossless pagination.
async fn query_audit(
    Extension(ctx): Extension<InvocationContext>,
    Extension(self_id): Extension<crate::api::auth::AuditIntentId>,
    State(state): State<ApiState>,
    Query(params): Query<AuditParams>,
) -> Result<Json<AuditBody>, AuditError> {
    require(&ctx, Action::HostAudit, &Resource::Host).map_err(AuditError::Scope)?;
    let limit = params
        .limit
        .unwrap_or(AUDIT_QUERY_DEFAULT_LIMIT)
        .clamp(1, AUDIT_QUERY_MAX_LIMIT);
    // Parse the opaque cursor. Bad shape is a 400 rather than
    // silently ignored, so a client that constructs one by hand and
    // gets it wrong learns immediately.
    let before = params
        .before
        .as_deref()
        .map(parse_audit_cursor)
        .transpose()
        .map_err(AuditError::BadCursor)?;
    let query = AuditQuery {
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        token_id: params.token_id,
        decision: params.decision,
        path: params.path,
        call_id: params.call_id,
        before,
        // F3 self-exclusion: hide the query's own pending intent
        // row from its results.
        exclude_id: Some(self_id.0),
    };
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    // `AuditLog::query` grabs the shared `std::sync::Mutex` on the
    // `Db` connection and decodes up to `AUDIT_QUERY_MAX_LIMIT`
    // rows synchronously. Doing that directly from an async
    // context would park the tokio worker under contention — the
    // AuditLog contract explicitly requires callers to hop to the
    // blocking pool (see `state::audit_log` module doc).
    let audit_log = state.engine.audit_log();
    let rows = tokio::task::spawn_blocking(move || audit_log.query(&query, limit_usize))
        .await
        .map_err(|join_err| {
            tracing::error!(
                target: "api.audit",
                error = %join_err,
                "audit query blocking task panicked",
            );
            AuditError::Storage(crate::state::AuditLogError::Sql(
                rusqlite::Error::InvalidQuery,
            ))
        })?
        .map_err(AuditError::Storage)?;
    // Cursor for the next page — the last row's (intent_ms, id).
    // If we returned fewer rows than the caller's limit, there's
    // nothing more to paginate through, so leave `next_cursor` at
    // `None` so callers don't loop forever.
    let next_cursor = if rows.len() == limit_usize {
        rows.last()
            .map(|last| format!("{}:{}", last.intent_ms, last.id))
    } else {
        None
    };
    let audit = rows.into_iter().map(WireAuditEntry::from_row).collect();
    Ok(Json(AuditBody { audit, next_cursor }))
}

/// Parse the opaque `<intent_ms>:<id>` cursor string. Both halves
/// must be integers; either malformed and the endpoint returns
/// 400 rather than silently ignore the cursor and hand back
/// unfiltered rows.
fn parse_audit_cursor(s: &str) -> Result<(i64, u64), &'static str> {
    let (ms, id) = s
        .split_once(':')
        .ok_or("cursor must be `<intent_ms>:<id>`")?;
    let ms: i64 = ms.parse().map_err(|_| "cursor intent_ms must be an i64")?;
    let id: u64 = id.parse().map_err(|_| "cursor id must be a u64")?;
    Ok((ms, id))
}

enum AuditError {
    Scope(ScopeDenied),
    Storage(crate::state::AuditLogError),
    BadCursor(&'static str),
}

impl IntoResponse for AuditError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuditError::Scope(s) => s.into_response(),
            AuditError::Storage(err) => {
                tracing::error!(target: "api.audit", error = %err, "audit query failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            AuditError::BadCursor(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
        }
    }
}

#[derive(Serialize)]
struct AuditBody {
    audit: Vec<WireAuditEntry>,
    /// Opaque `"<intent_ms>:<id>"` pagination cursor. When present,
    /// the caller passes it back as `?before=…` to fetch the next
    /// page. `None` indicates the last page (`rows.len() < limit`).
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct WireAuditEntry {
    id: u64,
    intent_ms: i64,
    finalized_ms: Option<i64>,
    token_id: String,
    actor_kind: String,
    method: String,
    path: String,
    status: u16,
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_fp: Option<String>,
    /// H6 invocation id shared by an entry point's row and its
    /// downstream `CALL` rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    /// H6 invocation context (root principal + delegation chain),
    /// decoded from the ledger's JSON column.
    #[serde(skip_serializing_if = "Option::is_none")]
    invocation: Option<serde_json::Value>,
    /// H5 device-command id, on command-dispatch rows and their
    /// `COMMAND` resolution rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    command_id: Option<String>,
    /// H5 explicit command outcome for `command_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    command_outcome: Option<String>,
}

impl WireAuditEntry {
    fn from_row(row: crate::state::AuditEntry) -> Self {
        Self {
            id: row.id,
            intent_ms: row.intent_ms,
            finalized_ms: row.finalized_ms,
            token_id: row.token_id,
            actor_kind: row.actor_kind,
            method: row.method,
            path: row.path,
            status: row.status,
            decision: row.decision,
            required_scope: row.required_scope,
            execution_outcome: row.execution_outcome,
            domain_error: row.domain_error,
            credential_fp: row.credential_fp,
            call_id: row.call_id,
            invocation: row
                .invocation
                .as_deref()
                .and_then(|j| serde_json::from_str(j).ok()),
            command_id: row.command_id,
            command_outcome: row.command_outcome,
        }
    }
}

// ── Dashboards (Phase 13 slice 3) ────────────────────────────────

/// C6 round-2 finding 2: stable owner id for v1's
/// single-role admin. Actor.id for API actors is the
/// **token id** (rotates when the operator issues a new
/// token) — using it as `owner_user_id` would mean two
/// admin tokens can't see each other's dashboards, and a
/// token rotation strands the operator's rows. The
/// multi-user follow-up replaces this constant with the
/// real session identity, and the migration is a single
/// `UPDATE dashboard SET owner_user_id = <real id> WHERE
/// owner_user_id = 'admin'` — one predicate, one row per
/// admin dashboard.
const DASHBOARD_ADMIN_OWNER: &str = "admin";

/// Wire shape for a dashboard row. `layout` is the shell's
/// opaque JSON tree — represented as `serde_json::Value` so
/// clients can send/receive typed JSON without base64.
#[derive(Debug, Serialize, Deserialize)]
struct WireDashboard {
    id: i64,
    name: String,
    owner_user_id: String,
    layout: serde_json::Value,
    schema_version: i64,
    created_ms: i64,
    updated_ms: i64,
}

impl WireDashboard {
    fn from_row(row: crate::state::Dashboard) -> Result<Self, DashboardsError> {
        let layout = serde_json::from_slice(&row.layout_json)
            .map_err(|err| DashboardsError::CorruptRow(err.to_string()))?;
        Ok(Self {
            id: row.id,
            name: row.name,
            owner_user_id: row.owner_user_id,
            layout,
            schema_version: row.schema_version,
            created_ms: row.created_ms,
            updated_ms: row.updated_ms,
        })
    }
}

/// Round-2 finding 3: list response omits `layout_json`
/// so the body is bounded by
/// `MAX_DASHBOARDS_PER_OWNER × (name + fixed metadata)`
/// regardless of layout size. Clients fetch the actual
/// layout via `GET /api/v1/dashboards/{id}` when the
/// operator selects one.
#[derive(Debug, Serialize)]
struct WireDashboardMetadata {
    id: i64,
    name: String,
    owner_user_id: String,
    schema_version: i64,
    created_ms: i64,
    updated_ms: i64,
    layout_bytes: usize,
}

impl From<crate::state::dashboards::DashboardMetadata> for WireDashboardMetadata {
    fn from(row: crate::state::dashboards::DashboardMetadata) -> Self {
        Self {
            id: row.id,
            name: row.name,
            owner_user_id: row.owner_user_id,
            schema_version: row.schema_version,
            created_ms: row.created_ms,
            updated_ms: row.updated_ms,
            layout_bytes: row.layout_bytes,
        }
    }
}

/// `POST /api/v1/dashboards` / `PUT /.../{id}` request body.
/// `layout` is the shell's opaque tree; the host encodes it
/// to bytes on the way in and back to `Value` on the way
/// out.
#[derive(Debug, Deserialize)]
struct DashboardInputBody {
    name: String,
    layout: serde_json::Value,
    #[serde(default = "default_schema_version")]
    schema_version: i64,
}

fn default_schema_version() -> i64 {
    1
}

#[derive(Debug, Serialize)]
struct DashboardsBody {
    dashboards: Vec<WireDashboardMetadata>,
}

/// `GET /api/v1/dashboards` — metadata-only list of every
/// dashboard the caller owns (`updated_ms DESC`). The
/// `layout` body is omitted for size — clients fetch it
/// via `GET /dashboards/{id}` when they need it.
///
/// # Errors
/// - `403` scope check failed.
async fn list_dashboards(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
) -> Result<Json<DashboardsBody>, DashboardsError> {
    require(&ctx, Action::DashboardRead, &Resource::dashboards())?;
    let rows = tokio::task::spawn_blocking(move || {
        state
            .engine
            .dashboards()
            .list_metadata_by_owner(DASHBOARD_ADMIN_OWNER)
    })
    .await
    .map_err(|err| DashboardsError::Internal(err.into()))??;
    let dashboards = rows.into_iter().map(WireDashboardMetadata::from).collect();
    Ok(Json(DashboardsBody { dashboards }))
}

/// `POST /api/v1/dashboards` — create a fresh dashboard
/// owned by the caller. Returns the stored row with its
/// server-minted id.
///
/// # Errors
/// - `400` request body isn't valid JSON, or `name` /
///   `layout` exceeds the per-row cap.
/// - `403` scope check failed.
/// - `409` the owner is already at `MAX_DASHBOARDS_PER_OWNER`.
async fn create_dashboard(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Json(body): Json<DashboardInputBody>,
) -> Result<Json<WireDashboard>, DashboardsError> {
    require(&ctx, Action::DashboardWrite, &Resource::dashboards())?;
    let layout_json =
        serde_json::to_vec(&body.layout).map_err(|err| DashboardsError::Internal(err.into()))?;
    let input = crate::state::DashboardInput {
        name: body.name,
        owner_user_id: DASHBOARD_ADMIN_OWNER.to_string(),
        layout_json,
        schema_version: body.schema_version,
    };
    let created = tokio::task::spawn_blocking(move || state.engine.dashboards().create(input))
        .await
        .map_err(|err| DashboardsError::Internal(err.into()))??;
    Ok(Json(WireDashboard::from_row(created)?))
}

/// `GET /api/v1/dashboards/{id}` — load one dashboard the
/// caller owns. Owner-scoped predicate travels inside
/// the SELECT statement; cross-owner reads return 404.
///
/// # Errors
/// - `403` scope check failed.
/// - `404` dashboard doesn't exist OR is owned by a
///   different user.
async fn get_dashboard(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<WireDashboard>, DashboardsError> {
    require(&ctx, Action::DashboardRead, &Resource::dashboard(id))?;
    let row = tokio::task::spawn_blocking(move || {
        state
            .engine
            .dashboards()
            .get_owned(id, DASHBOARD_ADMIN_OWNER)
    })
    .await
    .map_err(|err| DashboardsError::Internal(err.into()))??
    .ok_or(DashboardsError::NotFound)?;
    Ok(Json(WireDashboard::from_row(row)?))
}

/// `PUT /api/v1/dashboards/{id}` — replace the caller's
/// dashboard. Round-2 finding 1: the owner predicate
/// travels **inside** the UPDATE statement (via
/// `store.update_owned`) so a concurrent delete + create
/// that recycles the primary key under a different owner
/// can't be modified by this request.
///
/// # Errors
/// - `400` `name` / `layout` exceeds the per-row cap.
/// - `403` scope check failed.
/// - `404` dashboard doesn't exist OR is owned by a
///   different user.
async fn update_dashboard(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    Json(body): Json<DashboardInputBody>,
) -> Result<Json<WireDashboard>, DashboardsError> {
    require(&ctx, Action::DashboardWrite, &Resource::dashboard(id))?;
    let layout_json =
        serde_json::to_vec(&body.layout).map_err(|err| DashboardsError::Internal(err.into()))?;
    let input = crate::state::DashboardInput {
        name: body.name,
        owner_user_id: DASHBOARD_ADMIN_OWNER.to_string(),
        layout_json,
        schema_version: body.schema_version,
    };
    let updated = tokio::task::spawn_blocking(move || {
        state
            .engine
            .dashboards()
            .update_owned(id, DASHBOARD_ADMIN_OWNER, input)
    })
    .await
    .map_err(|err| DashboardsError::Internal(err.into()))??;
    Ok(Json(WireDashboard::from_row(updated)?))
}

/// `DELETE /api/v1/dashboards/{id}` — remove the caller's
/// dashboard. Owner predicate travels inside the DELETE
/// (round-2 finding 1). Cross-owner attempts return 404
/// (idempotent on the owner path — deleting a dashboard
/// the caller already deleted returns 404).
///
/// # Errors
/// - `403` scope check failed.
/// - `404` dashboard doesn't exist OR is owned by a
///   different user.
async fn delete_dashboard(
    Extension(ctx): Extension<InvocationContext>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, DashboardsError> {
    require(&ctx, Action::DashboardWrite, &Resource::dashboard(id))?;
    let removed = tokio::task::spawn_blocking(move || {
        state
            .engine
            .dashboards()
            .delete_owned(id, DASHBOARD_ADMIN_OWNER)
    })
    .await
    .map_err(|err| DashboardsError::Internal(err.into()))??;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DashboardsError::NotFound)
    }
}

/// Handler-local error type. Errors from the store fold
/// into this via `?`.
enum DashboardsError {
    Scope(ScopeDenied),
    NotFound,
    /// Round-2 finding 3: input violated the per-row cap
    /// or per-owner quota. Wired distinctly from
    /// `Internal` so the client sees 400 / 409 instead of
    /// 500.
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    QuotaExceeded {
        existing: usize,
        max: usize,
    },
    /// `layout_json` on disk doesn't parse as JSON. Should
    /// never happen — the write path always serializes via
    /// `serde_json::to_vec` — but if it does, treat as an
    /// integrity failure.
    CorruptRow(String),
    Internal(anyhow::Error),
}

impl From<ScopeDenied> for DashboardsError {
    fn from(value: ScopeDenied) -> Self {
        Self::Scope(value)
    }
}

impl From<crate::state::DashboardError> for DashboardsError {
    fn from(value: crate::state::DashboardError) -> Self {
        match value {
            crate::state::DashboardError::NotFound(_) => Self::NotFound,
            crate::state::DashboardError::TooLarge { field, size, max } => {
                Self::TooLarge { field, size, max }
            }
            crate::state::DashboardError::QuotaExceeded { existing, max } => {
                Self::QuotaExceeded { existing, max }
            }
            crate::state::DashboardError::Persistence(err) => Self::Internal(err.into()),
        }
    }
}

impl IntoResponse for DashboardsError {
    fn into_response(self) -> Response {
        match self {
            Self::Scope(s) => s.into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "").into_response(),
            Self::TooLarge { field, size, max } => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "too_large",
                    "field": field,
                    "size": size,
                    "max": max,
                })),
            )
                .into_response(),
            Self::QuotaExceeded { existing, max } => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "quota_exceeded",
                    "existing": existing,
                    "max": max,
                })),
            )
                .into_response(),
            Self::CorruptRow(err) => {
                tracing::error!(target: "api.dashboards", error = %err, "corrupt dashboard row");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            Self::Internal(err) => {
                tracing::error!(target: "api.dashboards", error = %err, "dashboard store failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H3 follow-up: a degraded event-log mirror shows on both
    /// anonymous probes, REST `/readyz` and Connect `Health.Check`,
    /// while both keep reporting the daemon itself as up.
    #[tokio::test(flavor = "current_thread")]
    async fn degraded_event_log_shows_on_readyz_and_connect_health() {
        use tower::ServiceExt as _;
        async fn probe(
            router: &Router,
            method: &str,
            uri: &str,
        ) -> (StatusCode, serde_json::Value) {
            let mut req = axum::http::Request::builder().method(method).uri(uri);
            let body = if method == "POST" {
                req = req.header(axum::http::header::CONTENT_TYPE, "application/json");
                axum::body::Body::from("{}")
            } else {
                axum::body::Body::empty()
            };
            let resp = router
                .clone()
                .oneshot(req.body(body).expect("request"))
                .await
                .expect("response");
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("body");
            (status, serde_json::from_slice(&bytes).expect("json"))
        }
        let engine = Engine::new().expect("engine");
        let router = build_router(engine.clone());
        let check = "/oxidhome.v1.HealthService/Check";

        let (code, body) = probe(&router, "POST", check).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["eventLog"], "ok", "{body}");

        engine
            .event_log()
            .degrade_for_test("injected: database or disk is full");
        let (code, body) = probe(&router, "POST", check).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok", "degraded history keeps the daemon up");
        assert_eq!(body["eventLog"], "degraded", "{body}");
        let (code, body) = probe(&router, "GET", "/api/v1/readyz").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["event_log"], "degraded", "{body}");
        assert_eq!(body["device_state"], "ok", "{body}");
        assert_eq!(body["status"], "ok", "{body}");

        // H2: failing device-state flushes show the same way.
        engine
            .device_state()
            .degrade_for_test("injected: disk I/O error");
        let (code, body) = probe(&router, "POST", check).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["deviceState"], "degraded", "{body}");
        let (code, body) = probe(&router, "GET", "/api/v1/readyz").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["device_state"], "degraded", "{body}");
    }

    /// M7 + H5: a `completed` report's `bytes-val` state is withheld
    /// from a caller without `blobs:read` (REST and MCP share this
    /// encoder) and passed through for one with it.
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
        let narrow = serde_json::to_value(WireCommandReport::from_report(report(), false)).unwrap();
        let full = serde_json::to_value(WireCommandReport::from_report(report(), true)).unwrap();
        assert_ne!(narrow["state"]["frame"], full["state"]["frame"], "{narrow}");
        let mut withheld = Value::BytesVal(vec![1, 2, 3]);
        crate::redact::withhold_bytes(&mut withheld);
        let expected: WireValue = withheld.into();
        assert_eq!(
            narrow["state"]["frame"],
            serde_json::to_value(expected).unwrap()
        );
    }
    use crate::host_impl::plugin::oxidhome::plugin::events::{
        ButtonEvent as WitButtonEvent, Event,
    };

    /// `WireEvent::from_host` projects each `ButtonEvent` variant to
    /// the matching `snake_case` string, with `delta` set only on
    /// `Rotated`. Pre-fix the wire shape collapsed every button
    /// event to `variant: "event"` — a UI tailing button events had
    /// no way to distinguish a press from a release.
    /// `WireValue` round-trips losslessly through both directions
    /// of the API: a client posts `{"t":"int","v":5}` and reads
    /// `{"t":"int","v":5}` back from `OkWithState`. Pins the
    /// tagged-shape symmetry so a future code change can't
    /// silently flatten the response side.
    #[test]
    fn wire_value_roundtrips_in_both_directions() {
        let cases = [
            Value::BoolVal(true),
            Value::IntVal(-42),
            Value::FloatVal(3.5),
            Value::StringVal("hi".into()),
            Value::BytesVal(vec![0x00, 0xff, 0x42]),
            Value::JsonVal(r#"{"nested":1}"#.into()),
        ];
        for input in cases {
            // Host -> wire (response side, e.g. OkWithState).
            let wire = WireValue::from(input.clone());
            let json = serde_json::to_string(&wire).expect("serialize");
            // Round trip through JSON like a client would.
            let parsed: WireValue = serde_json::from_str(&json).expect("deserialize");
            let back = Value::from(parsed);
            assert!(
                values_equal(&input, &back),
                "round trip failed for {input:?} (json={json})",
            );
        }
    }

    /// Variant-aware equality for the round-trip test. Compares
    /// floats by `to_bits` so the assertion can't be fooled by a
    /// `Float(0.0) == Float(-0.0)` quirk, and so clippy doesn't
    /// flag a strict `==` on `f64` (the test's whole point is that
    /// the wire encoding is bit-exact for the same input).
    fn values_equal(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::BoolVal(x), Value::BoolVal(y)) => x == y,
            (Value::IntVal(x), Value::IntVal(y)) => x == y,
            (Value::FloatVal(x), Value::FloatVal(y)) => x.to_bits() == y.to_bits(),
            (Value::StringVal(x), Value::StringVal(y)) | (Value::JsonVal(x), Value::JsonVal(y)) => {
                x == y
            }
            (Value::BytesVal(x), Value::BytesVal(y)) => x == y,
            _ => false,
        }
    }

    #[test]
    fn button_variant_projects_one_to_one() {
        let cases = [
            (WitButtonEvent::Pressed, "pressed", None),
            (WitButtonEvent::Released, "released", None),
            (WitButtonEvent::SinglePress, "single_press", None),
            (WitButtonEvent::DoublePress, "double_press", None),
            (WitButtonEvent::LongPress, "long_press", None),
            (WitButtonEvent::Rotated(1.5), "rotated", Some(1.5)),
        ];
        for (input, expected_variant, expected_delta) in cases {
            let event = Event {
                device: Some("dev-1".into()),
                timestamp: 0,
                origin_plugin_id: String::new(),
                origin_instance_id: String::new(),
                row_id: None,
                payload: EventPayload::Button(input),
            };
            let wire = WireEvent::from_host(&event, true);
            match wire.payload {
                WireEventPayload::Button { variant, delta } => {
                    assert_eq!(variant, expected_variant, "variant mismatch for {input:?}");
                    assert_eq!(delta, expected_delta, "delta mismatch for {input:?}");
                }
                other => panic!("expected Button payload, got {other:?}"),
            }
            assert_eq!(wire.topic, "button");
        }
    }

    /// C2b: the `WireEvent` projection carries `origin_plugin_id` /
    /// `origin_instance_id` verbatim from the bus-side event. The
    /// host stamps these on publish (see the C2b tests in
    /// `runtime::state`); this test pins that the wire shape
    /// actually surfaces them to a JSON subscriber.
    #[test]
    fn wire_event_carries_origin_envelope() {
        let event = Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: "com.example.publisher".into(),
            origin_instance_id: "publisher-42".into(),
            row_id: None,
            payload: EventPayload::Custom(
                crate::host_impl::plugin::oxidhome::plugin::events::CustomEvent {
                    topic: "automation.morning".into(),
                    payload: String::new(),
                },
            ),
        };
        let wire = WireEvent::from_host(&event, true);
        assert_eq!(wire.origin_plugin_id, "com.example.publisher");
        assert_eq!(wire.origin_instance_id, "publisher-42");
        // The origin fields serialize into the wire JSON so a
        // tailing client can filter by them.
        let json = serde_json::to_value(&wire).expect("serialize");
        assert_eq!(json["origin_plugin_id"], "com.example.publisher");
        assert_eq!(json["origin_instance_id"], "publisher-42");
    }
}
