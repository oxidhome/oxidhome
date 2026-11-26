//! Token scopes and the REST adapter for [`crate::auth::authorize()`].
//!
//! A **scope** is a free-form string like `"devices:list"` or
//! `"instances:start"`. Each token carries a list of authorized
//! scopes in its `scope_json` blob (see
//! [`crate::auth::parse_policy`]). Handlers don't check scopes
//! directly: they call [`require`] with an
//! [`Action`](crate::auth::Action) and a
//! [`Resource`](crate::auth::Resource), and the
//! [`crate::auth::authorize()`] evaluator maps the action to the scope
//! below that has always gated it
//! (`Action::legacy_scope`).
//!
//! ## Matching rules (v1, deliberately simple)
//!
//! - **Literal match.** A token with `["devices:list"]` satisfies
//!   `devices:list`.
//! - **Wildcard.** A token whose scope list contains the single
//!   element `"*"` satisfies every required scope. This is the
//!   first-run bootstrap admin token's shape (`ADMIN_SCOPE_JSON`).
//! - **Sensitive categories (H6 slice 2).** No scope, the wildcard
//!   included, reaches a command on a lock, opener or alarm device or
//!   camera bytes: those need an explicit grant in the token's policy
//!   (`"sensitive": ["lock"]`, see [`crate::auth::SensitiveGrant`]).
//!   The bootstrap / recovered owner token holds every category.
//!
//! Hierarchical / glob matching (`devices:*` matches `devices:list`
//! *and* `devices:write`) is **not** in v1.
//!
//! ## Audit shape
//!
//! A deny becomes [`ScopeDenied`], a `403 Forbidden` with an empty
//! body. The auth middleware records one audit row per request after
//! the response; a `decision=deny` row with `status=403` carries the
//! deny's audit label (the missing scope or a `constraint:…`
//! sentinel) in `required_scope`. See [`crate::api::auth`] for the
//! emission site.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::{Action, Decision, InvocationContext, Resource, authorize};

/// Wildcard sentinel — a token whose scope list contains exactly this
/// element satisfies every required scope.
pub(crate) const WILDCARD: &str = "*";

/// A required scope, attached to a handler via [`RequireScope`].
/// Owned so a `static` constant in the route module is the natural
/// shape; cheap to clone.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope(&'static str);

impl Scope {
    pub(crate) const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub(crate) fn name(self) -> &'static str {
        self.0
    }

    /// Does `authorized` (a token's scope list) satisfy this scope?
    /// Wildcard tokens match anything; otherwise the required name
    /// has to appear verbatim.
    pub(crate) fn satisfied_by(self, authorized: &[String]) -> bool {
        authorized
            .iter()
            .any(|s| s == WILDCARD || s.as_str() == self.0)
    }
}

/// Handler-level denial response. Handlers pull
/// `Extension<InvocationContext>`, call [`require`], and propagate the
/// `Err` with `?`; the `IntoResponse` impl below turns the failure into
/// a 403 with an empty body. The deny's audit label travels back to the
/// auth middleware via a [`DeniedScope`] response extension so the
/// audit event can record *why* the request was refused — we
/// deliberately don't include it in the response body so a probing
/// caller can't enumerate required scopes.
#[derive(Debug)]
pub(crate) struct ScopeDenied {
    pub(crate) required: &'static str,
}

/// Smuggled on the response's extension map by [`ScopeDenied`] so
/// the audit-log middleware ([`crate::api::auth::require_token`])
/// can surface the missing-scope name as a structured field on the
/// `decision=deny` audit row. Cheap to clone (`&'static str`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeniedScope(pub(crate) &'static str);

impl IntoResponse for ScopeDenied {
    fn into_response(self) -> Response {
        let mut resp = (StatusCode::FORBIDDEN, "").into_response();
        // Auth middleware reads this back off the response extension
        // after the handler returns; see `emit_audit` for the field
        // it lands in.
        resp.extensions_mut().insert(DeniedScope(self.required));
        resp
    }
}

/// Handler-side check: ask [`authorize`] whether the invocation's root
/// may perform `action` on `resource`. Use in handlers as:
///
/// ```ignore
/// async fn list_instances(
///     Extension(ctx): Extension<InvocationContext>,
///     ...
/// ) -> Result<Json<...>, ScopeDenied> {
///     require(&ctx, Action::InstanceRead, &Resource::instances())?;
///     ...
/// }
/// ```
pub(crate) fn require(
    ctx: &InvocationContext,
    action: Action,
    resource: &Resource,
) -> Result<Decision, ScopeDenied> {
    authorize(ctx, action, resource)
        .into_result()
        .map_err(|required| ScopeDenied { required })
}

// ── Canonical scope constants ───────────────────────────────────────

/// `instances:list` — see `GET /api/v1/instances`.
pub(crate) const INSTANCES_LIST: Scope = Scope::new("instances:list");

/// `devices:list` — see `GET /api/v1/devices`.
pub(crate) const DEVICES_LIST: Scope = Scope::new("devices:list");

/// `devices:read` — see `GET /api/v1/devices/{id}/state` and
/// `GET /api/v1/devices/state/changes` (H9). Read-only access to
/// the host-owned device-state projection. Distinct from
/// `devices:list` (registration snapshot) and `devices:command`
/// (write path); this is the "what's the current value of every
/// sensor / switch" surface.
pub(crate) const DEVICES_READ: Scope = Scope::new("devices:read");

/// `events:tail` — see `GET /api/v1/events/tail` (WebSocket).
pub(crate) const EVENTS_TAIL: Scope = Scope::new("events:tail");

/// `events:read` — see `GET /api/v1/events` (H5 historical query).
/// Distinct from `events:tail`: tail is a live stream (typically
/// held by a WebSocket client), read is a bounded historical query
/// against the durable `event_log` table.
pub(crate) const EVENTS_READ: Scope = Scope::new("events:read");

/// `logs:read` — see `GET /api/v1/logs`.
pub(crate) const LOGS_READ: Scope = Scope::new("logs:read");

/// `audit:read` — see `GET /api/v1/audit`. **Sensitive**: the
/// audit ledger holds every authenticated request's token id,
/// method, path, and outcome. A token holding this scope can
/// reconstruct who did what across the whole daemon; treat it
/// like the auth-token store itself.
pub(crate) const AUDIT_READ: Scope = Scope::new("audit:read");

/// `devices:command` — see `POST /api/v1/devices/{id}/command`.
/// **Sensitive** by the cross-cutting policy in
/// [`ARCHITECTURE.md`](../../../../../ARCHITECTURE.md): controls
/// device actuation (locks, garage doors, alarms). A token holding
/// this scope is empowered to drive physical-world effects.
pub(crate) const DEVICES_COMMAND: Scope = Scope::new("devices:command");

/// `services:call` — H6 slice 4: lets an invocation this token roots
/// reach a plugin service through a delegated `call-service` hop (a
/// script the token triggered calling another plugin's service). Each
/// hop needs it on top of the calling plugin's `consumes_services`
/// grant; a role grant can narrow it to some services. No REST route
/// checks it: it is the token's *delegation* grant.
pub(crate) const SERVICES_CALL: Scope = Scope::new("services:call");

/// `plugins:list` — see `GET /api/v1/plugins`.
pub(crate) const PLUGINS_LIST: Scope = Scope::new("plugins:list");

/// `plugins:install` — see `POST /api/v1/plugins`.
/// **Sensitive**: installing a plugin stages new code into
/// `<state_dir>/plugins/<plugin_id>/` and makes it ready to
/// `execute-command` against the household. A token holding this
/// scope can effectively load arbitrary `.wasm` into the host.
pub(crate) const PLUGINS_INSTALL: Scope = Scope::new("plugins:install");

/// `plugins:start` — see `POST /api/v1/plugins/{plugin_id}/start`.
pub(crate) const PLUGINS_START: Scope = Scope::new("plugins:start");

/// `plugins:stop` — see `POST /api/v1/plugins/{plugin_id}/stop`.
pub(crate) const PLUGINS_STOP: Scope = Scope::new("plugins:stop");

/// `plugins:uninstall` — see `DELETE /api/v1/plugins/{plugin_id}`.
/// **Sensitive**: removes `<state_dir>/plugins/<plugin_id>/`
/// recursively. The handler refuses if any instance of the plugin
/// is running, but a held token + the API-level stop endpoint is
/// enough to do both. Audited.
pub(crate) const PLUGINS_UNINSTALL: Scope = Scope::new("plugins:uninstall");

/// Phase 13 slice 3: `dashboards:read` — see
/// `GET /api/v1/dashboards` and `GET /api/v1/dashboards/{id}`.
/// Read-only view over an operator's persisted dashboards.
pub(crate) const DASHBOARDS_READ: Scope = Scope::new("dashboards:read");

/// Phase 13 slice 3: `dashboards:write` — see
/// `POST /api/v1/dashboards`, `PUT /api/v1/dashboards/{id}`,
/// `DELETE /api/v1/dashboards/{id}`. Layout bytes are
/// opaque to the host; the shell owns the serialization
/// contract, so `write` doesn't require any per-widget
/// grant.
pub(crate) const DASHBOARDS_WRITE: Scope = Scope::new("dashboards:write");

/// Phase 14.2c: `status:read` — see MCP `oxidhome://status`.
/// Read-only host status snapshot (version, DB reachability,
/// counts), added for LLM agents that need a "is the hub up
/// and how big is it" surface without pulling the full
/// plugins/instances/devices lists. Also gates the daemon's
/// effective configuration (MCP `oxidhome://config`, REST
/// `GET /api/v1/config`): the same kind of operational
/// metadata (paths, listen address, limits), no secrets.
pub(crate) const STATUS_READ: Scope = Scope::new("status:read");

/// Phase 14.2c: `blobs:read` — see MCP
/// `oxidhome://blobs/{instance_id}/{name}`. Access to plugin-
/// owned blob payloads (camera snapshots, inference outputs).
/// Deliberately **not** paired with a `blobs:list` — the MCP
/// surface doesn't advertise a blob catalog because that would
/// leak the full per-instance name space to any caller with
/// the scope; instead the plugin publishes named blobs via
/// events + tools and the agent reads them by their known
/// name.
pub(crate) const BLOBS_READ: Scope = Scope::new("blobs:read");

// M7: who may see raw `bytes-val` payloads in state, events and
// command results is decided per source by `crate::api::bytes::BytesGate`
// (H6 slice 2: a camera source needs the camera grant on top of
// `blobs:read`).

/// C6: `plugins:ui` — see `GET /api/v1/plugins/{plugin_id}/ui`.
/// Gates the sandboxed-iframe wrapper endpoint that hosts the
/// plugin's UI. The wrapper page mints a short-lived
/// HMAC-signed **ui ticket** scoped to this `plugin_id` and
/// embeds it in the sandboxed iframe's `src` query string, so
/// the iframe (which browsers won't let carry the bearer
/// Authorization header) can authenticate itself to the frame
/// endpoint. The ticket authorises `GET /ui/frame` for the
/// same `plugin_id` only, for a short window (~5 min), and
/// nothing else — no bearer-derived scopes ride with it.
pub(crate) const PLUGINS_UI: Scope = Scope::new("plugins:ui");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_scope_must_match_exactly() {
        let scope = Scope::new("devices:list");
        assert!(scope.satisfied_by(&["devices:list".into()]));
        assert!(!scope.satisfied_by(&["devices:read".into()]));
        assert!(!scope.satisfied_by(&[]));
    }

    #[test]
    fn wildcard_satisfies_anything() {
        let listing = Scope::new("devices:list");
        let admin = Scope::new("instances:start");
        let scopes = vec!["*".to_string()];
        assert!(listing.satisfied_by(&scopes));
        assert!(admin.satisfied_by(&scopes));
    }

    #[test]
    fn wildcard_alongside_literals_still_matches_everything() {
        let scope = Scope::new("plugins:install");
        let scopes = vec!["devices:list".into(), "*".into()];
        assert!(scope.satisfied_by(&scopes));
    }
}
