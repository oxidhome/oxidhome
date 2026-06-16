//! Phase 12-API-b — scope-policy matcher + axum extractor.
//!
//! A **scope** is a free-form string like `"devices:list"` or
//! `"instances:start"`. Each token carries a list of authorized
//! scopes in its `scope_json` blob (see
//! [`crate::api::parse_scopes`]); a handler declares the scope it
//! requires by adding a [`RequireScope`] extractor to its signature.
//!
//! ## Matching rules (v1, deliberately simple)
//!
//! - **Literal match.** A token with `["devices:list"]` satisfies a
//!   handler declaring `RequireScope::new("devices:list")`.
//! - **Wildcard.** A token whose scope list contains the single
//!   element `"*"` satisfies every required scope. This is the
//!   first-run bootstrap admin token's shape (`ADMIN_SCOPE_JSON`).
//!
//! Hierarchical / glob matching (`devices:*` matches `devices:list`
//! *and* `devices:write`) is **not** in v1. The extension point is
//! the body of [`Scope::satisfied_by`]; adding it later won't
//! require rewriting the call sites.
//!
//! ## Audit shape
//!
//! [`RequireScope`] denies with `403 Forbidden`. The auth middleware
//! emits one `tracing::info!` audit event per request after the
//! response — `target = "api.<path>"`, structured fields
//! `{token_id, actor_kind, status, decision}`. A `decision=deny`
//! audit row with `status=403` is the post-fix signal an operator
//! greps for. See [`crate::api::auth`] for the emission site.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::Actor;

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

/// Handler-level denial response. Handlers pull `Extension<Actor>`,
/// call [`require_scope`], and propagate the `Err` with `?`; the
/// `IntoResponse` impl below turns the failure into a 403 with an
/// empty body. The required scope name travels back to the auth
/// middleware via a [`DeniedScope`] response extension so the audit
/// event can record *which* scope was missing — we deliberately
/// don't include it in the response body so a probing caller can't
/// enumerate required scopes.
///
/// We don't expose a per-scope axum extractor (would require
/// `const &str` generics that aren't stable yet); the
/// `require_scope` helper keeps handler signatures readable.
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

/// Handler-side helper. Reads the [`Actor`] off the request and
/// checks `required` against its scopes. Use in handlers as:
///
/// ```ignore
/// async fn list_instances(
///     Extension(actor): Extension<Actor>,
///     ...
/// ) -> Result<Json<...>, ScopeDenied> {
///     require_scope(&actor, INSTANCES_LIST)?;
///     ...
/// }
/// ```
pub(crate) fn require_scope(actor: &Actor, required: Scope) -> Result<(), ScopeDenied> {
    if required.satisfied_by(actor.scopes()) {
        Ok(())
    } else {
        Err(ScopeDenied {
            required: required.name(),
        })
    }
}

// ── Canonical scope constants ───────────────────────────────────────

/// `instances:list` — see `GET /api/v1/instances`.
pub(crate) const INSTANCES_LIST: Scope = Scope::new("instances:list");

/// `devices:list` — see `GET /api/v1/devices`.
pub(crate) const DEVICES_LIST: Scope = Scope::new("devices:list");

/// `events:tail` — see `GET /api/v1/events/tail` (WebSocket).
pub(crate) const EVENTS_TAIL: Scope = Scope::new("events:tail");

/// `logs:read` — see `GET /api/v1/logs`.
pub(crate) const LOGS_READ: Scope = Scope::new("logs:read");

/// `devices:command` — see `POST /api/v1/devices/{id}/command`.
/// **Sensitive** by the cross-cutting policy in
/// [`ARCHITECTURE.md`](../../../../../ARCHITECTURE.md): controls
/// device actuation (locks, garage doors, alarms). A token holding
/// this scope is empowered to drive physical-world effects.
pub(crate) const DEVICES_COMMAND: Scope = Scope::new("devices:command");

/// `plugins:list` — see `GET /api/v1/plugins`.
pub(crate) const PLUGINS_LIST: Scope = Scope::new("plugins:list");

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

    #[test]
    fn require_scope_passes_actor_with_scope() {
        let actor = Actor::api("tok-1", vec!["devices:list".into()]);
        require_scope(&actor, DEVICES_LIST).expect("authorized");
    }

    #[test]
    fn require_scope_denies_actor_without_scope() {
        let actor = Actor::api("tok-1", vec!["instances:list".into()]);
        let err = require_scope(&actor, DEVICES_LIST).expect_err("denied");
        assert_eq!(err.required, "devices:list");
    }

    #[test]
    fn require_scope_accepts_wildcard_admin() {
        let actor = Actor::api("admin-tok", vec!["*".into()]);
        require_scope(&actor, INSTANCES_LIST).expect("authorized");
        require_scope(&actor, DEVICES_LIST).expect("authorized");
    }
}
