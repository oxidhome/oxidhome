//! Bearer-token auth middleware.
//!
//! Every request the router serves goes through [`require_token`]
//! except for the explicit anonymous list ([`PUBLIC_PATHS`]). The
//! middleware:
//!
//! 1. Reads `Authorization: Bearer <token>` (case-insensitive on
//!    the scheme per RFC 6750 §1.1; one or more SP between scheme
//!    and credential).
//! 2. Calls [`TokenStore::verify`] — the store hashes the presented
//!    secret with SHA-256 and looks the row up by hash.
//! 3. On success, builds an [`Actor::api(token_id, scopes)`] from
//!    the matched row's `id` + parsed `scope_json`, attaches it to
//!    the request via [`Extension`], and forwards to the route.
//! 4. On any failure (missing header, malformed token, unknown
//!    secret, revoked) responds with **`401 Unauthorized`** with a
//!    `WWW-Authenticate: Bearer` header and an empty body. The
//!    variants are not distinguished externally so an attacker can't
//!    probe shape, validity, or revocation state.
//!
//! Anonymous routes (`/api/v1/health`) skip the bearer extraction
//! entirely. They still go through the same middleware so the
//! request span / actor extension shape is consistent — an anonymous
//! request gets no `Actor` extension; route handlers that need one
//! pull it via `Extension<Actor>` and short-circuit to 500 if it's
//! missing (which would be a routing bug, not an auth failure).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::auth::Actor;
use crate::state::{TokenError, TokenRecord, TokenStore};

/// Routes that don't require a bearer token. Health is the canonical
/// liveness probe — has to work for an orchestrator / load balancer
/// that doesn't carry credentials.
pub(crate) const PUBLIC_PATHS: &[&str] = &["/api/v1/health"];

/// Shared state the middleware needs. Held behind `Arc` and cloned
/// per request — both fields are already `Arc`-backed, so the clone
/// is cheap.
#[derive(Clone)]
pub(crate) struct AuthState {
    pub tokens: Arc<TokenStore>,
}

/// Axum middleware. Wired via `axum::middleware::from_fn_with_state`
/// in `server::router`.
///
/// After the inner handler runs, emits **one** audit event per
/// authenticated request through `tracing::info!` with the constant
/// `target = "api.audit"` — that's the fixed tracing target the
/// existing `LogStore` layer in `main.rs` indexes on. The
/// per-request method+path lives in the `audit_target` field
/// (e.g. `audit_target = "api.GET-/api/v1/instances"`) so a future
/// `logs query --target api.audit --field audit_target=…` can pivot
/// on it. Other structured fields: `{token_id, actor_kind, method,
/// path, status, decision, required_scope?}` — `required_scope` is
/// only set on `decision=deny` rows from a scope failure (smuggled
/// back from the handler via [`crate::api::scopes::DeniedScope`] on
/// the response's extension map).
///
/// `decision` values:
/// - `"allow"` — 2xx
/// - `"deny"` — any 4xx returned by the handler (e.g. 403 from a
///   scope check). 401 / 5xx from this very middleware (missing
///   credentials, `Sqlite` verify error) return *before*
///   `emit_audit` runs and are deliberately not audited — no
///   authenticated principal to attribute them to.
/// - `"error"` — handler-returned 5xx.
///
/// Anonymous (`PUBLIC_PATHS`) requests skip audit emission — no
/// token id to attribute them to.
///
/// **Lossy-channel note.** Audit events ride the same bounded
/// `tracing` channel as regular logs; under load the `LogStore`
/// layer drops events rather than blocking (the drop counter is
/// surfaced separately). This is a deliberate inheritance —
/// blocking on audit would block the request thread — but it
/// means a determined flooder can punch holes in the audit trail.
/// A dedicated never-drop channel for `target = "api.audit"` is a
/// candidate follow-up if this becomes a real forensic gap.
pub(crate) async fn require_token(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    if PUBLIC_PATHS.iter().any(|p| *p == req.uri().path()) {
        return next.run(req).await;
    }

    let Some(bearer) = extract_bearer(&req) else {
        return unauthorized();
    };

    let (token_id, actor_kind, http_path, method) = match state.tokens.verify(bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            // Snapshot the strings we'll need post-handler for the
            // audit row *before* moving `actor` onto the request
            // extension, so the audit path doesn't need to clone the
            // Arc-backed `Actor` (or bump-then-drop the refcount).
            let token_id = actor.id().to_string();
            let actor_kind = actor.kind().as_str().to_string();
            let path = req.uri().path().to_string();
            let method = req.method().to_string();
            req.extensions_mut().insert(actor);
            (token_id, actor_kind, path, method)
        }
        Err(TokenError::Malformed | TokenError::Unknown | TokenError::Revoked) => {
            return unauthorized();
        }
        Err(TokenError::Sqlite(err)) => {
            tracing::error!(target: "api.auth", error = %err, "token verify failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let response = next.run(req).await;
    let denied_scope = response
        .extensions()
        .get::<crate::api::scopes::DeniedScope>()
        .map(|d| d.0);
    emit_audit(
        &token_id,
        &actor_kind,
        &method,
        &http_path,
        response.status(),
        denied_scope,
    );
    response
}

/// One audit event per authenticated request. Routed through
/// `tracing::info!` with `target = "api.audit"`; the existing
/// `LogStore` layer captures it. See [`require_token`]'s docstring
/// for the field shape.
fn emit_audit(
    token_id: &str,
    actor_kind: &str,
    method: &str,
    path: &str,
    status: StatusCode,
    required_scope: Option<&'static str>,
) {
    let decision = if status.is_success() {
        "allow"
    } else if status.is_server_error() {
        "error"
    } else {
        "deny"
    };
    let audit_target = format!("api.{method}-{path}");
    // `required_scope` is only populated on scope-denial 403s
    // (`DeniedScope` came back on the response extension). Other
    // denies — and every allow — record it as an empty string so
    // the log_event row's `fields_blob` shape stays uniform across
    // every audit entry. A query like `--field required_scope=
    // devices:list` then picks the rows where that scope was the
    // tripwire.
    let required = required_scope.unwrap_or("");
    tracing::info!(
        target: "api.audit",
        audit_target = %audit_target,
        token_id = %token_id,
        actor_kind = %actor_kind,
        method = %method,
        path = %path,
        status = status.as_u16(),
        decision = %decision,
        required_scope = %required,
        "api request",
    );
}

/// Build an [`Actor`] from a verified record. Scopes are parsed
/// best-effort from `scope_json` (UTF-8 JSON array of strings).
/// Parse failure ⇒ empty scopes (deny-all) rather than a 500, so an
/// operator who saved a malformed scope blob with the CLI gets a
/// useful "every request is denied" signal in the audit log rather
/// than the entire API going down.
fn actor_from_record(rec: &TokenRecord) -> Actor {
    let scopes = parse_scopes(&rec.scope_json).unwrap_or_else(|| {
        tracing::warn!(
            target: "api.auth",
            token_id = %rec.id,
            "scope_json failed to parse; defaulting to deny-all",
        );
        Vec::new()
    });
    Actor::api(rec.id.clone(), scopes)
}

/// Parse `scope_json` as a JSON array of strings. Returns `None` on
/// any parse failure. The wildcard contract: an element equal to
/// `"*"` means "any scope" — 12-API-b's scope-policy enforcer
/// recognizes it. `pub(crate)` so the bootstrap test can pin the
/// admin-blob round trip (see [`crate::api`]).
pub(crate) fn parse_scopes(blob: &[u8]) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
    let arr = value.as_array()?;
    arr.iter()
        .map(|v| v.as_str().map(String::from))
        .collect::<Option<Vec<_>>>()
}

/// Pull the bearer secret out of an `Authorization: <scheme> …`
/// header. RFC 6750 §1.1 says the scheme name is case-insensitive
/// (`Bearer` / `bearer` / `BEARER` / mixed all parse). One or more
/// SP between the scheme and the credential are tolerated. `None`
/// if the header is missing, the scheme isn't `Bearer`, or the
/// credential is empty.
fn extract_bearer(req: &Request) -> Option<&str> {
    let h = req.headers().get(header::AUTHORIZATION)?;
    let s = h.to_str().ok()?;
    let (scheme, rest) = s.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let trimmed = rest.trim_start_matches(' ');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// 401 with `WWW-Authenticate: Bearer`.
fn unauthorized() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scopes_accepts_string_array() {
        let blob = br#"["devices:read","plugins:list"]"#;
        let scopes = parse_scopes(blob).expect("parse");
        assert_eq!(scopes, vec!["devices:read", "plugins:list"]);
    }

    #[test]
    fn parse_scopes_rejects_non_array_and_non_string_elements() {
        assert!(parse_scopes(b"{}").is_none());
        assert!(parse_scopes(br#"["ok", 7]"#).is_none());
        assert!(parse_scopes(b"not json").is_none());
    }

    #[test]
    fn extract_bearer_handles_case_variants() {
        let req_with = |h: &str| {
            Request::builder()
                .header(header::AUTHORIZATION, h)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        // Case-insensitive scheme (RFC 6750 §1.1).
        assert_eq!(extract_bearer(&req_with("Bearer abc")), Some("abc"));
        assert_eq!(extract_bearer(&req_with("bearer xyz")), Some("xyz"));
        assert_eq!(extract_bearer(&req_with("BEARER tok")), Some("tok"));
        assert_eq!(extract_bearer(&req_with("BeArEr tok")), Some("tok"));
        // Extra whitespace between scheme and credential is tolerated.
        assert_eq!(extract_bearer(&req_with("Bearer   tok")), Some("tok"));
        // Empty credential / wrong scheme / no SP rejected.
        assert!(extract_bearer(&req_with("Bearer ")).is_none());
        assert!(extract_bearer(&req_with("Bearer")).is_none());
        assert!(extract_bearer(&req_with("Basic foo")).is_none());
    }
}
