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

    match state.tokens.verify(bearer) {
        Ok(rec) => {
            let actor = actor_from_record(&rec);
            req.extensions_mut().insert(actor);
            next.run(req).await
        }
        Err(TokenError::Malformed | TokenError::Unknown | TokenError::Revoked) => unauthorized(),
        Err(TokenError::Sqlite(err)) => {
            tracing::error!(target: "api.auth", error = %err, "token verify failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
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
