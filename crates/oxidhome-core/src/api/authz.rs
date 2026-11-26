//! The REST adapter for [`crate::auth::authorize()`].
//!
//! Handlers don't check permissions themselves: they call [`require`]
//! with an [`Action`] and a [`Resource`], and turn a deny into
//! [`Forbidden`], a `403 Forbidden` with an empty body. The auth
//! middleware records one audit row per request after the response; a
//! `decision=deny` row with `status=403` carries the refused action's
//! name in `required_scope`. See [`crate::api::auth`] for the emission
//! site.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::{Action, Decision, InvocationContext, Resource, authorize};

/// A refused permission check: a `403` whose audit label rides the
/// response to the auth middleware as a [`DeniedAction`] extension.
#[derive(Debug)]
pub(crate) struct Forbidden {
    /// The deny's audit label (the refused action's name).
    pub(crate) required: &'static str,
}

/// Smuggled on the response's extension map by [`Forbidden`] so the
/// auth middleware can write the label to the audit row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeniedAction(pub(crate) &'static str);

impl IntoResponse for Forbidden {
    fn into_response(self) -> Response {
        let mut resp = (StatusCode::FORBIDDEN, "").into_response();
        resp.extensions_mut().insert(DeniedAction(self.required));
        resp
    }
}

/// Authorize `action` on `resource` for the request's invocation.
///
/// # Errors
///
/// [`Forbidden`] carrying the deny's audit label.
pub(crate) fn require(
    ctx: &InvocationContext,
    action: Action,
    resource: &Resource,
) -> Result<Decision, Forbidden> {
    authorize(ctx, action, resource)
        .into_result()
        .map_err(|required| Forbidden { required })
}
