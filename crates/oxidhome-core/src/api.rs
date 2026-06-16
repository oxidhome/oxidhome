//! Phase 12 — external HTTP/WS API.
//!
//! [`serve`] builds an [`axum`] router on top of an [`Engine`] and
//! drives it forever. Auth is bearer-token via the SQLite-backed
//! [`TokenStore`](crate::state::TokenStore); every authenticated
//! request gets an [`Actor::api(token_id, scopes)`] stashed on the
//! request extension, ready for the dispatch layer that consumes
//! scopes (lands in a follow-up PR).
//!
//! This first slice (12-API-a) is the skeleton + two endpoints
//! (`GET /api/v1/health`, `GET /api/v1/instances`) — enough to prove
//! the auth pipeline end-to-end against an integration test that
//! mints a token through the registry and hits both routes. Device
//! / plugin / events / logs endpoints + full scope enforcement land
//! on top of this shell.
//!
//! The CLI (Phase 12 follow-up) is the only path that mints
//! / rotates / revokes tokens; this module never issues them — it
//! only verifies inbound `Authorization: Bearer …` headers against
//! [`TokenStore::verify`].

mod auth;
mod bootstrap;
mod scopes;
mod server;

pub use bootstrap::ensure_admin_token;
pub use server::{ApiConfig, bind, build_router, serve};

#[cfg(test)]
pub(crate) use auth::parse_scopes;
