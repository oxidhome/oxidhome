//! Phase 12 — external HTTP/WS API.
//!
//! [`serve`] builds an [`axum`] router on top of an [`Engine`](crate::Engine) and
//! drives it forever. Auth is bearer-token via the SQLite-backed
//! [`TokenStore`](crate::state::TokenStore); every authenticated
//! request gets an [`Actor::api(token_id, scopes)`](crate::Actor::api) stashed on the
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
//! Inbound `Authorization: Bearer …` headers are verified against
//! [`TokenStore::verify`](crate::state::TokenStore::verify). The only
//! network path that issues tokens is the owner's `token.manage`
//! (`POST /api/v1/tokens`, Connect `TokensService.CreateToken`, H6
//! slice 3, see [`token_admin`]); rotation and revocation stay offline
//! (`oxidhome recover-admin-token`).

pub(crate) mod auth;
mod bootstrap;
pub(crate) mod bytes;
mod connect_rpc;
pub mod mcp;
pub mod network_admin;
pub mod plugin_deny_admin;
pub(crate) mod scopes;
pub mod sensitive_admin;
pub(crate) mod server;
pub mod token_admin;
mod ui_ticket;

pub use bootstrap::{
    ADMIN_TOKEN_LABEL, RecoveryReport, RevokeScope, ensure_admin_token,
    reconcile_admin_token_files, recover_admin_token, recover_admin_token_offline,
};
pub use mcp::MCP_ENDPOINT;
pub use server::{ApiConfig, bind, build_router, serve};

#[cfg(test)]
pub(crate) use auth::parse_scopes;
pub(crate) use auth::wit_error_kind;
