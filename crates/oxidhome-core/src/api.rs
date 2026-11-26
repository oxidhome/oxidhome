//! Phase 12 — external HTTP/WS API.
//!
//! [`serve`] builds an [`axum`] router on top of an [`Engine`](crate::Engine) and
//! drives it forever. Auth is bearer-token via the SQLite-backed
//! [`TokenStore`](crate::state::TokenStore); every authenticated
//! request gets an [`Actor`](crate::Actor) (owner flag and roles) and
//! an invocation context stashed on the request extension, and each
//! handler checks its action through [`crate::auth::authorize()`].
//!
//! Inbound `Authorization: Bearer …` headers are verified against
//! [`TokenStore::verify`](crate::state::TokenStore::verify). The only
//! network path that issues tokens is the owner's `token.manage`
//! (`POST /api/v1/tokens`, Connect `TokensService.CreateToken`, see
//! [`token_admin`]); rotation and revocation stay offline
//! (`oxidhome recover-admin-token`).

pub(crate) mod auth;
pub(crate) mod authz;
mod bootstrap;
pub(crate) mod bytes;
mod connect_rpc;
pub mod mcp;
pub mod network_admin;
pub mod offline;
pub(crate) mod server;
pub mod token_admin;
mod ui_ticket;

pub use bootstrap::{
    ADMIN_TOKEN_LABEL, RecoveryReport, RevokeScope, ensure_admin_token,
    reconcile_admin_token_files, recover_admin_token, recover_admin_token_offline,
};
pub use mcp::MCP_ENDPOINT;
pub use server::{ApiConfig, bind, build_router, serve};

pub(crate) use auth::wit_error_kind;
