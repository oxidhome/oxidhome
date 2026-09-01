//! Phase 14 — Model Context Protocol server.
//!
//! Built-in surface for LLM agents. Mounts the official
//! [`rmcp`] SDK's streamable-HTTP transport on the same axum
//! listener that carries REST + Connect, so a client can talk
//! to the hub over one well-known URL. See
//! [`.claude/docs/10_mcp.md`](../../../../../.claude/docs/10_mcp.md)
//! for the phase plan and design rationale.
//!
//! # Layout
//!
//! - [`server`] — [`rmcp::transport::streamable_http_server::StreamableHttpService`]
//!   construction + axum mount.
//! - [`handler`] — the [`rmcp::ServerHandler`] impl that
//!   answers `initialize` and (via the trait defaults) returns
//!   empty tools / resources / prompts lists.
//! - [`session_store`] — [`BoundedSessionManager`], a
//!   `LocalSessionManager` wrapper with an admission cap that
//!   closes the concurrent-init overshoot the reviewer flagged
//!   in R3 F2 (against the previous SDK).
//! - [`tools`] — 14.3 tools registry. Starts with
//!   `device.send_command`; more tools land per the design
//!   doc's ordering.
//! - [`stdio`] — 14.5 subprocess transport (`oxidhome mcp-stdio`
//!   binary mode). Serves the same handler over
//!   `(stdin, stdout)` via `rmcp::transport::stdio()` under
//!   an ambient wildcard actor (parent-process trust model).
//!
//! [`BoundedSessionManager`]: session_store::BoundedSessionManager

mod handler;
mod prompts;
mod rate_limit;
mod resources;
mod server;
mod session_store;
mod stdio;
mod tools;

/// Re-export so `crate::api::auth::require_token` can pull the
/// pre-verify result off the request extensions without a
/// circular module dep (round-3 P1 on PR #140).
pub(crate) use rate_limit::{PreAdmissionInflight, PreVerifiedBearer};
pub use server::{
    MAX_REQUEST_BODY_BYTES, MCP_ENDPOINT, mount_routes, mount_routes_with_all_limits,
    mount_routes_with_cap, mount_routes_with_limits, mount_routes_with_rate_limiter,
};
pub use stdio::{ServeStdioError, serve_stdio, serve_stdio_over};
