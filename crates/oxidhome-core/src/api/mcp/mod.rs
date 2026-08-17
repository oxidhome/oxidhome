//! Phase 14 — Model Context Protocol server.
//!
//! Built-in surface for LLM agents: mounts the [MCP] protocol on the
//! same axum listener that carries the REST + Connect APIs so a
//! client can talk to the hub over a single well-known URL. See
//! [`.claude/docs/10_mcp.md`](../../../../../.claude/docs/10_mcp.md)
//! for the phase plan and design rationale.
//!
//! # Layout
//!
//! - [`server`] — construction of the MCP `Router` mount and the
//!   [`rust_mcp_sdk`] `InitializeResult` (server info + declared
//!   capabilities).
//! - [`handler`] — the [`rust_mcp_sdk::mcp_server::ServerHandler`]
//!   impl that answers `initialize`, `tools/list`, `resources/list`,
//!   and `prompts/list`. This 14.1 slice returns empty lists;
//!   14.2/14.3/14.6 fill them in.
//!
//! [MCP]: https://modelcontextprotocol.io/

mod handler;
mod server;

pub use server::{MCP_ENDPOINT, mount_routes};
