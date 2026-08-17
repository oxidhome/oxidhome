//! MCP [`ServerHandler`] for `OxidHome`.
//!
//! Phase 14.1 ships the smallest handler that answers a real MCP
//! handshake: `initialize` → capability negotiation → the three
//! discovery calls (`tools/list`, `resources/list`, `prompts/list`)
//! all return **empty** results rather than the SDK's default
//! `method_not_found`. That gives clients a working (but empty)
//! surface to enumerate against while 14.2/14.3/14.6 fill it in.
//!
//! The [`Engine`] handle is stashed on the struct so the read-only
//! resource handlers (14.2) and the action tools (14.3) can reach
//! the device registry, log store, event log, blob index, etc.,
//! without a second dependency-injection scheme. 14.1 doesn't
//! consume it — it's parked here to keep the follow-up slice a
//! pure additive change.

use std::sync::Arc;

use async_trait::async_trait;
use rust_mcp_sdk::{
    McpServer,
    mcp_server::ServerHandler,
    schema::{
        ListPromptsResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams, RpcError,
    },
};

use crate::Engine;

/// `OxidHome`'s MCP server handler. Currently a thin skeleton — the
/// [`Engine`] handle is captured so 14.2+ can wire the read/action
/// surface without changing the mount plumbing.
pub(super) struct OxidHomeMcpHandler {
    #[allow(dead_code)] // wired for 14.2/14.3
    engine: Engine,
}

impl OxidHomeMcpHandler {
    pub(super) fn new(engine: Engine) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl ServerHandler for OxidHomeMcpHandler {
    /// The SDK default returns `method_not_found`; overriding to
    /// return an empty list keeps a bare handshake honest — a
    /// client that enumerates tools sees "server advertises
    /// `tools`, has none right now" instead of an error.
    async fn handle_list_tools_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools: Vec::new(),
        })
    }

    /// See [`Self::handle_list_tools_request`] — same rationale for
    /// resources.
    async fn handle_list_resources_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<ListResourcesResult, RpcError> {
        Ok(ListResourcesResult {
            meta: None,
            next_cursor: None,
            resources: Vec::new(),
        })
    }

    /// See [`Self::handle_list_tools_request`] — same rationale for
    /// prompts.
    async fn handle_list_prompts_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<ListPromptsResult, RpcError> {
        Ok(ListPromptsResult {
            meta: None,
            next_cursor: None,
            prompts: Vec::new(),
        })
    }
}
