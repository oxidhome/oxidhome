//! MCP [`ServerHandler`] for `OxidHome`.
//!
//! Answers `initialize`, serves the resource catalogue built
//! in [`super::resources`], the tool catalogue built in
//! [`super::tools`] (14.3), and the prompt catalogue built in
//! [`super::prompts`] (14.6).
//!
//! The [`Engine`] handle is stashed on the struct so every
//! resource / tool handler can reach the device registry, log
//! store, event log, blob index, etc., without a second
//! dependency-injection scheme. Clone is required because
//! `StreamableHttpService` builds a fresh handler per session
//! via its `service_factory`; `Engine` is `Arc`-backed so the
//! clone is cheap.

use std::future::Future;

use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, GetPromptRequestParams, GetPromptResponse, Implementation,
        ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
        ServerCapabilities, ServerInfo,
    },
    service::{MaybeSendFuture, RequestContext},
};

use crate::Engine;
use crate::auth::Actor;

use super::{prompts, resources, tools};

/// `OxidHome`'s MCP server handler.
#[derive(Clone)]
pub(crate) struct OxidHomeMcpHandler {
    engine: Engine,
    /// Ambient actor used when the request context carries no
    /// axum `Parts` (stdio transport — 14.5). `None` on the
    /// HTTP mount, so the auth-layer's `Actor` in
    /// `Parts::extensions` remains the only source of truth
    /// there; a mis-wired HTTP mount still fails closed via
    /// `UNAUTHENTICATED_TOKEN_ID`.
    stdio_actor: Option<Actor>,
}

impl OxidHomeMcpHandler {
    pub(super) fn new(engine: Engine) -> Self {
        Self {
            engine,
            stdio_actor: None,
        }
    }

    /// Handler variant for the stdio transport (14.5). Every
    /// request context arriving via `rmcp::serve_server` over
    /// `(stdin, stdout)` carries a default (empty) `Extensions`;
    /// this ambient actor is what `resolve_actor` returns instead
    /// of the "no HTTP context = deny everything" fallback used
    /// on the HTTP mount. The parent process launched us with
    /// filesystem access to the state dir, so the trust model is
    /// the process boundary; scope enforcement remains real for
    /// audit purposes but the ambient actor holds `*`.
    pub(crate) fn for_stdio(engine: Engine, actor: Actor) -> Self {
        Self {
            engine,
            stdio_actor: Some(actor),
        }
    }
}

impl ServerHandler for OxidHomeMcpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info({
            // `Implementation` is `#[non_exhaustive]`, so we
            // start from `new(name, version)` and set the
            // optional fields we care about.
            let mut info = Implementation::new("oxidhome", env!("CARGO_PKG_VERSION"));
            info.title = Some("OxidHome MCP".into());
            info.description = Some(
                "OxidHome home-automation hub. Exposes device state, event history, logs, and \
                 plugin control to MCP-speaking agents."
                    .into(),
            );
            info.website_url = Some("https://github.com/oxidhome/oxidhome".into());
            info
        })
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .with_instructions(
            "Discover data with `resources/list`, actions with `tools/list`. Read tools are \
             safe; action tools carry an `oxidhome.audit` note when they mutate host state.",
        )
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        std::future::ready(Ok(ListResourcesResult {
            resources: resources::list_resources(),
            ..Default::default()
        }))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        std::future::ready(Ok(ListResourceTemplatesResult {
            resource_templates: resources::list_resource_templates(),
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        let engine = self.engine.clone();
        let actor = self.resolve_actor(&context);
        async move {
            let result = resources::read(engine, &request.uri, &actor).await?;
            Ok(result.into())
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + MaybeSendFuture + '_ {
        std::future::ready(Ok(ListToolsResult {
            tools: tools::list_tools(),
            ..Default::default()
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::CallToolResponse, rmcp::ErrorData>>
    + MaybeSendFuture
    + '_ {
        let engine = self.engine.clone();
        let actor = self.resolve_actor(&context);
        async move {
            let result = tools::call(engine, request, &actor).await?;
            Ok(result.into())
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: prompts::list_prompts(),
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        let actor = self.resolve_actor(&context);
        std::future::ready(prompts::get(&request, &actor).map(GetPromptResponse::from))
    }
}

impl OxidHomeMcpHandler {
    /// Pull the [`Actor`] off the request.
    ///
    /// 14.5 (stdio): when the handler was built with
    /// [`Self::for_stdio`], the ambient actor is returned
    /// unconditionally — no HTTP context exists to consult.
    ///
    /// HTTP mount: the bearer middleware
    /// ([`crate::api::auth::require_token`]) puts an `Actor`
    /// on the HTTP request's `Extensions`; `rmcp`'s tower
    /// service forwards the surviving `http::request::Parts`
    /// (which still owns those extensions) onto
    /// [`RequestContext::extensions`]. Missing at either hop
    /// means something upstream skipped the auth layer —
    /// synthesize a **no-scope anonymous actor** so every
    /// subsequent `require_scope` check fails closed. This
    /// protects against a future mis-wire (e.g. someone
    /// removing the `require_token` layer): the resource
    /// dispatch still refuses every read, records `decision
    /// = deny`, and the audit ledger surfaces the anomaly
    /// instead of silently serving requests as some
    /// ambiguous "trusted" caller.
    fn resolve_actor(&self, context: &RequestContext<RoleServer>) -> Actor {
        if let Some(actor) = &self.stdio_actor {
            return actor.clone();
        }
        let parts = context.extensions.get::<axum::http::request::Parts>();
        let actor = parts.and_then(|p| p.extensions.get::<Actor>()).cloned();
        actor.unwrap_or_else(|| Actor::api(resources::UNAUTHENTICATED_TOKEN_ID, Vec::new()))
    }
}
