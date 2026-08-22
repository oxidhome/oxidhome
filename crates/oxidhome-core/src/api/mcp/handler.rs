//! MCP [`ServerHandler`] for `OxidHome`.
//!
//! Currently answers `initialize`, exposes the resource
//! catalogue built in [`super::resources`], and lets the SDK's
//! default `tools/list` + `prompts/list` return empty lists
//! (14.3 / 14.6 fill those in).
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
        Implementation, ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
        ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities,
        ServerInfo,
    },
    service::{MaybeSendFuture, RequestContext},
};

use crate::Engine;
use crate::auth::Actor;

use super::resources;

/// `OxidHome`'s MCP server handler.
#[derive(Clone)]
pub(super) struct OxidHomeMcpHandler {
    engine: Engine,
}

impl OxidHomeMcpHandler {
    pub(super) fn new(engine: Engine) -> Self {
        Self { engine }
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
        let token_id = actor_token_id(&context);
        async move {
            let result = resources::read(engine, &request.uri, &token_id).await?;
            Ok(result.into())
        }
    }
}

/// Pull the [`Actor`]-shaped token id off the request. The
/// bearer middleware ([`crate::api::auth::require_token`]) puts
/// an `Actor` on the HTTP request's `Extensions`; `rmcp`'s
/// tower service forwards the surviving `http::request::Parts`
/// (which still owns those extensions) onto
/// [`RequestContext::extensions`]. Missing at either hop means
/// something upstream skipped the auth layer — treat that as
/// [`resources::UNAUTHENTICATED_TOKEN_ID`] rather than
/// panicking, since a mis-wire would otherwise break every
/// resource read at once with no useful signal.
fn actor_token_id(context: &RequestContext<RoleServer>) -> String {
    let parts = context.extensions.get::<axum::http::request::Parts>();
    let actor = parts.and_then(|p| p.extensions.get::<Actor>());
    actor.map_or_else(
        || resources::UNAUTHENTICATED_TOKEN_ID.to_string(),
        |a| a.id().to_string(),
    )
}
