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
use std::time::Instant;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, GetPromptRequestParams, GetPromptResponse,
        GetPromptResult, Implementation, ListPromptsResult, ListResourceTemplatesResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, ServerCapabilities,
        ServerInfo,
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
            // 14.7c: standardised completion event. `read` is
            // instrumented at the dispatch boundary (one event
            // per request, success or failure) so operators
            // can build `mcp.resource.complete` dashboards
            // without a metrics dep.
            //
            // `mcp_name` is the routed **family slug** (from
            // [`resources::ReadDispatch::family`]), not the
            // caller-controlled URI — URIs carry blob names,
            // device ids, and query params and would blow up
            // any Prometheus/Loki label cardinality budget.
            //
            // Completion events live under a dedicated
            // `mcp.resource.complete` target so a filter like
            // `count_by(mcp_outcome)` on that target sees a
            // uniform field shape — audit-error diagnostics
            // in this module stay on plain `mcp.*` targets and
            // don't leak into completion counts.
            let start = Instant::now();
            let dispatch = resources::read(engine, &request.uri, &actor).await;
            emit_completion(
                "mcp.resource.complete",
                dispatch.family,
                &actor,
                classify_read(&dispatch.result),
                start,
            );
            let response = dispatch.result?;
            Ok(response.into())
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
            // 14.7c: standardised completion event. See
            // `read_resource` above for the rationale.
            //
            // Round-2 P1 on PR #144: the caller-supplied
            // `request.name` is unbounded — a client can
            // submit any string on `tools/call`. Map it
            // through [`tools::canonical_tool_name`] so
            // `mcp_name` is either a routed static string
            // or the sentinel `"unknown"`. The dedicated
            // `mcp.tool.complete` target keeps this stream
            // isolated from the `target: "mcp.tool"` error
            // logs the audit-finalize paths in `tools.rs`
            // emit (different field shape).
            let start = Instant::now();
            let canonical = tools::canonical_tool_name(&request.name);
            let result = tools::call(engine, request, &actor).await;
            emit_completion(
                "mcp.tool.complete",
                canonical,
                &actor,
                classify_call(&result),
                start,
            );
            let response = result?;
            Ok(response.into())
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
        // 14.7c: standardised completion event. See
        // `read_resource` above for the rationale.
        //
        // Round-2 P1 on PR #144: `request.name` is
        // caller-supplied and unbounded. Map through
        // [`prompts::canonical_prompt_name`] so `mcp_name` is
        // a routed static string or the sentinel `"unknown"`.
        let start = Instant::now();
        let canonical = prompts::canonical_prompt_name(&request.name);
        let result = prompts::get(&request, &actor);
        emit_completion(
            "mcp.prompt.complete",
            canonical,
            &actor,
            classify_prompt(&result),
            start,
        );
        std::future::ready(result.map(GetPromptResponse::from))
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

// ── 14.7c: structured MCP completion tracing ────────────────────
//
// One `tracing::info!` per dispatched MCP request under a
// **dedicated completion target** — `mcp.resource.complete`,
// `mcp.tool.complete`, `mcp.prompt.complete` — with a stable
// field shape (`mcp_name`, `mcp_actor_id`, `mcp_outcome`,
// `mcp_duration_ms`). Lets operators build metric dashboards
// via their tracing pipeline (Vector, Grafana Alloy,
// otel-collector) without an in-process metrics crate + scrape
// endpoint.
//
// The `.complete` suffix keeps this stream isolated from the
// per-error `tracing::warn!`/`tracing::error!` diagnostics
// emitted from the handler bodies under plain `mcp.tool`,
// `mcp.resource`, `mcp.prompt` (different field shape, no
// completion counter contract). A dashboard filtering
// `target=mcp.tool.complete` therefore sees a uniform shape
// and can `count_by(mcp_outcome)` safely.
//
// Round-1 P1 on PR #144: `mcp_name` must be
// bounded-cardinality — for resources it's the routed family
// slug (see [`resources::ReadDispatch`]), not the URI; tool
// and prompt names are already a closed catalogue.

/// Emit the standardised completion event.
fn emit_completion(target: &'static str, name: &str, actor: &Actor, outcome: &str, start: Instant) {
    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = start.elapsed().as_millis() as u64;
    // Trampoline through match so `target:` gets a literal
    // string — `tracing::info!` requires that.
    match target {
        "mcp.resource.complete" => tracing::info!(
            target: "mcp.resource.complete",
            mcp_name = %name,
            mcp_actor_id = %actor.id(),
            mcp_outcome = %outcome,
            mcp_duration_ms = duration_ms,
            "MCP resource read completed",
        ),
        "mcp.tool.complete" => tracing::info!(
            target: "mcp.tool.complete",
            mcp_name = %name,
            mcp_actor_id = %actor.id(),
            mcp_outcome = %outcome,
            mcp_duration_ms = duration_ms,
            "MCP tool call completed",
        ),
        "mcp.prompt.complete" => tracing::info!(
            target: "mcp.prompt.complete",
            mcp_name = %name,
            mcp_actor_id = %actor.id(),
            mcp_outcome = %outcome,
            mcp_duration_ms = duration_ms,
            "MCP prompt get completed",
        ),
        // Unknown target routes to a fallback bucket rather
        // than a plain `mcp` — plain `mcp` would collide with
        // any future generic MCP diagnostic. This arm is a
        // programming-error backstop: every emit site above
        // uses one of the three dedicated targets.
        _ => tracing::info!(
            target: "mcp.unknown.complete",
            mcp_name = %name,
            mcp_actor_id = %actor.id(),
            mcp_outcome = %outcome,
            mcp_duration_ms = duration_ms,
            "MCP request completed (unrecognised target — please file a bug)",
        ),
    }
}

/// Map the tool-call result to a stable outcome tag.
///
/// - `Ok(res)` where `is_error` is set → `"exec_err"` (a
///   plugin returned Err, a not-found precondition failed —
///   application-level failure the client sees as
///   `CallToolResult { isError: true }`).
/// - `Ok(_)` otherwise → `"ok"`.
/// - `Err(mcp_error)` → tag derived from the JSON-RPC code
///   ([`classify_mcp_error`]), so scope denials, oversized
///   responses, and the audit-queue busy path each get a
///   dashboard-friendly slice.
fn classify_call(result: &Result<CallToolResult, McpError>) -> &'static str {
    match result {
        Ok(r) if r.is_error == Some(true) => "exec_err",
        Ok(_) => "ok",
        Err(err) => classify_mcp_error(err),
    }
}

/// Read-side classifier — resource reads don't carry an
/// application-level `is_error` shape, so `Ok(_)` collapses to
/// `"ok"` and error paths go through the JSON-RPC-code
/// classifier.
fn classify_read(result: &Result<ReadResourceResult, McpError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(err) => classify_mcp_error(err),
    }
}

/// Prompt-side classifier — same shape as
/// [`classify_read`]; prompt failures carry the same JSON-RPC
/// codes tools/resources use.
fn classify_prompt(result: &Result<GetPromptResult, McpError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(err) => classify_mcp_error(err),
    }
}

/// Map a JSON-RPC error code to a stable dashboard-friendly
/// tag. Kept in sync with the codes MCP handlers emit.
fn classify_mcp_error(err: &McpError) -> &'static str {
    // Codes come from `resources::{SCOPE_DENIED_CODE, ...}`
    // and rmcp's standard JSON-RPC codes. Keep this match
    // aligned with the emit sites.
    match err.code.0 {
        -32001 => "denied",
        -32003 => "too_large",
        -32004 => "busy",
        -32601 => "unknown_method",
        -32602 => "invalid_params",
        -32603 => "internal",
        _ => "error",
    }
}
