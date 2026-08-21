//! MCP [`ServerHandler`] for `OxidHome`.
//!
//! Phase 14.1 ships the minimum handler that answers a real MCP
//! handshake: `initialize` + capability negotiation, and the
//! three discovery calls (`tools/list`, `resources/list`,
//! `prompts/list`) return **empty** results (the `rmcp` trait
//! defaults already do this, so we only need to override
//! [`ServerHandler::get_info`] to declare which capability
//! blocks we advertise). 14.2 / 14.3 / 14.6 fill in the actual
//! resources, tools, and prompts.
//!
//! The [`Engine`] handle is stashed on the struct so the read
//! resource handlers (14.2) and action tools (14.3) can reach
//! the device registry, log store, event log, blob index, etc.,
//! without a second dependency-injection scheme. 14.1 doesn't
//! consume it — it's parked here to keep the follow-up slice a
//! pure additive change.

use rmcp::{
    ServerHandler,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
};

use crate::Engine;

/// `OxidHome`'s MCP server handler. `Clone` is required because
/// `StreamableHttpService` builds a fresh handler per session
/// via its `service_factory`; `Engine` is `Arc`-backed so the
/// clone is cheap.
#[derive(Clone)]
pub(super) struct OxidHomeMcpHandler {
    #[allow(dead_code)] // wired for 14.2/14.3
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
}
