//! Network access for `streaming-plugin` instances (Phase 8).
//!
//! Which WASI interfaces an instance's linker gets depends on the world
//! its manifest selects:
//!
//! - `plugin` / `ai-plugin`: what libstd needs (`wasi:cli`, `wasi:clocks`,
//!   `wasi:io`, `wasi:random`, `wasi:filesystem`) and nothing that touches
//!   the network. A component that imports `wasi:sockets` or `wasi:http`
//!   fails to instantiate.
//! - `streaming-plugin` / `streaming-ai-plugin`: the above plus
//!   `wasi:sockets/*`, `wasi:http/{types,outgoing-handler}`, and the
//!   `host-media` / `media` imports (placeholders until media pipelines
//!   exist).
//!
//! Every network operation of a streaming instance is decided by its
//! [`NetworkPolicy`] (see [`policy`] for the rules):
//!
//! - TCP connect, UDP send / connect, binds and listens go through the
//!   `wasmtime-wasi` socket-address check ([`sockets::address_check`]);
//!   incoming datagrams the policy wouldn't allow are dropped.
//! - `wasi:sockets/ip-name-lookup` is implemented here, not by
//!   `wasmtime-wasi`, so the host only resolves names a rule mentions and
//!   remembers which addresses its name rules cover (public ones, and
//!   private ones for local-only names) each name resolved to.
//! - Socket creation is capped per instance.
//! - `wasi:http` requests are sent by [`http::HttpHooks`]: the host
//!   resolves the request's host, checks each address, and connects to
//!   exactly the address it checked.
//!
//! Refusals are audited (`method = NET`) through the shared deny-audit
//! worker, rate-limited per instance.

mod http;
mod policy;
mod sockets;

pub(crate) use http::{FIELD_SIZE_LIMIT, HttpHooks};
pub(crate) use policy::{NetworkPolicy, covers as rule_covers};
pub(crate) use sockets::address_check;

use oxidhome_manifest::World;
use wasmtime::component::Linker;

use super::state::PluginState;

/// Most resource-table entries a streaming instance may hold. Sockets,
/// lookups and `wasi:http` resources (each outgoing body buffering up
/// to one chunk on the host) live there, outside the guest's memory
/// ceiling; this bounds them.
pub(crate) const MAX_TABLE_ENTRIES: usize = 4096;

/// Run `fut` inside the invocation `ctx` (when there is one), so audit
/// rows written from spawned work name the call that caused them.
pub(crate) async fn in_invocation<F: std::future::Future>(
    ctx: Option<crate::auth::invocation::InvocationContext>,
    fut: F,
) -> F::Output {
    match ctx {
        Some(ctx) => crate::auth::invocation::CURRENT.scope(ctx, fut).await,
        None => fut.await,
    }
}

/// Whether `world` gets WASI sockets and HTTP.
pub(crate) const fn is_streaming(world: World) -> bool {
    world.has_network()
}

/// A streaming world's component must export `oxidhome:plugin/streaming`
/// (`setup-pipeline`); contract verification checks only the base
/// `plugin` exports.
///
/// # Errors
///
/// When the manifest selects a streaming world and the component
/// doesn't export the interface.
pub(crate) fn check_world_exports(
    component: &wasmtime::component::Component,
    engine: &wasmtime::Engine,
    world: World,
) -> anyhow::Result<()> {
    if !is_streaming(world) {
        return Ok(());
    }
    let exports_streaming = component
        .component_type()
        .exports(engine)
        .any(|(name, item)| {
            name.starts_with(STREAMING_EXPORT)
                && matches!(item.ty, wasmtime::component::types::ComponentItem::ComponentInstance(instance)
                    if instance.exports(engine).any(|(f, item)| f == "setup-pipeline"
                        && matches!(item.ty, wasmtime::component::types::ComponentItem::ComponentFunc(_))))
        });
    anyhow::ensure!(
        exports_streaming,
        "the manifest selects a streaming world, but the component doesn't export \
         `{STREAMING_EXPORT}` (build it with the SDK's `streaming-plugin` feature and \
         `streaming_plugin!`)"
    );
    Ok(())
}

/// The interface every streaming-world component exports.
const STREAMING_EXPORT: &str = "oxidhome:plugin/streaming@";

/// Add the WASI imports for an instance of `world` to `linker`.
///
/// # Errors
///
/// When a definition clashes with one already in the linker.
pub(crate) fn add_wasi_to_linker(
    linker: &mut Linker<PluginState>,
    world: World,
) -> anyhow::Result<()> {
    sockets::add_base_wasi(linker)?;
    if is_streaming(world) {
        sockets::add_sockets(linker)?;
        http::add_to_linker(linker)?;
        super::media_placeholder::add_to_linker(linker)?;
    }
    Ok(())
}
