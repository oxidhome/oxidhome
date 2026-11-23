//! WASI linking for plugin instances, and the parts of `wasi:sockets` the
//! host implements itself: name lookup, the socket-count cap, and the
//! address check every connect / send / bind goes through.

use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;

use futures_util::FutureExt as _;
use wasmtime::component::{HasData, Linker, Resource, ResourceTable};
use wasmtime_wasi::cli::{WasiCli, WasiCliView as _};
use wasmtime_wasi::clocks::{WasiClocks, WasiClocksView as _};
use wasmtime_wasi::filesystem::{WasiFilesystem, WasiFilesystemView as _};
use wasmtime_wasi::p2::bindings::sockets::ip_name_lookup::{self, ResolveAddressStream};
use wasmtime_wasi::p2::bindings::sockets::network::{ErrorCode, IpAddress, IpAddressFamily};
use wasmtime_wasi::p2::bindings::sockets::{tcp_create_socket, udp_create_socket};
use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, io, random, sockets};
use wasmtime_wasi::p2::{
    DynPollable, Network, Pollable, SocketError, SocketResult, TcpSocket, UdpSocket,
};
use wasmtime_wasi::random::{WasiRandom, WasiRandomView as _};
use wasmtime_wasi::sockets::{
    SocketAddrUse, WasiSockets, WasiSocketsCtxView, WasiSocketsView as _,
};

use super::policy::{Denial, LOOKUP_TIMEOUT, MAX_SOCKETS, NetworkPolicy, Use};
use crate::runtime::state::PluginState;

/// `wasi:io` host traits are implemented on the resource table.
struct HasTable;

impl HasData for HasTable {
    type Data<'a> = &'a mut ResourceTable;
}

/// WASI for every world: what libstd imports, without the network.
/// Mirrors `wasmtime_wasi::p2::add_to_linker_async` minus `wasi:sockets`.
pub(super) fn add_base_wasi(l: &mut Linker<PluginState>) -> anyhow::Result<()> {
    type T = PluginState;
    io::error::add_to_linker::<T, HasTable>(l, |t| &mut t.table)?;
    io::poll::add_to_linker::<T, HasTable>(l, |t| &mut t.table)?;
    io::streams::add_to_linker::<T, HasTable>(l, |t| &mut t.table)?;
    clocks::wall_clock::add_to_linker::<T, WasiClocks>(l, T::clocks)?;
    clocks::monotonic_clock::add_to_linker::<T, WasiClocks>(l, T::clocks)?;
    filesystem::preopens::add_to_linker::<T, WasiFilesystem>(l, T::filesystem)?;
    filesystem::types::add_to_linker::<T, WasiFilesystem>(l, T::filesystem)?;
    random::random::add_to_linker::<T, WasiRandom>(l, T::random)?;
    random::insecure::add_to_linker::<T, WasiRandom>(l, T::random)?;
    random::insecure_seed::add_to_linker::<T, WasiRandom>(l, T::random)?;
    cli::exit::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::environment::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::stdin::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::stdout::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::stderr::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::terminal_input::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::terminal_output::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::terminal_stdin::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::terminal_stdout::add_to_linker::<T, WasiCli>(l, T::cli)?;
    cli::terminal_stderr::add_to_linker::<T, WasiCli>(l, T::cli)?;
    Ok(())
}

/// `wasi:sockets/*` for streaming instances. `tcp`, `udp`, `network` and
/// `instance-network` are `wasmtime-wasi`'s (their checks call
/// [`address_check`]); socket creation and name lookup are ours.
pub(super) fn add_sockets(l: &mut Linker<PluginState>) -> anyhow::Result<()> {
    type T = PluginState;
    let options = wasmtime_wasi::p2::bindings::LinkOptions::default();
    sockets::instance_network::add_to_linker::<T, WasiSockets>(l, T::sockets)?;
    sockets::network::add_to_linker::<T, WasiSockets>(l, &(&options).into(), T::sockets)?;
    sockets::tcp::add_to_linker::<T, WasiSockets>(l, T::sockets)?;
    sockets::udp::add_to_linker::<T, WasiSockets>(l, T::sockets)?;
    tcp_create_socket::add_to_linker::<T, Net>(l, net_view)?;
    udp_create_socket::add_to_linker::<T, Net>(l, net_view)?;
    ip_name_lookup::add_to_linker::<T, Net>(l, net_view)?;
    Ok(())
}

/// The `wasmtime-wasi` socket-address check for a streaming instance:
/// every bind, listen, connect, send and received datagram is decided
/// by `policy`. Refusals other than dropped datagrams are audited.
pub(crate) fn address_check(
    policy: Arc<NetworkPolicy>,
) -> impl Fn(SocketAddr, SocketAddrUse) -> Pin<Box<dyn Future<Output = bool> + Send + Sync>>
+ Send
+ Sync
+ 'static {
    move |addr, usage| {
        let allowed = decide(&policy, addr, usage);
        Box::pin(std::future::ready(allowed))
    }
}

fn decide(policy: &NetworkPolicy, addr: SocketAddr, usage: SocketAddrUse) -> bool {
    let (op, result) = match usage {
        SocketAddrUse::TcpBind | SocketAddrUse::UdpBind => {
            ("bind", NetworkPolicy::check_bind(addr))
        }
        SocketAddrUse::TcpConnect => ("connect", policy.check_addr(Use::Tcp, addr, None)),
        SocketAddrUse::UdpSend => ("send", policy.check_addr(Use::Udp, addr, None)),
        // A filter on what arrives, not a request the plugin made:
        // dropped silently, like the datagram itself.
        SocketAddrUse::UdpReceive => return policy.check_addr(Use::Udp, addr, None).is_ok(),
        // Listening (and so accepting) is refused outright.
        _ => ("listen", Err(Denial::Listen)),
    };
    match result {
        Ok(()) => true,
        Err(denial) => {
            policy.audit_denial(op, &addr.to_string(), &denial);
            false
        }
    }
}

/// Host-trait view for the interfaces implemented here.
pub(super) struct NetView<'a> {
    sockets: WasiSocketsCtxView<'a>,
    policy: Arc<NetworkPolicy>,
}

struct Net;

impl HasData for Net {
    type Data<'a> = NetView<'a>;
}

fn net_view(state: &mut PluginState) -> NetView<'_> {
    let policy = Arc::clone(&state.network);
    NetView {
        sockets: state.sockets(),
        policy,
    }
}

// Needed by the generated traits for the `error-code` conversion.
impl sockets::network::Host for NetView<'_> {
    fn convert_error_code(&mut self, error: SocketError) -> wasmtime::Result<ErrorCode> {
        sockets::network::Host::convert_error_code(&mut self.sockets, error)
    }

    fn network_error_code(
        &mut self,
        err: Resource<wasmtime_wasi::p2::IoError>,
    ) -> wasmtime::Result<Option<ErrorCode>> {
        sockets::network::Host::network_error_code(&mut self.sockets, err)
    }
}

impl sockets::network::HostNetwork for NetView<'_> {
    fn drop(&mut self, this: Resource<Network>) -> wasmtime::Result<()> {
        sockets::network::HostNetwork::drop(&mut self.sockets, this)
    }
}

/// Live TCP and UDP sockets in an instance's resource table.
fn live_sockets(table: &mut ResourceTable) -> usize {
    table
        .iter_mut()
        .filter(|(_, entry)| entry.is::<TcpSocket>() || entry.is::<UdpSocket>())
        .count()
}

impl tcp_create_socket::Host for NetView<'_> {
    fn create_tcp_socket(
        &mut self,
        address_family: IpAddressFamily,
    ) -> SocketResult<Resource<TcpSocket>> {
        if live_sockets(self.sockets.table) >= MAX_SOCKETS {
            return Err(ErrorCode::NewSocketLimit.into());
        }
        tcp_create_socket::Host::create_tcp_socket(&mut self.sockets, address_family)
    }
}

impl udp_create_socket::Host for NetView<'_> {
    async fn create_udp_socket(
        &mut self,
        address_family: IpAddressFamily,
    ) -> SocketResult<Resource<UdpSocket>> {
        if live_sockets(self.sockets.table) >= MAX_SOCKETS {
            return Err(ErrorCode::NewSocketLimit.into());
        }
        udp_create_socket::Host::create_udp_socket(&mut self.sockets, address_family).await
    }
}

/// A name lookup in progress or done. Stored in the resource table under
/// the rep the guest's `resolve-address-stream` handle carries.
pub(super) struct Lookup {
    state: LookupState,
}

enum LookupState {
    Pending(tokio::task::JoinHandle<Result<Vec<IpAddr>, ErrorCode>>),
    Done(std::vec::IntoIter<IpAddr>),
    Failed(ErrorCode),
}

impl Drop for Lookup {
    fn drop(&mut self) {
        if let LookupState::Pending(task) = &self.state {
            // The blocking `getaddrinfo` it may be waiting on finishes on
            // its own and releases its lookup permit then.
            task.abort();
        }
    }
}

impl Lookup {
    fn finish(&mut self, result: Result<Result<Vec<IpAddr>, ErrorCode>, tokio::task::JoinError>) {
        self.state = match result {
            Ok(Ok(addrs)) => LookupState::Done(addrs.into_iter()),
            Ok(Err(code)) => LookupState::Failed(code),
            Err(_) => LookupState::Failed(ErrorCode::Unknown),
        };
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for Lookup {
    async fn ready(&mut self) {
        if let LookupState::Pending(task) = &mut self.state {
            let result = task.await;
            self.finish(result);
        }
    }
}

/// An IP literal as `wasi:sockets` accepts one: dotted IPv4, or IPv6
/// with or without brackets.
fn ip_literal(name: &str) -> Option<IpAddr> {
    let bare = name
        .strip_prefix('[')
        .and_then(|n| n.strip_suffix(']'))
        .unwrap_or(name);
    bare.parse().ok()
}

/// Blocking name lookups in flight across every instance.
static HOST_LOOKUPS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_HOST_LOOKUPS);
/// Cap for [`HOST_LOOKUPS`].
const MAX_HOST_LOOKUPS: usize = 32;

/// Resolve `name` (already allowed by `rules`) on the blocking pool,
/// holding one of the instance's lookup permits until `getaddrinfo`
/// returns, so timed-out lookups can't pile up threads.
pub(super) async fn resolve(
    policy: &Arc<NetworkPolicy>,
    name: &str,
    rules: &[usize],
    op: &'static str,
    target: &str,
) -> Result<Vec<IpAddr>, ErrorCode> {
    let Ok(permit) = Arc::clone(&policy.lookups).try_acquire_owned() else {
        return Err(ErrorCode::TemporaryResolverFailure);
    };
    // A timed-out `getaddrinfo` keeps its thread until it returns, and a
    // restarted instance gets a fresh per-instance limit; this one is
    // process-wide, so lookups can't pile up threads across restarts.
    let Ok(global) = HOST_LOOKUPS.try_acquire() else {
        return Err(ErrorCode::TemporaryResolverFailure);
    };
    // Resolved as an absolute name, so a resolver search list can't
    // turn it into a different name than the one the rules matched.
    let host = format!("{}.", super::policy::normalize_name(name));
    let blocking = tokio::task::spawn_blocking(move || {
        let _permits = (permit, global);
        (host.as_str(), 0)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>())
    });
    let addrs = match tokio::time::timeout(LOOKUP_TIMEOUT, blocking).await {
        Err(_) => return Err(ErrorCode::TemporaryResolverFailure),
        Ok(Err(_)) => return Err(ErrorCode::Unknown),
        Ok(Ok(Err(_))) => return Err(ErrorCode::NameUnresolvable),
        Ok(Ok(Ok(addrs))) => addrs,
    };
    let admitted = policy.admit_resolved(addrs, rules);
    if admitted.is_empty() {
        // Resolved, but only to addresses the rules refuse: a policy
        // refusal, not a DNS failure.
        policy.audit_denial(op, target, &Denial::ResolvedRefused(name.to_owned()));
        return Err(ErrorCode::AccessDenied);
    }
    Ok(admitted)
}

impl ip_name_lookup::Host for NetView<'_> {
    fn resolve_addresses(
        &mut self,
        network: Resource<Network>,
        name: String,
    ) -> SocketResult<Resource<ResolveAddressStream>> {
        // The network handle is the capability to call this.
        self.sockets.table.get(&network)?;
        let state = if let Some(ip) = ip_literal(&name) {
            // No DNS; the address is checked when it is used.
            LookupState::Done(vec![ip.to_canonical()].into_iter())
        } else {
            let rules = match self.policy.name_rules(&name, &[Use::Tcp, Use::Udp]) {
                Ok(rules) => rules,
                Err(denial) => {
                    let code = match denial {
                        Denial::InvalidName(_) => ErrorCode::InvalidArgument,
                        _ => ErrorCode::AccessDenied,
                    };
                    self.policy.audit_denial("lookup", &name, &denial);
                    return Err(code.into());
                }
            };
            let policy = Arc::clone(&self.policy);
            // The task-local invocation doesn't cross `spawn`; carry it so
            // a refusal is audited against the call that caused it.
            let ctx = crate::auth::invocation::current();
            LookupState::Pending(tokio::spawn(super::in_invocation(ctx, async move {
                resolve(&policy, &name, &rules, "lookup", &name).await
            })))
        };
        let lookup = self.sockets.table.push(Lookup { state })?;
        // The guest's handle is typed `resolve-address-stream`; the table
        // entry behind its rep is our `Lookup` (see the trait methods).
        Ok(Resource::new_own(lookup.rep()))
    }
}

fn lookup_handle(stream: &Resource<ResolveAddressStream>) -> Resource<Lookup> {
    Resource::new_borrow(stream.rep())
}

impl ip_name_lookup::HostResolveAddressStream for NetView<'_> {
    fn resolve_next_address(
        &mut self,
        stream: Resource<ResolveAddressStream>,
    ) -> SocketResult<Option<IpAddress>> {
        let lookup = self.sockets.table.get_mut(&lookup_handle(&stream))?;
        if let LookupState::Pending(task) = &mut lookup.state {
            let Some(result) = task.now_or_never() else {
                return Err(ErrorCode::WouldBlock.into());
            };
            lookup.finish(result);
        }
        match &mut lookup.state {
            LookupState::Done(addrs) => Ok(addrs.next().map(IpAddress::from)),
            LookupState::Failed(code) => Err((*code).into()),
            LookupState::Pending(_) => Err(ErrorCode::WouldBlock.into()),
        }
    }

    fn subscribe(
        &mut self,
        stream: Resource<ResolveAddressStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        wasmtime_wasi::p2::subscribe(self.sockets.table, lookup_handle(&stream))
    }

    async fn drop(&mut self, stream: Resource<ResolveAddressStream>) -> wasmtime::Result<()> {
        self.sockets
            .table
            .delete(Resource::<Lookup>::new_own(stream.rep()))?;
        Ok(())
    }
}
