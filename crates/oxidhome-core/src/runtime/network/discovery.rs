//! `host-network` for streaming instances (Phase 8.3): the host's local
//! networks, and discovery sockets that may reach broadcast and
//! multicast destinations.
//!
//! `wasi:sockets/udp` 0.2 has no `SO_BROADCAST` and no group membership,
//! and `wasmtime-wasi`'s socket keeps its descriptor private, so a
//! discovery socket is the host's own: a non-blocking `tokio` UDP socket
//! set up with `socket2`. Every send, join and fixed-port bind is decided
//! by the instance's [`NetworkPolicy`]; received datagrams from senders
//! the rules don't cover are dropped, both by `receive` and while the
//! socket's pollable (or the readiness wakeup) waits, so a flood from a
//! refused sender never wakes the plugin.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use wasmtime::component::{HasSelf, Linker, Resource};

use super::policy::{Denial, MAX_SOCKETS, NetworkPolicy, Use};
use crate::host_impl::streaming_plugin::oxidhome::plugin::host_network::{
    self, Datagram, LocalNetwork,
};
use crate::host_impl::streaming_plugin::wasi::sockets::network::{
    ErrorCode, IpAddress, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress,
};
use crate::runtime::state::PluginState;

/// Most datagrams one `receive` returns.
pub(crate) const MAX_RECEIVE: usize = 32;
/// Largest datagram read; longer ones are truncated.
const MAX_DATAGRAM: usize = 65_535;
/// Largest UDP payload over IPv4 (65535 minus the IP and UDP headers).
const MAX_SEND: usize = 65_507;
/// Refused datagrams one `receive` discards before it returns, so a flood
/// from a refused sender can't hold the call.
const MAX_DISCARDS: usize = 256;
/// Refused datagrams the pollable discards before it yields.
const DISCARDS_PER_YIELD: usize = 64;
/// How long the host's interface list is reused.
const INTERFACES_TTL: Duration = Duration::from_secs(2);
/// Multicast TTL / hop limit: discovery stays on the local link.
const MULTICAST_HOPS: u32 = 1;

/// A discovery socket in an instance's resource table.
///
/// Two descriptors of one socket: sends, receives and options go
/// straight to the non-blocking `std` one, and the `tokio` one is only
/// awaited for read readiness. tokio's `try_*` calls answer
/// `would-block` without asking the OS until its reactor has seen the
/// socket ready, which would lose a probe sent right after `open` and
/// hide datagrams from a `receive` that didn't wait first.
pub struct DiscoverySocket {
    socket: std::net::UdpSocket,
    readiness: tokio::net::UdpSocket,
    ipv6: bool,
    policy: Arc<NetworkPolicy>,
}

impl DiscoverySocket {
    /// Whether a datagram from `from` may reach the plugin: the same
    /// check as a `wasi:sockets` receive.
    fn admits(&self, from: SocketAddr) -> bool {
        self.policy.check_addr(Use::Udp, from, None).is_ok()
    }
}

#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::p2::Pollable for DiscoverySocket {
    async fn ready(&mut self) {
        let mut discarded = 0usize;
        loop {
            if self.readiness.readable().await.is_err() {
                return;
            }
            // Through `try_io`, so a `would-block` clears the readiness
            // tokio cached.
            let socket = &self.socket;
            match self.readiness.try_io(tokio::io::Interest::READABLE, || {
                socket.peek_from(&mut [0u8; 1]).map(|(_, from)| from)
            }) {
                Ok(from) if self.admits(from) => return,
                Ok(_) => {
                    // Dropped unread (a one-byte read truncates it; some
                    // systems refuse a zero-length one).
                    let _ = self.socket.recv_from(&mut [0u8; 1]);
                    discarded += 1;
                    if discarded.is_multiple_of(DISCARDS_PER_YIELD) {
                        tokio::task::yield_now().await;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                // A pending socket error: `receive` reports it.
                Err(_) => return,
            }
        }
    }
}

pub(super) fn add_to_linker(linker: &mut Linker<PluginState>) -> anyhow::Result<()> {
    host_network::add_to_linker::<PluginState, HasSelf<PluginState>>(linker, |state| state)?;
    Ok(())
}

/// The host's interface networks, reused for [`INTERFACES_TTL`]. `None`
/// when they can't be listed (not cached, so the next call retries).
fn interface_networks() -> Option<Arc<[IpNet]>> {
    static CACHE: Mutex<Option<(Instant, Arc<[IpNet]>)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((at, nets)) = cache.as_ref()
        && at.elapsed() < INTERFACES_TTL
    {
        return Some(Arc::clone(nets));
    }
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            tracing::warn!(target: "host.network", error = %e, "listing network interfaces failed");
            return None;
        }
    };
    let nets: Arc<[IpNet]> = interfaces
        .iter()
        .filter_map(|iface| {
            let (ip, prefix) = match &iface.addr {
                if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), v4.prefixlen),
                if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), v6.prefixlen),
            };
            IpNet::new(ip, prefix).ok().map(|net| net.trunc())
        })
        .collect();
    *cache = Some((Instant::now(), Arc::clone(&nets)));
    Some(nets)
}

fn ip_from_wit(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((s0, s1, s2, s3, s4, s5, s6, s7)) => {
            IpAddr::V6(Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7))
        }
    }
}

fn ip_to_wit(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            IpAddress::Ipv4((a, b, c, d))
        }
        IpAddr::V6(v6) => {
            let [s0, s1, s2, s3, s4, s5, s6, s7] = v6.segments();
            IpAddress::Ipv6((s0, s1, s2, s3, s4, s5, s6, s7))
        }
    }
}

fn addr_from_wit(addr: IpSocketAddress) -> SocketAddr {
    match addr {
        IpSocketAddress::Ipv4(v4) => {
            let IpAddr::V4(ip) = ip_from_wit(IpAddress::Ipv4(v4.address)) else {
                unreachable!("an IPv4 address")
            };
            SocketAddr::V4(SocketAddrV4::new(ip, v4.port))
        }
        IpSocketAddress::Ipv6(v6) => {
            let IpAddr::V6(ip) = ip_from_wit(IpAddress::Ipv6(v6.address)) else {
                unreachable!("an IPv6 address")
            };
            SocketAddr::V6(SocketAddrV6::new(ip, v6.port, v6.flow_info, v6.scope_id))
        }
    }
}

fn addr_to_wit(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(v4) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: v4.port(),
            address: v4.ip().octets().into(),
        }),
        SocketAddr::V6(v6) => {
            let [s0, s1, s2, s3, s4, s5, s6, s7] = v6.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: v6.port(),
                flow_info: v6.flowinfo(),
                address: (s0, s1, s2, s3, s4, s5, s6, s7),
                scope_id: v6.scope_id(),
            })
        }
    }
}

/// The `error-code` for an OS socket error.
fn error_code(err: &std::io::Error) -> ErrorCode {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::WouldBlock => ErrorCode::WouldBlock,
        ErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        ErrorKind::AddrInUse => ErrorCode::AddressInUse,
        ErrorKind::AddrNotAvailable => ErrorCode::AddressNotBindable,
        ErrorKind::InvalidInput => ErrorCode::InvalidArgument,
        ErrorKind::ConnectionRefused => ErrorCode::ConnectionRefused,
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::NetworkDown => {
            ErrorCode::RemoteUnreachable
        }
        ErrorKind::OutOfMemory => ErrorCode::OutOfMemory,
        _ => ErrorCode::Unknown,
    }
}

/// Bind a discovery socket (see the WIT `open`): the socket, and a
/// second descriptor of it registered with tokio for readiness.
fn bind(ipv6: bool, port: u16) -> std::io::Result<(std::net::UdpSocket, tokio::net::UdpSocket)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    if ipv6 {
        socket.set_only_v6(true)?;
        socket.set_multicast_hops_v6(MULTICAST_HOPS)?;
    } else {
        // `SO_BROADCAST` stays off except around a send the policy
        // approved as a broadcast, so a destination the kernel treats as
        // a broadcast and the policy didn't (a network's first address,
        // an interface change the cached list missed) is refused.
        socket.set_multicast_ttl_v4(MULTICAST_HOPS)?;
    }
    // Linux otherwise delivers every group joined on the host (by any
    // socket) to a wildcard-bound socket on that port.
    #[cfg(target_os = "linux")]
    if ipv6 {
        socket.set_multicast_all_v6(false)?;
    } else {
        socket.set_multicast_all_v4(false)?;
    }
    if port != 0 {
        // Shared with the system's responder on 5353 / 1900.
        socket.set_reuse_address(true)?;
        #[cfg(all(
            unix,
            not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
        ))]
        socket.set_reuse_port(true)?;
    }
    let ip = if ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    socket.bind(&SocketAddr::new(ip, port).into())?;
    let socket: std::net::UdpSocket = socket.into();
    let readiness = tokio::net::UdpSocket::from_std(socket.try_clone()?)?;
    Ok((socket, readiness))
}

impl PluginState {
    fn discovery_socket(
        &mut self,
        handle: &Resource<DiscoverySocket>,
    ) -> Result<&mut DiscoverySocket, ErrorCode> {
        // The component model has already checked the handle; the table
        // also checks the entry's type.
        self.table
            .get_mut(handle)
            .map_err(|_| ErrorCode::InvalidArgument)
    }

    fn refuse(&self, op: &'static str, target: &str, denial: &Denial) -> ErrorCode {
        self.network.audit_denial(op, target, denial);
        ErrorCode::AccessDenied
    }
}

impl host_network::Host for PluginState {
    async fn local_networks(&mut self) -> Vec<LocalNetwork> {
        let interfaces = interface_networks().unwrap_or_else(|| Arc::from([]));
        self.network
            .local_networks(&interfaces)
            .into_iter()
            .map(|net| LocalNetwork {
                address: ip_to_wit(net.network()),
                prefix_len: net.prefix_len(),
            })
            .collect()
    }
}

impl host_network::HostDiscoverySocket for PluginState {
    async fn open(
        &mut self,
        family: IpAddressFamily,
        local_port: u16,
    ) -> Result<Resource<DiscoverySocket>, ErrorCode> {
        let ipv6 = matches!(family, IpAddressFamily::Ipv6);
        if let Err(denial) = self.network.check_discovery_bind(local_port, ipv6) {
            let unspecified = if ipv6 { "[::]" } else { "0.0.0.0" };
            return Err(self.refuse("bind", &format!("{unspecified}:{local_port}"), &denial));
        }
        if super::sockets::live_sockets(&mut self.table) >= MAX_SOCKETS {
            return Err(ErrorCode::NewSocketLimit);
        }
        let (socket, readiness) = bind(ipv6, local_port).map_err(|e| error_code(&e))?;
        let socket = DiscoverySocket {
            socket,
            readiness,
            ipv6,
            policy: Arc::clone(&self.network),
        };
        self.table
            .push(socket)
            .map_err(|_| ErrorCode::NewSocketLimit)
    }

    async fn local_address(
        &mut self,
        this: Resource<DiscoverySocket>,
    ) -> Result<IpSocketAddress, ErrorCode> {
        let socket = self.discovery_socket(&this)?;
        socket
            .socket
            .local_addr()
            .map(addr_to_wit)
            .map_err(|e| error_code(&e))
    }

    async fn join_multicast(
        &mut self,
        this: Resource<DiscoverySocket>,
        group: IpAddress,
    ) -> Result<(), ErrorCode> {
        let group = ip_from_wit(group);
        let ipv6 = self.discovery_socket(&this)?.ipv6;
        if group.is_ipv6() != ipv6 || !group.is_multicast() {
            return Err(ErrorCode::InvalidArgument);
        }
        if let Err(denial) = self.network.check_join(group) {
            return Err(self.refuse("join", &group.to_string(), &denial));
        }
        let socket = &self.discovery_socket(&this)?.socket;
        match group {
            IpAddr::V4(v4) => socket.join_multicast_v4(&v4, &Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(v6) => socket.join_multicast_v6(&v6, 0),
        }
        .map_err(|e| error_code(&e))
    }

    async fn send(
        &mut self,
        this: Resource<DiscoverySocket>,
        data: Vec<u8>,
        remote_address: IpSocketAddress,
    ) -> Result<(), ErrorCode> {
        let addr = addr_from_wit(remote_address);
        let ipv6 = self.discovery_socket(&this)?.ipv6;
        if addr.is_ipv6() != ipv6 || addr.port() == 0 {
            return Err(ErrorCode::InvalidArgument);
        }
        if data.len() > MAX_SEND {
            return Err(ErrorCode::DatagramTooLarge);
        }
        let broadcast = match self
            .network
            .check_discovery_send(addr, interface_networks().as_deref())
        {
            Ok(broadcast) => broadcast,
            Err(denial) => return Err(self.refuse("send", &addr.to_string(), &denial)),
        };
        let socket = &self.discovery_socket(&this)?.socket;
        if broadcast {
            socket.set_broadcast(true).map_err(|e| error_code(&e))?;
        }
        let sent = socket.send_to(&data, addr);
        if broadcast {
            // Off again, or the socket stays unusable for this check.
            socket.set_broadcast(false).map_err(|e| error_code(&e))?;
        }
        sent.map(|_| ()).map_err(|e| error_code(&e))
    }

    async fn receive(
        &mut self,
        this: Resource<DiscoverySocket>,
        max_results: u32,
    ) -> Result<Vec<Datagram>, ErrorCode> {
        let max = usize::try_from(max_results).map_or(MAX_RECEIVE, |n| n.min(MAX_RECEIVE));
        let socket = self.discovery_socket(&this)?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut discarded = 0;
        while out.len() < max && discarded < MAX_DISCARDS {
            match socket.socket.recv_from(&mut buf) {
                Ok((n, from)) if socket.admits(from) => out.push(Datagram {
                    data: buf[..n].to_vec(),
                    remote_address: addr_to_wit(from),
                }),
                // Not audited: a filter on what arrives, as for
                // `wasi:sockets` receives.
                Ok(_) => discarded += 1,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if out.is_empty() => return Err(error_code(&e)),
                Err(_) => break,
            }
        }
        Ok(out)
    }

    async fn subscribe(
        &mut self,
        this: Resource<DiscoverySocket>,
    ) -> wasmtime::Result<Resource<wasmtime_wasi::p2::DynPollable>> {
        wasmtime_wasi::p2::subscribe(&mut self.table, this)
    }

    async fn drop(&mut self, this: Resource<DiscoverySocket>) -> wasmtime::Result<()> {
        self.table.delete(this)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip_through_wit() {
        for addr in ["192.168.1.5:9999", "[ff02::fb%3]:5353", "[2001:db8::1]:1"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(addr_from_wit(addr_to_wit(addr)), addr);
        }
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(ip_from_wit(ip_to_wit(ip)), ip);
    }

    #[test]
    fn os_errors_map_to_error_codes() {
        use std::io::{Error, ErrorKind};
        assert!(matches!(
            error_code(&Error::from(ErrorKind::PermissionDenied)),
            ErrorCode::AccessDenied
        ));
        assert!(matches!(
            error_code(&Error::from(ErrorKind::WouldBlock)),
            ErrorCode::WouldBlock
        ));
        assert!(matches!(error_code(&Error::other("x")), ErrorCode::Unknown));
    }

    #[tokio::test]
    async fn ephemeral_and_shared_ports_bind() {
        let (socket, _) = bind(false, 0).unwrap();
        assert_ne!(socket.local_addr().unwrap().port(), 0);
        // Two sockets share a fixed port, as one does with the system's
        // mDNS responder.
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let (first, _) = bind(false, port).unwrap();
        let (second, _) = bind(false, port).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);
    }

    #[test]
    fn interfaces_are_listed_and_cached() {
        let first = interface_networks().expect("interfaces");
        let second = interface_networks().expect("interfaces");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.iter().all(|net| *net == net.trunc()));
    }

    #[tokio::test]
    async fn sends_and_receives_need_no_reactor_turn() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (socket, _readiness) = bind(false, 0).unwrap();
        socket.send_to(b"hi", peer.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 2];
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(n, 2);
        peer.send_to(b"ok", from).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, _)) => break assert_eq!(&buf[..n], b"ok"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no datagram");
                    std::thread::yield_now();
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[tokio::test]
    async fn broadcast_is_off_unless_a_send_turns_it_on() {
        let (socket, _readiness) = bind(false, 0).unwrap();
        let err = socket.send_to(b"x", "255.255.255.255:9").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }
}
