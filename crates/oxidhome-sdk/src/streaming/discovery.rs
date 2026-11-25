//! LAN discovery: broadcast and multicast probes, and the host's local
//! networks.
//!
//! [`std::net::UdpSocket`] can't send to a broadcast or multicast
//! address in this world (WASI sockets have no `SO_BROADCAST` and no
//! group membership); a [`DiscoverySocket`] can, behind `udp` rules that
//! name those addresses:
//!
//! ```no_run
//! use oxidhome_sdk::streaming::discovery::{DiscoverySocket, LIMITED_BROADCAST};
//!
//! // Needs `udp://255.255.255.255:9999` (the probe) and a rule covering
//! // the devices that answer, such as `udp://192.168.0.0/16:9999`.
//! let socket = DiscoverySocket::bind_v4(0)?;
//! socket.send_to(b"probe", (LIMITED_BROADCAST, 9999).into())?;
//! // Later, from `tick`:
//! for datagram in socket.recv(16)? {
//!     oxidhome_sdk::tracing::info!(from = %datagram.from, "reply");
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! - **Broadcast and multicast** (`255.255.255.255`, `224.0.0.251`,
//!   `239.255.255.250`, `ff02::fb`, …) need a `udp` rule naming that exact
//!   address and the port (`udp://224.0.0.251:5353`); a CIDR rule never
//!   covers them. [`DiscoverySocket::join_multicast`] needs a `udp` rule
//!   naming the group.
//! - **A subnet-directed broadcast** (`192.168.1.255` on
//!   `192.168.1.0/24`, see [`LocalNetwork::broadcast`]) reaches the whole
//!   network, so it needs a rule naming it or an IP rule covering that
//!   whole network (`udp://192.168.1.0/24:9999`).
//! - **Other destinations** are checked like any UDP send.
//! - **Replies** arrive only from senders a rule covers; others are
//!   dropped by the host. Devices usually answer from their own unicast
//!   address, so a broadcast probe needs a rule for the devices too.
//! - **Fixed local ports** ([`DiscoverySocket::bind_v4`] with a port
//!   other than 0) need a broadcast or multicast rule with that port, and
//!   are shared with other sockets on the host (the system's mDNS
//!   responder, say). Multicast is sent with a TTL of 1: it stays on the
//!   local link.
//!
//! The socket never blocks: [`DiscoverySocket::recv`] returns what is
//! waiting. When the manifest sets `tick_interval_ms`, the host ticks the
//! plugin early when a datagram is waiting, as for other sockets.
//!
//! [`local_networks`] lists the host's interface networks as far as the
//! instance's IP and CIDR rules cover them, so a plugin can sweep (or
//! broadcast to) its LAN without being configured with it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::bindings::oxidhome::plugin::host_network;
use crate::bindings::wasi::io::poll::Pollable;
use crate::bindings::wasi::sockets::network::{
    ErrorCode, IpAddress, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress,
};

/// The limited broadcast address.
pub const LIMITED_BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;
/// The mDNS group and port (`224.0.0.251:5353`).
pub const MDNS_V4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
/// The IPv6 mDNS group and port (`[ff02::fb]:5353`).
pub const MDNS_V6: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5353, 0, 0);
/// The SSDP group and port (`239.255.255.250:1900`).
pub const SSDP_V4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
/// Most datagrams one [`DiscoverySocket::recv`] returns.
pub const MAX_RECV: usize = 32;

/// A network the host is attached to, as far as the grant covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalNetwork {
    /// The network's first address.
    pub address: IpAddr,
    /// Its prefix length.
    pub prefix_len: u8,
}

impl LocalNetwork {
    /// The subnet-directed broadcast address of an IPv4 network shorter
    /// than `/31`.
    #[must_use]
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        match self.address {
            IpAddr::V4(v4) if self.prefix_len < 31 => Some(Ipv4Addr::from_bits(
                v4.to_bits() | (u32::MAX >> self.prefix_len),
            )),
            _ => None,
        }
    }

    /// Whether `ip` lies in this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for LocalNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// The host's interface networks the instance's IP and CIDR rules cover:
/// a network inside a rule whole, and a rule inside a network as the
/// rule's range. Empty without such rules.
#[must_use]
pub fn local_networks() -> Vec<LocalNetwork> {
    host_network::local_networks()
        .into_iter()
        .map(|net| LocalNetwork {
            address: ip_from_wit(net.address),
            prefix_len: net.prefix_len,
        })
        .collect()
}

/// One received datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The payload (truncated past 65535 bytes).
    pub data: Vec<u8>,
    /// Who sent it.
    pub from: SocketAddr,
}

/// A non-blocking UDP socket that may reach broadcast and multicast
/// destinations (see the module docs). Closed when dropped.
#[derive(Debug)]
pub struct DiscoverySocket {
    inner: host_network::DiscoverySocket,
}

impl DiscoverySocket {
    /// An IPv4 socket on `0.0.0.0:port` (0 for an ephemeral port).
    ///
    /// # Errors
    ///
    /// `PermissionDenied` for a fixed port no broadcast or multicast rule
    /// names; the host's socket limit; the OS refusing the bind.
    pub fn bind_v4(port: u16) -> io::Result<Self> {
        Self::open(IpAddressFamily::Ipv4, port)
    }

    /// An IPv6 socket on `[::]:port` (0 for an ephemeral port).
    ///
    /// # Errors
    ///
    /// As [`DiscoverySocket::bind_v4`].
    pub fn bind_v6(port: u16) -> io::Result<Self> {
        Self::open(IpAddressFamily::Ipv6, port)
    }

    fn open(family: IpAddressFamily, port: u16) -> io::Result<Self> {
        host_network::DiscoverySocket::open(family, port)
            .map(|inner| Self { inner })
            .map_err(io_error)
    }

    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// When the host can't read it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner
            .local_address()
            .map(addr_from_wit)
            .map_err(io_error)
    }

    /// Join the multicast `group` (of the socket's family).
    ///
    /// # Errors
    ///
    /// `PermissionDenied` when no `udp` rule names the group;
    /// `InvalidInput` when it isn't a multicast address of the socket's
    /// family.
    pub fn join_multicast(&self, group: IpAddr) -> io::Result<()> {
        self.inner
            .join_multicast(ip_to_wit(group))
            .map_err(io_error)
    }

    /// Send `data` to `to` in one datagram.
    ///
    /// # Errors
    ///
    /// `PermissionDenied` when the rules refuse `to` (the host audits
    /// it); `InvalidInput` for another family or port 0; `WouldBlock`
    /// when the send buffer is full.
    pub fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        self.inner.send(data, addr_to_wit(to)).map_err(io_error)
    }

    /// Up to `max` (at most [`MAX_RECV`]) waiting datagrams, without
    /// blocking; empty when none is waiting.
    ///
    /// # Errors
    ///
    /// A socket error the OS reported.
    pub fn recv(&self, max: usize) -> io::Result<Vec<Datagram>> {
        let max = u32::try_from(max.min(MAX_RECV)).unwrap_or(0);
        self.inner
            .receive(max)
            .map(|datagrams| {
                datagrams
                    .into_iter()
                    .map(|d| Datagram {
                        data: d.data,
                        from: addr_from_wit(d.remote_address),
                    })
                    .collect()
            })
            .map_err(io_error)
    }

    /// A pollable that is ready when a datagram is waiting (for
    /// `wasi:io/poll`).
    #[must_use]
    pub fn subscribe(&self) -> Pollable {
        self.inner.subscribe()
    }
}

fn io_error(code: ErrorCode) -> io::Error {
    let kind = match code {
        ErrorCode::AccessDenied => io::ErrorKind::PermissionDenied,
        ErrorCode::WouldBlock => io::ErrorKind::WouldBlock,
        ErrorCode::InvalidArgument | ErrorCode::DatagramTooLarge => io::ErrorKind::InvalidInput,
        ErrorCode::AddressInUse => io::ErrorKind::AddrInUse,
        ErrorCode::AddressNotBindable => io::ErrorKind::AddrNotAvailable,
        ErrorCode::RemoteUnreachable => io::ErrorKind::HostUnreachable,
        ErrorCode::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        ErrorCode::OutOfMemory => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{code:?}"))
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
            let (a, b, c, d) = v4.address;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), v4.port))
        }
        IpSocketAddress::Ipv6(v6) => {
            let (s0, s1, s2, s3, s4, s5, s6, s7) = v6.address;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7),
                v6.port,
                v6.flow_info,
                v6.scope_id,
            ))
        }
    }
}

fn addr_to_wit(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(v4) => {
            let [a, b, c, d] = v4.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: v4.port(),
                address: (a, b, c, d),
            })
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str, prefix_len: u8) -> LocalNetwork {
        LocalNetwork {
            address: s.parse().unwrap(),
            prefix_len,
        }
    }

    #[test]
    fn broadcast_addresses() {
        assert_eq!(
            net("192.168.1.0", 24).broadcast(),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            net("10.0.0.0", 8).broadcast(),
            Some(Ipv4Addr::new(10, 255, 255, 255))
        );
        assert_eq!(net("0.0.0.0", 0).broadcast(), Some(Ipv4Addr::BROADCAST));
        assert_eq!(net("10.0.0.0", 31).broadcast(), None);
        assert_eq!(net("fd00::", 64).broadcast(), None);
    }

    #[test]
    fn containment() {
        let lan = net("192.168.1.0", 24);
        assert!(lan.contains("192.168.1.77".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(!lan.contains("fd00::1".parse().unwrap()));
        assert!(net("0.0.0.0", 0).contains("8.8.8.8".parse().unwrap()));
        assert!(net("fd00::", 8).contains("fd12::1".parse().unwrap()));
        assert!(net("10.0.0.5", 32).contains("10.0.0.5".parse().unwrap()));
        assert_eq!(lan.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn addresses_round_trip() {
        for addr in ["192.168.1.5:9999", "[ff02::fb%3]:5353"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(addr_from_wit(addr_to_wit(addr)), addr);
        }
        let ip: IpAddr = "224.0.0.251".parse().unwrap();
        assert_eq!(ip_from_wit(ip_to_wit(ip)), ip);
    }

    #[test]
    fn error_codes_map_to_io_kinds() {
        assert_eq!(
            io_error(ErrorCode::AccessDenied).kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            io_error(ErrorCode::WouldBlock).kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            io_error(ErrorCode::NewSocketLimit).kind(),
            io::ErrorKind::Other
        );
    }
}
