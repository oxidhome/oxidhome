//! The per-instance network policy: which addresses a `streaming-plugin`
//! instance may reach, decided on the resolved IP.
//!
//! Built once per instance from its **effective** `[capabilities] network`
//! rules (requested ∩ granted). Every enforcement point — socket connect
//! and send, incoming datagrams, binds, name lookups, outgoing HTTP —
//! asks the same object, so they can't disagree.
//!
//! The rules, in the order they're applied:
//!
//! 1. The address is classified with
//!    [`native_policy::endpoint::classify`](crate::native_policy::endpoint::classify)
//!    after IPv4-mapped IPv6 is canonicalized. A *forbidden* address
//!    (unspecified, broadcast, multicast, documentation, reserved, …) is
//!    always refused.
//! 2. An **IP rule** (an IP literal or CIDR host) covers an address it
//!    contains, for its proto and port. An IP literal grants its own
//!    address whatever its class. A CIDR grants loopback, link-local or
//!    private addresses only when the whole range lies inside that
//!    class's address blocks, so `0.0.0.0/0` covers public space only.
//! 3. A **name rule** (exact DNS name or `*.suffix`) covers the *public*
//!    addresses the host itself resolved a matching name to. A rule whose
//!    name ends in a local-only suffix ([`LOCAL_SUFFIXES`]: `.local`,
//!    `.lan`, `.home.arpa`, `.internal`) also covers *private* addresses
//!    (`mqtt.lan` → `192.168.1.5`). No name rule covers loopback or
//!    link-local addresses (`metadata.google.internal` is
//!    `169.254.169.254`), and a name outside those suffixes never reaches
//!    the LAN (DNS rebinding). Socket lookups record the covered
//!    addresses in a bounded, expiring table that the connect / send
//!    check reads; an HTTP request carries its matched rules directly.
//!
//! An operator narrows a grant by containment: the effective rules are
//! the granted rules some requested rule covers plus the requested rules
//! some granted rule covers ([`covers`]).
//!
//! Discovery sockets (`host-network`, Phase 8.3) add three checks on
//! their sends ([`NetworkPolicy::check_discovery_send`]):
//!
//! - The limited broadcast `255.255.255.255` and multicast groups
//!   ([`is_group_address`]) are reached only through a `udp` rule naming
//!   that exact address, for the port. A CIDR never covers them, and
//!   `wasi:sockets` never reaches them.
//! - A subnet-directed broadcast (the last address of a local IPv4
//!   network) reaches every host of that network, so it needs a `udp`
//!   (or `any`) IP rule covering the whole network. When the host can't
//!   list its networks, IPv4 destinations other than named groups are
//!   refused.
//! - Everything else is an ordinary UDP send.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use oxidhome_manifest::{HostMatch, NetworkRule, PortMatch, Proto};

use crate::native_policy::endpoint::{AddressClass, classify};

/// Live socket cap per instance.
pub(crate) const MAX_SOCKETS: usize = 64;
/// Concurrent name lookups per instance (each one may hold a blocking
/// `getaddrinfo` thread).
pub(crate) const MAX_CONCURRENT_LOOKUPS: usize = 4;
/// Concurrent outgoing HTTP requests per instance.
pub(crate) const MAX_CONCURRENT_HTTP: usize = 16;
/// How long a name lookup may take.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an address a name rule resolved to stays usable.
pub(crate) const RESOLVED_TTL: Duration = Duration::from_mins(10);
/// Most resolved addresses remembered per instance.
pub(crate) const MAX_RESOLVED: usize = 1024;
/// Most addresses one lookup hands the plugin (and records).
pub(crate) const MAX_LOOKUP_RESULTS: usize = 32;
/// Most networks `local-networks` lists.
pub(crate) const MAX_LOCAL_NETWORKS: usize = 64;

/// One of the host's interface networks, as a discovery send sees it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalInterface {
    /// The network (truncated to its prefix).
    pub(crate) net: IpNet,
    /// The broadcast address the interface is configured with, when the
    /// system reports one: the kernel treats it as a broadcast too.
    pub(crate) broadcast: Option<IpAddr>,
}

impl From<IpNet> for LocalInterface {
    fn from(net: IpNet) -> Self {
        Self {
            net,
            broadcast: None,
        }
    }
}
/// Longest DNS name, without the root dot.
const MAX_NAME_LEN: usize = 253;
/// Audited denials allowed in a burst, per instance.
const AUDIT_BURST: f64 = 16.0;
/// Audited denials refilled per second, per instance.
const AUDIT_PER_SEC: f64 = 1.0;
/// Name suffixes that are never delegated in public DNS, so a name
/// under them is answered by the local network: a name rule ending in
/// one may reach private addresses.
pub(crate) const LOCAL_SUFFIXES: [&str; 4] = [".local", ".lan", ".home.arpa", ".internal"];

/// What the plugin is doing with an address, which picks the rules that
/// can allow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// TCP connect (`tcp` / `any` rules).
    Tcp,
    /// UDP send or receive (`udp` / `any` rules).
    Udp,
    /// Plain-text `http://` request (`tcp` / `any` rules).
    Http,
    /// `https://` request (`https` / `any` rules).
    Https,
}

impl Use {
    fn matches(self, proto: Proto) -> bool {
        matches!(
            (self, proto),
            (_, Proto::Any)
                | (Self::Tcp | Self::Http, Proto::Tcp)
                | (Self::Udp, Proto::Udp)
                | (Self::Https, Proto::Https)
        )
    }

    /// Short name for audit rows and logs.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Why the policy refused an address or name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Denial {
    #[error("{0} is a {1} address, which is never allowed")]
    Forbidden(IpAddr, AddressClass),
    #[error("no network rule allows {proto} to {addr} ({class} address)")]
    NotAllowed {
        proto: &'static str,
        addr: SocketAddr,
        class: AddressClass,
    },
    #[error("no network rule names `{0}`")]
    NameNotAllowed(String),
    #[error("`{0}` is not a valid host name")]
    InvalidName(String),
    #[error("`{0}` resolved only to addresses no network rule allows")]
    ResolvedRefused(String),
    #[error("binding to {0} is not allowed; bind to the unspecified address")]
    Bind(SocketAddr),
    #[error("listening for incoming connections is not allowed")]
    Listen,
    /// A TLS server refused by its certificate pin.
    #[error("{0}")]
    Tls(String),
    #[error("no udp network rule names {0}")]
    GroupNotNamed(SocketAddr),
    #[error(
        "{addr} is the broadcast address of {net}; no udp network rule covers that whole network"
    )]
    SubnetBroadcast { addr: SocketAddr, net: IpNet },
    #[error("joining {0} needs a udp network rule naming that group")]
    Join(IpAddr),
    #[error("binding discovery port {0} needs a udp broadcast or multicast rule for that port")]
    DiscoveryPort(u16),
    #[error("the host's networks couldn't be listed, so {0} may be a broadcast address")]
    InterfacesUnknown(SocketAddr),
    #[error("the system treats {0} as a broadcast address the host's network list didn't show")]
    UnlistedBroadcast(SocketAddr),
}

/// The per-instance policy object. Shared (`Arc`) between the socket
/// address check, the name-lookup implementation and the HTTP client.
pub(crate) struct NetworkPolicy {
    instance_id: Arc<str>,
    /// The plugin installation the instance runs: TLS pins are recorded
    /// against it, so uninstalling deletes them.
    installation_uuid: Arc<str>,
    rules: Vec<CompiledRule>,
    resolved: Mutex<Resolved>,
    audit: Mutex<AuditBucket>,
    audit_log: Option<Arc<crate::state::AuditLog>>,
    /// The engine clock: resolved-grant expiry and the audit bucket.
    clock: crate::clock::Clock,
    pub(crate) lookups: Arc<tokio::sync::Semaphore>,
    pub(crate) http_requests: Arc<tokio::sync::Semaphore>,
    /// Test seam: answers name lookups instead of the platform resolver.
    pub(crate) dns: Option<Arc<super::DnsOverrides>>,
}

impl std::fmt::Debug for NetworkPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkPolicy")
            .field("instance_id", &self.instance_id)
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

/// One rule, split by host kind.
#[derive(Debug, Clone)]
struct CompiledRule {
    proto: Proto,
    port: PortMatch,
    host: RuleHost,
    /// A name rule under a [`LOCAL_SUFFIXES`] suffix.
    local: bool,
}

#[derive(Debug, Clone)]
enum RuleHost {
    /// An IP literal: covers exactly this (canonical) address.
    Ip(IpAddr),
    /// A CIDR range.
    Net(IpNet),
    /// An exact DNS name, lowercase, no trailing dot.
    Name(String),
    /// `*.suffix`, stored as `.suffix`, lowercase.
    Suffix(String),
}

impl CompiledRule {
    fn compile(rule: &NetworkRule) -> Self {
        let host = match &rule.host {
            HostMatch::Exact(host) => match host.parse::<IpAddr>() {
                Ok(ip) => RuleHost::Ip(ip.to_canonical()),
                Err(_) => RuleHost::Name(normalize_name(host)),
            },
            HostMatch::SuffixWildcard(suffix) => RuleHost::Suffix(normalize_name(suffix)),
            HostMatch::Cidr(net) => RuleHost::Net(canonical_net(*net)),
        };
        let local = match &host {
            RuleHost::Name(name) | RuleHost::Suffix(name) => is_local_name(name),
            RuleHost::Ip(_) | RuleHost::Net(_) => false,
        };
        Self {
            proto: rule.proto,
            port: rule.port,
            host,
            local,
        }
    }

    /// Whether this name rule covers resolved addresses of `class`.
    fn name_grants(&self, class: AddressClass) -> bool {
        self.is_name_rule()
            && match class {
                AddressClass::Public => true,
                AddressClass::Private => self.local,
                _ => false,
            }
    }

    fn allows(&self, using: Use, port: u16) -> bool {
        using.matches(self.proto)
            && match self.port {
                PortMatch::Any => true,
                PortMatch::Exact(p) => p == port,
                PortMatch::Range(lo, hi) => (lo..=hi).contains(&port),
            }
    }

    /// Whether this IP rule covers `ip`, whose class is `class`.
    fn covers_ip(&self, ip: IpAddr, class: AddressClass) -> bool {
        match &self.host {
            RuleHost::Ip(rule_ip) => *rule_ip == ip,
            RuleHost::Net(net) => {
                net.contains(&ip) && (class == AddressClass::Public || net_within_class(net, class))
            }
            RuleHost::Name(_) | RuleHost::Suffix(_) => false,
        }
    }

    /// Whether this name rule matches `name` (already normalized).
    fn matches_name(&self, name: &str) -> bool {
        match &self.host {
            RuleHost::Name(rule) => rule == name,
            RuleHost::Suffix(suffix) => {
                name.len() > suffix.len() && name.ends_with(suffix.as_str())
            }
            RuleHost::Ip(_) | RuleHost::Net(_) => false,
        }
    }

    fn is_name_rule(&self) -> bool {
        matches!(self.host, RuleHost::Name(_) | RuleHost::Suffix(_))
    }

    /// Whether this is a `udp` rule naming exactly `ip`: the only rule
    /// that reaches a broadcast or multicast group.
    fn names_group(&self, ip: IpAddr) -> bool {
        self.proto == Proto::Udp && matches!(self.host, RuleHost::Ip(rule_ip) if rule_ip == ip)
    }

    /// Whether this IP rule covers every address of `net`: it contains
    /// `net`, and grants every class `net` holds ([`net_class`]).
    fn covers_net(&self, net: &IpNet) -> bool {
        match &self.host {
            RuleHost::Ip(ip) => {
                net.prefix_len() == net.max_prefix_len()
                    && *ip == net.network()
                    && classify(*ip) != AddressClass::Forbidden
            }
            RuleHost::Net(rule_net) => {
                rule_net.contains(net)
                    && match net_class(net) {
                        Some(AddressClass::Public) => true,
                        Some(class) => net_within_class(rule_net, class),
                        None => false,
                    }
            }
            RuleHost::Name(_) | RuleHost::Suffix(_) => false,
        }
    }
}

/// Whether `ip` is a destination only a discovery socket may reach: the
/// limited broadcast address or a multicast group (IPv4-mapped forms
/// included).
pub(crate) fn is_group_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// The subnet-directed broadcast address of an IPv4 network; none for
/// IPv6 and for `/31` and `/32`, which have no broadcast address.
fn directed_broadcast(net: &IpNet) -> Option<IpAddr> {
    match net {
        IpNet::V4(v4) if v4.prefix_len() < 31 => Some(IpAddr::V4(v4.broadcast())),
        _ => None,
    }
}

/// A CIDR inside the IPv4-mapped IPv6 range (`::ffff:0:0/96`) as the
/// IPv4 range it maps, since addresses are matched in canonical form.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
        && let Ok(v4net) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96)
    {
        return IpNet::V4(v4net.trunc());
    }
    net.trunc()
}

/// Lowercase, without a trailing dot.
pub(crate) fn normalize_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Whether a normalized name (or `.suffix`) lies under a local-only
/// suffix: `mqtt.lan` and `.lan` do, `lan` and `.arpa` don't.
fn is_local_name(name: &str) -> bool {
    LOCAL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Whether every address, proto and port `narrow` grants is also granted
/// by `wide`, under this module's rules — so an operator may grant
/// `narrow` against a request for `wide` (or the reverse) without
/// widening anything.
///
/// - Proto: equal, or `wide` is `any`.
/// - Port: `wide`'s ports include all of `narrow`'s (`0-65535` covers
///   `*`).
/// - Name hosts: an exact name is covered by itself or a `*.suffix` it
///   matches; `*.a.b` by `*.b` (or itself). A local-only name is covered
///   only by a local-only rule, since it may grant private addresses.
/// - IP hosts: `wide`'s range contains `narrow`'s, and `narrow` grants no
///   loopback, link-local or private address `wide` doesn't (`0.0.0.0/0`
///   covers public space only, so it doesn't cover `10.0.0.0/8` or
///   `10.0.0.5`).
/// - A name never covers an IP rule, nor an IP rule a name.
pub(crate) fn covers(wide: &NetworkRule, narrow: &NetworkRule) -> bool {
    let (wide, narrow) = (CompiledRule::compile(wide), CompiledRule::compile(narrow));
    // Only a `udp` rule reaches a broadcast or multicast group, so an
    // `any` rule naming one grants nothing and covers nothing.
    let names_group = matches!(narrow.host, RuleHost::Ip(ip) if is_group_address(ip));
    let proto = wide.proto == narrow.proto || (wide.proto == Proto::Any && !names_group);
    let port = match (wide.port, narrow.port) {
        (PortMatch::Any, _) => true,
        // Only the full range: a UDP sender may use source port 0.
        (wide, PortMatch::Any) => port_range(wide) == (0..=u16::MAX),
        (wide, PortMatch::Exact(p)) => port_range(wide).contains(&p),
        (wide, PortMatch::Range(lo, hi)) => {
            let range = port_range(wide);
            range.contains(&lo) && range.contains(&hi)
        }
    };
    proto && port && host_covers(&wide, &narrow)
}

fn port_range(port: PortMatch) -> std::ops::RangeInclusive<u16> {
    match port {
        PortMatch::Any => 0..=u16::MAX,
        PortMatch::Exact(p) => p..=p,
        PortMatch::Range(lo, hi) => lo..=hi,
    }
}

fn host_covers(wide: &CompiledRule, narrow: &CompiledRule) -> bool {
    match (&wide.host, &narrow.host) {
        (RuleHost::Name(_) | RuleHost::Suffix(_), RuleHost::Name(name)) => {
            wide.matches_name(name) && (wide.local || !narrow.local)
        }
        (RuleHost::Suffix(wide_suffix), RuleHost::Suffix(suffix)) => {
            suffix.ends_with(wide_suffix.as_str()) && (wide.local || !narrow.local)
        }
        (RuleHost::Ip(_) | RuleHost::Net(_), RuleHost::Ip(_) | RuleHost::Net(_)) => {
            let (wide_net, narrow_net) = (ip_host_net(&wide.host), ip_host_net(&narrow.host));
            wide_net.contains(&narrow_net)
                && (grants_whole_range(&wide.host) || !grants_non_public(&narrow.host))
        }
        _ => false,
    }
}

/// An IP rule's host as a range (a literal is its single-address net).
fn ip_host_net(host: &RuleHost) -> IpNet {
    match host {
        RuleHost::Ip(ip) => IpNet::from(*ip),
        RuleHost::Net(net) => *net,
        RuleHost::Name(_) | RuleHost::Suffix(_) => unreachable!("only called on IP rules"),
    }
}

/// Whether an IP rule grants every (non-forbidden) address it contains:
/// a literal does, and so does a CIDR inside one class's blocks.
fn grants_whole_range(host: &RuleHost) -> bool {
    match host {
        RuleHost::Ip(_) => true,
        RuleHost::Net(net) => NON_PUBLIC.iter().any(|class| net_within_class(net, *class)),
        RuleHost::Name(_) | RuleHost::Suffix(_) => false,
    }
}

/// Whether an IP rule grants some loopback, link-local or private address.
fn grants_non_public(host: &RuleHost) -> bool {
    match host {
        // A forbidden literal counts too: a broadcast or multicast group
        // is reached only through a rule naming it, so `0.0.0.0/0` must
        // not cover `255.255.255.255`.
        RuleHost::Ip(ip) => classify(*ip) != AddressClass::Public,
        RuleHost::Net(_) => grants_whole_range(host),
        RuleHost::Name(_) | RuleHost::Suffix(_) => false,
    }
}

/// The classes only an explicit IP rule (or a local name) reaches.
const NON_PUBLIC: [AddressClass; 3] = [
    AddressClass::Loopback,
    AddressClass::LinkLocal,
    AddressClass::Private,
];

/// Address blocks of the classes a CIDR rule has to stay inside to grant
/// them. Mirrors `native_policy::endpoint::classify` for the forms a CIDR
/// can name directly (IPv4-embedding IPv6 ranges get no class grant).
fn class_blocks(class: AddressClass) -> &'static [&'static str] {
    match class {
        AddressClass::Loopback => &["127.0.0.0/8", "::1/128"],
        AddressClass::LinkLocal => &["169.254.0.0/16", "fe80::/10"],
        AddressClass::Private => &[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "fc00::/7",
            "fec0::/10",
            "64:ff9b:1::/48",
        ],
        AddressClass::Public | AddressClass::Forbidden => &[],
    }
}

/// The one class every address of `net` has, as far as a rule grant
/// goes: the class whose blocks hold all of it, or public when it
/// overlaps none of them. `None` for a range that mixes classes
/// (`172.0.0.0/11` holds public and private addresses).
fn net_class(net: &IpNet) -> Option<AddressClass> {
    if let Some(class) = NON_PUBLIC
        .iter()
        .find(|class| net_within_class(net, **class))
    {
        return Some(*class);
    }
    let overlaps = |block: &str| {
        block
            .parse::<IpNet>()
            .is_ok_and(|block| block.contains(net) || net.contains(&block))
    };
    let mixed = NON_PUBLIC
        .iter()
        .flat_map(|class| class_blocks(*class))
        .chain(NOT_WHOLLY_PUBLIC.iter())
        .any(|block| overlaps(block));
    let public = match net {
        IpNet::V4(_) => true,
        // Global unicast is the only public IPv6 space.
        IpNet::V6(_) => "2000::/3"
            .parse::<IpNet>()
            .is_ok_and(|global| global.contains(net)),
    };
    (public && !mixed && classify(net.network()) == AddressClass::Public)
        .then_some(AddressClass::Public)
}

/// Blocks a public CIDR may not overlap to count as wholly public: the
/// forbidden ones `classify` knows, and the IPv6 ranges it classifies by
/// an embedded IPv4 address.
const NOT_WHOLLY_PUBLIC: [&str; 15] = [
    "0.0.0.0/8",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "2001::/23",
    "2001:db8::/32",
    "3fff::/20",
    "2002::/16",
    "64:ff9b::/96",
    "::ffff:0:0/96",
];

fn net_within_class(net: &IpNet, class: AddressClass) -> bool {
    class_blocks(class).iter().any(|block| {
        block
            .parse::<IpNet>()
            .is_ok_and(|block| block.contains(net))
    })
}

/// Addresses name rules resolved to, with the rules that matched.
#[derive(Default)]
struct Resolved {
    entries: HashMap<IpAddr, ResolvedEntry>,
}

/// One address: each matching rule (index into `NetworkPolicy::rules`)
/// with its own expiry, so resolving one name never extends the grant
/// another name's rule gave the same address.
struct ResolvedEntry {
    rules: Vec<(usize, Instant)>,
}

impl ResolvedEntry {
    /// When the last of its rules expires.
    fn expires(&self) -> Option<Instant> {
        self.rules.iter().map(|(_, e)| *e).max()
    }
}

impl Resolved {
    fn insert(&mut self, ip: IpAddr, rules: &[usize], now: Instant) {
        let expires = now + RESOLVED_TTL;
        if !self.entries.contains_key(&ip) && self.entries.len() >= MAX_RESOLVED {
            for entry in self.entries.values_mut() {
                entry.rules.retain(|(_, e)| *e > now);
            }
            self.entries.retain(|_, e| !e.rules.is_empty());
            if self.entries.len() >= MAX_RESOLVED
                && let Some(oldest) = self
                    .entries
                    .iter()
                    // The address breaks ties (a frozen virtual
                    // clock gives every grant the same expiry), so
                    // eviction never depends on hash order.
                    .min_by_key(|(ip, e)| (e.expires(), **ip))
                    .map(|(ip, _)| *ip)
            {
                self.entries.remove(&oldest);
            }
        }
        let entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ResolvedEntry { rules: Vec::new() });
        for rule in rules {
            match entry.rules.iter_mut().find(|(r, _)| r == rule) {
                Some((_, e)) => *e = expires,
                None => entry.rules.push((*rule, expires)),
            }
        }
    }

    /// The rules whose resolution of `ip` hasn't expired.
    fn rules_for(&self, ip: IpAddr, now: Instant) -> Vec<usize> {
        self.entries.get(&ip).map_or_else(Vec::new, |entry| {
            entry
                .rules
                .iter()
                .filter(|(_, e)| *e > now)
                .map(|(r, _)| *r)
                .collect()
        })
    }
}

/// Token bucket for audited denials.
struct AuditBucket {
    tokens: f64,
    last: Instant,
    suppressed: u64,
}

impl AuditBucket {
    fn new(now: Instant) -> Self {
        Self {
            tokens: AUDIT_BURST,
            last: now,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a row may be written, `n` being the denials
    /// suppressed since the last one; `None` when throttled.
    fn take(&mut self, now: Instant) -> Option<u64> {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * AUDIT_PER_SEC).min(AUDIT_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        }
    }
}

impl NetworkPolicy {
    /// The policy for an instance with these effective rules.
    pub(crate) fn new(
        instance_id: &str,
        rules: &[NetworkRule],
        audit_log: Option<Arc<crate::state::AuditLog>>,
        clock: crate::clock::Clock,
    ) -> Self {
        Self {
            instance_id: Arc::from(instance_id),
            installation_uuid: Arc::from(""),
            rules: rules.iter().map(CompiledRule::compile).collect(),
            resolved: Mutex::default(),
            audit: Mutex::new(AuditBucket::new(clock.std_instant())),
            audit_log,
            clock,
            lookups: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            http_requests: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HTTP)),
            dns: None,
        }
    }

    /// Check one address for `using`. `name_rules` are the name rules a
    /// caller already matched (HTTP); socket callers pass `None` and the
    /// addresses recorded by earlier lookups are used instead.
    pub(crate) fn check_addr(
        &self,
        using: Use,
        addr: SocketAddr,
        name_rules: Option<&[usize]>,
    ) -> Result<(), Denial> {
        let ip = addr.ip().to_canonical();
        let class = classify(ip);
        if class == AddressClass::Forbidden {
            return Err(Denial::Forbidden(ip, class));
        }
        let port = addr.port();
        if self
            .rules
            .iter()
            .any(|r| r.allows(using, port) && r.covers_ip(ip, class))
        {
            return Ok(());
        }
        if matches!(class, AddressClass::Public | AddressClass::Private) {
            let allowed_by = |idx: &usize| {
                self.rules
                    .get(*idx)
                    .is_some_and(|r| r.name_grants(class) && r.allows(using, port))
            };
            let allowed = match name_rules {
                Some(rules) => rules.iter().any(allowed_by),
                None => self
                    .resolved
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .rules_for(ip, self.clock.std_instant())
                    .iter()
                    .any(allowed_by),
            };
            if allowed {
                return Ok(());
            }
        }
        Err(Denial::NotAllowed {
            proto: using.as_str(),
            addr: SocketAddr::new(ip, port),
            class,
        })
    }

    /// Binds: only to the unspecified address (any port).
    pub(crate) fn check_bind(addr: SocketAddr) -> Result<(), Denial> {
        if addr.ip().to_canonical().is_unspecified() {
            Ok(())
        } else {
            Err(Denial::Bind(addr))
        }
    }

    /// Check a discovery socket's send to `addr` (see the module docs):
    /// whether it is a broadcast (`SO_BROADCAST` is set for that send
    /// only), or why it is refused. `local` are the host's interface
    /// networks, which tell a subnet-directed broadcast from a unicast
    /// address; `None` when the host couldn't list them, which refuses
    /// every IPv4 destination but a named group (any could be a broadcast
    /// address).
    pub(crate) fn check_discovery_send(
        &self,
        addr: SocketAddr,
        local: Option<&[LocalInterface]>,
    ) -> Result<bool, Denial> {
        let ip = addr.ip().to_canonical();
        let port = addr.port();
        if is_group_address(ip) {
            return if self
                .rules
                .iter()
                .any(|r| r.names_group(ip) && r.allows(Use::Udp, port))
            {
                Ok(!ip.is_multicast())
            } else {
                Err(Denial::GroupNotNamed(SocketAddr::new(ip, port)))
            };
        }
        let Some(local) = local else {
            return if ip.is_ipv4() {
                Err(Denial::InterfacesUnknown(SocketAddr::new(ip, port)))
            } else {
                self.check_addr(Use::Udp, addr, None).map(|()| false)
            };
        };
        // Every network it is a broadcast address of (computed or
        // configured; overlapping interface networks can share one) must
        // be covered whole.
        let mut nets = local
            .iter()
            .filter(|iface| {
                directed_broadcast(&iface.net) == Some(ip)
                    || iface.broadcast.map(|b| b.to_canonical()) == Some(ip)
            })
            .map(|iface| &iface.net)
            .peekable();
        if nets.peek().is_some() {
            if classify(ip) == AddressClass::Forbidden {
                return Err(Denial::Forbidden(ip, AddressClass::Forbidden));
            }
            for net in nets {
                if !self
                    .rules
                    .iter()
                    .any(|r| r.allows(Use::Udp, port) && r.covers_net(net))
                {
                    return Err(Denial::SubnetBroadcast {
                        addr: SocketAddr::new(ip, port),
                        net: *net,
                    });
                }
            }
            return Ok(true);
        }
        self.check_addr(Use::Udp, addr, None).map(|()| false)
    }

    /// Joining the multicast `group`: a `udp` rule must name it.
    pub(crate) fn check_join(&self, group: IpAddr) -> Result<(), Denial> {
        let group = group.to_canonical();
        if group.is_multicast() && self.rules.iter().any(|r| r.names_group(group)) {
            Ok(())
        } else {
            Err(Denial::Join(group))
        }
    }

    /// Binding a discovery socket of the given family to `port`: an
    /// ephemeral port always, a fixed one only when a `udp` broadcast or
    /// multicast rule of that family allows that port (a socket on `5353`
    /// for `udp://224.0.0.251:5353`).
    pub(crate) fn check_discovery_bind(&self, port: u16, ipv6: bool) -> Result<(), Denial> {
        let named = self.rules.iter().any(|r| {
            r.proto == Proto::Udp
                && matches!(r.host, RuleHost::Ip(ip) if is_group_address(ip) && ip.is_ipv6() == ipv6)
                && r.allows(Use::Udp, port)
        });
        if port == 0 || named {
            Ok(())
        } else {
            Err(Denial::DiscoveryPort(port))
        }
    }

    /// The host's interface networks `interfaces` that one IP rule (of
    /// any proto) covers whole, under the class rules of [`covers`].
    /// Sorted, deduplicated, at most [`MAX_LOCAL_NETWORKS`].
    pub(crate) fn local_networks(&self, interfaces: &[IpNet]) -> Vec<IpNet> {
        let listed: std::collections::BTreeSet<IpNet> = interfaces
            .iter()
            .map(|net| canonical_net(*net))
            .filter(|net| self.rules.iter().any(|rule| rule.covers_net(net)))
            .collect();
        listed.into_iter().take(MAX_LOCAL_NETWORKS).collect()
    }

    /// The name rules matching `name` for any of `uses`, after checking
    /// it is a host name. Empty means the name may not be resolved.
    pub(crate) fn name_rules(&self, name: &str, uses: &[Use]) -> Result<Vec<usize>, Denial> {
        // A DNS name is at most 253 bytes (254 with the root dot); refuse
        // longer guest input before copying it.
        if name.len() > MAX_NAME_LEN + 1 {
            return Err(Denial::InvalidName(
                crate::auth::invocation::audit_cap(name).to_owned(),
            ));
        }
        let normalized = normalize_name(name);
        if crate::native_policy::endpoint::validate_endpoint(&normalized, None, "/").is_err()
            || normalized.parse::<IpAddr>().is_ok()
        {
            return Err(Denial::InvalidName(
                crate::auth::invocation::audit_cap(name).to_owned(),
            ));
        }
        let matched: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.matches_name(&normalized) && uses.iter().any(|u| u.matches(r.proto)))
            .map(|(i, _)| i)
            .collect();
        if matched.is_empty() {
            Err(Denial::NameNotAllowed(normalized))
        } else {
            Ok(matched)
        }
    }

    /// Keep the addresses a lookup of a name matching `rules` may hand to
    /// the plugin, and remember the ones a name rule covers (public ones,
    /// and private ones under a local-only rule) for later connects.
    /// Addresses no rule could ever allow are dropped here, so a
    /// rebinding answer never reaches the plugin.
    ///
    /// With `only`, keep just the addresses that use and port may reach
    /// (an HTTP request), so the result cap never drops the one answer
    /// the request could use.
    pub(crate) fn admit_resolved(
        &self,
        addrs: Vec<IpAddr>,
        rules: &[usize],
        only: Option<(Use, u16)>,
    ) -> Vec<IpAddr> {
        let now = self.clock.std_instant();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for ip in addrs {
            if out.len() >= MAX_LOOKUP_RESULTS {
                break;
            }
            let ip = ip.to_canonical();
            if !seen.insert(ip) {
                continue;
            }
            let class = classify(ip);
            let usable = match class {
                AddressClass::Forbidden => false,
                AddressClass::Public => true,
                // Reachable through a local-only name rule, or an IP
                // rule; still listed in the latter case so a LAN name
                // with a matching CIDR rule works.
                _ => {
                    self.grants_by_name(rules, class)
                        || self.rules.iter().any(|r| r.covers_ip(ip, class))
                }
            };
            let wanted = only.is_none_or(|(using, port)| {
                self.check_addr(using, SocketAddr::new(ip, port), Some(rules))
                    .is_ok()
            });
            if usable && wanted {
                out.push(ip);
            }
        }
        let mut resolved = self.resolved.lock().unwrap_or_else(PoisonError::into_inner);
        for ip in &out {
            if self.grants_by_name(rules, classify(*ip)) {
                resolved.insert(*ip, rules, now);
            }
        }
        out
    }

    /// Whether one of the name rules `rules` covers addresses of `class`.
    fn grants_by_name(&self, rules: &[usize], class: AddressClass) -> bool {
        rules
            .iter()
            .any(|idx| self.rules.get(*idx).is_some_and(|r| r.name_grants(class)))
    }

    /// The instance this policy belongs to.
    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// This policy for an instance of the plugin installation
    /// `installation_uuid`.
    #[must_use]
    pub(crate) fn for_installation(mut self, installation_uuid: Arc<str>) -> Self {
        self.installation_uuid = installation_uuid;
        self
    }

    /// Resolve names from `dns` instead of the platform resolver (the
    /// engine's test seam; `None` keeps the platform resolver).
    pub(crate) fn with_dns(mut self, dns: Option<Arc<super::DnsOverrides>>) -> Self {
        self.dns = dns;
        self
    }

    /// The plugin installation the instance runs.
    pub(crate) fn installation_uuid(&self) -> &str {
        &self.installation_uuid
    }

    /// Record that a request to `target` pinned a LAN device's
    /// certificate on first use: an audit `allow` row (`net.tls_pin`).
    /// Not rate-limited: pins are capped per instance.
    pub(crate) fn audit_pinned(&self, target: &str, fingerprint: crate::state::Fingerprint) {
        crate::runtime::state_read::queue_deny_audit(
            self.audit_log.clone(),
            &self.instance_id,
            crate::runtime::state_read::DeniedRead::TlsPinned {
                target: crate::auth::invocation::audit_cap(target).to_owned(),
                sha256: fingerprint.to_hex(),
            },
        );
    }

    /// Record a refusal: a `tracing` warning and an audit `deny` row,
    /// both rate-limited per instance.
    /// `target` and the reason may carry guest-chosen strings (a lookup
    /// name), so both are capped before they reach the log or the row.
    pub(crate) fn audit_denial(&self, op: &'static str, target: &str, denial: &Denial) {
        let Some(suppressed) = self
            .audit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(self.clock.std_instant())
        else {
            return;
        };
        let target = crate::auth::invocation::audit_cap(target);
        let reason = denial.to_string();
        let reason = crate::auth::invocation::audit_cap(&reason);
        tracing::warn!(
            target: "host.network",
            instance_id = %self.instance_id,
            op,
            target_addr = %target,
            suppressed,
            "network access denied: {reason}",
        );
        crate::runtime::state_read::queue_deny_audit(
            self.audit_log.clone(),
            &self.instance_id,
            crate::runtime::state_read::DeniedRead::Network {
                op,
                target: target.to_owned(),
                reason: reason.to_owned(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &[&str]) -> NetworkPolicy {
        let rules: Vec<NetworkRule> = rules.iter().map(|r| r.parse().expect("rule")).collect();
        NetworkPolicy::new("inst-1", &rules, None, crate::clock::Clock::system())
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("socket addr")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = policy(&[]);
        assert!(p.check_addr(Use::Tcp, sa("8.8.8.8:53"), None).is_err());
        assert!(
            p.check_addr(Use::Udp, sa("192.168.1.2:9999"), None)
                .is_err()
        );
        assert!(matches!(
            p.name_rules("example.com", &[Use::Tcp]),
            Err(Denial::NameNotAllowed(_))
        ));
    }

    #[test]
    fn ip_literal_rule_grants_its_address_and_port() {
        let p = policy(&["tcp://127.0.0.1:1883", "udp://192.168.1.20:9999"]);
        assert_eq!(p.check_addr(Use::Tcp, sa("127.0.0.1:1883"), None), Ok(()));
        assert!(p.check_addr(Use::Tcp, sa("127.0.0.1:1884"), None).is_err());
        assert!(p.check_addr(Use::Tcp, sa("127.0.0.2:1883"), None).is_err());
        assert!(p.check_addr(Use::Udp, sa("127.0.0.1:1883"), None).is_err());
        assert_eq!(
            p.check_addr(Use::Udp, sa("192.168.1.20:9999"), None),
            Ok(())
        );
        assert!(
            p.check_addr(Use::Tcp, sa("192.168.1.20:9999"), None)
                .is_err()
        );
        // Plain HTTP rides on `tcp` rules, HTTPS doesn't.
        assert_eq!(p.check_addr(Use::Http, sa("127.0.0.1:1883"), None), Ok(()));
        assert!(
            p.check_addr(Use::Https, sa("127.0.0.1:1883"), None)
                .is_err()
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_matched_as_ipv4() {
        let p = policy(&["tcp://127.0.0.1:80", "tcp://10.0.0.0/8:*"]);
        assert_eq!(
            p.check_addr(Use::Tcp, sa("[::ffff:127.0.0.1]:80"), None),
            Ok(())
        );
        assert_eq!(
            p.check_addr(Use::Tcp, sa("[::ffff:10.1.2.3]:22"), None),
            Ok(())
        );
        // NAT64 / 6to4 forms of a loopback / private address are not the
        // literal the rule names, and no CIDR rule grants them.
        assert!(
            p.check_addr(Use::Tcp, sa("[64:ff9b::7f00:1]:80"), None)
                .is_err()
        );
        assert!(
            p.check_addr(Use::Tcp, sa("[2002:7f00:1::1]:80"), None)
                .is_err()
        );
        assert!(
            p.check_addr(Use::Tcp, sa("[64:ff9b::a01:203]:22"), None)
                .is_err()
        );
    }

    #[test]
    fn cidr_grants_a_class_only_from_inside_it() {
        let p = policy(&["tcp://0.0.0.0/0:*", "tcp://[::/0]:*"]);
        // Public space is covered…
        assert_eq!(p.check_addr(Use::Tcp, sa("1.1.1.1:443"), None), Ok(()));
        assert_eq!(
            p.check_addr(Use::Tcp, sa("[2606:4700::1111]:443"), None),
            Ok(())
        );
        // …but not the host's loopback, the LAN or the metadata service.
        for addr in [
            "127.0.0.1:80",
            "10.0.0.1:80",
            "192.168.1.1:80",
            "172.16.0.1:80",
            "100.64.0.1:80",
            "169.254.169.254:80",
            "[::1]:80",
            "[fe80::1]:80",
            "[fd00::1]:80",
            "[::ffff:127.0.0.1]:80",
        ] {
            assert!(
                matches!(
                    p.check_addr(Use::Tcp, sa(addr), None),
                    Err(Denial::NotAllowed { .. })
                ),
                "{addr}"
            );
        }
        let lan = policy(&["udp://192.168.0.0/16:9999", "tcp://169.254.169.254:80"]);
        assert_eq!(
            lan.check_addr(Use::Udp, sa("192.168.4.5:9999"), None),
            Ok(())
        );
        assert!(lan.check_addr(Use::Udp, sa("10.0.0.5:9999"), None).is_err());
        assert_eq!(
            lan.check_addr(Use::Tcp, sa("169.254.169.254:80"), None),
            Ok(())
        );
        // A CIDR straddling two classes grants neither private half.
        let straddle = policy(&["tcp://172.0.0.0/8:*"]);
        assert!(
            straddle
                .check_addr(Use::Tcp, sa("172.16.0.1:80"), None)
                .is_err()
        );
        assert_eq!(
            straddle.check_addr(Use::Tcp, sa("172.1.0.1:80"), None),
            Ok(())
        );
    }

    #[test]
    fn ipv4_mapped_cidr_rules_match_ipv4_addresses() {
        let p = policy(&["udp://[::ffff:192.168.1.0/120]:9999"]);
        assert_eq!(
            p.check_addr(Use::Udp, sa("192.168.1.20:9999"), None),
            Ok(())
        );
        assert_eq!(
            p.check_addr(Use::Udp, sa("[::ffff:192.168.1.20]:9999"), None),
            Ok(())
        );
        assert!(
            p.check_addr(Use::Udp, sa("192.168.2.20:9999"), None)
                .is_err()
        );
        // Still contained in the private blocks, so a mapped `/96`
        // (all of IPv4) grants public space only.
        let all = policy(&["tcp://[::ffff:0.0.0.0/96]:*"]);
        assert_eq!(all.check_addr(Use::Tcp, sa("1.1.1.1:80"), None), Ok(()));
        assert!(all.check_addr(Use::Tcp, sa("10.0.0.1:80"), None).is_err());
    }

    #[test]
    fn forbidden_addresses_are_refused_even_with_a_rule() {
        let p = policy(&[
            "udp://255.255.255.255:9999",
            "udp://224.0.0.0/4:*",
            "udp://0.0.0.0:9999",
            "any://[ff02::1]:*",
        ]);
        for addr in [
            "255.255.255.255:9999",
            "224.0.0.251:5353",
            "0.0.0.0:9999",
            "[ff02::1]:5353",
            "[::]:80",
        ] {
            assert!(
                matches!(
                    p.check_addr(Use::Udp, sa(addr), None),
                    Err(Denial::Forbidden(..))
                ),
                "{addr}"
            );
        }
    }

    #[test]
    fn port_ranges_and_any_proto() {
        let p = policy(&["any://1.2.3.4:8000-8010"]);
        assert_eq!(p.check_addr(Use::Tcp, sa("1.2.3.4:8000"), None), Ok(()));
        assert_eq!(p.check_addr(Use::Udp, sa("1.2.3.4:8010"), None), Ok(()));
        assert_eq!(p.check_addr(Use::Https, sa("1.2.3.4:8005"), None), Ok(()));
        assert!(p.check_addr(Use::Tcp, sa("1.2.3.4:8011"), None).is_err());
    }

    #[test]
    fn name_rules_cover_only_public_resolved_addresses() {
        let p = policy(&["tcp://mqtt.example.com:1883", "https://*.example.org"]);
        let rules = p
            .name_rules("MQTT.example.com.", &[Use::Tcp])
            .expect("named");
        assert_eq!(rules, vec![0]);
        // Before a lookup the address isn't known to belong to the name.
        assert!(
            p.check_addr(Use::Tcp, sa("93.184.216.34:1883"), None)
                .is_err()
        );
        let admitted = p.admit_resolved(
            vec![
                ip("93.184.216.34"),
                ip("127.0.0.1"),
                ip("10.0.0.7"),
                ip("::ffff:93.184.216.34"),
            ],
            &rules,
            None,
        );
        // The rebinding answers never reach the plugin.
        assert_eq!(admitted, vec![ip("93.184.216.34")]);
        assert_eq!(
            p.check_addr(Use::Tcp, sa("93.184.216.34:1883"), None),
            Ok(())
        );
        assert!(
            p.check_addr(Use::Tcp, sa("93.184.216.34:1884"), None)
                .is_err()
        );
        assert!(
            p.check_addr(Use::Udp, sa("93.184.216.34:1883"), None)
                .is_err()
        );
        assert!(p.check_addr(Use::Tcp, sa("127.0.0.1:1883"), None).is_err());

        // Suffix rules need a label before the suffix.
        assert!(p.name_rules("example.org", &[Use::Https]).is_err());
        let https = p
            .name_rules("api.example.org", &[Use::Https])
            .expect("suffix");
        assert_eq!(
            p.check_addr(Use::Https, sa("93.184.216.35:443"), Some(&https)),
            Ok(())
        );
        assert!(
            p.check_addr(Use::Https, sa("10.0.0.1:443"), Some(&https))
                .is_err()
        );
        // An `https` rule doesn't allow raw sockets to the name.
        assert!(
            p.name_rules("api.example.org", &[Use::Tcp, Use::Udp])
                .is_err()
        );
    }

    #[test]
    fn lookup_results_are_deduplicated_and_capped() {
        let p = policy(&["tcp://*.example.com:*"]);
        let rules = p.name_rules("a.example.com", &[Use::Tcp]).expect("named");
        let many: Vec<IpAddr> = (0..100u32)
            .map(|i| IpAddr::from(std::net::Ipv4Addr::from(0x0808_0000 + i)))
            .chain([ip("8.8.0.0"), ip("::ffff:8.8.0.1")])
            .collect();
        let admitted = p.admit_resolved(many, &rules, None);
        assert_eq!(admitted.len(), MAX_LOOKUP_RESULTS);
        assert_eq!(admitted[0], ip("8.8.0.0"));
        assert_eq!(admitted[1], ip("8.8.0.1"));
    }

    #[test]
    fn an_http_lookup_keeps_only_what_the_request_can_use() {
        let p = policy(&["udp://10.0.0.0/8:*", "tcp://*.example.com:80"]);
        let rules = p.name_rules("a.example.com", &[Use::Http]).expect("named");
        // 40 LAN answers only the UDP rule covers, then one public one.
        let answers: Vec<IpAddr> = (0..40u32)
            .map(|i| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0001 + i)))
            .chain([ip("93.184.216.34")])
            .collect();
        assert_eq!(
            p.admit_resolved(answers.clone(), &rules, Some((Use::Http, 80))),
            vec![ip("93.184.216.34")]
        );
        assert_eq!(
            p.admit_resolved(answers, &rules, None).len(),
            MAX_LOOKUP_RESULTS
        );
    }

    #[test]
    fn public_names_reach_the_lan_only_through_a_cidr_rule() {
        let p = policy(&["tcp://mqtt.example.net:1883", "tcp://192.168.1.0/24:1883"]);
        let rules = p
            .name_rules("mqtt.example.net", &[Use::Tcp])
            .expect("named");
        let admitted = p.admit_resolved(vec![ip("192.168.1.5"), ip("192.168.2.5")], &rules, None);
        assert_eq!(admitted, vec![ip("192.168.1.5")]);
        assert_eq!(p.check_addr(Use::Tcp, sa("192.168.1.5:1883"), None), Ok(()));
        assert!(
            p.check_addr(Use::Tcp, sa("192.168.2.5:1883"), None)
                .is_err()
        );
    }

    #[test]
    fn local_name_rules_grant_private_addresses() {
        let p = policy(&[
            "tcp://mqtt.lan:1883",
            "tcp://*.home.arpa:80",
            "tcp://metadata.google.internal:80",
            "tcp://*.example.com:1883",
        ]);
        let lan = p.name_rules("mqtt.lan", &[Use::Tcp]).expect("named");
        let admitted = p.admit_resolved(
            vec![
                ip("192.168.1.5"),
                ip("127.0.0.1"),
                ip("169.254.169.254"),
                ip("93.184.216.34"),
            ],
            &lan,
            None,
        );
        // Private and public answers, never loopback or link-local.
        assert_eq!(admitted, vec![ip("192.168.1.5"), ip("93.184.216.34")]);
        assert_eq!(p.check_addr(Use::Tcp, sa("192.168.1.5:1883"), None), Ok(()));
        assert!(
            p.check_addr(Use::Tcp, sa("192.168.1.5:1884"), None)
                .is_err()
        );
        assert!(
            p.check_addr(Use::Udp, sa("192.168.1.5:1883"), None)
                .is_err()
        );

        let home = p.name_rules("cam.home.arpa", &[Use::Http]).expect("named");
        assert_eq!(
            p.check_addr(Use::Http, sa("10.0.0.9:80"), Some(&home)),
            Ok(())
        );
        assert!(
            p.check_addr(Use::Http, sa("[fe80::1]:80"), Some(&home))
                .is_err()
        );

        // The metadata name stays unreachable through its link-local answer.
        let meta = p
            .name_rules("metadata.google.internal", &[Use::Tcp])
            .expect("named");
        assert_eq!(
            p.admit_resolved(vec![ip("169.254.169.254")], &meta, None),
            Vec::<IpAddr>::new()
        );
        assert!(
            p.check_addr(Use::Tcp, sa("169.254.169.254:80"), None)
                .is_err()
        );

        // A public name resolving into the LAN is still a rebinding answer.
        let public = p.name_rules("a.example.com", &[Use::Tcp]).expect("named");
        assert_eq!(
            p.admit_resolved(vec![ip("10.0.0.7")], &public, None),
            Vec::<IpAddr>::new()
        );
        assert!(
            p.check_addr(Use::Tcp, sa("10.0.0.7:1883"), Some(&public))
                .is_err()
        );
    }

    #[test]
    fn local_suffixes_need_a_label_boundary() {
        for (name, local) in [
            ("mqtt.lan", true),
            (".lan", true),
            ("cam.home.arpa", true),
            ("x.local", true),
            ("db.internal", true),
            ("lan", false),
            ("notlan", false),
            ("x.mylan", false),
            (".arpa", false),
            ("x.local.example.com", false),
        ] {
            assert_eq!(is_local_name(name), local, "{name}");
        }
    }

    fn covers_str(wide: &str, narrow: &str) -> bool {
        covers(
            &wide.parse().expect("wide"),
            &narrow.parse().expect("narrow"),
        )
    }

    #[test]
    fn containment_narrows_ip_rules_without_widening_classes() {
        for (wide, narrow) in [
            ("tcp://192.168.0.0/16:*", "tcp://192.168.1.20:80"),
            ("tcp://192.168.0.0/16:*", "tcp://192.168.1.0/24:8000-8080"),
            ("any://192.168.0.0/16:*", "udp://192.168.1.20:9999"),
            ("any://10.0.0.0/8:1-1000", "https://10.1.2.3"),
            ("tcp://0.0.0.0/0:*", "tcp://1.1.1.1:443"),
            ("tcp://0.0.0.0/0:*", "tcp://172.0.0.0/8:80"),
            ("tcp://10.0.0.5:80", "tcp://10.0.0.5/32:80"),
            ("tcp://[fd00::/8]:*", "tcp://[fd00::1]:22"),
            ("tcp://[::ffff:192.168.1.0/120]:*", "tcp://192.168.1.7:80"),
            ("tcp://a.example.com:80", "tcp://a.example.com:80"),
            ("any://192.168.1.2:0-65535", "udp://192.168.1.2:*"),
        ] {
            assert!(covers_str(wide, narrow), "{wide} ⊇ {narrow}");
        }
        for (wide, narrow) in [
            // A broad CIDR grants public space only.
            ("tcp://0.0.0.0/0:*", "tcp://10.0.0.0/8:*"),
            ("tcp://0.0.0.0/0:*", "tcp://10.0.0.5:80"),
            ("tcp://0.0.0.0/0:*", "tcp://127.0.0.1:80"),
            ("tcp://[::/0]:*", "tcp://[fe80::1]:80"),
            // Wider than the request on some axis.
            ("tcp://192.168.1.0/24:*", "tcp://192.168.0.0/16:*"),
            ("tcp://192.168.0.0/16:80", "tcp://192.168.1.2:*"),
            ("tcp://192.168.0.0/16:80-90", "tcp://192.168.1.2:85-95"),
            // Received datagrams may come from source port 0.
            ("any://192.168.1.2:1-65535", "udp://192.168.1.2:*"),
            ("tcp://192.168.0.0/16:*", "udp://192.168.1.2:80"),
            ("tcp://192.168.0.0/16:*", "any://192.168.1.2:80"),
            ("https://10.0.0.0/8", "tcp://10.0.0.1:443"),
            // Names and addresses never cover each other.
            ("tcp://mqtt.lan:1883", "tcp://192.168.1.5:1883"),
            ("tcp://0.0.0.0/0:*", "tcp://a.example.com:80"),
        ] {
            assert!(!covers_str(wide, narrow), "{wide} ⊉ {narrow}");
        }
    }

    #[test]
    fn containment_narrows_name_rules() {
        for (wide, narrow) in [
            ("tcp://*.example.com:*", "tcp://mqtt.example.com:1883"),
            ("tcp://*.example.com:*", "tcp://*.eu.example.com:*"),
            ("https://*.example.com", "https://api.example.com"),
            ("tcp://*.lan:*", "tcp://mqtt.lan:1883"),
            (
                "tcp://MQTT.example.com.:1883",
                "tcp://mqtt.example.com:1883",
            ),
        ] {
            assert!(covers_str(wide, narrow), "{wide} ⊇ {narrow}");
        }
        for (wide, narrow) in [
            ("tcp://*.example.com:*", "tcp://example.com:80"),
            ("tcp://*.example.com:*", "tcp://*.com:80"),
            ("tcp://mqtt.example.com:*", "tcp://*.mqtt.example.com:80"),
            ("tcp://*.example.com:*", "tcp://*.badexample.com:80"),
            // A local-only name may grant private addresses the wider
            // public-suffix rule never could.
            ("tcp://*.arpa:*", "tcp://cam.home.arpa:80"),
            ("tcp://*.arpa:*", "tcp://*.home.arpa:80"),
        ] {
            assert!(!covers_str(wide, narrow), "{wide} ⊉ {narrow}");
        }
    }

    #[test]
    fn names_are_validated() {
        let p = policy(&["tcp://*.example.com:*"]);
        for bad in [
            "",
            "127.1",
            "0x7f.1",
            "a..example.com",
            "-x.example.com",
            "1.2.3.4",
            "::1",
        ] {
            assert!(
                matches!(p.name_rules(bad, &[Use::Tcp]), Err(Denial::InvalidName(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn binds_only_to_the_unspecified_address() {
        assert_eq!(NetworkPolicy::check_bind(sa("0.0.0.0:0")), Ok(()));
        assert_eq!(NetworkPolicy::check_bind(sa("0.0.0.0:5353")), Ok(()));
        assert_eq!(NetworkPolicy::check_bind(sa("[::]:0")), Ok(()));
        assert!(NetworkPolicy::check_bind(sa("127.0.0.1:0")).is_err());
        assert!(NetworkPolicy::check_bind(sa("192.168.1.2:80")).is_err());
    }

    #[test]
    fn resolved_table_is_bounded_and_expires() {
        let mut table = Resolved::default();
        let now = Instant::now();
        let nth = |i: usize| {
            IpAddr::from(std::net::Ipv4Addr::from(
                0x0808_0000 + u32::try_from(i).unwrap(),
            ))
        };
        for i in 0..(MAX_RESOLVED + 10) {
            table.insert(
                nth(i),
                &[0],
                now + Duration::from_millis(u64::try_from(i).unwrap()),
            );
        }
        assert_eq!(table.entries.len(), MAX_RESOLVED);
        // The oldest entries were evicted first.
        assert_eq!(table.rules_for(nth(0), now), Vec::<usize>::new());
        let newest = nth(MAX_RESOLVED + 9);
        assert_eq!(table.rules_for(newest, now), vec![0]);
        assert_eq!(
            table.rules_for(newest, now + RESOLVED_TTL * 2),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn resolving_one_name_does_not_renew_another_names_grant() {
        let mut table = Resolved::default();
        let now = Instant::now();
        let shared = ip("93.184.216.34");
        table.insert(shared, &[0], now);
        let later = now + RESOLVED_TTL.saturating_sub(Duration::from_secs(1));
        table.insert(shared, &[1], later);
        let after_first_expired = now + RESOLVED_TTL + Duration::from_secs(1);
        assert_eq!(table.rules_for(shared, after_first_expired), vec![1]);
    }

    #[test]
    fn grants_and_audit_bucket_follow_the_virtual_clock() {
        let v = crate::clock::VirtualClock::new();
        let rules: Vec<NetworkRule> = vec!["tcp://mqtt.example.com:1883".parse().expect("rule")];
        let p = NetworkPolicy::new("inst-1", &rules, None, v.clone().into());
        let named = p
            .name_rules("mqtt.example.com", &[Use::Tcp])
            .expect("named");
        p.admit_resolved(vec![ip("93.184.216.34")], &named, None);
        let addr = sa("93.184.216.34:1883");
        v.advance(RESOLVED_TTL.saturating_sub(Duration::from_secs(1)));
        assert_eq!(p.check_addr(Use::Tcp, addr, None), Ok(()));
        v.advance(Duration::from_secs(2));
        assert!(p.check_addr(Use::Tcp, addr, None).is_err());

        let suppressed = || {
            p.audit
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .suppressed
        };
        let deny = || p.audit_denial("connect", "10.0.0.1:1", &Denial::Listen);
        for _ in 0..16 {
            deny();
        }
        assert_eq!(suppressed(), 0);
        // Frozen time refills nothing; one virtual second does.
        deny();
        deny();
        assert_eq!(suppressed(), 2);
        v.advance(Duration::from_secs(1));
        deny();
        assert_eq!(suppressed(), 0);
    }

    #[test]
    fn eviction_ties_break_by_address() {
        let mut table = Resolved::default();
        let now = Instant::now();
        let nth = |i: usize| {
            IpAddr::from(std::net::Ipv4Addr::from(
                0x0808_0000 + u32::try_from(i).unwrap(),
            ))
        };
        for i in (0..=MAX_RESOLVED).rev() {
            table.insert(nth(i), &[0], now);
        }
        // Every grant expires together; inserting the last address
        // evicts the lowest one already held.
        assert_eq!(table.rules_for(nth(1), now), Vec::<usize>::new());
        assert_eq!(table.rules_for(nth(0), now), vec![0]);
        assert_eq!(table.rules_for(nth(2), now), vec![0]);
    }

    #[test]
    fn overlong_names_are_refused_before_matching() {
        let p = policy(&["tcp://*.example.com:*"]);
        let long = format!("{}.example.com", "a.".repeat(200));
        assert!(matches!(
            p.name_rules(&long, &[Use::Tcp]),
            Err(Denial::InvalidName(n)) if n.len() <= 128
        ));
    }

    #[test]
    fn audit_bucket_throttles_and_counts() {
        let now = Instant::now();
        let mut bucket = AuditBucket::new(now);
        for _ in 0..16 {
            assert_eq!(bucket.take(now), Some(0));
        }
        assert_eq!(bucket.take(now), None);
        assert_eq!(bucket.take(now), None);
        assert_eq!(bucket.take(now + Duration::from_secs(1)), Some(2));
    }

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|n| n.parse().expect("net")).collect()
    }

    fn ifaces(list: &[&str]) -> Vec<LocalInterface> {
        nets(list).into_iter().map(LocalInterface::from).collect()
    }

    #[test]
    fn groups_need_a_udp_rule_naming_them() {
        let p = policy(&[
            "udp://255.255.255.255:9999",
            "udp://224.0.0.251:5353",
            "udp://[ff02::fb]:5353",
            "any://239.255.255.250:1900",
            "udp://224.0.0.0/4:*",
            "udp://0.0.0.0/0:*",
        ]);
        let send = |a: &str| p.check_discovery_send(sa(a), Some(&[]));
        // The limited broadcast needs `SO_BROADCAST`; multicast doesn't.
        assert_eq!(send("255.255.255.255:9999"), Ok(true));
        assert_eq!(send("224.0.0.251:5353"), Ok(false));
        assert!(send("[::ffff:224.0.0.251]:5353").is_ok());
        assert!(send("[ff02::fb]:5353").is_ok());
        // Wrong port, an `any` rule, a CIDR: none names the group.
        assert_eq!(
            send("255.255.255.255:9998"),
            Err(Denial::GroupNotNamed(sa("255.255.255.255:9998")))
        );
        assert!(send("239.255.255.250:1900").is_err());
        assert!(send("224.0.0.252:5355").is_err());
        assert!(send("[ff02::1]:5353").is_err());
        // Ordinary sends still go through the UDP rules.
        assert!(send("8.8.8.8:53").is_ok());
        assert!(send("192.168.1.5:53").is_err());
        // `wasi:sockets` never reaches a group, whatever the rules.
        assert!(
            p.check_addr(Use::Udp, sa("255.255.255.255:9999"), None)
                .is_err()
        );
        assert!(
            p.check_addr(Use::Udp, sa("224.0.0.251:5353"), None)
                .is_err()
        );
    }

    #[test]
    fn unknown_interfaces_refuse_ipv4_but_named_groups() {
        let p = policy(&[
            "udp://255.255.255.255:9999",
            "udp://0.0.0.0/0:*",
            "udp://[::/0]:*",
        ]);
        assert!(
            p.check_discovery_send(sa("255.255.255.255:9999"), None)
                .is_ok()
        );
        assert_eq!(
            p.check_discovery_send(sa("8.8.8.8:53"), None),
            Err(Denial::InterfacesUnknown(sa("8.8.8.8:53")))
        );
        assert!(
            p.check_discovery_send(sa("[2001:4860::1]:53"), None)
                .is_ok()
        );
    }

    #[test]
    fn subnet_broadcasts_need_the_whole_network() {
        let local = ifaces(&["192.168.1.0/24", "10.0.0.2/31", "198.18.0.0/24"]);
        let whole = policy(&["udp://192.168.0.0/16:9999"]);
        assert!(
            whole
                .check_discovery_send(sa("192.168.1.255:9999"), Some(&local))
                .is_ok()
        );
        let half = policy(&["udp://192.168.1.128/25:9999"]);
        assert_eq!(
            half.check_discovery_send(sa("192.168.1.255:9999"), Some(&local)),
            Err(Denial::SubnetBroadcast {
                addr: sa("192.168.1.255:9999"),
                net: "192.168.1.0/24".parse().unwrap(),
            })
        );
        // A literal naming the broadcast address doesn't do: grant
        // narrowing lets `192.168.1.128/25` cover it.
        let named = policy(&["udp://192.168.1.255:9999"]);
        assert!(
            named
                .check_discovery_send(sa("192.168.1.255:9999"), Some(&local))
                .is_err()
        );
        // Overlapping networks sharing a broadcast address must all be
        // covered, whatever the order they are listed in.
        let overlapping = ifaces(&["192.168.1.128/25", "192.168.1.0/24"]);
        // A configured broadcast address counts as the network's too.
        let configured = [
            LocalInterface::from("192.168.1.0/24".parse::<IpNet>().unwrap()),
            LocalInterface {
                net: "10.9.0.0/16".parse().unwrap(),
                broadcast: Some("192.168.1.255".parse().unwrap()),
            },
        ];
        let lan = policy(&["udp://192.168.1.0/24:9999"]);
        assert!(
            lan.check_discovery_send(sa("192.168.1.255:9999"), Some(&local))
                .is_ok()
        );
        assert!(
            lan.check_discovery_send(sa("192.168.1.255:9999"), Some(&configured))
                .is_err()
        );
        assert!(
            half.check_discovery_send(sa("192.168.1.255:9999"), Some(&overlapping))
                .is_err()
        );
        // A /31 has no broadcast address.
        let p2p = policy(&["udp://10.0.0.3:9999"]);
        assert!(
            p2p.check_discovery_send(sa("10.0.0.3:9999"), Some(&local))
                .is_ok()
        );
        // `0.0.0.0/0` covers public space only, and no rule covers a
        // forbidden network's broadcast address.
        let public = policy(&["udp://0.0.0.0/0:9999", "udp://198.18.0.255:9999"]);
        assert!(
            public
                .check_discovery_send(sa("192.168.1.255:9999"), Some(&local))
                .is_err()
        );
        assert!(
            public
                .check_discovery_send(sa("198.18.0.255:9999"), Some(&local))
                .is_err()
        );
        // A public-looking network holding a forbidden block isn't
        // covered by public space.
        let mixed = ifaces(&["198.16.0.0/14"]);
        assert!(
            public
                .check_discovery_send(sa("198.19.255.255:9999"), Some(&mixed))
                .is_err()
        );
        // Broadcasts are flagged so the socket enables `SO_BROADCAST`
        // for them only.
        assert_eq!(
            whole.check_discovery_send(sa("192.168.1.255:9999"), Some(&local)),
            Ok(true)
        );
        assert_eq!(
            whole.check_discovery_send(sa("192.168.1.7:9999"), Some(&local)),
            Ok(false)
        );
    }

    #[test]
    fn joins_and_fixed_ports_need_group_rules() {
        let p = policy(&[
            "udp://224.0.0.251:5353",
            "udp://255.255.255.255:9999",
            "udp://192.168.0.0/16:*",
            "any://239.255.255.250:1900",
        ]);
        assert!(p.check_join(ip("224.0.0.251")).is_ok());
        assert_eq!(
            p.check_join(ip("239.255.255.250")),
            Err(Denial::Join(ip("239.255.255.250")))
        );
        // Not a group at all.
        assert!(p.check_join(ip("192.168.1.5")).is_err());
        assert!(p.check_discovery_bind(0, false).is_ok());
        assert!(p.check_discovery_bind(5353, false).is_ok());
        assert!(p.check_discovery_bind(9999, false).is_ok());
        // An IPv4 group rule doesn't open the port for IPv6.
        assert!(p.check_discovery_bind(5353, true).is_err());
        // A unicast rule's port doesn't open a shared fixed port, nor
        // does an `any` group rule.
        assert_eq!(
            p.check_discovery_bind(1900, false),
            Err(Denial::DiscoveryPort(1900))
        );
        assert!(policy(&[]).check_discovery_bind(5353, false).is_err());
    }

    #[test]
    fn wide_grants_never_cover_a_group_rule() {
        assert!(!covers_str(
            "udp://0.0.0.0/0:*",
            "udp://255.255.255.255:9999"
        ));
        assert!(!covers_str("udp://224.0.0.0/4:*", "udp://224.0.0.251:5353"));
        assert!(!covers_str("any://[::/0]:*", "udp://[ff02::fb]:5353"));
        assert!(covers_str("udp://224.0.0.251:*", "udp://224.0.0.251:5353"));
        // `any` names no group, so it covers no group rule.
        assert!(!covers_str(
            "any://255.255.255.255:*",
            "udp://255.255.255.255:9999"
        ));
        assert!(covers_str(
            "any://255.255.255.255:*",
            "any://255.255.255.255:9999"
        ));
        // Public literals are still covered by a public range.
        assert!(covers_str("udp://0.0.0.0/0:*", "udp://8.8.8.8:53"));
    }

    #[test]
    fn local_networks_are_the_interface_networks_the_grant_covers() {
        let ifaces = nets(&[
            "192.168.1.0/24",
            "10.0.0.0/8",
            "127.0.0.0/8",
            "fe80::/64",
            "2001:4860::/64",
            "fd00:1::/64",
            "172.0.0.0/11",
            "198.16.0.0/14",
            "2002:8000::/17",
        ]);
        let p = policy(&[
            "udp://192.168.0.0/16:9999",
            // Inside a network: lists nothing.
            "tcp://10.1.2.0/24:80",
            "udp://10.9.9.9:1",
            "udp://255.255.255.255:9999",
            "tcp://mqtt.lan:1883",
            "https://[::/0]",
            // Public space only: not the mixed public / private /11.
            "udp://0.0.0.0/0:*",
        ]);
        let listed: Vec<String> = p
            .local_networks(&ifaces)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(listed, ["192.168.1.0/24", "2001:4860::/64"]);
        assert_eq!(policy(&[]).local_networks(&ifaces), Vec::<IpNet>::new());
        let loopback = policy(&["udp://127.0.0.0/8:*", "udp://[fe80::/10]:*"]);
        let listed: Vec<String> = loopback
            .local_networks(&ifaces)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(listed, ["127.0.0.0/8", "fe80::/64"]);
    }
}
