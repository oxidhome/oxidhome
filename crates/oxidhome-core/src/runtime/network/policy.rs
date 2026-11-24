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
//!    addresses the host itself resolved a matching name to — never a
//!    loopback, link-local or private one, which would let a DNS answer
//!    reach the LAN (rebinding). Socket lookups record those addresses
//!    in a bounded, expiring table that the connect / send check reads;
//!    an HTTP request carries its matched rules directly.

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
/// Longest DNS name, without the root dot.
const MAX_NAME_LEN: usize = 253;
/// Audited denials allowed in a burst, per instance.
const AUDIT_BURST: f64 = 16.0;
/// Audited denials refilled per second, per instance.
const AUDIT_PER_SEC: f64 = 1.0;

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
}

/// The per-instance policy object. Shared (`Arc`) between the socket
/// address check, the name-lookup implementation and the HTTP client.
pub(crate) struct NetworkPolicy {
    instance_id: Arc<str>,
    rules: Vec<CompiledRule>,
    resolved: Mutex<Resolved>,
    audit: Mutex<AuditBucket>,
    audit_log: Option<Arc<crate::state::AuditLog>>,
    /// The engine clock: resolved-grant expiry and the audit bucket.
    clock: crate::clock::Clock,
    pub(crate) lookups: Arc<tokio::sync::Semaphore>,
    pub(crate) http_requests: Arc<tokio::sync::Semaphore>,
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
        Self {
            proto: rule.proto,
            port: rule.port,
            host,
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
            rules: rules.iter().map(CompiledRule::compile).collect(),
            resolved: Mutex::default(),
            audit: Mutex::new(AuditBucket::new(clock.std_instant())),
            audit_log,
            clock,
            lookups: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            http_requests: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HTTP)),
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
        if class == AddressClass::Public {
            let allowed_by = |idx: &usize| {
                self.rules
                    .get(*idx)
                    .is_some_and(|r| r.is_name_rule() && r.allows(using, port))
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
    /// the plugin, and remember the public ones for later connects.
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
                // Reachable only through an IP rule; still listed so a
                // LAN name with a matching CIDR rule works.
                _ => self.rules.iter().any(|r| r.covers_ip(ip, class)),
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
            if classify(*ip) == AddressClass::Public {
                resolved.insert(*ip, rules, now);
            }
        }
        out
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
    fn lan_names_resolve_through_a_cidr_rule() {
        let p = policy(&["tcp://mqtt.lan:1883", "tcp://192.168.1.0/24:1883"]);
        let rules = p.name_rules("mqtt.lan", &[Use::Tcp]).expect("named");
        let admitted = p.admit_resolved(vec![ip("192.168.1.5"), ip("192.168.2.5")], &rules, None);
        assert_eq!(admitted, vec![ip("192.168.1.5")]);
        assert_eq!(p.check_addr(Use::Tcp, sa("192.168.1.5:1883"), None), Ok(()));
        assert!(
            p.check_addr(Use::Tcp, sa("192.168.2.5:1883"), None)
                .is_err()
        );
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
}
