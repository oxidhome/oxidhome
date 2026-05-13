//! Outbound network rules — the typed shape of `[capabilities] network`.
//!
//! Each entry in the TOML list is a string like
//! `"tcp://mqtt.example.com:1883"`, `"udp://192.168.1.0/24:5353"`,
//! `"https://*.api.example.com"`, or `"tcp://192.168.1.1:*"`. The
//! manifest parser turns each into a [`NetworkRule`] eagerly so a
//! malformed rule fails install, not first-connect.
//!
//! Phase 8 (`streaming-plugin` world) writes the connect-gate against
//! `Vec<NetworkRule>`; Phase 4 only parses and exposes the types so
//! plugin authors can declare what they need.
//!
//! ## Grammar
//!
//! ```text
//! rule    := proto "://" host [":" port]
//! proto   := "tcp" | "udp" | "https" | "any"
//! host    := exact-host | "*." suffix | cidr
//! port    := digits | digits "-" digits | "*"
//! ```
//!
//! Defaults: omitting `:port` on an `https` rule means `:443`. Omitting
//! `:port` on any other proto requires explicit `:*` for "any port".

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// One outbound-network rule. The manifest's
/// `[capabilities].network` is `Vec<NetworkRule>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    pub proto: Proto,
    pub host: HostMatch,
    pub port: PortMatch,
}

/// Wire-level protocol. `Any` is the explicit "any of the below" token
/// — distinct from omitting the proto (which is a parse error).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Https,
    Any,
}

impl Proto {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Https => "https",
            Proto::Any => "any",
        }
    }
}

/// Host-side matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    /// Exact DNS name or IP literal: `"mqtt.example.com"`, `"10.0.0.5"`.
    Exact(String),
    /// `*.example.com` ⇒ stored as `".example.com"`; matches any host
    /// whose DNS name ends with that suffix and has at least one label
    /// before it (the bare `example.com` does *not* match).
    SuffixWildcard(String),
    /// CIDR range. Covers both IPv4 and IPv6 via [`ipnet::IpNet`].
    Cidr(IpNet),
}

/// Port-side matcher.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PortMatch {
    Exact(u16),
    /// Inclusive range; parsing rejects `start > end`.
    Range(u16, u16),
    /// `*` — any port.
    Any,
}

/// Errors raised by the [`NetworkRule`] string parser.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkRuleParseError {
    #[error("missing `://` between proto and host in `{0}`")]
    MissingScheme(String),
    #[error("unknown proto `{0}` (expected tcp/udp/https/any)")]
    UnknownProto(String),
    #[error("empty host in `{0}`")]
    EmptyHost(String),
    #[error("invalid CIDR `{0}`: {1}")]
    InvalidCidr(String, ipnet::AddrParseError),
    #[error("invalid wildcard host `{0}`: must be `*.<suffix>` with at least one label after `*`")]
    InvalidWildcard(String),
    #[error("invalid port `{0}`: {1}")]
    InvalidPort(String, std::num::ParseIntError),
    #[error("invalid port range `{0}`: start must be <= end")]
    InvalidPortRange(String),
    #[error("port required for proto `{0}` (use `:*` for any port)")]
    MissingPort(&'static str),
}

impl FromStr for NetworkRule {
    type Err = NetworkRuleParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();

        let (proto_str, rest) = raw
            .split_once("://")
            .ok_or_else(|| NetworkRuleParseError::MissingScheme(raw.to_owned()))?;
        let proto = match proto_str {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "https" => Proto::Https,
            "any" => Proto::Any,
            other => return Err(NetworkRuleParseError::UnknownProto(other.to_owned())),
        };

        // Split host[:port]. IPv4 CIDRs contain `/` but no `:`.
        // IPv6 hosts/CIDRs aren't supported today: `split_host_port`
        // treats any host containing `:` as "no port suffix", so an
        // IPv6 rule has no way to express a port. Phase 8 will add
        // bracketed IPv6 syntax (`[2001:db8::]/32:*`) when the
        // streaming-plugin enforcer needs it. The
        // `ipv6_cidr_currently_unsupported` test pins this so removing
        // the limitation is a deliberate change.
        let (host_str, port_str_opt) = split_host_port(rest);

        let host = parse_host(host_str, raw)?;
        let port = match port_str_opt {
            Some(s) => parse_port(s, raw)?,
            None => default_port(proto)?,
        };

        Ok(NetworkRule { proto, host, port })
    }
}

/// Split off an optional trailing `:port` token. Returns `(host, None)`
/// when no `:` appears, `(host, Some(port_str))` otherwise. IPv6 in
/// CIDR form (e.g. `2001:db8::/32`) has no port and is correctly
/// detected as such because the last colon is inside the address.
fn split_host_port(rest: &str) -> (&str, Option<&str>) {
    // If the candidate "port" portion contains `/` it's actually part
    // of a CIDR, not a port — treat the whole thing as host.
    if let Some(idx) = rest.rfind(':') {
        let (host, after_colon) = rest.split_at(idx);
        let port_str = &after_colon[1..];
        // Reject `:port` parses for IPv6 CIDRs / addresses (which have
        // multiple `:`s) by requiring the host side to not also contain
        // a `:` outside brackets. Phase 8 may revisit if IPv6 literals
        // are needed; for 0.1, IPv6 must be expressed as a CIDR
        // (e.g. `2001:db8::/32`) without a port suffix.
        if host.contains(':') || port_str.contains('/') {
            return (rest, None);
        }
        (host, Some(port_str))
    } else {
        (rest, None)
    }
}

fn parse_host(host_str: &str, full: &str) -> Result<HostMatch, NetworkRuleParseError> {
    if host_str.is_empty() {
        return Err(NetworkRuleParseError::EmptyHost(full.to_owned()));
    }
    if let Some(suffix) = host_str.strip_prefix("*.") {
        if suffix.is_empty() || suffix.starts_with('.') {
            return Err(NetworkRuleParseError::InvalidWildcard(host_str.to_owned()));
        }
        return Ok(HostMatch::SuffixWildcard(format!(".{suffix}")));
    }
    if host_str.contains('/') {
        let net = host_str
            .parse::<IpNet>()
            .map_err(|e| NetworkRuleParseError::InvalidCidr(host_str.to_owned(), e))?;
        return Ok(HostMatch::Cidr(net));
    }
    // Bare IP literals are stored as Exact for now — Phase 8 may want
    // to canonicalize them via IpAddr at the match call. The string
    // form keeps the manifest readable.
    if let Ok(ip) = host_str.parse::<IpAddr>() {
        return Ok(HostMatch::Exact(ip.to_string()));
    }
    Ok(HostMatch::Exact(host_str.to_owned()))
}

fn parse_port(port_str: &str, full: &str) -> Result<PortMatch, NetworkRuleParseError> {
    if port_str == "*" {
        return Ok(PortMatch::Any);
    }
    if let Some((lo, hi)) = port_str.split_once('-') {
        let lo: u16 = lo
            .parse()
            .map_err(|e| NetworkRuleParseError::InvalidPort(full.to_owned(), e))?;
        let hi: u16 = hi
            .parse()
            .map_err(|e| NetworkRuleParseError::InvalidPort(full.to_owned(), e))?;
        if lo > hi {
            return Err(NetworkRuleParseError::InvalidPortRange(full.to_owned()));
        }
        return Ok(PortMatch::Range(lo, hi));
    }
    let p: u16 = port_str
        .parse()
        .map_err(|e| NetworkRuleParseError::InvalidPort(full.to_owned(), e))?;
    Ok(PortMatch::Exact(p))
}

const fn default_port(proto: Proto) -> Result<PortMatch, NetworkRuleParseError> {
    match proto {
        Proto::Https => Ok(PortMatch::Exact(443)),
        Proto::Tcp => Err(NetworkRuleParseError::MissingPort("tcp")),
        Proto::Udp => Err(NetworkRuleParseError::MissingPort("udp")),
        Proto::Any => Err(NetworkRuleParseError::MissingPort("any")),
    }
}

impl fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = match &self.host {
            HostMatch::Exact(s) => s.clone(),
            HostMatch::SuffixWildcard(suffix) => {
                // suffix is stored leading-dot, e.g. ".example.com"
                format!("*{suffix}")
            }
            HostMatch::Cidr(net) => net.to_string(),
        };
        match self.port {
            PortMatch::Any => write!(f, "{}://{}:*", self.proto.as_str(), host),
            PortMatch::Exact(p) if self.proto == Proto::Https && p == 443 => {
                write!(f, "{}://{}", self.proto.as_str(), host)
            }
            PortMatch::Exact(p) => write!(f, "{}://{}:{}", self.proto.as_str(), host, p),
            PortMatch::Range(lo, hi) => {
                write!(f, "{}://{}:{}-{}", self.proto.as_str(), host, lo, hi)
            }
        }
    }
}

impl Serialize for NetworkRule {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NetworkRule {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> NetworkRule {
        s.parse().expect("parse")
    }

    #[test]
    fn exact_host_with_port() {
        let r = rule("tcp://mqtt.example.com:1883");
        assert_eq!(r.proto, Proto::Tcp);
        assert_eq!(r.host, HostMatch::Exact("mqtt.example.com".into()));
        assert_eq!(r.port, PortMatch::Exact(1883));
    }

    #[test]
    fn cidr_with_port() {
        let r = rule("udp://192.168.1.0/24:5353");
        assert_eq!(r.proto, Proto::Udp);
        let HostMatch::Cidr(net) = &r.host else {
            panic!("expected Cidr, got {:?}", r.host)
        };
        assert_eq!(net.to_string(), "192.168.1.0/24");
        assert_eq!(r.port, PortMatch::Exact(5353));
    }

    #[test]
    fn wildcard_subdomain_https_default_port() {
        let r = rule("https://*.api.example.com");
        assert_eq!(r.proto, Proto::Https);
        assert_eq!(r.host, HostMatch::SuffixWildcard(".api.example.com".into()));
        assert_eq!(r.port, PortMatch::Exact(443));
    }

    #[test]
    fn any_port_on_ip() {
        let r = rule("tcp://192.168.1.1:*");
        assert_eq!(r.host, HostMatch::Exact("192.168.1.1".into()));
        assert_eq!(r.port, PortMatch::Any);
    }

    #[test]
    fn port_range() {
        let r = rule("tcp://api.example.com:8000-9000");
        assert_eq!(r.port, PortMatch::Range(8000, 9000));
    }

    /// IPv6 CIDR currently errors because the unbracketed colon-split
    /// can't see past IPv6 colons to find a `:port`. Phase 8 will
    /// revisit with bracketed form (`[2001:db8::]/32:*`). Pinned as a
    /// test so the limitation is explicit and removing it is a
    /// deliberate change.
    #[test]
    fn ipv6_cidr_currently_unsupported() {
        let err = "tcp://2001:db8::/32".parse::<NetworkRule>().unwrap_err();
        assert!(
            matches!(err, NetworkRuleParseError::MissingPort(_)),
            "got {err:?}",
        );
    }

    #[test]
    fn missing_scheme() {
        assert_eq!(
            "mqtt.example.com:1883".parse::<NetworkRule>().unwrap_err(),
            NetworkRuleParseError::MissingScheme("mqtt.example.com:1883".into()),
        );
    }

    #[test]
    fn unknown_proto() {
        let err = "ftp://example.com:21".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::UnknownProto(ref p) if p == "ftp"));
    }

    #[test]
    fn empty_host() {
        let err = "tcp://:1883".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::EmptyHost(_)));
    }

    #[test]
    fn invalid_wildcard() {
        let err = "https://*..example.com".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::InvalidWildcard(_)));
        let err = "https://*.".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::InvalidWildcard(_)));
    }

    #[test]
    fn invalid_port() {
        let err = "tcp://example.com:notanumber"
            .parse::<NetworkRule>()
            .unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::InvalidPort(_, _)));
    }

    #[test]
    fn invalid_port_range() {
        let err = "tcp://example.com:9000-8000"
            .parse::<NetworkRule>()
            .unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::InvalidPortRange(_)));
    }

    #[test]
    fn missing_port_for_tcp_default() {
        let err = "tcp://example.com".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::MissingPort("tcp")));
    }

    #[test]
    fn invalid_cidr() {
        let err = "udp://10.0.0.0/99:53".parse::<NetworkRule>().unwrap_err();
        assert!(matches!(err, NetworkRuleParseError::InvalidCidr(_, _)));
    }

    #[test]
    fn round_trip_via_display() {
        for input in [
            "tcp://mqtt.example.com:1883",
            "udp://192.168.1.0/24:5353",
            "https://*.api.example.com",
            "tcp://192.168.1.1:*",
            "tcp://example.com:8000-9000",
            "any://example.com:*",
        ] {
            let parsed: NetworkRule = input.parse().unwrap();
            let displayed = parsed.to_string();
            let reparsed: NetworkRule = displayed.parse().unwrap();
            assert_eq!(parsed, reparsed, "roundtrip mismatch for {input}");
        }
    }

    #[test]
    fn deserialize_from_toml_string_list() {
        #[derive(Deserialize)]
        struct Wrap {
            network: Vec<NetworkRule>,
        }
        let w: Wrap = toml::from_str(
            r#"
network = [
  "tcp://mqtt.example.com:1883",
  "udp://192.168.1.0/24:5353",
  "https://*.api.example.com",
]
"#,
        )
        .unwrap();
        assert_eq!(w.network.len(), 3);
        assert_eq!(w.network[0].port, PortMatch::Exact(1883));
        assert_eq!(w.network[2].port, PortMatch::Exact(443));
    }

    #[test]
    fn serialize_back_to_toml_string() {
        let rule: NetworkRule = "tcp://mqtt.example.com:1883".parse().unwrap();
        let s = toml::to_string(&serde_json_compat::Wrap { v: rule }).unwrap();
        assert!(s.contains("tcp://mqtt.example.com:1883"));
    }

    // Tiny private wrapper so we can call `toml::to_string` on a
    // single value (toml's top-level encoder needs a table).
    mod serde_json_compat {
        use super::NetworkRule;
        use serde::Serialize;

        #[derive(Serialize)]
        pub struct Wrap {
            pub v: NetworkRule,
        }
    }
}
