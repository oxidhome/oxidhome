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
//! rule        := proto "://" authority
//! authority   := host-no-port | bracketed-ipv6 [":" port] | host-with-port
//! host-no-port  := exact-host | "*." suffix | ipv4-cidr | ipv6-cidr | ipv6-literal
//! bracketed-ipv6 := "[" (ipv6-literal | ipv6-cidr) "]"
//! host-with-port := host-no-port ":" port    -- but only when host has no `:`
//! proto       := "tcp" | "udp" | "https" | "any"
//! port        := digits | digits "-" digits | "*"
//! ```
//!
//! Defaults: omitting `:port` on an `https` rule means `:443`. Omitting
//! `:port` on any other proto requires explicit `:*` for "any port".
//!
//! IPv6: hosts whose textual form contains `:` need bracket syntax when
//! a port is supplied — `tcp://[2001:db8::1]:1883` (literal),
//! `udp://[2001:db8::/32]:5353` (CIDR). The entire IP-literal goes
//! inside the brackets; only `:port` follows the closing `]`.
//! Bracket-less IPv6 is accepted only when no port is attached
//! (e.g. `https://2001:db8::1` falls back on the HTTPS default
//! `:443`). `Display` emits the bracketed form whenever it would be
//! needed to round-trip cleanly.

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
    #[error("invalid host `{0}`: a host containing `:` must be a valid IPv6 literal or CIDR")]
    InvalidHost(String),
    #[error("invalid token `{0}` in rule `{1}`: whitespace not allowed")]
    WhitespaceInToken(String, String),
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

        // Split host[:port]. Two forms:
        //   - Bracketed `[host]:port` — required when host is IPv6
        //     and a port is supplied (else the colon-split can't tell
        //     the address from the port). Inside the brackets the
        //     host must parse as an IPv6 literal or IPv6 CIDR.
        //   - Unbracketed `host:port` — for DNS names, wildcards,
        //     IPv4 (CIDR or literal), and IPv6 *without* an explicit
        //     port (HTTPS supplies the default :443).
        let (host_str, port_str_opt, bracketed) = if let Some(after_open) = rest.strip_prefix('[') {
            let Some(close_idx) = after_open.find(']') else {
                return Err(NetworkRuleParseError::InvalidHost(rest.to_owned()));
            };
            let host = &after_open[..close_idx];
            let after_close = &after_open[close_idx + 1..];
            let port = if after_close.is_empty() {
                None
            } else if let Some(p) = after_close.strip_prefix(':') {
                Some(p)
            } else {
                // Stuff after `]` that isn't `:port` — e.g. `[host]junk`.
                return Err(NetworkRuleParseError::InvalidHost(rest.to_owned()));
            };
            (host, port, true)
        } else {
            let (h, p) = split_host_port(rest);
            (h, p, false)
        };

        // Reject any whitespace inside the split tokens. The full `raw`
        // is `trim()`'d above; internal whitespace (e.g. `tcp:// host`
        // or `tcp://host: 1883`) is a typo we want to surface, not
        // silently absorb into a host string.
        reject_whitespace(host_str, raw)?;
        if let Some(p) = port_str_opt {
            reject_whitespace(p, raw)?;
        }

        let host = parse_host(host_str, raw, bracketed)?;
        let port = match port_str_opt {
            Some(s) => parse_port(s, raw)?,
            None => default_port(proto)?,
        };

        Ok(NetworkRule { proto, host, port })
    }
}

fn reject_whitespace(token: &str, raw: &str) -> Result<(), NetworkRuleParseError> {
    if token.chars().any(char::is_whitespace) {
        return Err(NetworkRuleParseError::WhitespaceInToken(
            token.to_owned(),
            raw.to_owned(),
        ));
    }
    Ok(())
}

/// Split off an optional trailing `:port` token from an unbracketed
/// `host[:port]` string. Returns `(host, None)` when there's no port
/// to extract, `(host, Some(port_str))` when there is.
///
/// IPv6 literals and CIDRs (e.g. `2001:db8::1`, `2001:db8::/32`) are
/// detected as port-less here because their last colon sits inside
/// the address — the host gets the whole string and `parse_host`
/// hands it off to `IpAddr` / `IpNet`. To attach an explicit port
/// to an IPv6 host, callers use the bracketed form
/// (`[2001:db8::1]:1883`) which is parsed before this function is
/// called.
fn split_host_port(rest: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rest.rfind(':') {
        let (host, after_colon) = rest.split_at(idx);
        let port_str = &after_colon[1..];
        // If the candidate "host" side still contains `:`, it's an
        // IPv6 form (multiple colons) — there's no port suffix here,
        // so hand the whole thing back as the host and let
        // `parse_host` validate it. Same if the candidate "port"
        // contains `/`: that's a CIDR mask sitting where we'd expect
        // a port number, so the whole `rest` is the host string.
        if host.contains(':') || port_str.contains('/') {
            return (rest, None);
        }
        (host, Some(port_str))
    } else {
        (rest, None)
    }
}

/// Parse the host portion of a rule. `bracketed = true` means the
/// host came out of `[…]` brackets and must be an IPv6 literal or
/// IPv6 CIDR — DNS names, wildcards, and IPv4 forms are rejected
/// (RFC-3986 only allows brackets around IP-literals).
fn parse_host(
    host_str: &str,
    full: &str,
    bracketed: bool,
) -> Result<HostMatch, NetworkRuleParseError> {
    if host_str.is_empty() {
        return Err(NetworkRuleParseError::EmptyHost(full.to_owned()));
    }
    if bracketed {
        // Inside brackets: IPv6 only.
        if host_str.contains('/') {
            let net = host_str
                .parse::<IpNet>()
                .map_err(|e| NetworkRuleParseError::InvalidCidr(host_str.to_owned(), e))?;
            if !net.network().is_ipv6() {
                return Err(NetworkRuleParseError::InvalidHost(host_str.to_owned()));
            }
            return Ok(HostMatch::Cidr(net));
        }
        let ip = host_str
            .parse::<IpAddr>()
            .map_err(|_| NetworkRuleParseError::InvalidHost(host_str.to_owned()))?;
        if !ip.is_ipv6() {
            return Err(NetworkRuleParseError::InvalidHost(host_str.to_owned()));
        }
        return Ok(HostMatch::Exact(ip.to_string()));
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
    // A host that still contains `:` at this point isn't a wildcard,
    // CIDR, or valid IP literal — that's a malformed rule like
    // `https://example.com:80:90` (two ports) or a typo'd IPv6. Reject
    // rather than absorbing the colons into a Exact host string.
    if host_str.contains(':') {
        return Err(NetworkRuleParseError::InvalidHost(host_str.to_owned()));
    }
    Ok(HostMatch::Exact(host_str.to_owned()))
}

fn parse_port(port_str: &str, full: &str) -> Result<PortMatch, NetworkRuleParseError> {
    if port_str == "*" {
        return Ok(PortMatch::Any);
    }
    if let Some((lo, hi)) = port_str.split_once('-') {
        // Pass the failing sub-token (`lo` or `hi`) into the error, not
        // the full rule — the message reads "invalid port `<token>`:
        // …" and the token should identify what couldn't be parsed.
        // `InvalidPortRange` keeps `full` so the operator still sees
        // the rule context for the range-shape error.
        let lo: u16 = lo
            .parse()
            .map_err(|e| NetworkRuleParseError::InvalidPort(lo.to_owned(), e))?;
        let hi: u16 = hi
            .parse()
            .map_err(|e| NetworkRuleParseError::InvalidPort(hi.to_owned(), e))?;
        if lo > hi {
            return Err(NetworkRuleParseError::InvalidPortRange(full.to_owned()));
        }
        return Ok(PortMatch::Range(lo, hi));
    }
    let p: u16 = port_str
        .parse()
        .map_err(|e| NetworkRuleParseError::InvalidPort(port_str.to_owned(), e))?;
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
        let host_raw = match &self.host {
            HostMatch::Exact(s) => s.clone(),
            HostMatch::SuffixWildcard(suffix) => {
                // suffix is stored leading-dot, e.g. ".example.com"
                format!("*{suffix}")
            }
            HostMatch::Cidr(net) => net.to_string(),
        };
        // Whether we'll emit a `:port` suffix. The one no-port case is
        // an HTTPS rule on the default port (443).
        let emit_port = !matches!(
            (self.proto, self.port),
            (Proto::Https, PortMatch::Exact(443))
        );
        // Bracket the host whenever it serializes with `:` (IPv6) *and*
        // we're attaching a port — otherwise the round-trip would
        // fail (`FromStr` can't split `:port` past IPv6 colons). For
        // the no-port HTTPS case, brackets are unnecessary and we
        // keep the unbracketed form to match what the parser
        // already accepts.
        let host = if emit_port && host_raw.contains(':') {
            format!("[{host_raw}]")
        } else {
            host_raw
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

    /// IPv6 works when the proto supplies a default port. HTTPS does,
    /// so `https://2001:db8::/32` and `https://2001:db8::1` both parse
    /// cleanly with port 443.
    #[test]
    fn ipv6_https_uses_default_port() {
        let r = rule("https://2001:db8::/32");
        let HostMatch::Cidr(net) = &r.host else {
            panic!("expected Cidr, got {:?}", r.host)
        };
        assert!(net.to_string().starts_with("2001:db8::"));
        assert_eq!(r.port, PortMatch::Exact(443));

        let r = rule("https://2001:db8::1");
        let HostMatch::Exact(s) = &r.host else {
            panic!("expected Exact, got {:?}", r.host)
        };
        assert_eq!(s, "2001:db8::1");
        assert_eq!(r.port, PortMatch::Exact(443));
    }

    /// Unbracketed IPv6 with a proto that requires an explicit port
    /// (tcp/udp/any) still fails — the colon-split can't separate the
    /// address from the port without brackets. The fix is to use
    /// `[…]:port`, exercised by `ipv6_tcp_with_bracketed_port_works`.
    #[test]
    fn ipv6_tcp_without_brackets_still_rejected() {
        let err = "tcp://2001:db8::/32".parse::<NetworkRule>().unwrap_err();
        assert!(
            matches!(err, NetworkRuleParseError::MissingPort(_)),
            "got {err:?}",
        );
    }

    /// Bracketed IPv6 literals + CIDRs accept an explicit port. This
    /// makes `Display` ↔ `FromStr` round-trip safe for any
    /// programmatically-built rule. The grammar puts the *entire*
    /// IP-literal (including any `/mask` for CIDRs) inside the
    /// brackets; only `:port` follows the closing bracket.
    #[test]
    fn ipv6_tcp_with_bracketed_port_works() {
        let r = rule("tcp://[2001:db8::1]:1883");
        assert_eq!(r.proto, Proto::Tcp);
        assert_eq!(r.host, HostMatch::Exact("2001:db8::1".into()));
        assert_eq!(r.port, PortMatch::Exact(1883));

        let r = rule("udp://[2001:db8::/32]:5353");
        assert_eq!(r.proto, Proto::Udp);
        let HostMatch::Cidr(net) = &r.host else {
            panic!("expected Cidr, got {:?}", r.host)
        };
        assert!(net.network().is_ipv6());
        assert_eq!(r.port, PortMatch::Exact(5353));

        let r = rule("tcp://[2001:db8::1]:*");
        assert_eq!(r.port, PortMatch::Any);
    }

    /// Brackets are only valid around IPv6 — DNS names, IPv4 literals,
    /// and wildcards in brackets are rejected to match RFC 3986.
    #[test]
    fn brackets_reject_non_ipv6() {
        for bad in [
            "tcp://[example.com]:80",
            "tcp://[10.0.0.1]:80",
            "tcp://[*.example.com]:443",
        ] {
            let err = bad.parse::<NetworkRule>().unwrap_err();
            assert!(
                matches!(err, NetworkRuleParseError::InvalidHost(_)),
                "expected InvalidHost for `{bad}`, got {err:?}",
            );
        }
    }

    /// Stuff trailing `]` other than `:port` is malformed.
    #[test]
    fn bracketed_trailing_junk_rejected() {
        for bad in ["tcp://[2001:db8::1]junk:80", "tcp://[2001:db8::1junk"] {
            let err = bad.parse::<NetworkRule>().unwrap_err();
            assert!(
                matches!(err, NetworkRuleParseError::InvalidHost(_)),
                "expected InvalidHost for `{bad}`, got {err:?}",
            );
        }
    }

    /// `Display` emits the bracketed form whenever it would be needed
    /// for round-trip. This pins the asymmetry-free behavior: a rule
    /// built programmatically with an IPv6 host + explicit port
    /// serializes to a string `FromStr` can read back.
    #[test]
    fn display_brackets_ipv6_when_port_present() {
        let r: NetworkRule = "tcp://[2001:db8::1]:1883".parse().unwrap();
        assert_eq!(r.to_string(), "tcp://[2001:db8::1]:1883");

        let r: NetworkRule = "udp://[2001:db8::/32]:5353".parse().unwrap();
        // ipnet may canonicalize the CIDR; just check the shape.
        let s = r.to_string();
        assert!(s.starts_with("udp://[") && s.ends_with("]:5353"), "got {s}");

        // No-port HTTPS case stays unbracketed (matches what
        // `ipv6_https_uses_default_port` asserts).
        let r: NetworkRule = "https://2001:db8::1".parse().unwrap();
        assert_eq!(r.to_string(), "https://2001:db8::1");
    }

    #[test]
    fn double_port_rejected() {
        // The previously-too-lenient parser would silently turn
        // `https://example.com:80:90` into host = "example.com:80:90",
        // port = 443. Tighter `parse_host` now rejects it.
        let err = "https://example.com:80:90"
            .parse::<NetworkRule>()
            .unwrap_err();
        assert!(
            matches!(err, NetworkRuleParseError::InvalidHost(_)),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        // Stray whitespace *inside* a token is almost certainly a typo;
        // surfacing it as a parse error beats silently building a host
        // string with embedded spaces. Whitespace at the *edges* of the
        // whole rule is intentionally trimmed (see
        // `outer_whitespace_is_trimmed`).
        for bad in [
            "tcp:// mqtt.example.com:1883", // leading space in host
            "tcp://mqtt.example.com :1883", // trailing space in host
            "tcp://mqtt.example.com: 1883", // leading space in port
            "tcp://mqtt example.com:1883",  // embedded space in host
        ] {
            let err = bad.parse::<NetworkRule>().unwrap_err();
            assert!(
                matches!(err, NetworkRuleParseError::WhitespaceInToken(_, _)),
                "expected WhitespaceInToken for `{bad}`, got {err:?}",
            );
        }
    }

    /// Whitespace at the *edges* of the whole rule string is intentionally
    /// trimmed by `from_str` — a TOML author's stray leading/trailing
    /// space shouldn't fail the install. Only whitespace *inside* a
    /// token (host or port) is rejected.
    #[test]
    fn outer_whitespace_is_trimmed() {
        let r = rule("  tcp://mqtt.example.com:1883  ");
        assert_eq!(r.host, HostMatch::Exact("mqtt.example.com".into()));
        assert_eq!(r.port, PortMatch::Exact(1883));
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
    fn invalid_port_carries_just_the_token() {
        // The `InvalidPort` variant's first field is the token that
        // couldn't be parsed — not the entire rule. The rendered
        // message reads "invalid port `notanumber`: …", not
        // "invalid port `tcp://example.com:notanumber`: …".
        let err = "tcp://example.com:notanumber"
            .parse::<NetworkRule>()
            .unwrap_err();
        let NetworkRuleParseError::InvalidPort(token, _) = &err else {
            panic!("expected InvalidPort, got {err:?}");
        };
        assert_eq!(token, "notanumber");
    }

    #[test]
    fn invalid_port_range_low_token() {
        // For ranges, the failing side (`lo` or `hi`) is identified.
        let err = "tcp://example.com:abc-9000"
            .parse::<NetworkRule>()
            .unwrap_err();
        let NetworkRuleParseError::InvalidPort(token, _) = &err else {
            panic!("expected InvalidPort, got {err:?}");
        };
        assert_eq!(token, "abc");
    }

    #[test]
    fn invalid_port_range_high_token() {
        let err = "tcp://example.com:8000-xyz"
            .parse::<NetworkRule>()
            .unwrap_err();
        let NetworkRuleParseError::InvalidPort(token, _) = &err else {
            panic!("expected InvalidPort, got {err:?}");
        };
        assert_eq!(token, "xyz");
    }

    #[test]
    fn invalid_port_range_inverted() {
        // The `lo > hi` case is a shape error about the whole range,
        // not a single token — `InvalidPortRange` carries the full
        // rule so the operator sees the context.
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
