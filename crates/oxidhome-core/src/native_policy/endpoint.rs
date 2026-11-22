//! `network-endpoint` validation and the resolved-address policy.
//!
//! Two separate checks, because they run at different times:
//!
//! 1. [`validate_endpoint`] runs when a plugin hands the host a
//!    `media-source::{rtsp, http}`: it checks the parts are well-formed
//!    and can't smuggle a scheme, userinfo, or second authority.
//! 2. [`check_resolved_addr`] runs on **every address the host is about to
//!    connect to**: after the host resolves `host` itself, and again for
//!    every redirect hop. The host must connect to exactly the address it
//!    checked (no second DNS lookup), or DNS rebinding can swap the target
//!    between check and connect. [`check_redirect`] caps the hops and
//!    refuses TLS downgrades.
//!
//! A hostname allowlist alone is not enough: a public name can resolve to
//! `127.0.0.1`, and a public server can redirect to a private one. That is
//! why the policy is keyed on the resolved IP.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest DNS name accepted as `network-endpoint.host`.
pub const MAX_HOST_LEN: usize = 253;
/// Longest DNS label.
const MAX_LABEL_LEN: usize = 63;
/// Longest `network-endpoint.path` (path plus query).
pub const MAX_PATH_LEN: usize = 2048;
/// Most redirects the host follows for one media source.
pub const MAX_REDIRECTS: usize = 5;

/// Address classes a plugin may be granted beyond public unicast.
///
/// Comes from the plugin's granted capabilities (the operator-approved
/// copy, not the manifest's request). The default denies all three.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddressGrant {
    /// `127.0.0.0/8`, `::1`.
    pub loopback: bool,
    /// `169.254.0.0/16`, `fe80::/10`.
    pub link_local: bool,
    /// RFC 1918, `100.64.0.0/10`, `fc00::/7`, `fec0::/10`, `64:ff9b:1::/48`.
    pub private: bool,
}

/// What kind of address an IP is, for policy purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Globally routable unicast. Always allowed.
    Public,
    /// Loopback. Allowed only with [`AddressGrant::loopback`].
    Loopback,
    /// Link-local. Allowed only with [`AddressGrant::link_local`].
    LinkLocal,
    /// Private / shared / unique-local. Allowed only with
    /// [`AddressGrant::private`].
    Private,
    /// Unspecified, broadcast, multicast, documentation, benchmarking,
    /// IETF protocol assignments (incl. Teredo), or otherwise reserved.
    /// Never allowed.
    Forbidden,
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Public => "public",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Private => "private",
            Self::Forbidden => "forbidden",
        })
    }
}

/// Why an endpoint or address was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("endpoint host is empty")]
    EmptyHost,
    #[error("endpoint host is longer than {MAX_HOST_LEN} bytes")]
    HostTooLong,
    #[error("endpoint host is neither a DNS name nor an IP literal")]
    InvalidHost,
    #[error("endpoint port 0 is not allowed")]
    ZeroPort,
    #[error("endpoint path must start with '/'")]
    RelativePath,
    #[error("endpoint path is longer than {MAX_PATH_LEN} bytes")]
    PathTooLong,
    #[error("endpoint path may only contain printable ASCII and no '#'")]
    InvalidPathChar,
    #[error("{addr} is a {class} address, which this plugin is not granted")]
    AddressDenied { addr: IpAddr, class: AddressClass },
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("redirect from TLS to plaintext")]
    TlsDowngrade,
}

/// Check a `network-endpoint`'s host, port, and path.
///
/// `host` is a DNS name or an IP literal (IPv6 without brackets or zone
/// id). A DNS name is LDH labels of 1–63 bytes, not starting or ending
/// with `-`, and its last label must not be a decimal or `0x` hex number
/// — so numeric forms such as `127.1` or `0x7f.1`, which URL parsers and
/// `inet_aton` treat as IPv4 addresses, can't pose as names.
pub fn validate_endpoint(host: &str, port: Option<u16>, path: &str) -> Result<(), EndpointError> {
    validate_host(host)?;
    if port == Some(0) {
        return Err(EndpointError::ZeroPort);
    }
    validate_path(path)
}

fn validate_host(host: &str) -> Result<(), EndpointError> {
    if host.is_empty() {
        return Err(EndpointError::EmptyHost);
    }
    if host.len() > MAX_HOST_LEN {
        return Err(EndpointError::HostTooLong);
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let mut last = "";
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return Err(EndpointError::InvalidHost);
        }
        last = label;
    }
    if is_numeric_label(last) {
        return Err(EndpointError::InvalidHost);
    }
    Ok(())
}

/// A decimal or `0x` hex number. A host whose last label is one is
/// parsed as an IPv4 address by URL parsers and `inet_aton` (`127.1`,
/// `0x7f.1`, `2130706433`), so it can't be accepted as a name.
fn is_numeric_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    match lower.strip_prefix("0x") {
        Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => lower.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn validate_path(path: &str) -> Result<(), EndpointError> {
    if !path.starts_with('/') {
        return Err(EndpointError::RelativePath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(EndpointError::PathTooLong);
    }
    if !path.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Err(EndpointError::InvalidPathChar);
    }
    Ok(())
}

/// Check one resolved address against the plugin's grant.
///
/// Call this for every address before connecting to it, including after
/// each redirect.
pub fn check_resolved_addr(addr: IpAddr, grant: AddressGrant) -> Result<(), EndpointError> {
    let class = classify(addr);
    let allowed = match class {
        AddressClass::Public => true,
        AddressClass::Loopback => grant.loopback,
        AddressClass::LinkLocal => grant.link_local,
        AddressClass::Private => grant.private,
        AddressClass::Forbidden => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(EndpointError::AddressDenied { addr, class })
    }
}

/// Check that the host may follow one more redirect: at most
/// [`MAX_REDIRECTS`] hops, and never from TLS to plaintext (the request
/// may carry credentials). `followed` is the number already followed.
///
/// The redirect target is a new endpoint: the caller still runs
/// [`validate_endpoint`] on it and [`check_resolved_addr`] on every
/// address it resolves to.
pub fn check_redirect(followed: usize, from_tls: bool, to_tls: bool) -> Result<(), EndpointError> {
    if followed >= MAX_REDIRECTS {
        Err(EndpointError::TooManyRedirects)
    } else if from_tls && !to_tls {
        Err(EndpointError::TlsDowngrade)
    } else {
        Ok(())
    }
}

/// Classify an address. IPv6 addresses that carry an IPv4 address
/// (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) take the class of
/// the IPv4 address, so `::ffff:127.0.0.1` is loopback, not public.
#[must_use]
pub fn classify(addr: IpAddr) -> AddressClass {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, c, _] = ip.octets();
    match (a, b, c) {
        (127, _, _) => AddressClass::Loopback,
        (169, 254, _) => AddressClass::LinkLocal,
        (10 | 192 | 172 | 100, _, _) if is_private_v4(a, b) => AddressClass::Private,
        // 0/8 "this network" (incl. unspecified), 192.0.0/24 IETF protocol
        // assignments, documentation nets, 198.18/15 benchmarking,
        // 224/4 multicast, 240/4 reserved (incl. broadcast).
        (0 | 224..=255, _, _)
        | (192, 0, 0 | 2)
        | (198, 51, 100)
        | (203, 0, 113)
        | (198, 18..=19, _) => AddressClass::Forbidden,
        _ => AddressClass::Public,
    }
}

/// RFC 1918 plus `100.64.0.0/10` shared address space.
fn is_private_v4(a: u8, b: u8) -> bool {
    matches!(
        (a, b),
        (10, _) | (192, 168) | (172, 16..=31) | (100, 64..=127)
    )
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4);
    }
    let seg = ip.segments();
    match seg {
        [0, 0, 0, 0, 0, 0, 0, 1] => AddressClass::Loopback,
        // Special-purpose blocks inside global unicast: IETF protocol
        // assignments 2001::/23 (Teredo, benchmarking, ORCHID, ...) and
        // documentation 2001:db8::/32 and 3fff::/20.
        [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..] => AddressClass::Forbidden,
        // NAT64 local-use prefix (RFC 8215): a site-local translator.
        [0x64, 0xff9b, 1, ..] => AddressClass::Private,
        [s0, ..] => match s0 {
            // Link-local fe80::/10.
            0xfe80..=0xfebf => AddressClass::LinkLocal,
            // Unique-local fc00::/7 and deprecated site-local fec0::/10.
            0xfc00..=0xfdff | 0xfec0..=0xfeff => AddressClass::Private,
            // Global unicast 2000::/3. Everything else is unassigned or
            // reserved: `::`, IPv4-compatible `::/96`, discard 100::/64,
            // SRv6 5f00::/16, multicast ff00::/8, ...
            0x2000..=0x3fff => AddressClass::Public,
            _ => AddressClass::Forbidden,
        },
    }
}

/// The IPv4 address an IPv6 address carries, for the forms that route to
/// it: IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96` (segments 6–7),
/// and 6to4 `2002::/16` (segments 1–2).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let v4_from = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match ip.segments() {
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] | [0x2002, hi, lo, ..] => Some(v4_from(hi, lo)),
        _ => ip.to_ipv4_mapped(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(s: &str) -> AddressClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn classifies_ipv4() {
        assert_eq!(class("8.8.8.8"), AddressClass::Public);
        assert_eq!(class("127.0.0.1"), AddressClass::Loopback);
        assert_eq!(class("127.255.0.9"), AddressClass::Loopback);
        assert_eq!(class("169.254.169.254"), AddressClass::LinkLocal);
        assert_eq!(class("10.1.2.3"), AddressClass::Private);
        assert_eq!(class("172.16.0.1"), AddressClass::Private);
        assert_eq!(class("172.31.255.255"), AddressClass::Private);
        assert_eq!(class("172.32.0.1"), AddressClass::Public);
        assert_eq!(class("192.168.1.10"), AddressClass::Private);
        assert_eq!(class("100.64.0.1"), AddressClass::Private);
        assert_eq!(class("100.128.0.1"), AddressClass::Public);
        for forbidden in [
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "240.0.0.1",
            "224.0.0.251",
            "239.255.255.250",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "192.0.0.1",
        ] {
            assert_eq!(class(forbidden), AddressClass::Forbidden, "{forbidden}");
        }
    }

    #[test]
    fn classifies_ipv6() {
        assert_eq!(class("2606:4700::1111"), AddressClass::Public);
        assert_eq!(class("::1"), AddressClass::Loopback);
        assert_eq!(class("::"), AddressClass::Forbidden);
        assert_eq!(class("::7f00:1"), AddressClass::Forbidden);
        assert_eq!(class("fe80::1"), AddressClass::LinkLocal);
        assert_eq!(class("febf::1"), AddressClass::LinkLocal);
        assert_eq!(class("fd12:3456::1"), AddressClass::Private);
        assert_eq!(class("fc00::1"), AddressClass::Private);
        assert_eq!(class("fec0::1"), AddressClass::Private);
        assert_eq!(class("ff02::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:db8::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:0::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:2::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:20::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:1ff::1"), AddressClass::Forbidden);
        assert_eq!(class("2001:200::1"), AddressClass::Public);
        assert_eq!(class("3fff::1"), AddressClass::Forbidden);
        assert_eq!(class("3fff:fff::1"), AddressClass::Forbidden);
        assert_eq!(class("3fff:1000::1"), AddressClass::Public);
        assert_eq!(class("5f00::1"), AddressClass::Forbidden);
        assert_eq!(class("100::1"), AddressClass::Forbidden);
        assert_eq!(class("100:0:0:1::1"), AddressClass::Forbidden);
        // Outside global unicast 2000::/3: unassigned / reserved.
        assert_eq!(class("4000::1"), AddressClass::Forbidden);
        assert_eq!(class("1::1"), AddressClass::Forbidden);
        assert_eq!(class("fe00::1"), AddressClass::Forbidden);
        assert_eq!(class("2000::1"), AddressClass::Public);
    }

    #[test]
    fn embedded_ipv4_takes_the_ipv4_class() {
        assert_eq!(class("::ffff:127.0.0.1"), AddressClass::Loopback);
        assert_eq!(class("::ffff:10.0.0.1"), AddressClass::Private);
        assert_eq!(class("::ffff:8.8.8.8"), AddressClass::Public);
        assert_eq!(class("64:ff9b::7f00:1"), AddressClass::Loopback);
        assert_eq!(class("64:ff9b::a9fe:a9fe"), AddressClass::LinkLocal);
        assert_eq!(class("64:ff9b::808:808"), AddressClass::Public);
        assert_eq!(class("64:ff9b:1::1"), AddressClass::Private);
        assert_eq!(class("2002:7f00:1::1"), AddressClass::Loopback);
        assert_eq!(class("2002:c0a8:101::1"), AddressClass::Private);
        assert_eq!(class("2002:808:808::1"), AddressClass::Public);
    }

    #[test]
    fn grant_gates_each_class() {
        let none = AddressGrant::default();
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(check_resolved_addr(addr("1.1.1.1"), none), Ok(()));
        for (ip, grant) in [
            (
                "127.0.0.1",
                AddressGrant {
                    loopback: true,
                    ..none
                },
            ),
            (
                "169.254.1.1",
                AddressGrant {
                    link_local: true,
                    ..none
                },
            ),
            (
                "192.168.0.2",
                AddressGrant {
                    private: true,
                    ..none
                },
            ),
        ] {
            assert!(
                matches!(
                    check_resolved_addr(addr(ip), none),
                    Err(EndpointError::AddressDenied { .. })
                ),
                "{ip} denied without grant"
            );
            assert_eq!(check_resolved_addr(addr(ip), grant), Ok(()), "{ip}");
        }
        // A private grant doesn't open loopback or link-local.
        let private = AddressGrant {
            private: true,
            ..none
        };
        assert!(check_resolved_addr(addr("127.0.0.1"), private).is_err());
        assert!(check_resolved_addr(addr("fe80::1"), private).is_err());
        // Nothing opens forbidden classes.
        let all = AddressGrant {
            loopback: true,
            link_local: true,
            private: true,
        };
        for ip in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            "4000::1",
            "fe00::1",
        ] {
            assert_eq!(
                check_resolved_addr(addr(ip), all),
                Err(EndpointError::AddressDenied {
                    addr: addr(ip),
                    class: AddressClass::Forbidden
                }),
                "{ip}"
            );
        }
    }

    #[test]
    fn redirect_rules() {
        assert_eq!(check_redirect(0, false, false), Ok(()));
        assert_eq!(check_redirect(0, false, true), Ok(()));
        assert_eq!(check_redirect(MAX_REDIRECTS - 1, true, true), Ok(()));
        assert_eq!(
            check_redirect(MAX_REDIRECTS, false, false),
            Err(EndpointError::TooManyRedirects)
        );
        assert_eq!(
            check_redirect(0, true, false),
            Err(EndpointError::TlsDowngrade)
        );
    }

    #[test]
    fn accepts_well_formed_endpoints() {
        for host in [
            "camera.lan",
            "cam-1.example.com",
            "localhost",
            "192.168.1.20",
            "fe80::1",
            "2001:db8::5",
            "a",
            "3d-camera",
            "1cam.lan",
            "cam.1x",
            "0xcam",
        ] {
            assert_eq!(
                validate_endpoint(host, Some(554), "/stream1"),
                Ok(()),
                "{host}"
            );
        }
        assert_eq!(
            validate_endpoint("cam.lan", None, "/cgi-bin/mjpg?res=hd&x=%20"),
            Ok(())
        );
    }

    #[test]
    fn rejects_malformed_hosts() {
        let long = format!("{}.com", "a".repeat(MAX_HOST_LEN));
        assert_eq!(
            validate_endpoint("", None, "/"),
            Err(EndpointError::EmptyHost)
        );
        assert_eq!(
            validate_endpoint(&long, None, "/"),
            Err(EndpointError::HostTooLong)
        );
        for host in [
            "user:pass@cam.lan",
            "cam.lan:554",
            "cam.lan/path",
            "[::1]",
            "fe80::1%eth0",
            "cam..lan",
            "cam.lan.",
            ".cam.lan",
            "-cam.lan",
            "cam-.lan",
            "cam lan",
            "127.1",
            "0x7f.1",
            "2130706433",
            "cam.123",
            "0X7F000001",
            "0x",
            &format!("{}.lan", "a".repeat(64)),
        ] {
            assert_eq!(
                validate_endpoint(host, None, "/"),
                Err(EndpointError::InvalidHost),
                "{host}"
            );
        }
    }

    #[test]
    fn rejects_bad_port_and_path() {
        assert_eq!(
            validate_endpoint("cam.lan", Some(0), "/"),
            Err(EndpointError::ZeroPort)
        );
        assert_eq!(
            validate_endpoint("cam.lan", None, ""),
            Err(EndpointError::RelativePath)
        );
        assert_eq!(
            validate_endpoint("cam.lan", None, "stream"),
            Err(EndpointError::RelativePath)
        );
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(
            validate_endpoint("cam.lan", None, &long),
            Err(EndpointError::PathTooLong)
        );
        for path in ["/a b", "/a\nb", "/a#frag", "/a\u{0}", "/caf\u{e9}"] {
            assert_eq!(
                validate_endpoint("cam.lan", None, path),
                Err(EndpointError::InvalidPathChar),
                "{path:?}"
            );
        }
    }
}
