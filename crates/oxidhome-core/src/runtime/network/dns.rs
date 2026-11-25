//! Test seam for name resolution: a fixed table of names and the
//! addresses they resolve to, consulted instead of the platform
//! resolver. Set only through [`crate::Engine::with_dns_overrides_for_tests`]
//! (the test host's `TestHost::with_dns_overrides`); the daemon never
//! sets one.

use std::collections::HashMap;
use std::net::IpAddr;

/// Names and their answers. With a table in place, a name it doesn't
/// list is unresolvable: lookups never fall through to real DNS, so a
/// test's results don't depend on the machine it runs on.
#[derive(Debug, Default)]
pub(crate) struct DnsOverrides {
    names: HashMap<String, Vec<IpAddr>>,
}

impl DnsOverrides {
    /// A table from `(name, addresses)` pairs. Names match like the
    /// policy matches them (case-insensitive, a trailing dot ignored);
    /// a name listed twice gets the addresses of both entries.
    pub(crate) fn new(entries: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        let mut names: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for (name, addrs) in entries {
            names
                .entry(super::policy::normalize_name(&name))
                .or_default()
                .extend(addrs);
        }
        Self { names }
    }

    /// The addresses `name` resolves to, or `None` when it is
    /// unresolvable: not listed, or listed with no addresses.
    pub(crate) fn lookup(&self, name: &str) -> Option<Vec<IpAddr>> {
        self.names
            .get(&super::policy::normalize_name(name))
            .filter(|addrs| !addrs.is_empty())
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_case_insensitively_without_the_trailing_dot() {
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let other: IpAddr = "192.168.1.21".parse().unwrap();
        let table = DnsOverrides::new([
            ("Camera.LAN.".to_owned(), vec![ip]),
            ("camera.lan".to_owned(), vec![other]),
            ("empty.lan".to_owned(), Vec::new()),
        ]);
        assert_eq!(table.lookup("camera.lan"), Some(vec![ip, other]));
        assert_eq!(table.lookup("CAMERA.lan."), Some(vec![ip, other]));
        assert_eq!(table.lookup("printer.lan"), None);
        assert_eq!(table.lookup("empty.lan"), None);
    }
}
