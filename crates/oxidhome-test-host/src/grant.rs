//! Requested-vs-granted check for injected grants.
//!
//! Production never lets a grant widen what a manifest requests: the
//! loader intersects the two (`oxidhome_core::state::effective_capabilities`)
//! and the service dispatcher checks both lists. A test that injects a
//! wider grant would therefore not get what it asked for, silently.
//! [`grant_excess`] spots that up front so the harness can refuse it.

use oxidhome_manifest::{CapabilitiesSection, ServiceGrant};

/// List every way `granted` asks for more than `requested`. Empty
/// means the grant is a (possibly narrowed) subset of the request —
/// one an operator could actually issue for this manifest.
///
/// Set-shaped fields must be subsets, quotas must not exceed the
/// request (nor may `script_sandboxes`), `subscribes_events` may only
/// be granted when requested, and each `consumes_services` entry must
/// be covered by some requested entry (same plugin and service, a
/// selector no wider than the requested one, commands drawn from the
/// requested list).
#[must_use]
pub fn grant_excess(requested: &CapabilitiesSection, granted: &CapabilitiesSection) -> Vec<String> {
    let mut excess = Vec::new();
    for rule in &granted.network {
        if !requested.network.contains(rule) {
            excess.push(format!("network rule `{rule}` is not requested"));
        }
    }
    if granted.storage_quota_kb > requested.storage_quota_kb {
        excess.push(format!(
            "storage_quota_kb {} exceeds the requested {}",
            granted.storage_quota_kb, requested.storage_quota_kb
        ));
    }
    if granted.blob_quota_mb > requested.blob_quota_mb {
        excess.push(format!(
            "blob_quota_mb {} exceeds the requested {}",
            granted.blob_quota_mb, requested.blob_quota_mb
        ));
    }
    for cap in &granted.declares_devices {
        if !requested.declares_devices.contains(cap) {
            excess.push(format!("device capability `{cap}` is not requested"));
        }
    }
    for svc in &granted.declares_services {
        if !requested.declares_services.contains(svc) {
            excess.push(format!("service `{svc}` is not requested"));
        }
    }
    for (index, grant) in granted.consumes_services.iter().enumerate() {
        if !service_grant_covered(&requested.consumes_services, grant) {
            excess.push(format!(
                "consumes_services[{index}] ({}/{}) is not covered by any requested entry",
                grant.plugin, grant.service
            ));
        }
    }
    if granted.subscribes_events && !requested.subscribes_events {
        excess.push("subscribes_events is not requested".to_owned());
    }
    if granted.script_sandboxes > requested.script_sandboxes {
        excess.push(format!(
            "script_sandboxes {} exceeds the requested {}",
            granted.script_sandboxes, requested.script_sandboxes
        ));
    }
    excess
}

/// Whether every call `grant` authorizes is also authorized by at
/// least one entry in `requested` — checked per command, because the
/// dispatcher accepts a call when *any* requested entry matches it, so
/// several narrower requested entries can together cover one wider
/// grant.
fn service_grant_covered(requested: &[ServiceGrant], grant: &ServiceGrant) -> bool {
    let selector_covers = |req: &str, granted: &str| req == ServiceGrant::ANY || req == granted;
    let covers_command = |req: &ServiceGrant, command: &str| {
        req.plugin == grant.plugin
            && req.service == grant.service
            && selector_covers(&req.instance, &grant.instance)
            && selector_covers(&req.caller_instance, &grant.caller_instance)
            && req
                .commands
                .iter()
                .any(|c| c == ServiceGrant::ANY_COMMAND || c == command)
    };
    // A granted `*` command means "any command", so only a requested
    // `*` covers it; an empty command list authorizes nothing.
    grant
        .commands
        .iter()
        .all(|command| requested.iter().any(|req| covers_command(req, command)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(instance: &str, commands: &[&str], caller: &str) -> ServiceGrant {
        ServiceGrant {
            plugin: "example.counter".into(),
            instance: instance.into(),
            service: "counter".into(),
            commands: commands.iter().map(|c| (*c).to_owned()).collect(),
            caller_instance: caller.into(),
        }
    }

    fn requested() -> CapabilitiesSection {
        CapabilitiesSection {
            network: vec!["tcp://mqtt.example.com:1883".parse().expect("rule")],
            storage_quota_kb: 4,
            blob_quota_mb: 1,
            declares_devices: vec!["switch".into()],
            declares_services: vec!["svc".into()],
            consumes_services: vec![svc("*", &["get", "increment"], "*")],
            subscribes_events: true,
            script_sandboxes: 2,
        }
    }

    #[test]
    fn identical_and_narrowed_grants_have_no_excess() {
        let req = requested();
        assert_eq!(grant_excess(&req, &req), Vec::<String>::new());
        assert_eq!(
            grant_excess(&req, &CapabilitiesSection::default()),
            Vec::<String>::new()
        );
        let narrowed = CapabilitiesSection {
            storage_quota_kb: 1,
            consumes_services: vec![svc("counter-1", &["get"], "me")],
            ..req.clone()
        };
        assert_eq!(grant_excess(&req, &narrowed), Vec::<String>::new());
    }

    #[test]
    fn every_widened_field_is_reported() {
        let req = CapabilitiesSection::default();
        let wide = requested();
        let excess = grant_excess(&req, &wide);
        assert_eq!(excess.len(), 8, "{excess:?}");
    }

    #[test]
    fn service_grant_wider_than_request_is_reported() {
        let req = CapabilitiesSection {
            consumes_services: vec![svc("counter-1", &["get"], "me")],
            ..CapabilitiesSection::default()
        };
        for wider in [
            svc("*", &["get"], "me"),
            svc("counter-1", &["get", "increment"], "me"),
            svc("counter-1", &["*"], "me"),
            svc("counter-1", &["get"], "*"),
        ] {
            let grant = CapabilitiesSection {
                consumes_services: vec![wider.clone()],
                ..CapabilitiesSection::default()
            };
            assert_eq!(grant_excess(&req, &grant).len(), 1, "{wider:?}");
        }
    }

    #[test]
    fn several_requested_entries_cover_one_wider_grant() {
        let req = CapabilitiesSection {
            consumes_services: vec![svc("c", &["get"], "*"), svc("c", &["increment"], "*")],
            ..CapabilitiesSection::default()
        };
        let grant = CapabilitiesSection {
            consumes_services: vec![svc("c", &["get", "increment"], "me")],
            ..CapabilitiesSection::default()
        };
        assert_eq!(grant_excess(&req, &grant), Vec::<String>::new());
        let wider = CapabilitiesSection {
            consumes_services: vec![svc("c", &["get", "reset"], "me")],
            ..CapabilitiesSection::default()
        };
        assert_eq!(grant_excess(&req, &wider).len(), 1);
    }

    #[test]
    fn wildcard_command_request_covers_any_command() {
        let req = CapabilitiesSection {
            consumes_services: vec![svc("*", &["*"], "*")],
            ..CapabilitiesSection::default()
        };
        let grant = CapabilitiesSection {
            consumes_services: vec![svc("x", &["anything", "*"], "y")],
            ..CapabilitiesSection::default()
        };
        assert_eq!(grant_excess(&req, &grant), Vec::<String>::new());
    }
}
