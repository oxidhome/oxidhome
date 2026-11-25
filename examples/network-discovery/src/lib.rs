//! OxidHome Phase 8 example: UDP discovery from the `streaming-plugin`
//! world.
//!
//! On `init` the plugin opens a discovery socket (bound to the
//! unspecified address, ephemeral port) and sends a probe datagram to
//! every target in its `targets` config: by default the limited
//! broadcast address `255.255.255.255:9999`. A target `local:<port>`
//! stands for the broadcast address of each local IPv4 network the
//! grant covers (`discovery::local_networks`), so the plugin can sweep
//! its LAN without being told the subnet. On each `tick` it drains the
//! replies without blocking and publishes each one as a
//! `network-discovery.reply` custom event (`<addr>:<port> <payload>`).
//! The host runs `tick` early when a reply is waiting (at least 100 ms
//! after the previous tick returned), so the manifest's cadence is only a
//! fallback.
//!
//! The host decides each send and each received datagram against the
//! manifest's `[capabilities] network` rules: broadcast needs a `udp`
//! rule naming `255.255.255.255` and the port, a target no rule allows
//! fails with `PermissionDenied` (and the host audits it), and replies
//! from addresses no rule allows never arrive.

use std::net::{IpAddr, SocketAddr};

use oxidhome_sdk::bindings::oxidhome::plugin::types::Value;
use oxidhome_sdk::host::{self, config, storage};
use oxidhome_sdk::streaming::discovery::{self, DiscoverySocket};
use oxidhome_sdk::{Plugin, StreamingPlugin};

/// Custom-event topic for each reply.
const REPLY_TOPIC: &str = "network-discovery.reply";
/// KV key holding the number of replies published so far.
const REPLIES_KEY: &str = "replies";
/// Longest reply published; longer payloads are truncated.
const MAX_REPLY: usize = 512;
/// Most replies handled per tick, so one tick stays short.
const MAX_REPLIES_PER_TICK: usize = 32;

#[derive(Default)]
struct NetworkDiscovery {
    /// One socket per address family the targets use.
    sockets: Vec<DiscoverySocket>,
    replies: i64,
}

fn config_string(key: &str) -> Option<String> {
    match config::get(key) {
        Ok(Some(Value::StringVal(s))) => Some(s),
        _ => None,
    }
}

/// The targets: `ip:port`, or `local:<port>` for the broadcast address
/// of each local IPv4 network the grant covers.
fn parse_targets(targets: &str) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for target in targets.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Some(port) = target.strip_prefix("local:") {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("target `{target}` is not local:<port>"))?;
            out.extend(
                discovery::local_networks()
                    .iter()
                    .filter_map(discovery::LocalNetwork::broadcast)
                    .map(|ip| SocketAddr::new(IpAddr::V4(ip), port)),
            );
        } else {
            out.push(
                target
                    .parse()
                    .map_err(|_| format!("target `{target}` is not ip:port or local:<port>"))?,
            );
        }
    }
    Ok(out)
}

impl NetworkDiscovery {
    fn drain(&mut self) {
        let before = self.replies;
        for socket in &self.sockets {
            self.replies += drain_socket(socket);
        }
        if self.replies != before
            && let Err(e) = storage::set(REPLIES_KEY, &Value::IntVal(self.replies))
        {
            oxidhome_sdk::tracing::warn!(error = ?e, "storing the reply count failed");
        }
    }
}

/// A discovery socket for `family` on an ephemeral port. It never
/// blocks.
fn bind(ipv6: bool) -> Result<DiscoverySocket, String> {
    if ipv6 {
        DiscoverySocket::bind_v6(0)
    } else {
        DiscoverySocket::bind_v4(0)
    }
    .map_err(|e| format!("bind: {e}"))
}

/// Publish the replies waiting on `socket`; returns how many.
fn drain_socket(socket: &DiscoverySocket) -> i64 {
    let datagrams = match socket.recv(MAX_REPLIES_PER_TICK) {
        Ok(datagrams) => datagrams,
        Err(e) => {
            oxidhome_sdk::tracing::warn!(error = %e, "receiving failed");
            return 0;
        }
    };
    let mut replies = 0;
    for datagram in datagrams {
        let data = &datagram.data[..datagram.data.len().min(MAX_REPLY)];
        let payload = String::from_utf8_lossy(data);
        let from = datagram.from;
        match host::publish_custom_event(None, REPLY_TOPIC, format!("{from} {payload}")) {
            Ok(()) => replies += 1,
            Err(e) => oxidhome_sdk::tracing::warn!(error = ?e, "publishing a reply failed"),
        }
    }
    replies
}

impl Plugin for NetworkDiscovery {
    fn init(&mut self) -> Result<(), String> {
        // Keep counting across restarts.
        if let Ok(Some(Value::IntVal(n))) = storage::get(REPLIES_KEY) {
            self.replies = n;
        }
        let targets = parse_targets(&config_string("targets").unwrap_or_default())?;
        let probe = config_string("probe").unwrap_or_else(|| "discover".into());
        for ipv6 in [false, true] {
            let family: Vec<&SocketAddr> = targets.iter().filter(|t| t.is_ipv6() == ipv6).collect();
            if family.is_empty() {
                continue;
            }
            let socket = bind(ipv6)?;
            for target in family {
                match socket.send_to(probe.as_bytes(), *target) {
                    Ok(()) => oxidhome_sdk::tracing::info!(%target, "probe sent"),
                    // Refused by the host when no network rule allows it.
                    Err(e) => oxidhome_sdk::tracing::warn!(%target, error = %e, "probe not sent"),
                }
            }
            self.sockets.push(socket);
        }
        Ok(())
    }

    fn shutdown(&mut self) {
        self.sockets.clear();
    }

    fn tick(&mut self) {
        self.drain();
    }
}

// No media pipelines: the default `setup_pipeline` answers an error.
impl StreamingPlugin for NetworkDiscovery {}

oxidhome_sdk::streaming_plugin!(NetworkDiscovery);
