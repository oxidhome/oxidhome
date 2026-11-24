//! OxidHome Phase 8 example: UDP discovery from the `streaming-plugin`
//! world.
//!
//! On `init` the plugin opens one UDP socket (bound to the unspecified
//! address, the only bind the host allows) and sends a probe datagram to
//! every address in its `targets` config. On each `tick` it drains the
//! replies without blocking and publishes each one as a
//! `network-discovery.reply` custom event (`<addr>:<port> <payload>`).
//! The host runs `tick` early when a reply is readable, so the manifest's
//! cadence is only a fallback.
//!
//! Everything goes through plain `std::net`. The host decides each send
//! and each received datagram against the manifest's
//! `[capabilities] network` rules: a target no rule allows fails with
//! `PermissionDenied` (and the host audits it), and replies from
//! addresses no rule allows never arrive.
//!
//! Broadcast and multicast are refused by the host in this release, so
//! discovery probes a configured list of unicast addresses.

use std::net::{SocketAddr, UdpSocket};

use oxidhome_sdk::bindings::oxidhome::plugin::types::Value;
use oxidhome_sdk::host::{self, config, storage};
use oxidhome_sdk::{Plugin, StreamingPlugin};

/// Custom-event topic for each reply.
const REPLY_TOPIC: &str = "network-discovery.reply";
/// KV key holding the number of replies published so far.
const REPLIES_KEY: &str = "replies";
/// Largest reply read; longer datagrams are truncated.
const MAX_REPLY: usize = 512;
/// Most replies handled per tick, so one tick stays short.
const MAX_REPLIES_PER_TICK: usize = 32;

#[derive(Default)]
struct NetworkDiscovery {
    /// One socket per address family the targets use.
    sockets: Vec<UdpSocket>,
    replies: i64,
}

fn config_string(key: &str) -> Option<String> {
    match config::get(key) {
        Ok(Some(Value::StringVal(s))) => Some(s),
        _ => None,
    }
}

fn parse_targets(targets: &str) -> Result<Vec<SocketAddr>, String> {
    targets
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            t.parse()
                .map_err(|_| format!("target `{t}` is not ip:port"))
        })
        .collect()
}

impl NetworkDiscovery {
    fn drain(&mut self) {
        let mut buf = [0u8; MAX_REPLY];
        let before = self.replies;
        for socket in &self.sockets {
            self.replies += drain_socket(socket, &mut buf);
        }
        if self.replies != before
            && let Err(e) = storage::set(REPLIES_KEY, &Value::IntVal(self.replies))
        {
            oxidhome_sdk::tracing::warn!(error = ?e, "storing the reply count failed");
        }
    }
}

/// An unspecified-address socket for `family` — the only bind the host
/// allows.
fn bind(ipv6: bool) -> Result<UdpSocket, String> {
    let socket = if ipv6 {
        UdpSocket::bind("[::]:0")
    } else {
        UdpSocket::bind("0.0.0.0:0")
    }
    .map_err(|e| format!("bind: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {e}"))?;
    Ok(socket)
}

/// Publish the replies waiting on `socket`; returns how many.
fn drain_socket(socket: &UdpSocket, buf: &mut [u8]) -> i64 {
    let mut replies = 0;
    for _ in 0..MAX_REPLIES_PER_TICK {
        match socket.recv_from(buf) {
            Ok((n, from)) => {
                let payload = String::from_utf8_lossy(&buf[..n]);
                match host::publish_custom_event(None, REPLY_TOPIC, format!("{from} {payload}")) {
                    Ok(()) => replies += 1,
                    Err(e) => oxidhome_sdk::tracing::warn!(error = ?e, "publishing a reply failed"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => {
                oxidhome_sdk::tracing::warn!(error = %e, "receiving failed");
                break;
            }
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
                match socket.send_to(probe.as_bytes(), target) {
                    Ok(_) => oxidhome_sdk::tracing::info!(%target, "probe sent"),
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
