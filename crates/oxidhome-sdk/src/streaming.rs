//! The `streaming-plugin` world: network access for plugins that talk to
//! devices and services directly.
//!
//! Enable it by depending on the SDK with
//! `default-features = false, features = ["streaming-plugin"]`, set
//! `world = "streaming-plugin"` in the manifest, implement
//! [`StreamingPlugin`] on top of [`Plugin`](crate::Plugin), and export the
//! type with [`streaming_plugin!`](crate::streaming_plugin).
//!
//! # Sockets
//!
//! Use [`std::net`] as on any other target: `TcpStream`, `UdpSocket`,
//! and name resolution through `ToSocketAddrs` all run over the WASI
//! sockets the world imports. Use non-blocking mode (or a read timeout)
//! for sockets drained from [`Plugin::tick`](crate::Plugin::tick): a
//! blocking read waits inside the host, where the liveness watchdog
//! doesn't reach, so the instance is stuck until data arrives or it is
//! stopped.
//!
//! # Readiness wakeups
//!
//! When the manifest sets `tick_interval_ms`, the host also calls
//! [`Plugin::tick`](crate::Plugin::tick) early when a socket the plugin
//! keeps open between calls becomes readable: a connected `TcpStream`, or
//! a `UdpSocket` that has connected, sent, or tried a receive (a
//! non-blocking `recv_from` that answered `WouldBlock` counts). The
//! cadence can then be a slow fallback rather than a polling rate.
//! Wakeups are coalesced (one tick however much arrived) and start at
//! least 100 ms after the previous tick returned. Read what a tick finds,
//! up to a bound per tick so a busy peer can't hold the call, and drop
//! sockets that reached their end: a socket left readable (data still
//! queued, or at its end) wakes the plugin again after each gap. Without `tick_interval_ms` the plugin is never ticked.
//!
//! # HTTP
//!
//! Outgoing HTTP goes through `wasi:http/outgoing-handler`; the raw
//! bindings are in [`wasi::http`]. Only `http://` is served today. The
//! host never follows redirects: a 3xx response comes back to the plugin,
//! and following it is a new request that the host checks again.
//!
//! # What the host allows
//!
//! Every TCP connect, UDP send, name lookup and HTTP request is checked
//! against the instance's granted `[capabilities] network` rules, on the
//! resolved IP address:
//!
//! - A refused socket call fails with `PermissionDenied`
//!   ([`std::io::ErrorKind`]); a refused HTTP request fails with
//!   `HTTP-request-denied`. The host records the refusal in its audit log.
//! - A name rule (`tcp://mqtt.example.com:1883`, `tcp://*.example.com:*`)
//!   covers the **public** addresses the host resolved that name to. Name
//!   lookups for names no rule mentions are refused.
//! - A name rule under `.local`, `.lan`, `.home.arpa` or `.internal`
//!   (`tcp://mqtt.lan:1883`) also covers the **private** addresses its
//!   names resolve to.
//! - Other private addresses, and every loopback and link-local one, need
//!   an IP or CIDR rule inside that range (`tcp://127.0.0.1:1883`,
//!   `udp://192.168.0.0/16:9999`). Broadcast and multicast are refused.
//! - Sockets may bind only to the unspecified address (`0.0.0.0:0` and
//!   the like, any port); listening is refused.
//! - Datagrams from senders the rules don't cover are dropped.
//!
//! The host also caps each instance at 64 live sockets, 4 concurrent
//! name lookups and 16 concurrent HTTP requests.

/// Media pipeline types of the `streaming-plugin` world (`media-pipeline`,
/// `media-source`, `output-sink`, …), returned from
/// [`StreamingPlugin::setup_pipeline`].
pub mod media {
    pub use crate::bindings::oxidhome::plugin::media::*;
}

/// Raw WASI bindings of the `streaming-plugin` world's imports, for what
/// [`std`] doesn't cover (`wasi:http`), and the `wasi:io` streams and
/// pollables it uses.
pub mod wasi {
    pub use crate::bindings::wasi::{clocks, http, io, sockets};
}

/// What a `streaming-plugin` world plugin implements on top of
/// [`Plugin`](crate::Plugin).
///
/// Network access needs nothing here: sockets and HTTP are imports, used
/// from any [`Plugin`](crate::Plugin) method. The trait carries the
/// world's extra export.
pub trait StreamingPlugin: crate::Plugin {
    /// Describe the media pipeline for one of this plugin's devices. The
    /// host does not call it yet: native pipelines come with media
    /// support. The default returns an error.
    ///
    /// # Errors
    ///
    /// A message saying why no pipeline can be set up for `device`.
    fn setup_pipeline(&mut self, _device: String) -> Result<media::MediaPipeline, String> {
        Err("setup-pipeline is not implemented by this plugin".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct NoPipeline;

    impl crate::Plugin for NoPipeline {
        fn init(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn shutdown(&mut self) {}
    }

    impl StreamingPlugin for NoPipeline {}

    #[test]
    fn default_setup_pipeline_is_an_error() {
        let err = NoPipeline.setup_pipeline("d-1".into()).unwrap_err();
        assert!(err.contains("not implemented"), "{err}");
    }
}
