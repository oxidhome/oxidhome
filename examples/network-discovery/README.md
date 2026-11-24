# network-discovery

A `streaming-plugin` world example: discovery over UDP with plain
`std::net`.

On start the plugin binds one UDP socket and sends a probe datagram to
each address in its `targets` config. Every tick it drains the replies
without blocking, publishes each as a `network-discovery.reply` custom
event (`<ip>:<port> <payload>`), and keeps the running count in plugin
storage under `replies`. The host ticks the plugin as soon as a reply is
readable, so the manifest's one-minute `tick_interval_ms` is only a
fallback.

The host checks every send and every received datagram against the
manifest's `[capabilities] network` rules:

- a probe to an address no rule allows fails with `PermissionDenied`,
  and the host writes an audit `deny` row (`method = NET`);
- a reply from an address no rule allows is dropped before the plugin
  sees it;
- broadcast and multicast are refused in this release, so the plugin
  probes a list of unicast addresses;
- the socket may only bind to the unspecified address (`0.0.0.0:0`).

Network rules are granted explicitly at install time; a rule the
operator didn't grant has no effect.

## Build

From this directory:

```shell
cargo build --target wasm32-wasip2
```

The component is at
`target/wasm32-wasip2/debug/network_discovery.wasm`, which the
manifest's `[runtime] wasm` points at.

## Configure

Edit `network` in `manifest.toml` to cover the addresses you probe —
for example `udp://192.168.1.0/24:9999` for every host on that subnet,
port 9999 — and set `targets`, e.g. `192.168.1.20:9999,192.168.1.21:9999`.

The test host runs it against a local UDP echo server
(`crates/oxidhome-test-host/tests/network.rs`).
