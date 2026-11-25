# network-discovery

A `streaming-plugin` world example: LAN discovery over UDP broadcast,
with the SDK's discovery socket (`oxidhome_sdk::streaming::discovery`).

On start the plugin opens one discovery socket and sends a probe
datagram to each target in its `targets` config: by default the
limited broadcast address `255.255.255.255:9999`. A target
`local:<port>` stands for the broadcast address of each local IPv4
network the grant covers, which the host lists for the plugin, so it
can sweep its LAN without being told the subnet. Every tick it drains
the replies without blocking, publishes each as a
`network-discovery.reply` custom event (`<ip>:<port> <payload>`), and
keeps the running count in plugin storage under `replies`. The host
ticks the plugin early when a reply is waiting, at least 100 ms after
the previous tick returned, so the manifest's one-minute
`tick_interval_ms` is only a fallback.

The host checks every send and every received datagram against the
manifest's `[capabilities] network` rules:

- broadcast to `255.255.255.255` needs a `udp` rule naming that address
  and the port (`udp://255.255.255.255:9999`); a CIDR rule never covers
  it;
- a subnet's broadcast address (`192.168.1.255`) needs a rule covering
  that whole subnet (`udp://192.168.0.0/16:9999` does);
- devices answer from their own addresses, so a rule must cover them
  too, or their replies are dropped before the plugin sees them;
- a probe no rule allows fails with `PermissionDenied`, and the host
  writes an audit `deny` row (`method = NET`).

Network rules are granted explicitly at install time, and a rule that
wasn't granted has no effect. A grant narrower than the request (one
host out of the subnet, say) is honored as granted; anything outside the
request grants nothing, and no IP range grants a broadcast rule. Only
streaming-world manifests may declare network rules.

## Build

From this directory:

```shell
cargo build --target wasm32-wasip2
```

The component is at
`target/wasm32-wasip2/debug/network_discovery.wasm`, which the
manifest's `[runtime] wasm` points at.

## Configure

The manifest asks for `udp://255.255.255.255:9999` (the broadcast probe)
and `udp://192.168.0.0/16:9999` (the replies, and the broadcast address
of each `192.168.x` subnet). Change the port, or the range to match your
network, and set `targets` to unicast addresses
(`192.168.1.20:9999,192.168.1.21:9999`), `local:9999`, or the default
broadcast.

The test host runs it against a local UDP echo server
(`crates/oxidhome-test-host/tests/network.rs`).
