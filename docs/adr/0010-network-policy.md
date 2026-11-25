# ADR-0010: Network policy for streaming plugins

- **Status:** accepted
- **Date:** 2026-11-23
- **Deciders:** OxidHome maintainers
- **Supersedes:** none
- **Superseded by:** none
- **References:** Phase 8 slices 8.1 (PR #211), 8.2 and 8.3, [ADR-0006](0006-resource-ceilings.md) (fixed ceilings)

## Context

Phase 8 gives `streaming-plugin` and `streaming-ai-plugin` components WASI sockets and outgoing `wasi:http`, so a
plugin can talk to devices on the LAN (cameras, plugs, brokers) and to cloud APIs. A plugin is third-party code on
the household's network: unchecked, it could scan the LAN, reach the host's loopback services or a cloud metadata
endpoint, exfiltrate data through DNS, or be pointed at the LAN by a rebinding DNS answer. The manifest already
declares `[capabilities] network` rules (`tcp|udp|https|any` × exact name / `*.suffix` / IP / CIDR × port, port
range or `*`), and the operator grants them at install. The questions were what those rules mean, where they are
enforced, how operators narrow them, and how HTTPS trusts LAN devices that only have self-signed certificates.

## Decision

**Who gets the network.** Only the streaming worlds link `wasi:sockets` and `wasi:http`; a `plugin` or `ai-plugin`
component that imports them fails to load, and `network` rules on such a manifest are a validation error. The
effective rules are what the operator granted, narrowed by containment against what the manifest requests: every
granted rule some requested rule covers, plus every requested rule some granted rule covers. An operator can grant
one camera out of a requested `192.168.0.0/16`, a narrower port range or a deeper `*.suffix`; a rule only partly
inside the request grants nothing. No rules means no network.

**Rules are checked on the resolved address, at the point of use.** One policy object per instance decides every
TCP connect, UDP send, received datagram, bind, name lookup and HTTP request. Addresses are canonicalized
(IPv4-mapped IPv6 → IPv4) and classified as public, loopback, link-local, private or forbidden:

- *Forbidden* (unspecified, broadcast, multicast, documentation, reserved, …) is always refused, except the
  broadcast and multicast destinations a discovery socket reaches (below).
- An *IP or CIDR rule* covers the addresses it contains. A literal grants its address whatever its class; a CIDR
  grants loopback, link-local or private addresses only when the whole range lies inside that class's blocks, so
  `0.0.0.0/0` covers public space only.
- A *name rule* covers the public addresses the host itself resolved a matching name to. A name rule under a
  local-only suffix — `.local`, `.lan`, `.home.arpa`, `.internal` — also covers the private addresses its names
  resolve to. No name rule ever covers loopback or link-local addresses.
- Proto: `tcp` rules cover TCP and plain `http://`; `udp` covers UDP; `https` covers `https://`; `any` covers all.
  A rule covers another when its proto is the same or `any`, its ports include the other's, and its host covers the
  other's under these rules.

**Names are resolved by the host.** `wasi:sockets/ip-name-lookup` is host-implemented: a name no rule mentions is
not looked up (no DNS channel), names resolve as absolute names, answers the rules don't allow never reach the
plugin, and each admitted address is remembered per rule for a bounded time, so a connect is allowed only for the
rules whose names resolved to it. An HTTP request is resolved and checked by the host, which connects to exactly
the address it checked.

**No inbound sockets.** Binds go to the unspecified address only; `listen` is refused.

**Broadcast and multicast go through a host import.** `wasi:sockets/udp` 0.2 has no `SO_BROADCAST` and no group
membership, so the streaming worlds import a small OxidHome interface, `host-network`, with a non-blocking
*discovery socket* (the host's own UDP socket) and the host's local networks; `wasi:sockets` still never reaches a
broadcast or multicast address. On a discovery socket:

- The limited broadcast `255.255.255.255` and a multicast group (`224.0.0.251:5353` for mDNS,
  `239.255.255.250:1900` for SSDP, `ff02::fb`, …) are reached only through a `udp` rule naming that exact address
  and the port (`udp://255.255.255.255:9999`). No CIDR covers them, and in grant narrowing no IP range covers a rule
  naming one: granting `udp://0.0.0.0/0:*` doesn't grant a requested `udp://255.255.255.255:9999`, nor does an `any`
  rule naming the address. Joining a group needs a `udp` rule naming it. Multicast is sent with a TTL (hop limit) of 1,
  and on Linux a socket hears only the groups it joined itself (`IP_MULTICAST_ALL` off).
- A subnet-directed broadcast (the last address of one of the host's IPv4 networks, `192.168.1.255` on
  `192.168.1.0/24`) reaches every host of that network, so it needs a `udp` (or `any`) IP rule covering the whole
  network, and every interface network it is the broadcast address of; a rule for part of the network, or a literal
  naming the address (which a partial range covers in grant narrowing), doesn't do. When the host can't list its
  networks, every IPv4 destination but a named group is refused. `SO_BROADCAST` is set only for the duration of a send
  the policy approved as a broadcast, so a destination the kernel treats as one and the policy didn't (a network's
  first address on BSD, an interface that changed in between) fails, and is audited, instead of reaching the link. The
  interfaces are listed for each send, with the broadcast address each is configured with counting as its network's.
- Every other destination is checked as a UDP send. Datagrams from senders a UDP send couldn't reach are dropped,
  by `receive` and while the socket waits for readiness, so a flood from a refused sender never wakes the plugin.
  Devices answer a broadcast from their own address, so a plugin needs a rule for them too.
- The socket binds to the unspecified address. A fixed local port needs a broadcast or multicast rule of the socket's
  family for that port, and is opened with `SO_REUSEADDR` (and `SO_REUSEPORT` where it exists) so it can share `5353` or `1900` with the
  system's responder.

`local-networks` returns the host's interface networks that one of the grant's IP or CIDR rules covers whole, under
the class rules above (a network mixing classes, like `172.0.0.0/11`, is covered by no CIDR), so a plugin can sweep
its LAN without being configured with it. A rule narrower than a network lists nothing: the plugin would take the
listed range for the whole network and broadcast to a host address. Name rules list nothing. Discovery sockets count towards the socket
ceiling.

**HTTP.** `wasi:http` never follows redirects; every hop the plugin (or the SDK client, at most 5 hops, never from
`https` to `http`) follows is a new, checked request. `https://` uses rustls with the `ring` provider, TLS 1.3 and
1.2, and the operating system's root store (`rustls-native-certs`); SNI and the certificate name check use the
host the request named. The network rule check runs before the connection is made.

**Self-signed LAN devices are trusted on first use.** When the connected address is private, link-local or loopback
(a co-located bridge is no different from a LAN device) and the certificate is self-signed with no other fault
(a leaf from a CA the roots don't know is refused even when the server sends that CA), the handshake must still prove the server holds the leaf certificate's key, and the leaf's SHA-256
is checked against the host-held pin for `(instance, host, port)`: no pin pins it (logged and audited), the same
certificate passes, a different one is refused and audited, even one the roots vouch for. Any other certificate
fault (expired, issued for another name, not for server use, a key a system root has) is refused, never pinned.
When the request names an IP literal (v4 or v6), the certificate's name alone is not checked: devices addressed by
IP rarely carry that address in their certificate, and the pin binds the leaf to that address and port; every other
check stays. A request by hostname keeps the name check. Public addresses, and NAT64
addresses (`64:ff9b::/96`, `64:ff9b:1::/48`, which may translate to public servers), never get this. Pins are bounded
(256 per instance, 4096 in all), survive restarts, and belong to the plugin installation whose instance made them
(an instance id another plugin reuses inherits nothing): uninstalling the plugin deletes them, each audited, like its
storage (a purge cut short is finished at the next start). The operator lists and resets them
(`oxidhome tls-pin`, REST, Connect; MCP lists them).

**Fixed ceilings, no knobs** (as in ADR-0006): per instance 64 live sockets (discovery sockets included), 4 concurrent name lookups (5 s each,
plus 32 in flight host-wide), 16 concurrent HTTP requests, 4096 resource-table entries, at most 32 addresses per
lookup and 1024 remembered resolutions (10 minutes each); per manifest at most 128 rules; per request a 30 s default
connect deadline covering lookup, connect, TLS and HTTP handshakes, request method / authority / path of at most
64 B / 512 B / 8 KiB, header maps of at most 16 KiB with names of at most 256 B, response heads of at most 64 KiB,
and outgoing-body writes of at most 16 KiB with at most two buffered; per discovery-socket `receive` at most 32
datagrams of at most 64 KiB, and at most 256 refused datagrams discarded; at most 64 listed local networks.

**Refusals are audited** (`method = NET`, `decision = deny`, `required_scope = network`,
`path = net.<op>/<instance>/<target>`), rate-limited per instance (burst 16, then 1/s).

## Rejected options

- **Name rules reaching any private address.** A rebinding DNS answer for a public name would reach the LAN.
- **Name rules reaching link-local addresses under local suffixes.** `metadata.google.internal` resolves to the
  cloud metadata service at `169.254.169.254`.
- **Grant narrowing by equality only.** An operator could drop a rule but not narrow a subnet to one device.
- **Pairwise rule intersection.** Exact for partly overlapping rules, but 128 × 128 rules can intersect into
  thousands, each checked on every connect.
- **An explicit `http` proto.** Plain HTTP stays on `tcp` rules: the rule grants the TCP connection either way.
- **OpenSSL / `native-tls`, `aws-lc-rs`, `webpki-roots`.** A C dependency and its CVE stream; a larger build; a
  bundled root list under CDLA-Permissive-2.0 that goes stale between releases.
- **A per-rule "insecure" manifest flag** for self-signed devices. Disables verification for whatever answers at
  that address, every time; a pin at least detects a swapped device.
- **Inbound sockets** in Phase 8. Nothing needs them yet; revisit with media (Phase 9).
- **Patching `wasmtime-wasi`** to set `SO_BROADCAST` or join groups when the address check approves: a fork of the
  embedding to carry, and `wasi:sockets` has no call to join a group anyway.
- **An OxidHome `wasi:sockets/udp`.** Replacing a whole standard interface for two socket options.
- **Broadcast or multicast under CIDR rules.** `udp://0.0.0.0/0:*` or `udp://224.0.0.0/4:*` would let a plugin talk to
  every host on the link without the operator naming that.

## Consequences

- LAN devices reached by name need a local-only name rule (`camera.lan`), or a name rule plus an IP / CIDR rule
  covering the address it resolves to; an IP / CIDR rule alone reaches IP-literal requests only.
- Hosts with no usable system roots reach only pinned LAN devices over `https://`.
- A device whose certificate changes is refused until the operator resets its pin.
- Old devices offering only CBC suites or TLS ≤ 1.1 are unreachable over `https://`.
- Trust on first use covers self-signed leaves only, deliberately: a device whose leaf comes from its own CA (sent
  with the chain or not) is refused. Anchoring a presented CA would need our own CA-constraint checks, which
  `WebPKI` skips for anchors; revisit if a real device needs it.
- Known gap, to fix later: the X.509 Key Usage extension is not checked (`WebPKI` ignores it on every path), so a
  self-signed leaf whose Key Usage lacks `digitalSignature` can still be pinned; the handshake still proves the
  server holds its key.
- Broadcast and multicast work only through `host-network`; `std::net` sockets in the guest still can't send them.
- A fixed discovery port shares the port with other sockets on the host, so unicast datagrams for another program on
  that port may reach the plugin when their sender passes its rules; only ports a broadcast or multicast rule names
  can be shared.
- Group joins use the default interface; there is no per-interface choice yet.
- Plugins that declared `network` rules on the `plugin` world must move to `streaming-plugin`.
