# ADR-0010: Network policy for streaming plugins

- **Status:** accepted
- **Date:** 2026-11-23
- **Deciders:** OxidHome maintainers
- **Supersedes:** none
- **Superseded by:** none
- **References:** Phase 8 slices 8.1 (PR #211) and 8.2, [ADR-0006](0006-resource-ceilings.md) (fixed ceilings)

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

- *Forbidden* (unspecified, broadcast, multicast, documentation, reserved, …) is always refused.
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

**HTTP.** `wasi:http` never follows redirects; every hop the plugin (or the SDK client, at most 5 hops, never from
`https` to `http`) follows is a new, checked request. `https://` uses rustls with the `ring` provider, TLS 1.3 and
1.2, and the operating system's root store (`rustls-native-certs`); SNI and the certificate name check use the
host the request named. The network rule check runs before the connection is made.

**Self-signed LAN devices are trusted on first use.** When the connected address is private, link-local or loopback
(a co-located bridge is no different from a LAN device) and the certificate's only fault is an issuer the system
roots don't know, the handshake must still prove the server holds the leaf certificate's key, and the leaf's SHA-256
is checked against the host-held pin for `(instance, host, port)`: no pin pins it (logged and audited), the same
certificate passes, a different one is refused and audited, even one the roots vouch for. Any other certificate
fault (expired, issued for another name, not for server use) is refused, never pinned. Public addresses, and NAT64
addresses (`64:ff9b::/96`, `64:ff9b:1::/48`, which may translate to public servers), never get this. Pins are bounded
(256 per instance, 4096 in all), survive restarts, and belong to the plugin installation whose instance made them
(an instance id another plugin reuses inherits nothing): uninstalling the plugin deletes them, each audited, like its
storage. The operator lists and resets them
(`oxidhome tls-pin`, REST, Connect; MCP lists them).

**Fixed ceilings, no knobs** (as in ADR-0006): per instance 64 live sockets, 4 concurrent name lookups (5 s each,
plus 32 in flight host-wide), 16 concurrent HTTP requests, 4096 resource-table entries, at most 32 addresses per
lookup and 1024 remembered resolutions (10 minutes each); per manifest at most 128 rules; per request a 30 s default
connect deadline covering lookup, connect, TLS and HTTP handshakes, request method / authority / path of at most
64 B / 512 B / 8 KiB, header maps of at most 16 KiB with names of at most 256 B, response heads of at most 64 KiB,
and outgoing-body writes of at most 16 KiB with at most two buffered.

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

## Consequences

- LAN devices reached by name need a local-only name rule (`camera.lan`), or a name rule plus an IP / CIDR rule
  covering the address it resolves to; an IP / CIDR rule alone reaches IP-literal requests only.
- Hosts with no usable system roots reach only pinned LAN devices over `https://`.
- A device whose certificate changes is refused until the operator resets its pin.
- Old devices offering only CBC suites or TLS ≤ 1.1 are unreachable over `https://`.
- Broadcast and multicast discovery need a small host import (Phase 8.3); until then they are forbidden.
- Plugins that declared `network` rules on the `plugin` world must move to `streaming-plugin`.
