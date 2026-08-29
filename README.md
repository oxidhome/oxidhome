# OxidHome

Home automation, forged in Rust.

## Model Context Protocol (MCP)

OxidHome speaks MCP (protocol version `2025-11-25`) as a first-class surface
for LLM agents, alongside its JSON/REST + Connect-RPC surfaces. All three
share one axum listener, so a household hub only exposes one endpoint.

- **Endpoint**: `POST /api/v1/mcp` on the daemon's bind address (default
  `127.0.0.1:7780`, override with `OXIDHOME_BIND=<ip>:<port>`). Transport is
  MCP's Streamable HTTP.
- **Loopback-only bind by default**: the daemon binds `127.0.0.1:7780` out
  of the box, so only local clients can connect. Rebinding to a non-loopback
  address (e.g. `OXIDHOME_BIND=0.0.0.0:7780`) removes that boundary —
  operator should front the hub with a household reverse proxy in that case.
- **DNS-rebinding header guard**: independent of where the daemon binds,
  the MCP mount rejects requests whose `Host` isn't `localhost` / `127.0.0.1`
  / `[::1]` and (for browser clients) whose `Origin` isn't a loopback
  origin. That defense sits *after* bearer auth in the middleware chain,
  so a malformed/expired bearer gets `401` first; only authenticated
  requests with a bad `Host`/`Origin` see the `403`. Because both are
  client-controlled headers, this is a DNS-rebinding defense (stopping a
  browser at `evil.example.com` from `fetch()`-ing the daemon), NOT a
  peer-IP filter — a remote client can still send `Host: localhost` if the
  daemon is bound to a non-loopback address.
- **Auth**: `Authorization: Bearer <token>`. The first-run daemon writes an
  admin token (scope `*`) to `<state_dir>/admin-token` (mode `0600`).
  Scope-limited tokens are minted programmatically today via
  `engine.auth_tokens().create(id, &scope_json)` (see
  `crates/oxidhome-core/src/state/auth_token.rs`); a CLI surface for
  minting / rotation / revocation is planned but not yet shipped, and by
  design token administration will not be exposed over REST (the API
  layer only ever *verifies* tokens). Missing or malformed bearer → `401`.
- **Scope model**: per-surface. `devices:list` reads the fleet;
  `devices:command` sends actuation commands; `events:read` / `logs:read`
  read history; `plugins:list` reads plugin metadata; `plugins:install` /
  `plugins:start` / `plugins:stop` / `plugins:uninstall` drive the plugin
  lifecycle. See `crates/oxidhome-core/src/api/scopes.rs` for the full list.

### Surface at a glance

| Kind | Name | Scope | Notes |
| --- | --- | --- | --- |
| Resource | `oxidhome://devices` [+ `/{id}`] | `devices:list` | Registered devices + registration detail. |
| Resource | `oxidhome://events` | `events:read` | Historical event log with filter URI params. |
| Resource | `oxidhome://logs` | `logs:read` | Structured logs with `since`/`level`/`plugin`/… filters. |
| Resource | `oxidhome://plugins` [+ `/{id}`] | `plugins:list` | Installed + running plugins; per-plugin detail. |
| Resource | `oxidhome://status` | `status:read` | Version, uptime, DB ping, counts. |
| Resource | `oxidhome://blobs/{instance}/{name}` | `blobs:read` | Base64-encoded blob store entries. |
| Tool | `device.send_command` | `devices:command` | Dispatch a capability command; sensitive. |
| Tool | `logs.query` | `logs:read` | Tool-shape of `oxidhome://logs`. |
| Tool | `events.history` | `events:read` | Tool-shape of `oxidhome://events`. |
| Tool | `plugins.list` / `plugins.show` | `plugins:list` | Read-only. |
| Tool | `plugins.install` | `plugins:install` | Takes a `source_dir` that must exist on the daemon-local filesystem — the tool copies from there into `<state_dir>/plugins/`. |
| Tool | `plugins.start` / `plugins.stop` | `plugins:start` / `plugins:stop` | Runtime lifecycle. |
| Tool | `plugins.uninstall` | `plugins:uninstall` | Refuses if instances still running. |
| Prompt | `summarize_today` | `events:read` + `logs:read` | 24 h household summary. |
| Prompt | `draft_automation` | `devices:list` | Composes `oxidhome://devices` + per-device detail. |
| Prompt | `explain_recent_errors` | `logs:read` | 24 h error-log walk. |

Every tool call lands in the audit ledger under a `mcp.tool.<name>` path;
resource reads land as `mcp.resource.<family>`. Mutating tools use a
two-phase audit (record-intent-then-finalize) so a kill or crash between
the intent write and the actual dispatch still leaves a
`decision = 'pending'` row for forensic sweep.

### Minimum working example

MCP's Streamable-HTTP lifecycle needs three legs: `initialize` (server
issues an `mcp-session-id` header), a fire-and-forget
`notifications/initialized`, and only then real RPC calls. Native MCP
clients (Claude Desktop, MCP Inspector, agent SDKs) handle the session
plumbing themselves; a hand-rolled `curl` walkthrough looks like:

```bash
export OXIDHOME_MCP_URL=http://127.0.0.1:7780/api/v1/mcp
# Default state_dir is `<cwd>/.oxidhome-state`; override with
# `$OXIDHOME_STATE_DIR`. Point this at the daemon's actual state_dir.
export OXIDHOME_MCP_TOKEN=$(cat "${OXIDHOME_STATE_DIR:-./.oxidhome-state}/admin-token")

mcp() {
  curl -sS "$OXIDHOME_MCP_URL" \
    -H "Authorization: Bearer $OXIDHOME_MCP_TOKEN" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Host: localhost' \
    "$@"
}

# 1. `initialize` — capture response headers to extract the session id.
#    Per MCP 2025-11-25 §Transports, the `MCP-Protocol-Version` header is
#    only required on requests *after* the handshake, so this leg omits it.
mcp -D /tmp/mcp-hdr.txt \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-11-25","capabilities":{},
       "clientInfo":{"name":"cli","version":"0"}}}' > /dev/null

# `mcp-session-id: <uuid>` is on the response header line.
SESSION_ID=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' /tmp/mcp-hdr.txt \
             | tr -d '\r')

# Every post-init request must carry the negotiated protocol version.
POST_INIT_HEADERS=(-H "mcp-session-id: $SESSION_ID"
                   -H 'MCP-Protocol-Version: 2025-11-25')

# 2. `notifications/initialized` — no id, no response body; server returns 202.
mcp "${POST_INIT_HEADERS[@]}" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3. Any real RPC. Call `resources/list` to see the catalogue,
#    or `tools/call` to invoke a tool.
mcp "${POST_INIT_HEADERS[@]}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/list"}'

mcp "${POST_INIT_HEADERS[@]}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"logs.query","arguments":{"since":"1h"}}}'
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

## Contribution

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
