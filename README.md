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
  admin token (scope `*`, the owner) to `<state_dir>/admin-token` (mode
  `0600`). Mint further tokens by **role** offline with
  `oxidhome token create <label> --role <name> [--scope <scope>]...
  [--sensitive <category>]... [--deny <action,...|*>[@<category,...>]]...`
  (the secret is printed once), or as the owner over
  `POST /api/v1/tokens` / Connect `TokensService.CreateToken`
  (`{"label": "hall tablet", "roles": ["tablet"]}`, `201` with the
  secret). `GET /api/v1/tokens`, Connect `ListTokens`, MCP `tokens.list`
  and `oxidhome token list` list tokens without secrets; only the owner
  reaches the API forms. Revocation is offline (`recover-admin-token
  --revoke-all`). Missing or malformed bearer → `401`.
- **Roles**: there are no built-in roles; the owner defines them. A role
  is a name plus grants (actions; `device.list`, `device.read` and
  `device.command` can be narrowed to device categories and device ids),
  sensitive categories and deny entries:
  `oxidhome role create tablet '{"grants": [{"actions": ["device.list",
  "device.read", "device.command"], "category": ["light"]}]}'` offline, or
  over `/api/v1/roles` (`GET`, `POST`, `PUT /{name}`, `DELETE
  /{name}[?force=true]`) and Connect `RolesService`, owner only. A token
  holds a role by id: editing the role changes every token holding it
  from its next request, deleting a role that live tokens hold is refused
  unless forced, and a reference to a deleted role grants nothing. A
  token's roles add to its scopes; a `deny` entry refuses the actions it
  names whatever grants them. A role grant narrowed to devices lists only
  its devices and is refused whole-fleet reads (`GET
  /api/v1/devices/state`, event history and tails).
- **Scope model**: per-surface. `devices:list` reads the fleet;
  `devices:command` sends actuation commands; `events:read` / `logs:read`
  read history; `plugins:list` reads plugin metadata; `plugins:install` /
  `plugins:start` / `plugins:stop` / `plugins:uninstall` drive the plugin
  lifecycle. See `crates/oxidhome-core/src/api/scopes.rs` for the full list.
- **Sensitive categories**: commands on `lock`, `opener` and `alarm`
  devices and camera bytes need an explicit grant on top of the scope; no
  scope reaches them, `*` included. The first-run (or recovered) admin
  token, the owner, holds every category implicitly; any other token holds
  a category through a grant of its own or through one of its roles. Grant one offline with
  `oxidhome token grant-sensitive <token-id> <lock|opener|alarm|camera>
  [--device <dev-id>]...` or at mint time (`--sensitive`);
  allowed sensitive actions are audited at `warn`
  (`GET /api/v1/audit?level=warn`) and, except for the owner's, rate
  limited per token and category. The daemon warns at startup about
  wildcard tokens that lost this access. `oxidhome mcp-stdio` reaches a
  sensitive category only with `--allow-sensitive <category>`. The owner can
  raise a device's category with `PUT /api/v1/devices/{id}/category`
  (`{"category": "lock"}`) or offline with `oxidhome device set-category`.
  **Upgrading:** this release adds the `lock`, `opener`, `alarm-panel` and
  `siren` capability cases to the WIT contract, so device plugins must be
  rebuilt against the new SDK and redeployed with the host.

### Surface at a glance

| Kind | Name | Scope | Notes |
| --- | --- | --- | --- |
| Resource | `oxidhome://devices` [+ `/{id}`] | `devices:list` | Registered devices + registration detail, with the host-derived `category` and `sensitive` categories. |
| Resource | `oxidhome://events` | `events:read` | Historical event log with filter URI params. |
| Resource | `oxidhome://logs` | `logs:read` | Structured logs with `since`/`level`/`plugin`/… filters. |
| Resource | `oxidhome://plugins` [+ `/{id}`] | `plugins:list` | Installed + running plugins, each installed one with its network rules (`requested`, `granted`, `effective`); per-plugin detail. |
| Resource | `oxidhome://status` | `status:read` | Version, uptime, DB ping, counts. |
| Resource | `oxidhome://config` | `status:read` | Daemon's effective configuration (state dir, listen address, retention, log filter, MCP limits), each value tagged with its source (`default` / `env` / `flag`), plus build, SDK and WIT versions. No secrets. REST: `GET /api/v1/config`. |
| Resource | `oxidhome://blobs/{instance}/{name}` | `blobs:read` | Base64-encoded blob store entries. `blobs:read` also unlocks raw `bytes-val` fields in events, device state, and command results on every surface; without it they come back as a `json-val` "withheld" marker. A camera instance's blobs and a camera's bytes also need the `camera` grant. |
| Tool | `device.send_command` | `devices:command` | Dispatch a capability command; a lock, opener or alarm also needs the category grant. |
| Tool | `logs.query` | `logs:read` | Tool-shape of `oxidhome://logs`. |
| Tool | `events.history` | `events:read` | Tool-shape of `oxidhome://events`. |
| Tool | `events.subscribe` | `events:read` | Long-poll for events past an `after_id` cursor (`timeout_ms` default 5 s, cap 30 s). |
| Tool | `plugins.list` / `plugins.show` | `plugins:list` | Read-only. |
| Tool | `plugins.install` | `plugins:install` | Takes an absolute `source_dir` (no `..` components) that must exist on the daemon-local filesystem — the tool copies from there into `<state_dir>/plugins/`. |
| Tool | `plugins.start` / `plugins.stop` | `plugins:start` / `plugins:stop` | Runtime lifecycle. |
| Tool | `plugins.uninstall` | `plugins:uninstall` | Refuses if instances still running. |
| Tool | `tokens.list` | owner only | Tokens with roles, scopes, sensitive grants and deny list; never a secret. No `tokens.create`: credentials never ride MCP responses. |
| Prompt | `summarize_today` | `events:read` + `logs:read` | 24 h household summary. |
| Prompt | `draft_automation` | `devices:list` | Composes `oxidhome://devices` + per-device detail. |
| Prompt | `explain_recent_errors` | `logs:read` | 24 h error-log walk. |

Every resource and tool body passes through the host's redaction pass
(`crates/oxidhome-core/src/redact.rs`): values under credential-looking
keys (`password`, `token`, `secret`, `api_key`, `authorization`, …) and
`Bearer` / `oxh_` credentials in text come back as `***`, and a plugin's
`type = "secret"` config fields appear as `{"secret": true, "set": …,
"value": "***"}`.

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
