# OxidHome

Home automation, forged in Rust.

## Model Context Protocol (MCP)

OxidHome speaks MCP (protocol version `2025-11-25`) as a first-class surface
for LLM agents, alongside its JSON/REST + Connect-RPC surfaces. All three
share one axum listener, so a household hub only exposes one endpoint.

- **Endpoint**: `POST /api/v1/mcp` on the daemon's bind address (default
  `127.0.0.1:7780`, override with `OXIDHOME_BIND=<ip>:<port>`). Transport is
  MCP's Streamable HTTP.
- **Loopback-only by default**: the endpoint refuses non-loopback `Origin`
  and `Host` values, so `curl http://<lan-ip>:7780/api/v1/mcp` from another
  machine gets 403 even before auth runs. Put the hub behind a household
  reverse proxy if you need remote access.
- **Auth**: `Authorization: Bearer <token>`. The first-run daemon writes an
  admin token (scope `*`) to `<state_dir>/admin-token` (mode `0600`); mint
  scope-limited tokens after that through the REST admin endpoints. Missing
  or malformed bearer → `401`.
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
| Tool | `plugins.install` | `plugins:install` | Loopback-only; takes a daemon-local `source_dir`. |
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

```sh
# 1. Point your MCP client at the endpoint.
export OXIDHOME_MCP_URL=http://127.0.0.1:7780/api/v1/mcp
# Default state_dir is `<cwd>/.oxidhome-state`; override with
# `$OXIDHOME_STATE_DIR`. Path this at the daemon's actual state_dir.
export OXIDHOME_MCP_TOKEN=$(cat "${OXIDHOME_STATE_DIR:-./.oxidhome-state}/admin-token")

# 2. Handshake + list resources.
curl -sS "$OXIDHOME_MCP_URL" \
  -H "Authorization: Bearer $OXIDHOME_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Host: localhost' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-11-25","capabilities":{},
       "clientInfo":{"name":"cli","version":"0"}}}'

# 3. Call a tool. Session id comes back on the initialize response
#    header (`mcp-session-id`); reuse it on subsequent calls.
curl -sS "$OXIDHOME_MCP_URL" \
  -H "Authorization: Bearer $OXIDHOME_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Host: localhost' \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"logs.query","arguments":{"since":"1h"}}}'
```

A native MCP client (Claude Desktop, MCP Inspector, an agent SDK) points
at the same URL and handles the handshake + session-id plumbing itself.

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
