//! MCP `tools/*` implementation for `OxidHome`.
//!
//! Phase 14.3 opens the tool surface. Tools are the write-
//! side counterpart to [`super::resources`]: an LLM agent
//! calls a tool to *act* on the household (dispatch a
//! device command, mutate config, install a plugin, …)
//! rather than to read state. See
//! [`.claude/docs/10_mcp.md`](../../../../../.claude/docs/10_mcp.md)
//! `§ Tools` for the full catalogue plan.
//!
//! Tools shipped so far:
//!
//! - `device.send_command` (14.3a — sensitive, gated on
//!   `devices:command`; runs two-phase audit for forensic
//!   protection).
//! - `logs.query` (14.3b — read-only, gated on `logs:read`;
//!   tool-shape of the `oxidhome://logs` resource).
//! - `events.history` (14.3c — read-only, gated on
//!   `events:read`; tool-shape of the `oxidhome://events`
//!   resource).
//! - `plugins.list` + `plugins.show` (14.3d — read-only,
//!   gated on `plugins:list`; tool-shape of the
//!   `oxidhome://plugins` + `oxidhome://plugins/{id}`
//!   resources).
//! - `plugins.stop` (14.3e — mutating admin, gated on
//!   `plugins:stop`; tool-shape of `POST
//!   /api/v1/plugins/{id}/stop`).
//! - `plugins.uninstall` (14.3e — mutating admin,
//!   destructive, gated on `plugins:uninstall`; tool-shape
//!   of `DELETE /api/v1/plugins/{id}`).
//! - `plugins.start` (14.3f — mutating admin, gated on
//!   `plugins:start`; tool-shape of `POST
//!   /api/v1/plugins/{id}/start`).
//! - `plugins.install` (14.3g — mutating admin, destructive,
//!   gated on `plugins:install`; tool-shape of `POST
//!   /api/v1/plugins`). Loopback-only (14.1 Origin+Host
//!   guard), so the `source_dir` path is the same trust
//!   surface REST uses.
//!
//! # Layout
//!
//! - [`list_tools`] — the tool catalogue (name, description,
//!   input JSON Schema).
//! - [`call`] — dispatch a `tools/call` request through the
//!   audit + scope + concurrency-gate plumbing shared with
//!   [`super::resources`].
//! - Per-tool builders (`device_send_command_call`, …) run
//!   the actual work.
//!
//! # Audit
//!
//! Every call records one [`AuditLog::record_completed`] row
//! with `path = "mcp.tool.<group>.<name>"` (e.g.
//! `mcp.tool.device.send_command`). Distinct from the
//! `mcp.resource.<family>` prefix `super::resources` uses so
//! an operator's ledger scan can filter read vs. write
//! surface trivially.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorData as McpError, Tool,
    ToolAnnotations,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::Engine;
use crate::api::auth::wit_error_kind;
use crate::api::scopes::{
    DEVICES_COMMAND, EVENTS_READ, LOGS_READ, PLUGINS_INSTALL, PLUGINS_LIST, PLUGINS_START,
    PLUGINS_STOP, PLUGINS_UNINSTALL, require_scope,
};
use crate::api::server::{WireCommandResult, command_result_to_wire};
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::types::KeyValue;
use crate::host_impl::plugin::oxidhome::plugin::types::Value;
use crate::state::audit_log::AuditEntry;

use super::resources::{
    AUDIT_QUEUE_MAX, AUDIT_QUEUE_SEMAPHORE, EncodedBody, MAX_TOOL_BODY_BYTES, MCP_ACTOR_KIND,
    RESOURCE_BUSY_CODE, RESOURCE_TOO_LARGE_CODE, SCOPE_DENIED_CODE, STORE_QUERY_MAX,
    STORE_QUERY_SEMAPHORE,
};

/// Publicly-visible catalogue of tools this handler exposes.
/// Rmcp calls [`list_tools`] out of `tools/list`; the tool
/// definitions carry a JSON Schema so clients can validate
/// input before hitting the wire (and so an LLM planner sees
/// the argument shape without a separate probe).
// One `Tool::new(...).annotate(...)` entry per tool — the
// function grows linearly with the catalogue. Splitting into
// per-tool builder helpers would hide the flat list from a
// grep; keep as one function.
#[allow(clippy::too_many_lines)]
pub(super) fn list_tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "device.send_command",
            "Dispatch a capability command to a device (e.g. switch/toggle, dimmer/set). \
             The owning plugin's `execute-command` handles the request; the response \
             carries the WIT `command-result` (Ok / OkWithState with a state map / Err with \
             a typed WIT error). SENSITIVE: gated on the `devices:command` scope — \
             physical actuation (locks, garage doors, alarms) rides this same path.",
            Arc::new(device_send_command_schema()),
        )
        .with_title("Send device command"),
        Tool::new(
            "logs.query",
            "Historical log query against the durable `LogStore`. Returns a JSON list of \
             `HistoricalLogEvent` rows matching the filters. Read-only; gated on \
             `logs:read`. Same wire shape as `oxidhome://logs` — a client that reads the \
             resource and one that calls this tool see identical row bodies. Durations \
             (`since`, `until`) use `Ns|Nm|Nh|Nd` suffixes (`60s`, `5m`, `2h`, `1d`) and \
             resolve relative to `now`. `level` filters to entries at or above the named \
             level (`Trace|Debug|Info|Warn|Error`). Response size is bounded server-side; \
             `limit` is clamped to 100 rows.",
            Arc::new(logs_query_schema()),
        )
        .with_title("Query log history")
        // Round-2 F4 on PR #124: machine-readable hints for
        // planner-style clients. `logs.query` reads the
        // durable `LogStore` and does not touch external
        // state; all three defaults would misclassify it
        // (`read_only_hint = false`, `destructive_hint = true`,
        // `open_world_hint = true`).
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .open_world(false),
        ),
        Tool::new(
            "plugins.list",
            "List all plugins currently known to the host — both installed \
             (via `plugins install`) and running-only (dev-time argv-driven \
             starts with no `plugin_installation` row). Each entry carries \
             `plugin_id`, `installed`, `version` (when installed), and \
             `instance_count`. Read-only; gated on `plugins:list`. Same wire \
             shape as `oxidhome://plugins` — a client that reads the resource \
             and one that calls this tool see identical row bodies.",
            Arc::new(plugins_list_schema()),
        )
        .with_title("List plugins")
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .open_world(false),
        ),
        Tool::new(
            "plugins.show",
            "Show detail for a single plugin: `plugin_id`, `installed`, \
             `version`, `singleton`, `content_digest` (SHA-256 of the \
             installed contents), `installation_uuid` (host-minted per-install \
             identity — a reinstall of the same `plugin_id` produces a \
             different UUID), and the list of currently-running instances \
             with their state. `content_digest` + `installation_uuid` are \
             `None` for a dev-time argv-driven start with no installation \
             row. Read-only; gated on `plugins:list`. Same wire shape as \
             `oxidhome://plugins/{plugin_id}`. Returns `INVALID_PARAMS` if \
             `plugin_id` is missing and an application-level error if the \
             plugin is neither installed nor running.",
            Arc::new(plugins_show_schema()),
        )
        .with_title("Show plugin detail")
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .open_world(false),
        ),
        Tool::new(
            "plugins.stop",
            "Stop one or all supervised instances of an installed plugin. Idempotent — \
             if the plugin has no running instances, the tool returns success with an \
             empty `stopped` list. If `instance_id` is supplied, only that one instance \
             is stopped; otherwise every instance of `plugin_id` is stopped. Waits for \
             the supervisor's shutdown ack + a brief registry-clear poll so a follow-up \
             call sees a consistent post-stop state. SENSITIVE: gated on `plugins:stop` \
             — a plugin driving physical actuation (locks, alarms) rides this same \
             lifecycle.",
            Arc::new(plugins_stop_schema()),
        )
        .with_title("Stop plugin instance(s)")
        .annotate(
            ToolAnnotations::new()
                // Mutates host runtime state.
                .read_only(false)
                // Reversible via `plugins.start`, but the observable
                // side effect (halted supervision) is real and can
                // interrupt in-flight commands — flag as destructive.
                .destructive(true)
                .open_world(false),
        ),
        Tool::new(
            "plugins.start",
            "Start a supervised instance of an installed plugin. Returns once the \
             instance reaches `Running` (or fails to). Optional `instance_id` (defaults \
             to `plugin_id`) lets multiple instances of the same plugin coexist. \
             Optional `config_overrides` is a TOML-shaped JSON blob that layers over \
             the manifest's `[config]` table. SENSITIVE: gated on `plugins:start` — \
             starting a plugin activates its declared capabilities (device drivers, \
             services, HTTP listeners), so the same admin surface admin operators \
             consider before enabling a plugin at the CLI.",
            Arc::new(plugins_start_schema()),
        )
        .with_title("Start plugin instance")
        .annotate(
            ToolAnnotations::new()
                // Mutates host runtime state (spawns a
                // supervisor task).
                .read_only(false)
                // Reversible via `plugins.stop`, but the
                // observable side effect (a running supervisor
                // driving physical actuation) is real — flag
                // as destructive so a planner treats it as
                // write surface.
                .destructive(true)
                .open_world(false),
        ),
        Tool::new(
            "plugins.install",
            "Install a plugin from a daemon-local staged directory. Reads \
             `<source_dir>/manifest.toml` for the canonical `plugin_id`, then \
             recursively copies `source_dir` into `<state_dir>/plugins/<plugin_id>/`. \
             Does NOT start the plugin — the operator follows up with \
             `plugins.start`. SENSITIVE + DESTRUCTIVE: gated on `plugins:install` — a \
             token holding this scope can effectively load arbitrary `.wasm` onto the \
             host. `source_dir` MUST already exist on the daemon-local filesystem; \
             the MCP endpoint is loopback-only, so this mirrors REST's trust model \
             for the same operation.",
            Arc::new(plugins_install_schema()),
        )
        .with_title("Install plugin")
        .annotate(
            ToolAnnotations::new()
                // Mutates persistent host state (FS + SQL
                // registry rows).
                .read_only(false)
                // Reversible via `plugins.uninstall`, but the
                // observable side effect (new code on disk +
                // a `plugin_installation` registry row) is
                // real.
                .destructive(true)
                .open_world(false),
        ),
        Tool::new(
            "plugins.uninstall",
            "Uninstall a plugin: remove `<plugins_root>/<plugin_id>/` recursively, purge \
             every per-instance KV row + blob for the plugin, and tombstone the \
             `plugin_installation` registry row. REFUSES if any supervised instance is \
             still running — call `plugins.stop` first. SENSITIVE + DESTRUCTIVE: gated \
             on `plugins:uninstall`; reinstall of the same `plugin_id` starts with an \
             empty per-instance keyspace and a fresh `installation_uuid`.",
            Arc::new(plugins_uninstall_schema()),
        )
        .with_title("Uninstall plugin")
        .annotate(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .open_world(false),
        ),
        Tool::new(
            "events.history",
            "Historical event query against the durable `EventLog`. Returns a JSON list \
             of `HistoricalEvent` rows matching the filters (state changes, button \
             presses, inference results, custom plugin events). Read-only; gated on \
             `events:read`. Same wire shape as `oxidhome://events` — a client that \
             reads the resource and one that calls this tool see identical row bodies. \
             Durations (`since`, `until`) use `Ns|Nm|Nh|Nd` suffixes (`60s`, `5m`, \
             `2h`, `1d`) and resolve relative to `now`. `topic` matches exactly; \
             `topic_prefix` prefix-matches (mutually exclusive with `topic` — supply \
             at most one). Response size is bounded server-side; `limit` is clamped \
             to 100 rows.",
            Arc::new(events_history_schema()),
        )
        .with_title("Query event history")
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .open_world(false),
        ),
    ]
}

/// Hand-authored JSON Schema for [`device_send_command_args`].
/// We're not pulling in `schemars` just for one tool's input
/// shape — the schema is small enough to keep in sync by
/// eye, and 14.4 (tool policy) will need a hand-authored
/// per-tool policy blob anyway.
fn device_send_command_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["device_id", "capability", "action"],
        "properties": {
            "device_id": {
                "type": "string",
                "description": "Device id from `oxidhome://devices`.",
            },
            "capability": {
                "type": "string",
                "description": "Capability key the target plugin advertises (e.g. `switch`, `dimmer`).",
            },
            "action": {
                "type": "string",
                "description": "Action verb the capability's `execute-command` matches on (e.g. `toggle`, `set`).",
            },
            "args": {
                "type": "array",
                "description": "Optional key/value arguments. Values use the same `{t, v}` tagged shape as the REST endpoint (`Bool | Int | Float | String | Bytes | Json`).",
                "items": {
                    "type": "object",
                    "required": ["key", "value"],
                    "additionalProperties": false,
                    "properties": {
                        "key": { "type": "string" },
                        // Round-3 F1 on PR #123: enumerate the
                        // per-tag types instead of `"v": {}`
                        // (which accepted any type — the
                        // serde deserializer then rejected
                        // mismatches at runtime, but the
                        // published contract lied). `oneOf`
                        // is the direct JSON Schema shape for
                        // the WIT `value` variant.
                        "value": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "Bool" },
                                        "v": { "type": "boolean" }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "Int" },
                                        // Round-4 F2 on PR #123: bound to
                                        // `i64` so schema validation and
                                        // serde deserialization agree.
                                        // JSON Schema `integer` alone is
                                        // unbounded and would accept
                                        // `2^63`, which serde then
                                        // rejects — a client trusting the
                                        // schema would send valid-per-
                                        // schema payloads that fail on
                                        // the wire.
                                        "v": {
                                            "type": "integer",
                                            "minimum": i64::MIN,
                                            "maximum": i64::MAX
                                        }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "Float" },
                                        "v": { "type": "number" }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "String" },
                                        "v": { "type": "string" }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "Bytes" },
                                        // `serde_json` serialises `Vec<u8>` as an
                                        // array of integers — that's the wire shape
                                        // clients must send.
                                        "v": {
                                            "type": "array",
                                            "items": { "type": "integer", "minimum": 0, "maximum": 255 }
                                        }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["t", "v"],
                                    "properties": {
                                        "t": { "const": "Json" },
                                        "v": { "type": "string", "description": "Pre-serialised JSON payload as a string." }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

/// Round-3 F1 on PR #123: `deny_unknown_fields` mirrors the
/// `additionalProperties: false` in
/// [`device_send_command_schema`], so a client can't slip an
/// unknown top-level key (`dry_run: true`, `simulate: 1`, …)
/// past serde's default lenience and have the tool actuate
/// the device anyway.
///
/// Round-4 F1 on PR #123: MCP-local strict wire types
/// ([`McpKeyValue`] / [`McpValue`]) instead of tightening
/// the shared REST types — the REST send-command endpoint's
/// wire contract stays lenient (its own history + tests
/// depend on that), and MCP gets stricter parsing scoped to
/// the surface this PR opens.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSendCommandArgs {
    device_id: String,
    capability: String,
    action: String,
    #[serde(default)]
    args: Vec<McpKeyValue>,
}

/// MCP-local strict counterpart to
/// [`crate::api::server::WireKeyValue`] — same wire shape
/// (`{"key": …, "value": {"t": …, "v": …}}`), but rejects
/// unknown fields at the outer key/value wrapper. Bound-in
/// by [`DeviceSendCommandArgs`] so its `deny_unknown_fields`
/// applies to nested structures too.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpKeyValue {
    key: String,
    value: McpValue,
}

/// MCP-local strict counterpart to
/// [`crate::api::server::WireValue`] — same
/// `tag = "t", content = "v"` layout, but rejects any extra
/// key alongside `t` / `v`. `From<McpValue>` bridges to the
/// WIT `Value` variant, so the tool body converts to the
/// exact type the plugin's `execute-command` handler
/// receives via REST.
#[derive(Deserialize)]
#[serde(tag = "t", content = "v", deny_unknown_fields)]
enum McpValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(String),
}

impl From<McpValue> for Value {
    fn from(v: McpValue) -> Self {
        match v {
            McpValue::Bool(b) => Value::BoolVal(b),
            McpValue::Int(i) => Value::IntVal(i),
            McpValue::Float(f) => Value::FloatVal(f),
            McpValue::String(s) => Value::StringVal(s),
            McpValue::Bytes(b) => Value::BytesVal(b),
            McpValue::Json(j) => Value::JsonVal(j),
        }
    }
}

/// Dispatch a concrete `tools/call` request.
///
/// Round-1 F1 on PR #123: uses the two-phase
/// [`AuditLog::record_intent`] + [`AuditLog::finalize`]
/// pattern rather than a single `record_completed` after
/// dispatch. `device.send_command` physically actuates
/// devices (locks, garage doors, alarms); recording the
/// intent BEFORE the dispatch guarantees a forensic row
/// exists even if:
///
/// - The process is signalled and killed mid-dispatch.
/// - The finalize write fails (disk full, mutex poison, …).
/// - The rmcp handler task is dropped after the physical
///   effect has landed but before we get to finalize.
///
/// A pending row is strictly better than no row: the
/// operator sees `mcp.tool.<name>`, the token id, and the
/// intent timestamp — enough to reconstruct what happened.
///
/// The audit-queue [`Semaphore`] still bounds concurrent
/// blocking-writer tasks (round-6 F3 on PR #122). One
/// permit covers both the intent write and the finalize
/// write for this call.
// One linear match-and-return function so the audit /
// dispatch / finalize / meta-attachment order is easy to
// follow top-to-bottom; splitting into helpers would spread
// the audit invariant across the module without shortening
// any decision. Same reasoning as `blob_read` on the
// resources side (PR #122).
#[allow(clippy::too_many_lines)]
pub(super) async fn call(
    engine: Engine,
    request: CallToolRequestParams,
    actor: &Actor,
) -> Result<CallToolResult, McpError> {
    let Ok(audit_permit) = Arc::clone(&AUDIT_QUEUE_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = AUDIT_QUEUE_MAX,
            tool = %request.name,
            "MCP audit-write queue saturated — refusing tool call without audit",
        );
        return Err(McpError::new(
            RESOURCE_BUSY_CODE,
            "MCP audit-write queue saturated; retry shortly",
            None,
        ));
    };

    let token_id = actor.id().to_string();
    let name = request.name.as_ref();

    // Route → (family, required scope). Scope + tool-name
    // problems land here without the tool ever executing;
    // no reason to write an intent row for them. They're
    // audited as single-shot `record_completed` rows below.
    // Kept as `match` (not `if`) because every follow-up
    // tool will land as another arm here.
    #[allow(clippy::single_match_else)]
    let (family, required) = match name {
        "device.send_command" => ("device.send_command", DEVICES_COMMAND),
        "logs.query" => ("logs.query", LOGS_READ),
        "events.history" => ("events.history", EVENTS_READ),
        "plugins.list" => ("plugins.list", PLUGINS_LIST),
        "plugins.show" => ("plugins.show", PLUGINS_LIST),
        "plugins.stop" => ("plugins.stop", PLUGINS_STOP),
        "plugins.uninstall" => ("plugins.uninstall", PLUGINS_UNINSTALL),
        "plugins.start" => ("plugins.start", PLUGINS_START),
        "plugins.install" => ("plugins.install", PLUGINS_INSTALL),
        _ => {
            let outcome = ToolOutcome::UnknownTool(format!("no MCP tool named `{name}`"));
            return finalize_synchronous(engine, &token_id, "unknown", outcome, audit_permit).await;
        }
    };
    if require_scope(actor, required).is_err() {
        let outcome = ToolOutcome::Denied {
            required: required.name(),
        };
        return finalize_synchronous(engine, &token_id, family, outcome, audit_permit).await;
    }

    // Two-phase audit: record intent BEFORE dispatch. Round-2
    // F1 on PR #123: the permit MOVES into the blocking
    // closure and is returned with the intent id, so a
    // cancelled outer future (client disconnect while
    // `record_intent` is blocked on the `SQLite` mutex) can't
    // release the permit while the detached blocking task is
    // still queued. Without this, a disconnect-flooded caller
    // could enqueue unbounded writers even though the
    // semaphore's `try_acquire` above returned successfully.
    let intent_entry = new_pending_audit_entry(&token_id, family);
    let audit_log_for_intent = engine.audit_log();
    let intent_join = tokio::task::spawn_blocking(move || {
        let result = audit_log_for_intent.record_intent(&intent_entry);
        // Hand the permit back to the outer future so the
        // finalize call below can hold it through its own
        // blocking write. The `Result` return keeps a failed
        // intent from leaking the permit either way.
        (result, audit_permit)
    })
    .await;
    let (intent_result, audit_permit) = match intent_join {
        Ok((result, permit)) => (result, permit),
        Err(join_err) => {
            tracing::error!(%join_err, tool = %name, "MCP tool intent task panicked — refusing dispatch");
            return Err(McpError::internal_error(
                "audit-log intent task panicked; MCP tool call refused",
                None,
            ));
        }
    };
    let intent_id = match intent_result {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(%err, tool = %name, "MCP tool intent write failed — refusing dispatch");
            return Err(McpError::internal_error(
                "audit-log intent write failed; MCP tool call refused",
                None,
            ));
        }
    };

    // Actually dispatch.
    let outcome = match name {
        "device.send_command" => device_send_command_call(engine.clone(), request.arguments).await,
        "logs.query" => logs_query_call(engine.clone(), request.arguments).await,
        "events.history" => events_history_call(engine.clone(), request.arguments).await,
        "plugins.list" => plugins_list_call(&engine, request.arguments),
        "plugins.show" => plugins_show_call(&engine, request.arguments),
        "plugins.stop" => plugins_stop_call(engine.clone(), request.arguments).await,
        "plugins.uninstall" => plugins_uninstall_call(engine.clone(), request.arguments).await,
        "plugins.start" => plugins_start_call(engine.clone(), request.arguments).await,
        "plugins.install" => plugins_install_call(engine.clone(), request.arguments).await,
        // Unreachable — every routed tool above has a body
        // arm here. If a future addition to the routing
        // table forgets to add one, surface it as a
        // finalize-visible internal error rather than
        // silently mis-routing.
        _ => ToolOutcome::Internal(format!("MCP tool `{name}` routed without a body impl")),
    };

    // Finalize — same audit permit covers this write.
    // Round-2 F2 on PR #123: a finalize failure MUST NOT
    // replace the dispatch result with an internal error. The
    // dispatch already ran; for non-idempotent tools (a
    // `switch/toggle` in particular) the caller retrying on a
    // spurious -32603 would flip the switch a second time.
    // Finalize is best-effort once the intent row exists — a
    // failed finalize leaves the pending row in place, and
    // an operator's sweep for `decision = 'pending'` surfaces
    // the anomaly.
    let finalize_input = FinalizeInput::from_outcome(&outcome);
    let audit_log_for_finalize = engine.audit_log();
    let audit_finalize = tokio::task::spawn_blocking(move || {
        let _guard = audit_permit;
        audit_log_for_finalize.finalize(
            intent_id,
            finalize_input.status,
            &finalize_input.decision,
            finalize_input.required_scope.as_deref(),
            finalize_input.execution_outcome.as_deref(),
            finalize_input.domain_error.as_deref(),
        )
    })
    .await;
    match audit_finalize {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: "mcp.tool",
                %err,
                tool = %name,
                intent_id,
                "MCP tool finalize failed — pending audit row remains; returning original outcome",
            );
        }
        Err(join_err) => {
            tracing::error!(
                target: "mcp.tool",
                %join_err,
                tool = %name,
                intent_id,
                "MCP tool finalize task panicked — pending audit row remains; returning original outcome",
            );
        }
    }
    // Round-3 F2 on PR #123: attach the `oxidhome.audit` note
    // the `initialize` instructions promise. Carries the
    // audit-row id + path so a client that reads the ledger
    // (or a support engineer eyeballing an SSE trace) can
    // correlate this response with the row it wrote.
    //
    // Round-4 F3 on PR #123: even a `ToolOutcome::Internal`
    // that surfaces as `Err(McpError)` must carry the
    // correlation — a plugin can trap AFTER performing an
    // external action (physical actuation, network call, …)
    // and that trap becomes an `Internal` outcome. The
    // client's -32603 must still name the audit row so a
    // support engineer can find "what happened" in the
    // ledger instead of hunting through logs. Attached to
    // `McpError.data`; the client SDK forwards it verbatim.
    match outcome.into_result() {
        Ok(mut result) => {
            attach_audit_meta(&mut result, intent_id, family);
            Ok(result)
        }
        Err(mut err) => {
            attach_audit_meta_to_error(&mut err, intent_id, family);
            Err(err)
        }
    }
}

/// Attach the `oxidhome.audit` metadata note to a
/// [`CallToolResult`]. Preserves any existing keys the SDK
/// or the tool body may have set on `_meta` (we only insert
/// our own namespaced key).
fn attach_audit_meta(result: &mut CallToolResult, intent_id: u64, family: &str) {
    let mut meta = result.meta.take().unwrap_or_default();
    meta.0.insert(
        "oxidhome.audit".to_string(),
        audit_meta_value(intent_id, family),
    );
    result.meta = Some(meta);
}

/// Attach the `oxidhome.audit` correlation object to an
/// [`McpError`]'s `data` field. Preserves any existing `data`
/// payload by nesting the correlation under an
/// `oxidhome.audit` key inside a fresh object — matches the
/// shape [`attach_audit_meta`] uses for successful results.
fn attach_audit_meta_to_error(err: &mut McpError, intent_id: u64, family: &str) {
    let audit = audit_meta_value(intent_id, family);
    let data = match err.data.take() {
        Some(JsonValue::Object(mut map)) => {
            // Preserve whatever the outcome already stashed
            // (`invalid_params` / `resource_not_found` etc.
            // don't set `data` today, but a future variant
            // might).
            map.insert("oxidhome.audit".to_string(), audit);
            JsonValue::Object(map)
        }
        Some(existing) => JsonValue::Object(serde_json::Map::from_iter([
            ("oxidhome.audit".to_string(), audit),
            ("previous".to_string(), existing),
        ])),
        None => JsonValue::Object(serde_json::Map::from_iter([(
            "oxidhome.audit".to_string(),
            audit,
        )])),
    };
    err.data = Some(data);
}

fn audit_meta_value(intent_id: u64, family: &str) -> JsonValue {
    serde_json::json!({
        "intent_id": intent_id,
        "path": format!("mcp.tool.{family}"),
    })
}

/// Single-shot audit path for outcomes decided BEFORE any
/// dispatch — unknown-tool, scope-denied. Uses
/// `record_completed` (`intent_ms == finalized_ms`) since
/// there's no physical actuation to protect against.
async fn finalize_synchronous(
    engine: Engine,
    token_id: &str,
    family: &str,
    outcome: ToolOutcome,
    audit_permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<CallToolResult, McpError> {
    let audit_log = engine.audit_log();
    let audit_entry = new_completed_audit_entry(token_id, family, &outcome);
    let audit_result = tokio::task::spawn_blocking(move || {
        let _guard = audit_permit;
        audit_log.record_completed(&audit_entry)
    })
    .await;
    match audit_result {
        Ok(Ok(_row_id)) => outcome.into_result(),
        Ok(Err(err)) => {
            tracing::error!(%err, "MCP tool audit write failed — refusing call");
            Err(McpError::internal_error(
                "audit-log write failed; MCP tool call refused",
                None,
            ))
        }
        Err(join_err) => {
            tracing::error!(%join_err, "MCP tool audit task panicked — refusing call");
            Err(McpError::internal_error(
                "audit-log write task panicked; MCP tool call refused",
                None,
            ))
        }
    }
}

/// What [`AuditLog::finalize`] needs from the outcome. Built
/// once so the finalize `spawn_blocking` closure captures only
/// owned strings — no cross-boundary lifetimes.
struct FinalizeInput {
    status: u16,
    decision: String,
    required_scope: Option<String>,
    execution_outcome: Option<String>,
    domain_error: Option<String>,
}

impl FinalizeInput {
    fn from_outcome(outcome: &ToolOutcome) -> Self {
        // Round-2 F3 on PR #123: align with the audit
        // ledger's contract as documented on
        // [`crate::state::audit_log::AuditEntry`]:
        //
        // - `Some("success")` — plugin returned
        //   `Ok`/`OkWithState`.
        // - `Some("failed")` — plugin returned
        //   `CommandResult::Err`, with `domain_error` naming
        //   the WIT kind.
        // - `None` — execution never reached the plugin
        //   (unknown-device fell out inside the tool body
        //   before `execute_command`; unknown-tool / bad
        //   args / scope-denied never even enter here).
        //
        // Round-1 F3 shipped `"ok"` and stamped `"failed"`
        // on the unknown-device path too — both wrong per
        // the contract; corrected here.
        // Round-2 F3 on PR #124: `"success"` is reserved for
        // tools that reached a plugin (device.send_command
        // Ok/OkWithState). Pure host-state reads
        // (`logs.query`) leave execution_outcome NULL —
        // matches how resource-side reads audit. Only
        // `domain_kind = Some(_)` means the plugin was
        // reached and reported an `Err`; the
        // `domain_kind = None` shape (unknown device caught
        // in the tool body before `execute_command`) falls
        // through to the wildcard.
        //
        // `match_same_arms` fires on the read-Ok +
        // wildcard pair (both map to `(None, None)`);
        // suppressed because the explicit `plugin_reached:
        // false` arm documents the read-tool case — the
        // wildcard's job is to catch every other outcome
        // (`InvalidParams`, `Denied`, `Internal`, etc.),
        // not to double as the read-Ok arm.
        #[allow(clippy::match_same_arms)]
        let (execution_outcome, domain_error): (Option<&'static str>, Option<String>) =
            match outcome {
                ToolOutcome::Ok {
                    plugin_reached: true,
                    ..
                } => (Some("success"), None),
                ToolOutcome::Ok {
                    plugin_reached: false,
                    ..
                } => (None, None),
                ToolOutcome::ExecErr {
                    domain_kind: Some(kind),
                    ..
                } => (Some("failed"), Some((*kind).to_string())),
                _ => (None, None),
            };
        FinalizeInput {
            status: outcome.status(),
            decision: outcome.decision().to_string(),
            required_scope: outcome.required_scope().map(str::to_string),
            execution_outcome: execution_outcome.map(str::to_string),
            domain_error,
        }
    }
}

/// Outcome shape for a single `tools/call`. Mirrors
/// [`super::resources::ReadOutcome`] — same audit-status /
/// audit-decision mapping so an operator's ledger scan can
/// filter across both surfaces uniformly.
enum ToolOutcome {
    /// Tool completed successfully; the JSON value becomes
    /// the `structuredContent` of the [`CallToolResult`].
    /// `plugin_reached` says whether this success involved
    /// dispatching to a plugin — `true` for
    /// `device.send_command` returning Ok/OkWithState,
    /// `false` for pure host-state reads like `logs.query`.
    /// The audit ledger contract on
    /// [`crate::state::audit_log::AuditEntry`] reserves
    /// `execution_outcome = "success"` for plugin Ok, so
    /// `plugin_reached = false` maps to `None` (round-2 F3
    /// on PR #124).
    Ok {
        value: JsonValue,
        plugin_reached: bool,
    },
    /// Tool ran and produced a caller-visible failure (device
    /// not found, plugin returned `CommandResult::Err`, …).
    /// Not an authz problem — audited as `200` because the
    /// tool DID run, with an `is_error: true` payload for the
    /// client. Optional `structured` mirrors the shape a
    /// successful call would return so clients that parse
    /// structured content on both paths get one code path.
    /// `domain_kind` populates the audit row's `domain_error`
    /// column when this outcome is a plugin-reported WIT
    /// error (`not-found` / `invalid-argument` / … — the
    /// same tag REST stamps via `wit_error_kind`).
    ExecErr {
        message: String,
        structured: Option<JsonValue>,
        domain_kind: Option<&'static str>,
    },
    /// Client sent bad arguments. Maps to `-32602`.
    InvalidParams(String),
    /// URI/arguments are valid, but the response would
    /// exceed the per-response size budget (`logs.query`
    /// with too many matching rows, etc.). Maps to
    /// [`RESOURCE_TOO_LARGE_CODE`] (`-32003`) and audits
    /// as HTTP 413 — mirrors the resource-side outcome
    /// shape (round-2 F2 on PR #124).
    TooLarge(String),
    /// Server is transiently at capacity — a concurrency
    /// semaphore (audit queue, store-query queue) had no
    /// permits. Maps to [`RESOURCE_BUSY_CODE`] (`-32004`)
    /// and audits as HTTP 503, matching the resource-side
    /// outcome (round-2 F3 on PR #124).
    Busy(String),
    /// Tool name isn't in the catalogue. Maps to `-32601`
    /// method-not-found.
    UnknownTool(String),
    /// Scope check failed. Maps to [`SCOPE_DENIED_CODE`].
    Denied { required: &'static str },
    /// Server-side failure. Maps to `-32603`.
    Internal(String),
}

impl ToolOutcome {
    fn into_result(self) -> Result<CallToolResult, McpError> {
        match self {
            Self::Ok { value, .. } => {
                // Round-3 F1 on PR #124: always keep
                // `CallToolResult::structured`'s text mirror
                // — legacy MCP clients that predate
                // `structuredContent` still get the result
                // via `content[0].text`. Peak memory is
                // bounded by [`MAX_TOOL_BODY_BYTES`]
                // (2.5 MiB) which reserves room for the 3×
                // wire footprint (`structuredContent` +
                // escaped text mirror + framing) under the
                // 8 MiB transport cap.
                //
                // The `plugin_reached` field on `Ok` is
                // now only consulted by
                // `FinalizeInput::from_outcome` to decide
                // whether `execution_outcome` gets stamped
                // `"success"` (plugin reached) or `NULL`
                // (pure host-state read); it no longer
                // gates the text-mirror shape.
                Ok(CallToolResult::structured(value))
            }
            Self::ExecErr {
                message,
                structured,
                domain_kind: _,
            } => Ok(match structured {
                Some(v) => CallToolResult::structured_error(v),
                None => CallToolResult::error(vec![ContentBlock::text(message)]),
            }),
            Self::InvalidParams(reason) => Err(McpError::invalid_params(reason, None)),
            Self::TooLarge(reason) => Err(McpError::new(RESOURCE_TOO_LARGE_CODE, reason, None)),
            Self::Busy(reason) => Err(McpError::new(RESOURCE_BUSY_CODE, reason, None)),
            Self::UnknownTool(reason) => Err(McpError::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                reason,
                None,
            )),
            Self::Denied { required: _ } => Err(McpError::new(
                SCOPE_DENIED_CODE,
                // Deliberately omits the scope name; see the
                // resource-side `SCOPE_DENIED_CODE` doc.
                "scope denied for MCP tool",
                None,
            )),
            Self::Internal(reason) => Err(McpError::internal_error(reason, None)),
        }
    }

    fn status(&self) -> u16 {
        match self {
            // A tool that ran and reported `is_error: true`
            // is still an authorization + transport success —
            // the tool WAS invoked. Matches the REST
            // send-command path (`200` with a
            // `CommandResult::Err` in the body).
            Self::Ok { .. } | Self::ExecErr { .. } => 200,
            Self::UnknownTool(_) => 404,
            Self::InvalidParams(_) => 400,
            Self::TooLarge(_) => 413,
            Self::Busy(_) => 503,
            Self::Denied { .. } => 403,
            Self::Internal(_) => 500,
        }
    }

    fn decision(&self) -> &'static str {
        match self {
            Self::Ok { .. } | Self::ExecErr { .. } => "allow",
            Self::UnknownTool(_)
            | Self::Denied { .. }
            | Self::InvalidParams(_)
            | Self::TooLarge(_) => "deny",
            // Match the REST auth classifier: 5xx → "error"
            // (Busy is 503; Internal is 500).
            Self::Internal(_) | Self::Busy(_) => "error",
        }
    }

    /// Scope name to record on the audit row's
    /// `required_scope` column. `Some` only for
    /// [`Self::Denied`], matching resources' shape.
    fn required_scope(&self) -> Option<&'static str> {
        match self {
            Self::Denied { required } => Some(required),
            _ => None,
        }
    }
}

// ── device.send_command ─────────────────────────────────────────

/// Cap on the plugin-supplied error message before we let it
/// enter any JSON serialisation. The WIT contract lets a
/// plugin's `command-result::err` payload carry an
/// unconstrained string — a misbehaving guest could push
/// close to its 128 MiB memory ceiling of text and drive the
/// host into two full copies (once through
/// `serde_json::to_value`, once through
/// `CallToolResult::structured_error`) before any downstream
/// bound sees it. 4 KiB is generous for a real error message
/// while capping the runaway path (round-1 F2 on PR #123).
const MAX_PLUGIN_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

async fn device_send_command_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let args: DeviceSendCommandArgs = match arguments {
        Some(map) => match serde_json::from_value(JsonValue::Object(map)) {
            Ok(a) => a,
            Err(err) => {
                return ToolOutcome::InvalidParams(format!(
                    "device.send_command arguments do not match the input schema: {err}",
                ));
            }
        },
        None => {
            return ToolOutcome::InvalidParams(
                "device.send_command requires `device_id`, `capability`, and `action`".into(),
            );
        }
    };

    // Resolve device → owning instance the same way the REST
    // handler does. `NotFound` is deliberately indistinct
    // between "no such device" and "owner not running" so a
    // probing caller can't enumerate device ids.
    let Some(owner) = engine.devices().get_owner(&args.device_id) else {
        return ToolOutcome::ExecErr {
            message: format!("device `{}` not found or not running", args.device_id),
            structured: None,
            domain_kind: None,
        };
    };
    let Some(handle) = engine.instances().get(&owner) else {
        return ToolOutcome::ExecErr {
            message: format!("device `{}` not found or not running", args.device_id),
            structured: None,
            domain_kind: None,
        };
    };

    let cmd = Command {
        capability: args.capability,
        action: args.action,
        args: args
            .args
            .into_iter()
            .map(|kv| KeyValue {
                key: kv.key,
                value: kv.value.into(),
            })
            .collect(),
    };

    let result = match handle.execute_command(args.device_id, cmd).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(target: "mcp.tool.device.send_command", %err, "dispatch failed");
            return ToolOutcome::Internal("device command dispatch failed".into());
        }
    };

    // Round-1 F2 on PR #123: truncate the plugin-supplied
    // error message BEFORE conversion to `WireCommandResult`
    // + `serde_json::Value`. Both those steps make a full
    // copy of the string, and a misbehaving plugin can push
    // arbitrarily many bytes into the WIT error variant.
    let result = truncate_plugin_error(result);

    // Match REST's shape: the plugin-visible response carries
    // the `CommandResult` verbatim; a `CommandResult::Err`
    // rides on the `is_error: true` branch so clients see the
    // domain-error, and the wire body's `error.kind` is the
    // same tagged shape REST already returns.
    let wire = command_result_to_wire(result);
    let structured = match serde_json::to_value(&wire) {
        Ok(v) => v,
        Err(err) => {
            tracing::error!(target: "mcp.tool.device.send_command", %err, "wire serialisation failed");
            return ToolOutcome::Internal("failed to serialise command result".into());
        }
    };
    match &wire {
        WireCommandResult::Ok | WireCommandResult::OkWithState { .. } => ToolOutcome::Ok {
            value: structured,
            // Plugin was reached and returned Ok — audits
            // as `execution_outcome = "success"`.
            plugin_reached: true,
        },
        WireCommandResult::Err { error } => {
            let domain_kind = wit_error_kind_of_wire(error);
            ToolOutcome::ExecErr {
                message: format!(
                    "device.send_command failed: {} — {}",
                    domain_kind,
                    message_of_wire_error(error),
                ),
                structured: Some(structured),
                domain_kind: Some(domain_kind),
            }
        }
    }
}

/// Truncate a plugin-supplied WIT `error` message to
/// [`MAX_PLUGIN_ERROR_MESSAGE_BYTES`] BEFORE it reaches the
/// wire-conversion helpers. `truncate` operates on UTF-8
/// char boundaries, so we back the cap off to the largest
/// char boundary that's ≤ the cap — avoids splitting a
/// multi-byte character. Only touches `CommandResult::Err`;
/// other variants pass through.
fn truncate_plugin_error(result: CommandResult) -> CommandResult {
    use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
    let CommandResult::Err(err) = result else {
        return result;
    };
    let truncated = match err {
        WitError::NotFound(m) => WitError::NotFound(cap_message(m)),
        WitError::InvalidArgument(m) => WitError::InvalidArgument(cap_message(m)),
        WitError::PermissionDenied(m) => WitError::PermissionDenied(cap_message(m)),
        WitError::Unavailable(m) => WitError::Unavailable(cap_message(m)),
        WitError::Internal(m) => WitError::Internal(cap_message(m)),
    };
    CommandResult::Err(truncated)
}

fn cap_message(mut m: String) -> String {
    if m.len() > MAX_PLUGIN_ERROR_MESSAGE_BYTES {
        // Walk back to the largest char boundary ≤ cap so
        // `truncate` doesn't panic on multi-byte characters.
        let mut cap = MAX_PLUGIN_ERROR_MESSAGE_BYTES;
        while !m.is_char_boundary(cap) {
            cap -= 1;
        }
        let original_len = m.len();
        m.truncate(cap);
        tracing::warn!(
            target: "mcp.tool.device.send_command",
            original_len,
            cap = MAX_PLUGIN_ERROR_MESSAGE_BYTES,
            "plugin error message exceeded cap — truncated",
        );
        m.push_str("… [truncated by host]");
    }
    m
}

fn wit_error_kind_of_wire(err: &crate::api::server::WireWitError) -> &'static str {
    use crate::api::server::WireWitError as W;
    use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
    // Reconstruct just enough of the WIT error to reuse the
    // shared classifier. Cheap — the constructor doesn't
    // allocate beyond one `String::new()`.
    let placeholder = match err {
        W::NotFound { .. } => WitError::NotFound(String::new()),
        W::InvalidArgument { .. } => WitError::InvalidArgument(String::new()),
        W::PermissionDenied { .. } => WitError::PermissionDenied(String::new()),
        W::Unavailable { .. } => WitError::Unavailable(String::new()),
        W::Internal { .. } => WitError::Internal(String::new()),
    };
    wit_error_kind(&placeholder)
}

fn message_of_wire_error(err: &crate::api::server::WireWitError) -> &str {
    use crate::api::server::WireWitError as W;
    match err {
        W::NotFound { message }
        | W::InvalidArgument { message }
        | W::PermissionDenied { message }
        | W::Unavailable { message }
        | W::Internal { message } => message,
    }
}

// ── logs.query ──────────────────────────────────────────────────

fn logs_query_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "since": {
                "type": "string",
                "description": "Relative duration: `Ns|Nm|Nh|Nd`. Resolves to `now - since`. e.g. `10m`, `2h`.",
            },
            "until": {
                "type": "string",
                "description": "Relative duration (same grammar as `since`). Resolves to `now - until`.",
            },
            "level": {
                "type": "string",
                "enum": ["Trace", "Debug", "Info", "Warn", "Error"],
                "description": "Minimum level. `Info` includes Info, Warn, Error.",
            },
            "instance": { "type": "string", "description": "Filter by owning instance id." },
            "plugin":   { "type": "string", "description": "Filter by owning plugin id." },
            "device":   { "type": "string", "description": "Filter by device id (for device-scoped log rows)." },
            "target":   { "type": "string", "description": "Exact-match `tracing` target." },
            "target_prefix":    { "type": "string", "description": "Prefix-match on `tracing` target (e.g. `oxidhome_core::runtime`)." },
            "span_path_prefix": { "type": "string", "description": "Prefix-match on the row's span path (e.g. `plugin.`)." },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": i64::from(crate::api::mcp::resources::LOGS_QUERY_MAX_LIMIT),
                "description": "Max rows to return (default 100, cap 100).",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

/// Deserialisable name of a log level. Serde derives a
/// unit-variant deserializer that accepts `"Trace"`,
/// `"Debug"`, etc. — the same tokens the resource-side
/// `oxidhome://logs?level=…` query parser accepts.
#[derive(Deserialize)]
enum LogLevelName {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevelName> for crate::state::LogLevel {
    fn from(v: LogLevelName) -> Self {
        use crate::state::LogLevel as L;
        match v {
            LogLevelName::Trace => L::Trace,
            LogLevelName::Debug => L::Debug,
            LogLevelName::Info => L::Info,
            LogLevelName::Warn => L::Warn,
            LogLevelName::Error => L::Error,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogsQueryArgs {
    since: Option<String>,
    until: Option<String>,
    level: Option<LogLevelName>,
    instance: Option<String>,
    plugin: Option<String>,
    device: Option<String>,
    target: Option<String>,
    target_prefix: Option<String>,
    span_path_prefix: Option<String>,
    limit: Option<u32>,
}

async fn logs_query_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    // `arguments = None` is fine here — `logs.query` has no
    // required fields, so an empty call means "give me the
    // latest 100 rows across everything." Deserialise from
    // an empty object in that case so the same code path
    // covers both shapes.
    let args_value = arguments.map_or(JsonValue::Object(serde_json::Map::new()), JsonValue::Object);
    let args: LogsQueryArgs = match serde_json::from_value(args_value) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "logs.query arguments do not match the input schema: {err}",
            ));
        }
    };

    let now = crate::state::event_log::now_unix_ms();
    let since_ms = match args
        .since
        .as_deref()
        .map(super::resources::parse_duration_ms)
        .transpose()
    {
        Ok(v) => v.map(|d| now.saturating_sub(d)),
        Err(err) => {
            return ToolOutcome::InvalidParams(format!("invalid `since` value: {err}"));
        }
    };
    let until_ms = match args
        .until
        .as_deref()
        .map(super::resources::parse_duration_ms)
        .transpose()
    {
        Ok(v) => v.map(|d| now.saturating_sub(d)),
        Err(err) => {
            return ToolOutcome::InvalidParams(format!("invalid `until` value: {err}"));
        }
    };

    let limit = args
        .limit
        .unwrap_or(super::resources::LOGS_QUERY_DEFAULT_LIMIT)
        .clamp(1, super::resources::LOGS_QUERY_MAX_LIMIT);

    let log_query = crate::state::LogQuery {
        since_ms,
        until_ms,
        min_level: args.level.map(Into::into),
        instance_id: args.instance,
        plugin_id: args.plugin,
        device_id: args.device,
        target: args.target,
        target_prefix: args.target_prefix,
        span_path_prefix: args.span_path_prefix,
    };
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    // Round-1 F1 on PR #124: bound the concurrent
    // blocking-writer tasks via the shared
    // `STORE_QUERY_SEMAPHORE`. Permit MOVES into the closure
    // so a cancelled outer future (client disconnect) doesn't
    // leave detached blocking tasks piled up on the mutex.
    // Round-2 F3 on PR #124: saturation surfaces as
    // `ToolOutcome::Busy` (`-32004` / 503) — retriable —
    // instead of a bare `Internal` (500). Matches the
    // resource-side outcome for the same signal.
    let Ok(query_permit) = Arc::clone(&STORE_QUERY_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = STORE_QUERY_MAX,
            "MCP logs.query store-query saturated — refusing call",
        );
        return ToolOutcome::Busy(format!(
            "MCP store-query queue saturated ({STORE_QUERY_MAX} in-flight); retry shortly"
        ));
    };
    let log_store = engine.log_store();
    let join = tokio::task::spawn_blocking(move || {
        let _guard = query_permit;
        log_store.query(&log_query, limit_usize)
    })
    .await;
    let rows = match join {
        Ok(Ok(rows)) => rows,
        Ok(Err(err)) => {
            tracing::error!(target: "mcp.tool.logs.query", %err, "log query failed");
            return ToolOutcome::Internal("log query failed".into());
        }
        Err(join_err) => {
            tracing::error!(target: "mcp.tool.logs.query", %join_err, "log query task panicked");
            return ToolOutcome::Internal("log query task panicked".into());
        }
    };

    // Reuse the resource-side wire shape so a client sees
    // the same JSON on `resources/read` and `tools/call`.
    // Round-3 F1 on PR #124: use `MAX_TOOL_BODY_BYTES`
    // (2.5 MiB) not `MAX_TEXT_BODY_BYTES` — a
    // `CallToolResult` ships the body twice on the wire
    // (`structuredContent` + escaped `content[0].text`),
    // so the per-body cap has to leave room for both.
    let body = super::resources::LogsBody { logs: &rows };
    match super::resources::encode_body_capped(&body, "logs.query", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Pure host-state read — no plugin was reached,
            // so `execution_outcome` stays `None` per the
            // audit ledger contract.
            plugin_reached: false,
        },
        // Round-2 F2 on PR #124: oversized responses map to
        // `TooLarge` (`-32003` / 413), NOT `InvalidParams`
        // (`-32602` / 400). Arguments were fine; the
        // response is too large. Matches the resource-side
        // outcome shape.
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── events.history ──────────────────────────────────────────────

/// Inclusive ceiling for `after_id` / `before_id`. See the
/// call site in [`events_history_call`] for the rationale
/// (store clamps `> i64::MAX` to `i64::MAX`, silently
/// widening the query).
#[allow(clippy::cast_sign_loss)]
const CURSOR_MAX: u64 = i64::MAX as u64;

fn events_history_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "since": {
                "type": "string",
                "description": "Relative duration: `Ns|Nm|Nh|Nd`. Resolves to `now - since`. e.g. `10m`, `2h`.",
            },
            "until": {
                "type": "string",
                "description": "Relative duration (same grammar as `since`). Resolves to `now - until`.",
            },
            "device":   { "type": "string", "description": "Filter by device id." },
            "instance": { "type": "string", "description": "Filter by owning instance id." },
            "plugin":   { "type": "string", "description": "Filter by owning plugin id." },
            "topic": {
                "type": "string",
                "description": "Exact-match topic (e.g. `switch`, `button`, `inference`). Mutually exclusive with `topic_prefix` — supply at most one.",
            },
            "topic_prefix": {
                "type": "string",
                "description": "Prefix-match on topic (e.g. `automation.` matches `automation.morning`, `automation.evening`, …). Mutually exclusive with `topic`.",
            },
            "after_id": {
                "type": "integer",
                "minimum": 0,
                "maximum": i64::MAX,
                "description": "Cursor: return only rows with `id > after_id`. Pairs with tail-client resume so a reconnect after N ms doesn't gap or duplicate rows.",
            },
            "before_id": {
                "type": "integer",
                "minimum": 0,
                "maximum": i64::MAX,
                "description": "Cursor: return only rows with `id < before_id`. Descending pagination — pass the lowest id from the previous batch to walk backwards.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": i64::from(crate::api::mcp::resources::EVENTS_QUERY_MAX_LIMIT),
                "description": "Max rows to return (default 100, cap 100).",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsHistoryArgs {
    since: Option<String>,
    until: Option<String>,
    device: Option<String>,
    instance: Option<String>,
    plugin: Option<String>,
    topic: Option<String>,
    topic_prefix: Option<String>,
    after_id: Option<u64>,
    before_id: Option<u64>,
    limit: Option<u32>,
}

// Linear top-to-bottom decision flow (parse → duration
// resolve → topic → limit → gate → spawn_blocking →
// encode). Splitting it into helpers would hide the sequence
// without shrinking any individual step; matches the shape of
// `logs_query_call`.
#[allow(clippy::too_many_lines)]
async fn events_history_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    // `arguments = None` → empty filter, latest 100 rows.
    let args_value = arguments.map_or(JsonValue::Object(serde_json::Map::new()), JsonValue::Object);
    let args: EventsHistoryArgs = match serde_json::from_value(args_value) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "events.history arguments do not match the input schema: {err}",
            ));
        }
    };

    let now = crate::state::event_log::now_unix_ms();
    let since_ms = match args
        .since
        .as_deref()
        .map(super::resources::parse_duration_ms)
        .transpose()
    {
        Ok(v) => v.map(|d| now.saturating_sub(d)),
        Err(err) => {
            return ToolOutcome::InvalidParams(format!("invalid `since` value: {err}"));
        }
    };
    let until_ms = match args
        .until
        .as_deref()
        .map(super::resources::parse_duration_ms)
        .transpose()
    {
        Ok(v) => v.map(|d| now.saturating_sub(d)),
        Err(err) => {
            return ToolOutcome::InvalidParams(format!("invalid `until` value: {err}"));
        }
    };

    // `topic` (exact) and `topic_prefix` are mutually
    // exclusive — same policy as the resource-side handler:
    // prefer prefix when both are set and warn so an operator
    // can spot the ambiguous client.
    let topic = match (args.topic, args.topic_prefix) {
        (topic_exact, Some(p)) => {
            if let Some(exact) = &topic_exact {
                tracing::warn!(
                    target: "mcp.tool.events.history",
                    topic_exact = %exact,
                    topic_prefix = %p,
                    "MCP events.history: both `topic` and `topic_prefix` supplied — using `topic_prefix`",
                );
            }
            Some((p, crate::state::TopicMatch::Prefix))
        }
        (Some(t), None) => Some((t, crate::state::TopicMatch::Exact)),
        (None, None) => None,
    };

    let limit = args
        .limit
        .unwrap_or(super::resources::EVENTS_QUERY_DEFAULT_LIMIT)
        .clamp(1, super::resources::EVENTS_QUERY_MAX_LIMIT);

    // Cursor IDs are wire-typed as `u64` but the store binds
    // them as SQLite `INTEGER` (signed 64-bit). Anything above
    // `i64::MAX` is silently clamped to `i64::MAX` by the store,
    // which would turn e.g. `before_id: u64::MAX` (a client
    // intending "start from the newest row") into `id <
    // i64::MAX` — a query broadening rather than restricting.
    // The advertised JSON Schema already caps both at
    // `i64::MAX`; enforce the same bound at the tool boundary
    // so an over-cap cursor lands as `INVALID_PARAMS` instead
    // of silently succeeding with the wrong page.
    if let Some(v) = args.after_id
        && v > CURSOR_MAX
    {
        return ToolOutcome::InvalidParams(format!(
            "invalid `after_id` value `{v}`; must be <= {CURSOR_MAX}",
        ));
    }
    if let Some(v) = args.before_id
        && v > CURSOR_MAX
    {
        return ToolOutcome::InvalidParams(format!(
            "invalid `before_id` value `{v}`; must be <= {CURSOR_MAX}",
        ));
    }

    let event_query = crate::state::EventQuery {
        since_ms,
        until_ms,
        device_id: args.device,
        instance_id: args.instance,
        plugin_id: args.plugin,
        topic,
        after_id: args.after_id,
        before_id: args.before_id,
    };
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    // Shared `STORE_QUERY_SEMAPHORE` — permit MOVES into the
    // closure so a cancelled outer future doesn't leave
    // detached blocking tasks piled up on the mutex.
    // Saturation surfaces as `Busy` (`-32004` / 503) — same
    // shape as the resource-side outcome.
    let Ok(query_permit) = Arc::clone(&STORE_QUERY_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = STORE_QUERY_MAX,
            "MCP events.history store-query saturated — refusing call",
        );
        return ToolOutcome::Busy(format!(
            "MCP store-query queue saturated ({STORE_QUERY_MAX} in-flight); retry shortly"
        ));
    };
    let event_log = engine.event_log();
    let join = tokio::task::spawn_blocking(move || {
        let _guard = query_permit;
        event_log.query(&event_query, limit_usize)
    })
    .await;
    let rows = match join {
        Ok(Ok(rows)) => rows,
        Ok(Err(err)) => {
            tracing::error!(target: "mcp.tool.events.history", %err, "event query failed");
            return ToolOutcome::Internal("event query failed".into());
        }
        Err(join_err) => {
            tracing::error!(target: "mcp.tool.events.history", %join_err, "event query task panicked");
            return ToolOutcome::Internal("event query task panicked".into());
        }
    };

    let events: Vec<_> = rows
        .into_iter()
        .map(super::super::server::WireHistoricalEvent::from_row)
        .collect();
    let body = super::resources::EventsBody { events };
    match super::resources::encode_body_capped(&body, "events.history", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Pure host-state read — plugin was never reached,
            // so `execution_outcome` stays `None` per the
            // audit ledger contract.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── plugins.list ────────────────────────────────────────────────

fn plugins_list_schema() -> serde_json::Map<String, JsonValue> {
    // Deliberately no filter fields for the initial cut: the
    // resource-side counterpart takes none either, and any
    // filter added later must arrive on both surfaces in
    // lockstep so their wire contracts stay identical.
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

/// Empty-args deserialiser for `plugins.list`. `deny_unknown_fields`
/// on a zero-field struct enforces the schema's
/// `additionalProperties: false` at the tool boundary — a client
/// sending `{"junk": 1}` (or any unknown field) lands as
/// `INVALID_PARAMS` instead of silently succeeding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsListArgs {}

fn plugins_list_call(
    engine: &Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    // Absent arguments and `{}` are both valid — the schema
    // has no required fields. Round-1 P2 on PR #131: any
    // other content violates `additionalProperties: false`.
    let args_value = arguments.map_or(JsonValue::Object(serde_json::Map::new()), JsonValue::Object);
    if let Err(err) = serde_json::from_value::<PluginsListArgs>(args_value) {
        return ToolOutcome::InvalidParams(format!(
            "plugins.list arguments do not match the input schema: {err}",
        ));
    }

    let body = super::resources::plugins_list_body(engine);
    match super::resources::encode_body_capped(&body, "plugins.list", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Pure host-state read — no plugin was reached,
            // so `execution_outcome` stays `None` per the
            // audit ledger contract.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── plugins.show ────────────────────────────────────────────────

fn plugins_show_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["plugin_id"],
        "properties": {
            "plugin_id": {
                "type": "string",
                "minLength": 1,
                "description": "Plugin id (`net.example.foo`) to look up. Must match an installed plugin or a currently-running instance's owning plugin.",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsShowArgs {
    plugin_id: String,
}

fn plugins_show_call(
    engine: &Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let Some(arguments) = arguments else {
        return ToolOutcome::InvalidParams("plugins.show requires a `plugin_id` argument".into());
    };
    let args: PluginsShowArgs = match serde_json::from_value(JsonValue::Object(arguments)) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "plugins.show arguments do not match the input schema: {err}",
            ));
        }
    };
    if args.plugin_id.is_empty() {
        return ToolOutcome::InvalidParams("`plugin_id` must not be empty".into());
    }

    let Some(body) = super::resources::plugins_detail_body(engine, &args.plugin_id) else {
        // Not-found is an application-level error carried as a
        // `CallToolResult { isError: true }` — mirrors the
        // resource-side `NotFound` outcome shape. `ExecErr` is
        // the tool-outcome slot for it; the audit row still
        // records `decision = "allow"` (the caller was
        // authorised; the target just didn't exist). No plugin
        // WIT error involved, so `domain_kind` stays `None`.
        return ToolOutcome::ExecErr {
            message: format!(
                "plugin `{}` is not installed and has no running instances",
                args.plugin_id,
            ),
            structured: None,
            domain_kind: None,
        };
    };
    match super::resources::encode_body_capped(&body, "plugins.show", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── plugins.stop ────────────────────────────────────────────────

fn plugins_stop_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["plugin_id"],
        "properties": {
            "plugin_id": {
                "type": "string",
                "minLength": 1,
                "description": "Installed `plugin_id` whose instances to stop.",
            },
            "instance_id": {
                "type": "string",
                "minLength": 1,
                "description": "Optional: stop only this specific instance. If omitted, every supervised instance of `plugin_id` is stopped.",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

/// Round-1 P1 on PR #132: `instance_id` is optional but must
/// NEVER be an explicit JSON `null`. The default
/// `#[serde(default)] Option<String>` accepts both "absent"
/// and `null` as `None` — the latter would silently widen a
/// targeted stop into a bulk stop-all when the caller
/// intended to send a value but mis-serialised it (client bug,
/// codegen glitch). Deserialising through a string-only helper
/// with `#[serde(default)]` keeps "absent → None" while making
/// `null` a schema-violating input that lands as
/// `INVALID_PARAMS`.
fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Some(s))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsStopArgs {
    plugin_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    instance_id: Option<String>,
}

#[derive(Serialize)]
struct PluginsStopBody {
    stopped: Vec<String>,
}

async fn plugins_stop_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let Some(arguments) = arguments else {
        return ToolOutcome::InvalidParams("plugins.stop requires a `plugin_id` argument".into());
    };
    let args: PluginsStopArgs = match serde_json::from_value(JsonValue::Object(arguments)) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "plugins.stop arguments do not match the input schema: {err}",
            ));
        }
    };
    if args.plugin_id.is_empty() {
        return ToolOutcome::InvalidParams("`plugin_id` must not be empty".into());
    }
    if args.instance_id.as_ref().is_some_and(String::is_empty) {
        return ToolOutcome::InvalidParams(
            "`instance_id`, when supplied, must not be empty".into(),
        );
    }

    // Mirror the REST handler: iterate the registry, filter to
    // matching plugin_id (+ optional instance_id), stop each
    // and wait for the reaper to clear the entry so a follow-up
    // caller sees consistent post-stop state. Idempotent — an
    // empty `stopped` list is a valid success (nothing was
    // running that matched).
    let registry = engine.instances();
    let mut stopped = Vec::new();
    for handle in registry.list() {
        if handle.plugin_id() != args.plugin_id {
            continue;
        }
        if let Some(want) = &args.instance_id
            && handle.instance_id() != want
        {
            continue;
        }
        let id = handle.instance_id().to_string();
        if let Err(err) = handle.stop().await {
            tracing::warn!(
                target: "mcp.tool.plugins.stop",
                instance_id = %id,
                error = %err,
                "stop instance failed; continuing with siblings",
            );
            continue;
        }
        let _ = handle.wait_terminal().await;
        wait_for_registry_clear(&registry, &id).await;
        stopped.push(id);
    }

    let body = PluginsStopBody { stopped };
    match super::resources::encode_body_capped(&body, "plugins.stop", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Round-1 P2 on PR #132: `execution_outcome` is a
            // plugin-command taxonomy field (`"success"` for
            // plugin Ok, `"failed"` for plugin Err). Stopping
            // a supervisor is a host-state lifecycle action,
            // not a plugin invocation — the plugin never runs
            // an `execute-command` handler here. Keep the
            // slot NULL to avoid corrupting a downstream
            // consumer's plugin-outcome analytics. Same rule
            // the read tools follow.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

/// Bounded poll for the instance to leave the registry after
/// its supervisor reached a terminal state. Same rationale as
/// the REST-side [`crate::api::server::wait_for_registry_clear`]:
/// the reaper runs on a separately-spawned tokio task, so
/// there's a brief window where the terminal state is
/// observable but the registry entry is still present. 5 s is
/// comfortably above any plausible reaper-scheduling latency.
async fn wait_for_registry_clear(registry: &crate::InstanceRegistry, instance_id: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while registry.get(instance_id).is_some() {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                target: "mcp.tool.plugins.stop",
                instance_id = %instance_id,
                "instance registry didn't clear after 5s — reaper task lagging?",
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

// ── plugins.uninstall ───────────────────────────────────────────

fn plugins_uninstall_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["plugin_id"],
        "properties": {
            "plugin_id": {
                "type": "string",
                "minLength": 1,
                "description": "Installed `plugin_id` to uninstall. Refuses if any supervised instance is still running — call `plugins.stop` first.",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsUninstallArgs {
    plugin_id: String,
}

#[derive(Serialize)]
struct PluginsUninstallBody {
    plugin_id: String,
}

async fn plugins_uninstall_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let Some(arguments) = arguments else {
        return ToolOutcome::InvalidParams(
            "plugins.uninstall requires a `plugin_id` argument".into(),
        );
    };
    let args: PluginsUninstallArgs = match serde_json::from_value(JsonValue::Object(arguments)) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "plugins.uninstall arguments do not match the input schema: {err}",
            ));
        }
    };
    if args.plugin_id.is_empty() {
        return ToolOutcome::InvalidParams("`plugin_id` must not be empty".into());
    }

    // Mirror REST's uninstall: hold the per-plugin_id
    // lifecycle lock across the running-instances check + the
    // compose uninstall, and MOVE the guard into the
    // `spawn_blocking` closure so a cancelled MCP request
    // (client disconnect mid-uninstall) can't race a concurrent
    // `plugins.start` re-acquiring the mutex while the FS/SQL
    // steps are still running.
    let lifecycle_lock = engine.plugin_lifecycle_lock(&args.plugin_id);
    let guard = lifecycle_lock.lock_owned().await;
    let running: Vec<String> = engine
        .instances()
        .list()
        .into_iter()
        .filter(|h| h.plugin_id() == args.plugin_id)
        .map(|h| h.instance_id().to_string())
        .collect();
    // Round-1 P2 on PR #132: `domain_kind` populates the
    // ledger's `domain_error` column, documented as "the WIT
    // error kind a plugin returned." Uninstall preconditions
    // (instances-running, not-installed, no-plugins-root) are
    // host-state conditions — no plugin was ever invoked, no
    // WIT error was raised — so `domain_kind` stays `None`
    // even on the ExecErr paths. The `structured.kind` field
    // still gives clients a machine-readable tag; only the
    // audit slot is unpolluted.
    if !running.is_empty() {
        let structured = json!({
            "kind": "instances_running",
            "plugin_id": args.plugin_id,
            "running": running,
        });
        return ToolOutcome::ExecErr {
            message: format!(
                "plugin `{}` has running instances: {} — call plugins.stop first",
                args.plugin_id,
                running.join(", "),
            ),
            structured: Some(structured),
            domain_kind: None,
        };
    }

    let engine_for_blocking = engine.clone();
    let plugin_id_for_blocking = args.plugin_id.clone();
    let join = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        engine_for_blocking.uninstall_plugin(&plugin_id_for_blocking)
    })
    .await;
    match join {
        Ok(Ok(())) => {}
        Ok(Err(crate::state::UninstallError::NotInstalled(_))) => {
            return ToolOutcome::ExecErr {
                message: format!("plugin `{}` is not installed", args.plugin_id),
                structured: Some(json!({
                    "kind": "not_installed",
                    "plugin_id": args.plugin_id,
                })),
                domain_kind: None,
            };
        }
        Ok(Err(crate::state::UninstallError::NoPluginsRoot)) => {
            // In-memory engine: uninstall isn't supported. Mirrors
            // REST's 503 shape.
            return ToolOutcome::ExecErr {
                message: "uninstall requires a state-dir-backed engine".into(),
                structured: Some(json!({
                    "kind": "no_plugins_root",
                    "plugin_id": args.plugin_id,
                })),
                domain_kind: None,
            };
        }
        Ok(Err(err)) => {
            // Round-1 P2 on PR #132: `UninstallError::Io` can
            // carry absolute filesystem paths and
            // `UninstallError::Persistence` can carry SQLite
            // internals. Log the full error server-side; hand
            // the caller a generic message so a hostile client
            // can't probe host layout via crafted `plugin_id`
            // values. Matches REST + Connect-RPC's opaque 500
            // response for the same conditions.
            tracing::error!(
                target: "mcp.tool.plugins.uninstall",
                plugin_id = %args.plugin_id,
                %err,
                "uninstall failed",
            );
            return ToolOutcome::Internal("uninstall failed; see server logs".into());
        }
        Err(join_err) => {
            tracing::error!(target: "mcp.tool.plugins.uninstall", %join_err, "uninstall task panicked");
            return ToolOutcome::Internal("uninstall task panicked".into());
        }
    }

    let body = PluginsUninstallBody {
        plugin_id: args.plugin_id,
    };
    match super::resources::encode_body_capped(&body, "plugins.uninstall", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Round-1 P2 on PR #132: `execution_outcome` is a
            // plugin-invocation taxonomy field. Uninstall
            // manipulates host state (FS + SQL registry rows)
            // — no plugin `execute-command` runs. Leave the
            // slot NULL, same as the read tools.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── plugins.start ───────────────────────────────────────────────

fn plugins_start_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["plugin_id"],
        "properties": {
            "plugin_id": {
                "type": "string",
                "minLength": 1,
                "description": "Installed `plugin_id` to start.",
            },
            "instance_id": {
                "type": "string",
                "minLength": 1,
                "description": "Optional: instance id to run under. Defaults to `plugin_id`. Must be a safe filesystem segment (no `/`, `..`, absolute paths, or leading dots).",
            },
            "config_overrides": {
                "type": "object",
                "description": "Optional: TOML-shaped JSON blob that layers over the manifest's `[config]` table. Follows the same shape the REST endpoint's `config_overrides` accepts.",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsStartArgs {
    plugin_id: String,
    // Round-1 P1 on PR #132: string-only helper rejects
    // explicit JSON `null` on the optional field so a malformed
    // client payload can't silently coerce to the default
    // (which for start means "instance_id = plugin_id").
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    instance_id: Option<String>,
    // Round-1 P1 on PR #133: same null-guard as
    // `instance_id`, plus a type-check that only accepts a
    // JSON object. Pre-fix, `Option<toml::Value>` accepted
    // explicit `null` (→ `None`, silently starting with
    // manifest defaults) and non-table scalars/arrays (which
    // only failed after the supervisor was already spawned).
    // The schema advertises `type: "object"`; enforce it here.
    #[serde(default, deserialize_with = "deserialize_optional_toml_table")]
    config_overrides: Option<toml::Value>,
}

/// Enforces the `config_overrides` field's schema at the tool
/// boundary: absent → `None` (via `#[serde(default)]` on the
/// field), object → `Some(toml::Value::Table)`, everything
/// else (explicit `null`, scalars, arrays) → a
/// `deserialize`-time error that lands as
/// `INVALID_PARAMS`. Converting through
/// `serde_json::Value` first makes the type-check explicit
/// and keeps the error message deterministic across serde
/// versions.
fn deserialize_optional_toml_table<'de, D>(deserializer: D) -> Result<Option<toml::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match &value {
        serde_json::Value::Object(_) => {
            let toml_value =
                serde_json::from_value::<toml::Value>(value).map_err(serde::de::Error::custom)?;
            Ok(Some(toml_value))
        }
        _ => Err(serde::de::Error::custom(
            "config_overrides must be a JSON object; null, scalars, and arrays are rejected",
        )),
    }
}

#[derive(Serialize)]
struct PluginsStartBody {
    plugin_id: String,
    instance_id: String,
    state: String,
}

async fn plugins_start_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let Some(arguments) = arguments else {
        return ToolOutcome::InvalidParams("plugins.start requires a `plugin_id` argument".into());
    };
    let args: PluginsStartArgs = match serde_json::from_value(JsonValue::Object(arguments)) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "plugins.start arguments do not match the input schema: {err}",
            ));
        }
    };
    if args.plugin_id.is_empty() {
        return ToolOutcome::InvalidParams("`plugin_id` must not be empty".into());
    }
    if args.instance_id.as_ref().is_some_and(String::is_empty) {
        return ToolOutcome::InvalidParams(
            "`instance_id`, when supplied, must not be empty".into(),
        );
    }

    let instance_id = args.instance_id.unwrap_or_else(|| args.plugin_id.clone());
    // Follow-up review H1 (mirroring REST): reject caller-
    // supplied `instance_id`s that aren't safe as FS segments
    // before they reach the KV / blob store (which use the id
    // directly in `<blobs_root>/<instance_id>/...`). Absolute
    // paths would replace the root under `Path::join`, `..`
    // escapes it, `\0` truncates on POSIX. Also rejected:
    // empty and leading-`.` (collides with blob-store `.tmp`
    // staging).
    if !crate::state::is_safe_instance_id(&instance_id) {
        return ToolOutcome::InvalidParams(format!(
            "`instance_id` `{instance_id}` is not a safe filesystem segment"
        ));
    }

    // H2 round-2 F1: serialize against a concurrent uninstall
    // for the same plugin_id. Without this lock, uninstall's
    // running-instances check could pass while start is mid-
    // supervisor-registration, and uninstall could then yank
    // the registry row + FS from under the fresh instance.
    let lifecycle_lock = engine.plugin_lifecycle_lock(&args.plugin_id);
    let _guard = lifecycle_lock.lock().await;
    let Some(installed) = engine.installed_plugins().get(&args.plugin_id) else {
        return ToolOutcome::ExecErr {
            message: format!("plugin `{}` is not installed", args.plugin_id),
            structured: Some(json!({
                "kind": "not_installed",
                "plugin_id": args.plugin_id,
            })),
            // Round-1 P2 on PR #132: host-state precondition,
            // not a plugin WIT error — keep the audit slot
            // NULL.
            domain_kind: None,
        };
    };

    // H11 round-2 F1: `start_installed_instance` pins the
    // load-time identity to the `installation_uuid` observed
    // under the lifecycle lock. Loader fails closed if the
    // registry row named by that uuid disappears between now
    // and the supervisor's re-read (concurrent uninstall
    // race) — never falls back to synthetic identity +
    // manifest-requested capabilities.
    let handle = match engine
        .start_installed_instance(
            installed.path.clone(),
            instance_id.clone(),
            args.config_overrides,
            std::sync::Arc::clone(&installed.installation_uuid),
        )
        .await
    {
        Ok(h) => h,
        Err(err) => {
            // Round-1 P2 on PR #132: raw errors from
            // `start_installed_instance` (loader failures,
            // wasmtime errors) can carry host filesystem paths
            // and internal type names. Log server-side; hand
            // the client a generic message.
            tracing::error!(
                target: "mcp.tool.plugins.start",
                plugin_id = %args.plugin_id,
                %instance_id,
                %err,
                "start failed",
            );
            return ToolOutcome::Internal("start failed; see server logs for details".into());
        }
    };
    if let Err(err) = handle.wait_for_running().await {
        tracing::error!(
            target: "mcp.tool.plugins.start",
            plugin_id = %args.plugin_id,
            %instance_id,
            %err,
            "instance failed to reach Running",
        );
        return ToolOutcome::Internal(
            "instance failed to reach Running; see server logs for details".into(),
        );
    }

    let body = PluginsStartBody {
        plugin_id: args.plugin_id,
        instance_id,
        state: format!("{:?}", handle.state()),
    };
    match super::resources::encode_body_capped(&body, "plugins.start", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Same taxonomy rule as `plugins.stop` /
            // `plugins.uninstall`: host lifecycle action, not
            // a plugin `execute-command` invocation. Keep
            // `execution_outcome` NULL.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── plugins.install ─────────────────────────────────────────────

fn plugins_install_schema() -> serde_json::Map<String, JsonValue> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source_dir"],
        "properties": {
            "source_dir": {
                "type": "string",
                "minLength": 1,
                "description": "Absolute path (daemon-local) to the staged plugin directory. Must contain a `manifest.toml` naming the canonical `plugin_id`; the tool recursively copies the whole directory into `<state_dir>/plugins/<plugin_id>/`.",
            }
        }
    });
    match schema {
        JsonValue::Object(map) => map,
        _ => unreachable!("json! macro built with object literal"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsInstallArgs {
    source_dir: String,
}

#[derive(Serialize)]
struct PluginsInstallBody {
    plugin_id: String,
    version: String,
    installed_path: String,
}

async fn plugins_install_call(
    engine: Engine,
    arguments: Option<serde_json::Map<String, JsonValue>>,
) -> ToolOutcome {
    let Some(arguments) = arguments else {
        return ToolOutcome::InvalidParams(
            "plugins.install requires a `source_dir` argument".into(),
        );
    };
    let args: PluginsInstallArgs = match serde_json::from_value(JsonValue::Object(arguments)) {
        Ok(a) => a,
        Err(err) => {
            return ToolOutcome::InvalidParams(format!(
                "plugins.install arguments do not match the input schema: {err}",
            ));
        }
    };
    if args.source_dir.is_empty() {
        return ToolOutcome::InvalidParams("`source_dir` must not be empty".into());
    }

    // REST wraps the sync install in `spawn_blocking` so a slow
    // disk doesn't stall the axum runtime — same reasoning
    // holds for MCP's rmcp task. The registry itself does the
    // FS + SQL work.
    let installed_registry = engine.installed_plugins();
    let source = std::path::PathBuf::from(args.source_dir);
    let join = tokio::task::spawn_blocking(move || installed_registry.install(&source)).await;

    let installed = match join {
        Ok(Ok(installed)) => installed,
        Ok(Err(crate::state::InstallError::SourceMissing(path))) => {
            return ToolOutcome::ExecErr {
                message: format!(
                    "source dir is missing or has no manifest.toml: {}",
                    path.display(),
                ),
                structured: Some(json!({
                    "kind": "source_missing",
                    "source_dir": path.display().to_string(),
                })),
                // Round-1 P2 lesson from PR #132: host-state
                // precondition, not a plugin WIT error — keep
                // the audit slot NULL.
                domain_kind: None,
            };
        }
        Ok(Err(crate::state::InstallError::AlreadyInstalled { plugin_id })) => {
            return ToolOutcome::ExecErr {
                message: format!("plugin `{plugin_id}` is already installed"),
                structured: Some(json!({
                    "kind": "already_installed",
                    "plugin_id": plugin_id,
                })),
                domain_kind: None,
            };
        }
        Ok(Err(crate::state::InstallError::BadManifest { path, reason })) => {
            // BadManifest.reason is authored by our own parser
            // over the operator's `manifest.toml`; it's safe to
            // surface. `path` may be absolute — hand back the
            // file-name only so we don't echo the operator's
            // full staging layout to a curious tool caller.
            let file = path.file_name().map_or_else(
                || "manifest.toml".into(),
                |f| f.to_string_lossy().into_owned(),
            );
            return ToolOutcome::ExecErr {
                message: format!("bad manifest in `{file}`: {reason}"),
                structured: Some(json!({
                    "kind": "bad_manifest",
                    "reason": reason,
                })),
                domain_kind: None,
            };
        }
        Ok(Err(crate::state::InstallError::NoPluginsRoot)) => {
            return ToolOutcome::ExecErr {
                message: "install requires a state-dir-backed engine".into(),
                structured: Some(json!({
                    "kind": "no_plugins_root",
                })),
                domain_kind: None,
            };
        }
        Ok(Err(err)) => {
            // Round-1 P2 lesson from PR #132: `InstallError::Io`
            // can carry absolute filesystem paths;
            // `InstallError::Persistence` can carry SQLite
            // diagnostics. Log server-side; hand the client a
            // generic message. Matches REST + Connect-RPC's
            // opaque 500 for the same conditions.
            tracing::error!(
                target: "mcp.tool.plugins.install",
                %err,
                "install failed",
            );
            return ToolOutcome::Internal("install failed; see server logs for details".into());
        }
        Err(join_err) => {
            tracing::error!(target: "mcp.tool.plugins.install", %join_err, "install task panicked");
            return ToolOutcome::Internal("install task panicked".into());
        }
    };

    let body = PluginsInstallBody {
        plugin_id: installed.plugin_id.to_string(),
        version: installed.version,
        installed_path: installed.path.display().to_string(),
    };
    match super::resources::encode_body_capped(&body, "plugins.install", MAX_TOOL_BODY_BYTES) {
        EncodedBody::Value(v) => ToolOutcome::Ok {
            value: v,
            // Same taxonomy rule as the other lifecycle tools:
            // host FS + SQL work, no plugin `execute-command`
            // invocation. Keep `execution_outcome` NULL.
            plugin_reached: false,
        },
        EncodedBody::TooLarge(reason) => ToolOutcome::TooLarge(reason),
        EncodedBody::SerializeFailed(reason) => ToolOutcome::Internal(reason),
    }
}

// ── Audit ───────────────────────────────────────────────────────

/// [`AuditEntry`] for [`AuditLog::record_intent`] — status /
/// decision fields are placeholders (`AuditLog::record_intent`
/// ignores them; the SQL INSERT stamps `status = 0`,
/// `decision = 'pending'`). Only `token_id`, `actor_kind`,
/// `method`, `path`, and `credential_fp` reach the row.
fn new_pending_audit_entry(token_id: &str, family: &str) -> AuditEntry {
    AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.to_string(),
        actor_kind: MCP_ACTOR_KIND.to_string(),
        method: "MCP".into(),
        path: format!("mcp.tool.{family}"),
        // These fields are ignored by `record_intent`.
        status: 0,
        decision: "pending".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
    }
}

/// [`AuditEntry`] for [`AuditLog::record_completed`] — used
/// on outcomes decided BEFORE any dispatch (unknown tool,
/// scope-denied). Populates status + decision from the
/// outcome; `execution_outcome` / `domain_error` stay `None`
/// because no tool body ran.
fn new_completed_audit_entry(token_id: &str, family: &str, outcome: &ToolOutcome) -> AuditEntry {
    AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.to_string(),
        actor_kind: MCP_ACTOR_KIND.to_string(),
        method: "MCP".into(),
        path: format!("mcp.tool.{family}"),
        status: outcome.status(),
        decision: outcome.decision().into(),
        required_scope: outcome.required_scope().map(str::to_string),
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
    }
}

#[cfg(test)]
mod message_cap_tests {
    use super::{MAX_PLUGIN_ERROR_MESSAGE_BYTES, cap_message};

    #[test]
    fn passes_through_short_messages_unchanged() {
        let short = "brief plugin error".to_string();
        assert_eq!(cap_message(short.clone()), short);
    }

    #[test]
    fn truncates_over_cap_ascii_message() {
        let big = "x".repeat(MAX_PLUGIN_ERROR_MESSAGE_BYTES + 100);
        let out = cap_message(big);
        assert!(
            out.len() <= MAX_PLUGIN_ERROR_MESSAGE_BYTES + 32,
            "capped output {} B must fit within cap + suffix; got {}",
            MAX_PLUGIN_ERROR_MESSAGE_BYTES,
            out.len(),
        );
        assert!(out.ends_with("[truncated by host]"));
    }

    #[test]
    fn truncation_respects_utf8_char_boundaries() {
        // Fill the message with 4-byte emojis so a naïve
        // byte truncation at exactly the cap would split a
        // scalar. `cap_message` walks back to the largest
        // safe boundary — the output is always valid UTF-8.
        let emoji = "😀";
        assert_eq!(emoji.len(), 4);
        let big: String = emoji.repeat((MAX_PLUGIN_ERROR_MESSAGE_BYTES / 4) + 100);
        assert!(big.len() > MAX_PLUGIN_ERROR_MESSAGE_BYTES);
        let out = cap_message(big);
        assert!(out.is_char_boundary(out.len() - "… [truncated by host]".len()));
        assert!(out.ends_with("[truncated by host]"));
    }
}

#[cfg(test)]
mod error_meta_tests {
    use super::{McpError, attach_audit_meta_to_error};
    use rmcp::model::ErrorCode;
    use serde_json::json;

    /// Round-4 F3 on PR #123: an `McpError` produced AFTER
    /// the intent row was written carries the audit
    /// correlation on its `data` field, so a client seeing a
    /// -32603 can still find the ledger row the tool wrote
    /// before it trapped.
    #[test]
    fn attaches_audit_correlation_when_data_is_absent() {
        let mut err = McpError::internal_error("plugin trapped after actuation", None);
        attach_audit_meta_to_error(&mut err, 42, "device.send_command");
        let data = err.data.expect("audit meta must land on data");
        assert_eq!(
            data["oxidhome.audit"]["intent_id"], 42,
            "intent id must reach the client",
        );
        assert_eq!(
            data["oxidhome.audit"]["path"],
            "mcp.tool.device.send_command",
        );
    }

    #[test]
    fn preserves_existing_object_data() {
        // A future outcome could set `data` via
        // `McpError::new(code, msg, Some(obj))` — the helper
        // must merge rather than clobber.
        let mut err = McpError::new(
            ErrorCode::INTERNAL_ERROR,
            "trapped",
            Some(json!({"trace_id": "abc"})),
        );
        attach_audit_meta_to_error(&mut err, 7, "device.send_command");
        let data = err.data.expect("data must remain");
        assert_eq!(data["trace_id"], "abc", "pre-existing keys must survive");
        assert_eq!(data["oxidhome.audit"]["intent_id"], 7);
    }

    #[test]
    fn wraps_non_object_data_under_previous_key() {
        let mut err = McpError::new(
            ErrorCode::INTERNAL_ERROR,
            "trapped",
            Some(json!("opaque string payload")),
        );
        attach_audit_meta_to_error(&mut err, 3, "device.send_command");
        let data = err.data.expect("data must remain");
        assert_eq!(data["previous"], "opaque string payload");
        assert_eq!(data["oxidhome.audit"]["intent_id"], 3);
    }
}
