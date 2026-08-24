//! MCP `tools/*` implementation for `OxidHome`.
//!
//! Phase 14.3 opens the tool surface. Tools are the write-
//! side counterpart to [`super::resources`]: an LLM agent
//! calls a tool to *act* on the household (dispatch a
//! device command, mutate config, install a plugin, …)
//! rather than to read state. See
//! [`.claude/docs/10_mcp.md`](../../../../../.claude/docs/10_mcp.md)
//! `§ Tools` for the full catalogue plan; this module ships
//! the first entry: `device.send_command`.
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
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::Engine;
use crate::api::auth::wit_error_kind;
use crate::api::scopes::{DEVICES_COMMAND, require_scope};
use crate::api::server::{WireCommandResult, command_result_to_wire};
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::types::KeyValue;
use crate::host_impl::plugin::oxidhome::plugin::types::Value;
use crate::state::audit_log::AuditEntry;

use super::resources::{
    AUDIT_QUEUE_MAX, AUDIT_QUEUE_SEMAPHORE, MCP_ACTOR_KIND, RESOURCE_BUSY_CODE, SCOPE_DENIED_CODE,
};

/// Publicly-visible catalogue of tools this handler exposes.
/// Rmcp calls [`list_tools`] out of `tools/list`; the tool
/// definitions carry a JSON Schema so clients can validate
/// input before hitting the wire (and so an LLM planner sees
/// the argument shape without a separate probe).
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
        let (execution_outcome, domain_error): (Option<&'static str>, Option<String>) =
            match outcome {
                ToolOutcome::Ok(_) => (Some("success"), None),
                // Only `domain_kind = Some(_)` means the
                // plugin was reached and reported an `Err`.
                // `domain_kind = None` is the "reached tool
                // body, refused before plugin" shape (unknown
                // device); it falls into the wildcard below
                // and stays as (None, None) per the contract.
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
    Ok(JsonValue),
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
            Self::Ok(value) => Ok(CallToolResult::structured(value)),
            Self::ExecErr {
                message,
                structured,
                domain_kind: _,
            } => Ok(match structured {
                Some(v) => CallToolResult::structured_error(v),
                None => CallToolResult::error(vec![ContentBlock::text(message)]),
            }),
            Self::InvalidParams(reason) => Err(McpError::invalid_params(reason, None)),
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
            Self::Ok(_) | Self::ExecErr { .. } => 200,
            Self::UnknownTool(_) => 404,
            Self::InvalidParams(_) => 400,
            Self::Denied { .. } => 403,
            Self::Internal(_) => 500,
        }
    }

    fn decision(&self) -> &'static str {
        match self {
            Self::Ok(_) | Self::ExecErr { .. } => "allow",
            Self::UnknownTool(_) | Self::Denied { .. } | Self::InvalidParams(_) => "deny",
            Self::Internal(_) => "error",
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
        WireCommandResult::Ok | WireCommandResult::OkWithState { .. } => {
            ToolOutcome::Ok(structured)
        }
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
