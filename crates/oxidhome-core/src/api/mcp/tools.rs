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
use crate::api::server::{WireCommandResult, WireKeyValue, command_result_to_wire};
use crate::auth::Actor;
use crate::host_impl::plugin::oxidhome::plugin::devices::Command;
use crate::host_impl::plugin::oxidhome::plugin::types::KeyValue;
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
                        "value": {
                            "type": "object",
                            "required": ["t", "v"],
                            "additionalProperties": false,
                            "properties": {
                                "t": {
                                    "type": "string",
                                    "enum": ["Bool", "Int", "Float", "String", "Bytes", "Json"],
                                },
                                "v": {}
                            }
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

#[derive(Deserialize)]
struct DeviceSendCommandArgs {
    device_id: String,
    capability: String,
    action: String,
    #[serde(default)]
    args: Vec<WireKeyValue>,
}

/// Dispatch a concrete `tools/call` request. Mirrors
/// [`super::resources::read`] shape: acquire an audit-queue
/// permit up front, dispatch to the tool, then run the audit
/// write under the same permit.
pub(super) async fn call(
    engine: Engine,
    request: CallToolRequestParams,
    actor: &Actor,
) -> Result<CallToolResult, McpError> {
    // Round-6 F3 (PR #122) audit-queue bound covers tools
    // too — a disconnect-flooded caller whose rmcp handler
    // tasks outlive the response future can't pile up
    // unbounded `spawn_blocking(record_completed)` tasks
    // behind the shared `SQLite` mutex.
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
    let (family, outcome) = call_inner(engine.clone(), request, actor).await;

    let audit_log = engine.audit_log();
    let audit_entry = new_audit_entry(&token_id, family, &outcome);
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

/// Route a `tools/call` request to its tool implementation
/// after scope enforcement. Returns the audit-family slug
/// alongside the outcome so [`call`] can log without
/// re-parsing.
async fn call_inner(
    engine: Engine,
    request: CallToolRequestParams,
    actor: &Actor,
) -> (&'static str, ToolOutcome) {
    let name = request.name.as_ref();
    let (family, required) = match name {
        "device.send_command" => ("device.send_command", DEVICES_COMMAND),
        _ => {
            return (
                "unknown",
                ToolOutcome::UnknownTool(format!("no MCP tool named `{name}`")),
            );
        }
    };

    if require_scope(actor, required).is_err() {
        return (
            family,
            ToolOutcome::Denied {
                required: required.name(),
            },
        );
    }

    let outcome = match name {
        "device.send_command" => device_send_command_call(engine, request.arguments).await,
        // Unknown-tool falls out of the routing match above;
        // this arm exists so a future tool addition to the
        // routing table can't skip the scope check by
        // omission — the `unreachable!` fails a debug build,
        // and a release build gets an audit-visible internal
        // error instead of silently mis-routing.
        _ => ToolOutcome::Internal(format!("MCP tool `{name}` routed without a body impl")),
    };
    (family, outcome)
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
    ExecErr {
        message: String,
        structured: Option<JsonValue>,
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
        };
    };
    let Some(handle) = engine.instances().get(&owner) else {
        return ToolOutcome::ExecErr {
            message: format!("device `{}` not found or not running", args.device_id),
            structured: None,
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
        WireCommandResult::Err { error } => ToolOutcome::ExecErr {
            // The `wit_error_kind` function is what REST uses
            // to stamp the audit ledger's `domain_error`
            // column; reusing it here means the MCP surface
            // and the REST surface classify plugin errors
            // identically.
            message: format!(
                "device.send_command failed: {} — {}",
                wit_error_kind_of_wire(error),
                message_of_wire_error(error),
            ),
            structured: Some(structured),
        },
    }
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

fn new_audit_entry(token_id: &str, family: &str, outcome: &ToolOutcome) -> AuditEntry {
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
