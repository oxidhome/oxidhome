//! MCP `prompts/*` implementation for `OxidHome`.
//!
//! Phase 14.6. Prompts are hand-authored templates that guide
//! an LLM client through common household tasks by composing
//! the resource + tool surface `super::resources` and
//! `super::tools` expose. They are NOT text-completion endpoints
//! — the server does not run inference. Each `prompts/get`
//! returns a `PromptMessage` sequence the client fills into its
//! own model turn.
//!
//! # Catalogue
//!
//! - `summarize_today` — walks the client through fetching
//!   today's events + logs and producing a plain-language
//!   summary. Gated on `events:read` + `logs:read`.
//! - `draft_automation` — walks the client through drafting an
//!   automation rule given a trigger + action. Gated on
//!   `devices:list` (both the collection `oxidhome://devices`
//!   and the per-id `oxidhome://devices/{id}` share this
//!   scope) so the draft can reference real device ids +
//!   capability names.
//! - `explain_recent_errors` — walks the client through
//!   fetching recent error-level logs and explaining what went
//!   wrong. Gated on `logs:read` — event rows carry state
//!   transitions, not command failures (those live in the audit
//!   ledger, which the MCP surface does not yet expose), so
//!   this prompt sticks to log evidence.
//!
//! # Scope gating
//!
//! `prompts/list` is public — every session sees the full
//! catalogue regardless of scope. `prompts/get` enforces the
//! per-prompt required scopes and lands scope failures as
//! `ScopeDenied` (`-32001`), matching the resource + tool
//! surface's shape. The rationale: a prompt template is not
//! itself sensitive (it's a documented pattern for using the
//! server), but embedding it inside a session where the caller
//! *cannot* execute the referenced resources/tools would give
//! them a template they can only inspect. Refusing at
//! `get` time keeps the surface consistent with tools/resources
//! and avoids handing an agent a plan it can't execute.

use rmcp::model::{
    ErrorData as McpError, GetPromptRequestParams, GetPromptResult, Prompt, PromptArgument,
    PromptMessage, Role,
};

use crate::api::scopes::{DEVICES_LIST, EVENTS_READ, LOGS_READ, Scope, require_scope};
use crate::auth::Actor;

use super::resources::SCOPE_DENIED_CODE;

/// Publicly-visible catalogue of prompts this handler exposes.
/// Every MCP session sees the full list regardless of scope —
/// see the module-level comment on why `get` is where scope is
/// enforced.
pub(super) fn list_prompts() -> Vec<Prompt> {
    vec![
        Prompt::new(
            "summarize_today",
            Some(
                "Produce a plain-language summary of today's household activity — device state \
                 transitions, notable events, and any logged warnings or errors. Composes \
                 `oxidhome://events` + `oxidhome://logs`.",
            ),
            None,
        )
        .with_title("Summarize today's household activity"),
        Prompt::new(
            "draft_automation",
            Some(
                "Draft a household automation rule given a plain-language `trigger` and \
                 `action`. Uses `oxidhome://devices` + `oxidhome://devices/{id}` to see what \
                 devices + capabilities actually exist, so the draft references real device \
                 ids and real capability names. Action verbs (e.g. `toggle`, `on`, `set`) are \
                 plugin-defined and NOT enumerable from the host — the draft must either use \
                 a well-known capability convention or defer the exact verb to the operator.",
            ),
            Some(vec![
                PromptArgument::new("trigger")
                    .with_title("Trigger")
                    .with_description(
                        "Plain-language description of what should trigger the automation \
                         (e.g. `when the front door unlocks after sunset`).",
                    )
                    .with_required(true),
                PromptArgument::new("action")
                    .with_title("Action")
                    .with_description(
                        "Plain-language description of what should happen (e.g. `turn on the \
                         hallway lights and start the porch camera`).",
                    )
                    .with_required(true),
            ]),
        )
        .with_title("Draft a household automation"),
        Prompt::new(
            "explain_recent_errors",
            Some(
                "Fetch recent error-level logs and produce a plain-language explanation of \
                 what went wrong and which components / plugins are involved. Composes \
                 `oxidhome://logs?level=Error`. Event rows carry state transitions, not \
                 command failures, so this prompt sticks to log evidence — command outcomes \
                 live in the audit ledger, which the MCP surface does not yet expose.",
            ),
            None,
        )
        .with_title("Explain recent errors"),
    ]
}

/// `prompts/get` — validate the requested name, check scopes,
/// build the templated `PromptMessage` sequence. Unknown
/// prompt names + missing / empty required arguments both
/// map to `-32602` (`INVALID_PARAMS`) — `prompts/get` itself
/// is a supported method, so `method_not_found` would be the
/// wrong shape; the *arguments* (specifically `name`) were
/// what didn't validate. Scope failures map to `-32001`
/// mirroring the tool + resource surfaces.
/// Map a caller-supplied prompt name to the routing table's
/// canonical static string, or `"unknown"` when the name isn't
/// registered. Bounds the `mcp_name` tracing label cardinality
/// on `prompts/get`: clients can send arbitrary strings and
/// echoing them would blow up a dashboard label index.
///
/// Kept in sync with the routing `match` in [`get`] below;
/// adding a prompt means adding an arm here.
///
/// Round-2 P1 on PR #144.
#[must_use]
pub(super) fn canonical_prompt_name(name: &str) -> &'static str {
    match name {
        "summarize_today" => "summarize_today",
        "draft_automation" => "draft_automation",
        "explain_recent_errors" => "explain_recent_errors",
        _ => "unknown",
    }
}

pub(super) fn get(
    request: &GetPromptRequestParams,
    actor: &Actor,
) -> Result<GetPromptResult, McpError> {
    let name = request.name.as_str();
    let (required_scopes, description, message_text) = match name {
        "summarize_today" => (
            &[EVENTS_READ, LOGS_READ][..],
            "Summarize today's household activity.",
            summarize_today_message(),
        ),
        "draft_automation" => {
            let (trigger, action) = draft_automation_args(request.arguments.as_ref())?;
            (
                // Round-2 P1 on PR #135: only `devices:list`
                // is needed. Both `oxidhome://devices` (the
                // collection) and `oxidhome://devices/{id}`
                // (per-device detail — same registration
                // metadata + capability names, filtered to
                // one id) share this single scope by design
                // (see resources.rs — round-2 F1 on PR #120
                // deliberately unified them). The previous
                // round-1 fix over-required `plugins:list` +
                // `devices:read` on top of this, which
                // rejected correctly-scoped least-privilege
                // tokens.
                &[DEVICES_LIST][..],
                "Draft an automation rule from a trigger and action.",
                draft_automation_message(&trigger, &action),
            )
        }
        "explain_recent_errors" => (
            // Round-1 P1 on PR #135: dropped `events:read` —
            // event rows are state transitions and don't carry
            // command failures. This prompt sticks to log
            // evidence; command-outcome failures would need the
            // audit ledger, which the MCP surface doesn't yet
            // expose.
            &[LOGS_READ][..],
            "Explain recent errors from logs.",
            explain_recent_errors_message(),
        ),
        _ => {
            return Err(McpError::invalid_params(
                format!("unknown prompt `{name}`"),
                None,
            ));
        }
    };

    if let Some(scope) = first_missing_scope(actor, required_scopes) {
        return Err(McpError::new(
            SCOPE_DENIED_CODE,
            format!("scope `{}` required for prompt `{name}`", scope.name()),
            None,
        ));
    }

    let mut result = GetPromptResult::new(vec![PromptMessage::new_text(Role::User, message_text)]);
    result.description = Some(description.into());
    Ok(result)
}

fn first_missing_scope(actor: &Actor, required: &[Scope]) -> Option<Scope> {
    for scope in required {
        if require_scope(actor, *scope).is_err() {
            return Some(*scope);
        }
    }
    None
}

fn draft_automation_args(
    arguments: Option<&rmcp::model::JsonObject>,
) -> Result<(String, String), McpError> {
    let Some(args) = arguments else {
        return Err(McpError::invalid_params(
            "draft_automation requires `trigger` and `action` arguments".to_string(),
            None,
        ));
    };
    let trigger = required_string_arg(args, "trigger")?;
    let action = required_string_arg(args, "action")?;
    Ok((trigger, action))
}

fn required_string_arg(args: &rmcp::model::JsonObject, key: &str) -> Result<String, McpError> {
    match args.get(key) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(serde_json::Value::String(_)) => Err(McpError::invalid_params(
            format!("prompt argument `{key}` must not be empty"),
            None,
        )),
        Some(_) => Err(McpError::invalid_params(
            format!("prompt argument `{key}` must be a non-empty string"),
            None,
        )),
        None => Err(McpError::invalid_params(
            format!("prompt argument `{key}` is required"),
            None,
        )),
    }
}

fn summarize_today_message() -> String {
    "You are helping the household operator understand what happened today. Use the OxidHome \
     MCP server's `oxidhome://events?since=24h` resource to fetch the last 24 hours of \
     historical events, and `oxidhome://logs?since=24h&level=Info` to fetch the same window of \
     logs. Then produce a plain-language summary organised as:\n\
     \n\
     1. Notable device state changes (lights, switches, locks, sensors).\n\
     2. Automation activity (scheduled jobs, custom rules that fired).\n\
     3. Anything unusual worth an operator's attention — warnings, errors, or a plugin that \
        went quiet.\n\
     \n\
     Keep it short (under 300 words). If nothing notable happened, say so."
        .into()
}

fn draft_automation_message(trigger: &str, action: &str) -> String {
    format!(
        "You are helping the household operator draft an automation rule. Their trigger is:\n\
         \n\
         > {trigger}\n\
         \n\
         Their action is:\n\
         \n\
         > {action}\n\
         \n\
         First, read `oxidhome://devices` to enumerate the household's devices, then read \
         `oxidhome://devices/{{device_id}}` on any device you plan to reference. The response \
         gives you the real `device_id` and the `capabilities: []` list — an array of \
         capability *names* the device exposes. The host's built-in capability names are: \
         `switch`, `dimmer`, `color-light`, `sensor`, `button`, `video-stream`, \
         `audio-stream`. Anything else appears in the list as `extension(<name>)` — that \
         literal wrapped form is what you must pass as the `capability` argument (a plugin \
         that declares a custom `lock` capability shows up as `extension(lock)`, NOT bare \
         `lock`). Ground the draft in the exact strings the resource returned — never invent \
         a `device_id` or a capability name that isn't in the list.\n\
         \n\
         IMPORTANT — action verbs are NOT enumerable from the host: `device.send_command` \
         takes a plugin-defined `action` string alongside `device_id` and `capability`, and \
         the host does not publish a catalogue of valid actions per capability. Use a \
         well-known convention where one clearly applies (e.g. `switch` → `on` / `off` / \
         `toggle`; `dimmer` → `set` with a `level` arg; `color-light` → `set-color`) and mark \
         it as a convention that the operator should confirm; when no obvious convention \
         fits (any `extension(<name>)` capability, or a built-in used in a non-standard way), \
         defer the exact verb to the operator rather than guess.\n\
         \n\
         Then produce a draft automation with:\n\
         \n\
         1. A short human-readable summary of what it does.\n\
         2. The trigger condition, phrased against a specific device id + capability.\n\
         3. The action(s), phrased as a `device.send_command` invocation with the real \
            `device_id` and `capability`, plus an action verb (call out whether the verb is \
            from a well-known convention or needs operator confirmation).\n\
         4. Any preconditions or safety notes the operator should know before enabling it (e.g. \
            `devices:command` scope, locks / alarms flagged destructive).\n\
         \n\
         If a needed device or capability isn't in the fleet, say so and stop — do not draft \
         against one that isn't there."
    )
}

fn explain_recent_errors_message() -> String {
    "You are helping the household operator understand what recently went wrong. Fetch \
     `oxidhome://logs?since=24h&level=Error` to see the last 24 hours of error-level logs. \
     Note: only logs are consulted here — event rows carry state transitions, not command \
     outcomes, so a plugin's `execute-command` that returned `Err` is NOT recoverable from the \
     event history; it lives in the audit ledger, which this MCP server does not yet expose. \
     Group the findings by component (host, specific plugin id, specific device) and, for each \
     group, produce:\n\
     \n\
     1. A short plain-language description of what went wrong.\n\
     2. The best evidence you have (log target + message).\n\
     3. A suggested next step — a follow-up log query, a config check, a plugin restart, or \
        `no action needed if transient`.\n\
     \n\
     Be honest about uncertainty. If a log line names an internal component the operator can't \
     act on, say so. If there are no errors in the window, say so."
        .into()
}
