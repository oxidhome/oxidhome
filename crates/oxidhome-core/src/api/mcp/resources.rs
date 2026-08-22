//! MCP `resources/*` implementation for `OxidHome`.
//!
//! Ships the read-only resources described in Phase 14.2 of
//! [`.claude/docs/10_mcp.md`](../../../../../.claude/docs/10_mcp.md).
//! Every URI here mirrors an existing CLI / REST read — the MCP
//! layer only translates that surface into the SDK's [`Resource`]
//! and [`ResourceContents`] shapes, and records one audit-log row
//! per read.
//!
//! # Layout
//!
//! - [`list_resources`] — the fixed-URI catalog (`oxidhome://devices`,
//!   `oxidhome://plugins`).
//! - [`list_resource_templates`] — parametric families
//!   (`oxidhome://devices/{device_id}`, `oxidhome://plugins/{plugin_id}`).
//! - [`read`] — dispatch on a concrete URI. Returns
//!   [`ErrorData::resource_not_found`] for anything we don't
//!   recognize; the SDK maps it to the spec `-32002`.
//!
//! # Audit
//!
//! Every read (success or failure) records one
//! [`AuditLog::record_completed`] row with
//! `path = "mcp.resource.<name>"`. The `<name>` is the resource
//! family (`devices`, `devices.detail`, `plugins`,
//! `plugins.detail`), NOT the concrete URI — a device id can
//! appear thousands of times in log-tail traffic and a
//! per-URI path would make the audit index churn without
//! adding forensic value (the resolved URI is already in the
//! `_meta` payload the SDK carries on the response).

use rmcp::model::{
    ErrorCode, ErrorData as McpError, ReadResourceResult, Resource, ResourceContents,
    ResourceTemplate,
};
use serde::Serialize;

use crate::Engine;
use crate::api::scopes::{DEVICES_LIST, PLUGINS_LIST, Scope, require_scope};
use crate::auth::Actor;
use crate::state::audit_log::AuditEntry;

/// Sentinel `token_id` recorded on the audit row when the
/// bearer middleware is somehow missing (only a mis-wired
/// mount can hit this — production always sits behind
/// `require_token`). Kept as a distinct constant so the
/// audit row identifies the miswire rather than pretending
/// a real token id was resolved.
pub(super) const UNAUTHENTICATED_TOKEN_ID: &str = "anonymous";

/// JSON-RPC error code for "the token doesn't hold the scope
/// this resource requires." MCP has no canonical
/// permission-denied code, so we pick from the
/// `-32000..=-32099` implementation-defined server-error
/// range (matches how OAuth's `403 Forbidden` maps into
/// JSON-RPC error surfaces elsewhere). The response message
/// deliberately does NOT name the required scope — the
/// audit row records that for forensic use — so a probing
/// caller can't enumerate the scope map by trial-and-error
/// (mirrors [`crate::api::scopes::ScopeDenied`]'s
/// deliberate silence on the response body).
pub(super) const SCOPE_DENIED_CODE: ErrorCode = ErrorCode(-32001);

/// [`AuditEntry::actor_kind`] value we stamp on every MCP row.
/// Matches [`crate::auth::ActorKind::Mcp`]'s `as_str()` — kept
/// as a literal here to avoid a cross-module dep just for the
/// string.
pub(super) const MCP_ACTOR_KIND: &str = "mcp";

/// Scheme every `OxidHome` MCP resource URI starts with.
const SCHEME: &str = "oxidhome://";

/// Catalog of fixed-URI resources the server advertises.
/// Parametric families (per-device, per-plugin) are surfaced
/// via [`list_resource_templates`] instead.
pub(super) fn list_resources() -> Vec<Resource> {
    vec![
        Resource::new("oxidhome://devices", "devices")
            .with_title("All devices")
            .with_description(
                "JSON list of every device registered with the host — id, owning \
                 instance, human-readable name. Mirrors `oxidhome device list`.",
            )
            .with_mime_type("application/json"),
        Resource::new("oxidhome://plugins", "plugins")
            .with_title("Installed plugins")
            .with_description(
                "JSON list of every plugin known to the host: installed manifests \
                 plus running-but-not-installed instances, each with its live \
                 instance count. Mirrors `oxidhome plugin list`.",
            )
            .with_mime_type("application/json"),
    ]
}

/// Parametric resource families the server advertises.
/// Clients render templates for URI construction; concrete
/// URIs go through [`read`] like any other read.
pub(super) fn list_resource_templates() -> Vec<ResourceTemplate> {
    vec![
        ResourceTemplate::new("oxidhome://devices/{device_id}", "device.detail")
            .with_title("One device")
            .with_description(
                "JSON detail for a single device — its full registration record \
                 (name, manufacturer, model, capabilities). Mirrors \
                 `oxidhome device show <device-id>`.",
            )
            .with_mime_type("application/json"),
        ResourceTemplate::new("oxidhome://plugins/{plugin_id}", "plugin.detail")
            .with_title("One plugin")
            .with_description(
                "JSON detail for a single installed plugin — version, manifest \
                 digest, singleton flag, plus live instances. Mirrors \
                 `oxidhome plugin show <plugin-id>`.",
            )
            .with_mime_type("application/json"),
    ]
}

/// Dispatch a concrete resource URI. Records one audit row
/// per read regardless of outcome — **fail-closed**: if the
/// audit ledger write fails, the read is refused with an
/// internal error rather than served without an audit trail
/// (round-1 F2 on PR #120, matching the same rule the REST
/// middleware in [`crate::api::auth::require_token`] applies).
///
/// `actor` carries the bearer's resolved [`Actor::id`] AND
/// [`Actor::scopes`]. Round-2 F1: enforce the per-resource
/// scope up front (mirrors the REST endpoints' `require_scope`
/// gates), so a token holding e.g. `logs:read` can't enumerate
/// devices just by hitting the MCP mount.
pub(super) async fn read(
    engine: Engine,
    uri: &str,
    actor: &Actor,
) -> Result<ReadResourceResult, McpError> {
    let token_id = actor.id().to_string();
    let (family, outcome) = read_inner(&engine, uri, actor);
    // Audit-log every read. The audit call is synchronous and
    // takes the shared `Db` mutex — spawn_blocking so it can't
    // park the tokio worker under a slow disk. Fail-closed:
    // both the join error (task panicked) and the audit error
    // (ledger unreachable, disk full, read-only DB, …) refuse
    // the read.
    let audit_log = engine.audit_log();
    let audit_entry = new_audit_entry(&token_id, family, &outcome);
    let audit_result =
        tokio::task::spawn_blocking(move || audit_log.record_completed(&audit_entry)).await;
    match audit_result {
        Ok(Ok(_row_id)) => outcome.into_result(uri),
        Ok(Err(err)) => {
            tracing::error!(%err, uri, "MCP resource audit write failed — refusing read");
            Err(McpError::internal_error(
                "audit-log write failed; MCP resource read refused",
                None,
            ))
        }
        Err(join_err) => {
            tracing::error!(%join_err, uri, "MCP resource audit task panicked — refusing read");
            Err(McpError::internal_error(
                "audit-log write task panicked; MCP resource read refused",
                None,
            ))
        }
    }
}

/// Outcome shape for a single resource-read attempt. Kept as
/// a separate enum so the audit path can look at the shape
/// (status, decision, required scope) without re-parsing an
/// SDK-shaped error.
enum ReadOutcome {
    Ok(String),
    NotFound(String),
    /// Bearer resolved, but its scope list does not include
    /// [`Self::Denied::required`]. Carried through so the
    /// audit row can name the scope that was missing.
    Denied {
        required: &'static str,
    },
    Internal(String),
}

impl ReadOutcome {
    fn into_result(self, uri: &str) -> Result<ReadResourceResult, McpError> {
        match self {
            Self::Ok(body) => Ok(ReadResourceResult::new(vec![
                ResourceContents::text(body, uri).with_mime_type("application/json"),
            ])),
            Self::NotFound(reason) => Err(McpError::resource_not_found(reason, None)),
            Self::Denied { required: _ } => Err(McpError::new(
                SCOPE_DENIED_CODE,
                // Deliberately omits the scope name; see
                // `SCOPE_DENIED_CODE`'s doc.
                "scope denied for MCP resource",
                None,
            )),
            Self::Internal(reason) => Err(McpError::internal_error(reason, None)),
        }
    }

    fn status(&self) -> u16 {
        match self {
            Self::Ok(_) => 200,
            Self::NotFound(_) => 404,
            Self::Denied { .. } => 403,
            Self::Internal(_) => 500,
        }
    }

    fn decision(&self) -> &'static str {
        match self {
            Self::Ok(_) => "allow",
            Self::NotFound(_) | Self::Denied { .. } => "deny",
            Self::Internal(_) => "error",
        }
    }

    /// Scope name to record on the audit row's
    /// `required_scope` column. `Some` only for
    /// [`Self::Denied`] — every other outcome leaves the
    /// column NULL (matches how the REST middleware only
    /// populates the field on scope-deny 403s).
    fn required_scope(&self) -> Option<&'static str> {
        match self {
            Self::Denied { required } => Some(required),
            _ => None,
        }
    }
}

/// Route a URI to its family, check the family's required
/// scope against the actor, and build the body if allowed.
/// Returns the audit-family slug alongside the outcome so
/// [`read`] can log without re-parsing. Sync today — kept as
/// a plain fn so dispatch is trivially inlineable; the outer
/// [`read`] is async only because the audit-log write goes
/// through `spawn_blocking`.
fn read_inner(engine: &Engine, uri: &str, actor: &Actor) -> (&'static str, ReadOutcome) {
    let Some(rest) = uri.strip_prefix(SCHEME) else {
        return (
            "unknown",
            ReadOutcome::NotFound(format!("URI {uri} does not use the oxidhome:// scheme")),
        );
    };
    // Path split: `authority[/tail]`. Authority is the family
    // (`devices`, `plugins`); tail (if any) is the id.
    let (family_seg, id_seg) = match rest.split_once('/') {
        Some((head, tail)) => (head, Some(tail)),
        None => (rest, None),
    };

    // Match resolves (family slug, required scope, body
    // builder). Scope check happens uniformly below so
    // every routed URI wears the same enforcement — no
    // way to accidentally add a family that skips it.
    let (family, required, build): (&'static str, Scope, Box<dyn FnOnce() -> ReadOutcome + '_>) =
        match (family_seg, id_seg) {
            ("devices", None) => ("devices", DEVICES_LIST, Box::new(|| devices_list(engine))),
            ("devices", Some(id)) if !id.is_empty() && !id.contains('/') => (
                "devices.detail",
                // Device-detail carries registration
                // metadata (owner, name, manufacturer,
                // model, capabilities) — the same shape
                // `oxidhome://devices` returns per row,
                // just filtered to one id. It shares the
                // `devices:list` scope with the collection
                // read (round-2 F1 on PR #120 originally
                // gated this under `devices:read`, which is
                // reserved for the H9 device-state
                // projection — `GET /api/v1/devices/{id}/state`
                // and `state/changes`. Handing metadata
                // access to `devices:read` tokens while
                // withholding it from `devices:list` tokens
                // was the opposite of the intended
                // boundary — round-3 F1 fix).
                DEVICES_LIST,
                Box::new(|| devices_detail(engine, id)),
            ),
            ("plugins", None) => ("plugins", PLUGINS_LIST, Box::new(|| plugins_list(engine))),
            ("plugins", Some(id)) if !id.is_empty() && !id.contains('/') => (
                "plugins.detail",
                PLUGINS_LIST,
                Box::new(|| plugins_detail(engine, id)),
            ),
            _ => {
                return (
                    "unknown",
                    ReadOutcome::NotFound(format!("no MCP resource is registered for {uri}")),
                );
            }
        };

    if require_scope(actor, required).is_err() {
        return (
            family,
            ReadOutcome::Denied {
                required: required.name(),
            },
        );
    }

    (family, build())
}

fn new_audit_entry(token_id: &str, family: &str, outcome: &ReadOutcome) -> AuditEntry {
    AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.to_string(),
        actor_kind: MCP_ACTOR_KIND.to_string(),
        method: "MCP".into(),
        path: format!("mcp.resource.{family}"),
        status: outcome.status(),
        decision: outcome.decision().into(),
        required_scope: outcome.required_scope().map(str::to_string),
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
    }
}

// ── Devices ───────────────────────────────────────────────────────

/// Wire shape for [`devices_list`] — matches the REST
/// `GET /api/v1/devices` `DeviceSummary` so any tooling that
/// already parses that JSON works against the MCP resource
/// too. Held here (not shared with `api::server`) so the two
/// surfaces can evolve independently without a wire-shape
/// cross-dependency; a diff-check test would catch drift if
/// we care later.
#[derive(Serialize)]
struct DeviceListEntry {
    device_id: String,
    owner_instance: String,
    name: String,
}

#[derive(Serialize)]
struct DeviceListBody {
    devices: Vec<DeviceListEntry>,
}

fn devices_list(engine: &Engine) -> ReadOutcome {
    let devices: Vec<DeviceListEntry> = engine
        .devices()
        .list()
        .into_iter()
        .map(|meta| DeviceListEntry {
            device_id: meta.id.clone(),
            owner_instance: meta.owner_instance.clone(),
            name: meta.info.name.clone(),
        })
        .collect();
    encode(&DeviceListBody { devices }, "devices list")
}

/// Wire shape for [`devices_detail`]. Carries the full
/// registration record (name, manufacturer, model,
/// capabilities) — the REST surface doesn't expose these
/// today, but they've been on `DeviceInfo` since Phase 3 and
/// the MCP client needs them for spec-matching + UI hints.
#[derive(Serialize)]
struct DeviceDetail {
    device_id: String,
    owner_instance: String,
    name: String,
    manufacturer: Option<String>,
    model: Option<String>,
    capabilities: Vec<String>,
}

fn devices_detail(engine: &Engine, id: &str) -> ReadOutcome {
    let Some(meta) = engine.devices().get_any(&id.to_string()) else {
        return ReadOutcome::NotFound(format!("device {id} is not registered with the host"));
    };
    let info = &meta.info;
    let detail = DeviceDetail {
        device_id: meta.id.clone(),
        owner_instance: meta.owner_instance.clone(),
        name: info.name.clone(),
        manufacturer: info.manufacturer.clone(),
        model: info.model.clone(),
        capabilities: info
            .capabilities
            .iter()
            .map(crate::runtime::capability_name)
            .collect(),
    };
    encode(&detail, "device detail")
}

// ── Plugins ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct PluginListEntry {
    plugin_id: String,
    installed: bool,
    version: Option<String>,
    instance_count: u32,
}

#[derive(Serialize)]
struct PluginListBody {
    plugins: Vec<PluginListEntry>,
}

fn plugins_list(engine: &Engine) -> ReadOutcome {
    let mut by_plugin: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for handle in engine.instances().list() {
        *by_plugin.entry(handle.plugin_id().to_string()).or_default() += 1;
    }
    let mut plugins: Vec<PluginListEntry> = Vec::new();
    for installed in engine.installed_plugins().list() {
        let id = installed.plugin_id.to_string();
        let count = by_plugin.remove(&id).unwrap_or(0);
        plugins.push(PluginListEntry {
            plugin_id: id,
            installed: true,
            version: Some(installed.version),
            instance_count: count,
        });
    }
    for (plugin_id, instance_count) in by_plugin {
        plugins.push(PluginListEntry {
            plugin_id,
            installed: false,
            version: None,
            instance_count,
        });
    }
    plugins.sort_by(|a, b| a.plugin_id.cmp(&b.plugin_id));
    encode(&PluginListBody { plugins }, "plugins list")
}

#[derive(Serialize)]
struct PluginInstanceDetail {
    instance_id: String,
    state: String,
}

#[derive(Serialize)]
struct PluginDetail {
    plugin_id: String,
    installed: bool,
    version: Option<String>,
    singleton: Option<bool>,
    /// SHA-256 hex of the installed plugin's on-disk contents
    /// (manifest + wasm + assets). `None` when the plugin
    /// is running-but-not-installed (dev-time argv-driven
    /// start path — no `plugin_installation` row exists).
    /// Round-1 F3 on PR #120: the template's documented
    /// contract promised this field; the pre-fix shape
    /// silently dropped it.
    content_digest: Option<String>,
    /// C1b host-minted per-install UUID (`inst-<32 hex>`).
    /// Uninstall + reinstall of the same `plugin_id`
    /// produces a different UUID. `None` alongside
    /// `content_digest` on the not-installed path.
    installation_uuid: Option<String>,
    instances: Vec<PluginInstanceDetail>,
}

fn plugins_detail(engine: &Engine, id: &str) -> ReadOutcome {
    let installed = engine.installed_plugins().get(id);
    let mut instances = Vec::new();
    for handle in engine.instances().list() {
        if handle.plugin_id() == id {
            instances.push(PluginInstanceDetail {
                instance_id: handle.instance_id().to_string(),
                state: format!("{:?}", handle.state()),
            });
        }
    }
    if installed.is_none() && instances.is_empty() {
        return ReadOutcome::NotFound(format!(
            "plugin {id} is not installed and has no running instances",
        ));
    }
    let detail = PluginDetail {
        plugin_id: id.into(),
        installed: installed.is_some(),
        version: installed.as_ref().map(|p| p.version.clone()),
        singleton: installed.as_ref().map(|p| p.singleton),
        content_digest: installed.as_ref().map(|p| p.content_digest.to_string()),
        installation_uuid: installed.as_ref().map(|p| p.installation_uuid.to_string()),
        instances,
    };
    encode(&detail, "plugin detail")
}

// ── Helpers ───────────────────────────────────────────────────────

fn encode<T: Serialize>(value: &T, what: &'static str) -> ReadOutcome {
    match serde_json::to_string(value) {
        Ok(body) => ReadOutcome::Ok(body),
        Err(err) => {
            tracing::error!(%err, what, "MCP resource serialization failed");
            ReadOutcome::Internal(format!("failed to serialize {what}"))
        }
    }
}
