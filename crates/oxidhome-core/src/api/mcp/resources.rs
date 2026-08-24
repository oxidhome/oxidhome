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
//! - [`list_resources`] — the fixed-URI catalog
//!   (`oxidhome://devices`, `oxidhome://plugins`,
//!   `oxidhome://events`, `oxidhome://logs`,
//!   `oxidhome://status`).
//! - [`list_resource_templates`] — parametric families
//!   (`oxidhome://devices/{device_id}`,
//!   `oxidhome://plugins/{plugin_id}`,
//!   `oxidhome://blobs/{instance_id}/{name}`).
//! - [`read`] — dispatch on a concrete URI. Returns
//!   [`ErrorData::resource_not_found`] for anything we don't
//!   recognize; the SDK maps it to the spec `-32002`.
//! - Query-string filters (`?since=1h&device=…&topic=…`) on
//!   `oxidhome://events` and `oxidhome://logs` follow the
//!   stable contract in `.claude/docs/10_mcp.md` — short
//!   names (`since`, `until`, `device`, `plugin`, `instance`,
//!   `level`, …) and relative durations (`10s`, `5m`, `2h`,
//!   `1d`), not REST's absolute `_ms` epochs. Unknown keys
//!   are rejected with `INVALID_PARAMS`.
//!
//! # Audit
//!
//! Every read (success or failure) records one
//! [`AuditLog::record_completed`] row with
//! `path = "mcp.resource.<name>"`. The `<name>` is the resource
//! family (`devices`, `devices.detail`, `plugins`,
//! `plugins.detail`, `events`, `logs`), NOT the concrete URI —
//! a device id can appear thousands of times in log-tail
//! traffic and a per-URI path would make the audit index churn
//! without adding forensic value (the resolved URI is already
//! in the `_meta` payload the SDK carries on the response).

use std::collections::HashMap;

use rmcp::model::{
    ErrorCode, ErrorData as McpError, ReadResourceResult, Resource, ResourceContents,
    ResourceTemplate,
};
use serde::Serialize;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::Engine;
use crate::api::scopes::{
    BLOBS_READ, DEVICES_LIST, EVENTS_READ, LOGS_READ, PLUGINS_LIST, STATUS_READ, Scope,
    require_scope,
};
use crate::auth::Actor;
use crate::state::audit_log::AuditEntry;
use crate::state::event_log::now_unix_ms;
use crate::state::{EventQuery, LogLevel, LogQuery, TopicMatch};

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

/// JSON-RPC error code for "the URI is valid and the caller
/// is authorized, but serving its content would exceed the
/// server's inline-response budget." Distinct from
/// `INVALID_PARAMS` (`-32602`, "the request shape was wrong")
/// because the request IS well-formed — server policy is
/// what refuses it. Audited as HTTP `413 Payload Too Large`
/// so an operator's ledger scan can tell "too big to serve"
/// apart from "bad input." Round-3 F4 on PR #122.
pub(super) const RESOURCE_TOO_LARGE_CODE: ErrorCode = ErrorCode(-32003);

/// JSON-RPC error code for "the server is transiently at
/// capacity for this resource family." Round-6 F4 on PR #122
/// split this out of [`RESOURCE_TOO_LARGE_CODE`] because a
/// full concurrency semaphore (blob-read gate, audit-write
/// gate) is a transient overload — a well-behaved client
/// should retry, and an operator scanning the audit ledger
/// wants to see it as `503 Service Unavailable`, not as a
/// permanent `413` on this particular resource.
pub(super) const RESOURCE_BUSY_CODE: ErrorCode = ErrorCode(-32004);

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
        Resource::new("oxidhome://events", "events")
            .with_title("Event history")
            .with_description(
                "JSON list of historical events — capability changes, button presses, \
                 inference results, custom plugin events. Accepts URI-query filters: \
                 `?since=<duration>&until=<duration>&device=<id>&instance=<id>&plugin=<id>\
                 &topic=<exact>&topic_prefix=<prefix>&after_id=<u64>&before_id=<u64>&limit=<u32>`. \
                 Durations use `Ns|Nm|Nh|Nd` suffixes (`60s`, `5m`, `2h`, `1d`) and \
                 resolve relative to `now`. Mirrors `GET /api/v1/events` semantically.",
            )
            .with_mime_type("application/json"),
        Resource::new("oxidhome://logs", "logs")
            .with_title("Log history")
            .with_description(
                "JSON list of historical log rows from the durable `LogStore`. Accepts \
                 URI-query filters: `?since=<duration>&until=<duration>&level=<Trace|Debug|Info\
                 |Warn|Error>&instance=<id>&plugin=<id>&device=<id>&target=<exact>\
                 &target_prefix=<prefix>&span_path_prefix=<prefix>&limit=<u32>`. \
                 Durations use `Ns|Nm|Nh|Nd` suffixes and resolve relative to `now`. \
                 Mirrors `GET /api/v1/logs` semantically.",
            )
            .with_mime_type("application/json"),
        Resource::new("oxidhome://status", "status")
            .with_title("Host status")
            .with_description(
                "JSON snapshot of host readiness: crate `version`, `uptime_ms` since \
                 the Engine was constructed (monotonic), whether the shared `SQLite` \
                 handle answers a ping (`ok`), plus counts of installed plugins, \
                 running instances, and registered devices. Callers wanting a plain \
                 HTTP probe should hit `GET /api/v1/readyz`; this resource is the \
                 MCP-agent-friendly equivalent with a broader body.",
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
        ResourceTemplate::new("oxidhome://blobs/{instance_id}/{name}", "blob")
            .with_title("Plugin-owned blob")
            .with_description(
                "Raw bytes for a named blob owned by a running plugin instance \
                 (e.g. `snapshot.jpg` under a camera instance). Response is a \
                 base64-encoded `BlobResourceContents` with the mime type recorded \
                 by the plugin at write time.",
            ),
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
    // Round-6 F3 on PR #122: bound the concurrent audit-write
    // tasks. `try_acquire_owned` refuses immediately when the
    // queue is at [`AUDIT_QUEUE_MAX`], so a disconnect-flooded
    // client — whose rmcp handler tasks keep running past the
    // client disconnect and whose earlier permit-drop released
    // the mount's pending-body slot — can't pile up unbounded
    // `spawn_blocking(record_completed)` tasks behind the
    // shared `SQLite` mutex.
    //
    // The refusal itself is NOT audited (that would defeat the
    // bound). It's logged at warn level via `tracing`, which
    // the durable `LogStore` captures — so an operator's
    // ledger scan still sees the overload signal, just not
    // the per-request audit row. The `RESOURCE_BUSY_CODE`
    // client response makes the transient-overload semantics
    // explicit; a well-behaved client retries.
    let Ok(audit_permit) = std::sync::Arc::clone(&AUDIT_QUEUE_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = AUDIT_QUEUE_MAX,
            uri,
            "MCP audit-write queue saturated — refusing read without audit",
        );
        return Err(McpError::new(
            RESOURCE_BUSY_CODE,
            "MCP audit-write queue saturated; retry shortly",
            None,
        ));
    };

    let token_id = actor.id().to_string();
    let (family, outcome) = read_inner(engine.clone(), uri, actor).await;
    // Audit-log every read. The audit call is synchronous and
    // takes the shared `Db` mutex — spawn_blocking so it can't
    // park the tokio worker under a slow disk. Fail-closed:
    // both the join error (task panicked) and the audit error
    // (ledger unreachable, disk full, read-only DB, …) refuse
    // the read.
    let audit_log = engine.audit_log();
    let audit_entry = new_audit_entry(&token_id, family, &outcome);
    let audit_result = tokio::task::spawn_blocking(move || {
        // Move the permit into the closure so it drops when
        // the actual audit write completes — not when the
        // outer `read` future returns.
        let _guard = audit_permit;
        audit_log.record_completed(&audit_entry)
    })
    .await;
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

/// Maximum concurrent MCP audit-write tasks. Bounds the size
/// of the `spawn_blocking` queue backed up behind the shared
/// `SQLite` mutex (round-6 F3 on PR #122). Sized to comfortably
/// exceed the mount's [`crate::api::mcp::server::PENDING_BODY_GATE`]
/// (16) so a fully-utilised mount never hits the audit gate,
/// while capping the runaway path (rmcp handler tasks that
/// outlive their originating request future).
pub(super) const AUDIT_QUEUE_MAX: usize = 32;

/// Global semaphore backing [`AUDIT_QUEUE_MAX`]. `static` for
/// the same reason as [`BLOB_READ_SEMAPHORE`] — no need to
/// thread through the SDK's `ServerHandler` trait. Shared
/// with [`super::tools`] (14.3) so a single mount-wide bound
/// covers audit writes from both surfaces.
pub(super) static AUDIT_QUEUE_SEMAPHORE: std::sync::LazyLock<
    std::sync::Arc<tokio::sync::Semaphore>,
> = std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(AUDIT_QUEUE_MAX)));

/// Maximum concurrent MCP store-query blocking tasks
/// (events and logs from both `resources/read` and
/// `tools/call`).
///
/// Round-1 F1 on PR #124: a cancelled outer future — client
/// disconnected while `spawn_blocking(log_store.query)` was
/// running — drops any outer-scope permit but leaves the
/// blocking task queued. Without a permit held inside the
/// closure, repeat cancellations can pile up unbounded
/// tasks behind the shared `SQLite` mutex.
///
/// Sized TIGHTER than [`AUDIT_QUEUE_MAX`] (8 vs. 32):
/// a query holds the shared `SQLite` mutex for a SELECT +
/// row decode — cheap and short — while an audit write is
/// an INSERT + index maintenance. Neither operation
/// benefits from unbounded parallelism (the mutex serialises
/// them anyway), so the tighter cap here is a
/// defense-in-depth choice for the disconnect-flood path,
/// not a throughput bound. 8 concurrent SELECTs is a
/// comfortable ceiling for a home hub; the mount's
/// transmission gate (`PENDING_BODY_GATE = 16`) still caps
/// total in-flight request work.
pub(super) const STORE_QUERY_MAX: usize = 8;

/// Global semaphore backing [`STORE_QUERY_MAX`]. Shared
/// with [`super::tools`].
pub(super) static STORE_QUERY_SEMAPHORE: std::sync::LazyLock<
    std::sync::Arc<tokio::sync::Semaphore>,
> = std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(STORE_QUERY_MAX)));

/// Outcome shape for a single resource-read attempt. Kept as
/// a separate enum so the audit path can look at the shape
/// (status, decision, required scope) without re-parsing an
/// SDK-shaped error.
enum ReadOutcome {
    /// Serialized text body + mime type. Every JSON resource
    /// (devices, plugins, events, logs, status) rides this
    /// variant with `application/json`.
    OkText {
        body: String,
        mime: &'static str,
    },
    /// Base64-encoded binary body + mime type. The blobs
    /// resource is the only user today; mime comes from the
    /// blob index row so the caller sees the same type the
    /// plugin wrote. Encoding runs inside the blocking task
    /// that reads the bytes (round-3 F3 on PR #122) so the
    /// tokio worker never sees the raw payload — the enum
    /// carries only the ready-to-serialize string.
    ///
    /// Transmission-phase memory is bounded by the mount's
    /// [`PENDING_BODY_GATE`]-holding [`PermitBody`] wrapper
    /// (round-4 F1 on PR #122); the earlier per-outcome permit
    /// was released too early to cover the SSE transmission
    /// window and is gone.
    OkBlob {
        blob_b64: String,
        mime: Option<String>,
    },
    NotFound(String),
    /// Client supplied a malformed / unknown / typed-parse
    /// failure on a query-string filter. Maps to JSON-RPC
    /// `INVALID_PARAMS` (-32602) — the closest MCP code for
    /// "the request shape was wrong." Round-1 F4 on PR #121:
    /// pre-fix, bad `since_ms=oops` was silently treated as
    /// absent and the query broadened.
    InvalidParams(String),
    /// URI is valid + caller is authorized, but the resource
    /// content exceeds the server's inline-response budget.
    /// Distinct from [`Self::InvalidParams`] so an audit sweep
    /// can tell "too big to serve" apart from "bad input"
    /// (round-3 F4 on PR #122). Reported to the client as
    /// [`RESOURCE_TOO_LARGE_CODE`]; audited as HTTP 413.
    TooLarge(String),
    /// Server is transiently at capacity for this resource
    /// family — a concurrency semaphore (blob-read gate,
    /// audit-write gate) had no permits available. Round-6 F4
    /// on PR #122 split this out of [`Self::TooLarge`] because
    /// they mean different things to the client (retry vs.
    /// reduce the request) and to an operator scanning the
    /// audit ledger. Reported as [`RESOURCE_BUSY_CODE`] and
    /// audited as HTTP 503.
    Busy(String),
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
            Self::OkText { body, mime } => Ok(ReadResourceResult::new(vec![
                ResourceContents::text(body, uri).with_mime_type(mime),
            ])),
            Self::OkBlob { blob_b64, mime } => {
                let mut contents = ResourceContents::blob(blob_b64, uri);
                if let Some(m) = mime {
                    contents = contents.with_mime_type(m);
                }
                Ok(ReadResourceResult::new(vec![contents]))
            }
            Self::NotFound(reason) => Err(McpError::resource_not_found(reason, None)),
            Self::InvalidParams(reason) => Err(McpError::invalid_params(reason, None)),
            Self::TooLarge(reason) => Err(McpError::new(RESOURCE_TOO_LARGE_CODE, reason, None)),
            Self::Busy(reason) => Err(McpError::new(RESOURCE_BUSY_CODE, reason, None)),
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
            Self::OkText { .. } | Self::OkBlob { .. } => 200,
            Self::NotFound(_) => 404,
            Self::InvalidParams(_) => 400,
            Self::TooLarge(_) => 413,
            Self::Busy(_) => 503,
            Self::Denied { .. } => 403,
            Self::Internal(_) => 500,
        }
    }

    fn decision(&self) -> &'static str {
        // Match the REST auth-classifier's status→decision map
        // in [`crate::api::auth`]: 2xx → "allow", 5xx →
        // "error", 4xx → "deny". Keeping the two surfaces
        // aligned means an operator's ledger scan can filter
        // by `decision` alone without knowing which surface
        // wrote the row.
        //
        // Round-7 F3 on PR #122: `Busy` is 503 (a server
        // failure, not an authorization denial), so it maps
        // to "error" alongside `Internal`. Pre-fix it fell
        // through the `deny` bucket next to `Denied`, which
        // conflated transient overload with permission
        // problems.
        match self {
            Self::OkText { .. } | Self::OkBlob { .. } => "allow",
            Self::NotFound(_)
            | Self::Denied { .. }
            | Self::InvalidParams(_)
            | Self::TooLarge(_) => "deny",
            Self::Internal(_) | Self::Busy(_) => "error",
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

/// Dispatch target after scope enforcement. Named as an enum
/// (rather than boxed closures) so [`read_inner`] can await
/// the async family builders without heap-allocating a
/// per-request `Box<dyn Future>`.
enum Kind<'a> {
    DevicesList,
    DevicesDetail(&'a str),
    PluginsList,
    PluginsDetail(&'a str),
    Events,
    Logs,
    Status,
    /// `(instance_id, name)`. Both segments are already validated
    /// by the routing match — non-empty and, for `instance_id`,
    /// slash-free. `name` may contain further path segments; the
    /// blob store treats it as an opaque name.
    Blob(&'a str, &'a str),
}

/// Route a URI to its family, check the family's required
/// scope against the actor, and build the body if allowed.
/// Async because the events / logs families hit the shared
/// `SQLite` mutex and must run under `spawn_blocking` to keep
/// the tokio worker free (round-1 F1 on PR #121).
async fn read_inner(engine: Engine, uri: &str, actor: &Actor) -> (&'static str, ReadOutcome) {
    let Some(rest) = uri.strip_prefix(SCHEME) else {
        return (
            "unknown",
            ReadOutcome::NotFound(format!("URI {uri} does not use the oxidhome:// scheme")),
        );
    };
    // Peel the optional query string first so path-splitting
    // (`/` separator) only walks the authority + id — a caller
    // hitting `oxidhome://events?since=1h` would otherwise
    // land in the "unknown" arm because `events?since=1h`
    // isn't a registered family.
    let (path, query_str) = rest.split_once('?').map_or((rest, ""), |(p, q)| (p, q));
    // Path split: `authority[/tail]`. Authority is the family
    // (`devices`, `plugins`, `events`, `logs`); tail (if any)
    // is the id.
    let (family_seg, id_seg) = match path.split_once('/') {
        Some((head, tail)) => (head, Some(tail)),
        None => (path, None),
    };

    // Route → (family slug, required scope). Scope check
    // happens uniformly below so every routed URI wears the
    // same enforcement — no way to accidentally add a family
    // that skips it. `Kind` names the dispatch after scope
    // succeeds; keeps the routing decision separate from the
    // async body-build.
    let (family, required, kind): (&'static str, Scope, Kind) = match (family_seg, id_seg) {
        ("devices", None) => ("devices", DEVICES_LIST, Kind::DevicesList),
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
            Kind::DevicesDetail(id),
        ),
        ("plugins", None) => ("plugins", PLUGINS_LIST, Kind::PluginsList),
        ("plugins", Some(id)) if !id.is_empty() && !id.contains('/') => {
            ("plugins.detail", PLUGINS_LIST, Kind::PluginsDetail(id))
        }
        ("events", None) => ("events", EVENTS_READ, Kind::Events),
        ("logs", None) => ("logs", LOGS_READ, Kind::Logs),
        ("status", None) => ("status", STATUS_READ, Kind::Status),
        // Blobs URI: `oxidhome://blobs/<instance_id>/<name>`.
        // Split the tail on the *first* `/` — instance ids are
        // slash-free (validated by the blob store's
        // `check_instance_id`) so anything after the first `/`
        // belongs to `name`. Empty either side is a
        // path-shape error, not a not-found.
        ("blobs", Some(tail)) => match tail.split_once('/') {
            Some((instance, name)) if !instance.is_empty() && !name.is_empty() => {
                ("blobs", BLOBS_READ, Kind::Blob(instance, name))
            }
            _ => {
                return (
                    "blobs",
                    ReadOutcome::NotFound(format!(
                        "blobs URI must be oxidhome://blobs/<instance_id>/<name>; got {uri}",
                    )),
                );
            }
        },
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

    let outcome = match kind {
        Kind::DevicesList => devices_list(&engine),
        Kind::DevicesDetail(id) => devices_detail(&engine, id),
        Kind::PluginsList => plugins_list(&engine),
        Kind::PluginsDetail(id) => plugins_detail(&engine, id),
        // Events + logs hit `SQLite`, so parse the query
        // and run the read under `spawn_blocking`.
        Kind::Events => events_read(engine, query_str).await,
        Kind::Logs => logs_read(engine, query_str).await,
        Kind::Status => status_read(engine.clone()).await,
        // Blob reads also hit `SQLite` (the blob index) plus
        // a filesystem `read()`, so run under `spawn_blocking`
        // like the events / logs paths.
        Kind::Blob(instance, name) => blob_read(engine, instance, name).await,
    };
    (family, outcome)
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

// ── Events ────────────────────────────────────────────────────────

/// Default `limit` when the caller omits one. Matches the
/// REST `/api/v1/events` endpoint so a client that pins the
/// same page size cross-transport sees identical pagination.
const EVENTS_QUERY_DEFAULT_LIMIT: u32 = 100;
/// Ceiling on a single events query. Deliberately tighter
/// than the REST endpoint's `1_000` — an event payload is
/// capped at [`crate::runtime::state::MAX_EVENT_PAYLOAD_BYTES`]
/// (64 KiB), so `1_000` records × 64 KiB = ~62.5 MiB of
/// serialized JSON per response; combined with the mount's
/// 16-slot response gate, aggregate transmission memory would
/// approach 1 GiB (round-5 F1 on PR #122). `100` records ×
/// 64 KiB = ~6.4 MiB per response is a defensible ceiling
/// that still delivers plenty of pagination granularity for
/// LLM agents (which usually iterate in pages of tens rather
/// than thousands).
const EVENTS_QUERY_MAX_LIMIT: u32 = 100;

/// Default / ceiling for `logs`. Same reasoning as
/// [`EVENTS_QUERY_MAX_LIMIT`]: a log row's `message` +
/// `fields` are unbounded by the WIT contract, and a
/// misbehaving plugin could easily push individual rows into
/// the tens of KiB. Capping at 100 rows per query keeps
/// worst-case serialized response under the mount's
/// transmission-body ceiling.
pub(super) const LOGS_QUERY_DEFAULT_LIMIT: u32 = 100;
pub(super) const LOGS_QUERY_MAX_LIMIT: u32 = 100;

#[derive(Serialize)]
struct EventsBody {
    events: Vec<super::super::server::WireHistoricalEvent>,
}

/// Keys the `oxidhome://events` filter recognizes. Anything
/// outside this set is rejected as `INVALID_PARAMS` so a typo
/// or a made-up filter can't silently broaden the query
/// (round-1 F2 on PR #121 — before the fix, an unknown key
/// like `level` on `oxidhome://events` was ignored and the
/// caller got an unfiltered result). Kept sorted alphabetically
/// so a scan is easy to eyeball.
const EVENTS_KNOWN_KEYS: &[&str] = &[
    "after_id",
    "before_id",
    "device",
    "instance",
    "limit",
    "plugin",
    "since",
    "topic",
    "topic_prefix",
    "until",
];

async fn events_read(engine: Engine, raw_query: &str) -> ReadOutcome {
    let query = match parse_query(raw_query) {
        Ok(q) => q,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    if let Err(err) = reject_unknown(&query, EVENTS_KNOWN_KEYS) {
        return ReadOutcome::InvalidParams(err);
    }
    let limit = match clamp_limit(&query, EVENTS_QUERY_DEFAULT_LIMIT, EVENTS_QUERY_MAX_LIMIT) {
        Ok(n) => n,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let since_ms = match parse_since(&query, "since") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let until_ms = match parse_since(&query, "until") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let after_id = match parse_opt_u64(&query, "after_id") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let before_id = match parse_opt_u64(&query, "before_id") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    // `topic` (exact) and `topic_prefix` are mutually
    // exclusive — same policy as REST: prefer prefix when
    // both are set and warn so an operator can spot the
    // ambiguous client.
    let topic = match (
        query.get("topic").cloned(),
        query.get("topic_prefix").cloned(),
    ) {
        (topic_exact, Some(p)) => {
            if let Some(exact) = &topic_exact {
                tracing::warn!(
                    target: "mcp.events",
                    topic_exact = %exact,
                    topic_prefix = %p,
                    "MCP oxidhome://events: both `topic` and `topic_prefix` supplied — using `topic_prefix`",
                );
            }
            Some((p, TopicMatch::Prefix))
        }
        (Some(t), None) => Some((t, TopicMatch::Exact)),
        (None, None) => None,
    };
    let event_query = EventQuery {
        since_ms,
        until_ms,
        device_id: query.get("device").cloned(),
        instance_id: query.get("instance").cloned(),
        plugin_id: query.get("plugin").cloned(),
        topic,
        after_id,
        before_id,
    };
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    // The shared `SQLite` mutex is std, not tokio — running
    // the query on the async worker would park it for the
    // whole read. `spawn_blocking` moves it to the blocking
    // pool (round-1 F1 on PR #121). Round-1 F1 on PR #124
    // adds `STORE_QUERY_SEMAPHORE` — the permit MOVES into
    // the closure so a cancelled outer future doesn't leave
    // detached blocking tasks piled up on the mutex.
    let Ok(permit) = std::sync::Arc::clone(&STORE_QUERY_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = STORE_QUERY_MAX,
            "MCP events store-query saturated — refusing read",
        );
        return ReadOutcome::Busy("MCP store-query queue saturated; retry shortly".into());
    };
    let event_log = engine.event_log();
    let join = tokio::task::spawn_blocking(move || {
        let _guard = permit;
        event_log.query(&event_query, limit_usize)
    })
    .await;
    let rows = match join {
        Ok(Ok(rows)) => rows,
        Ok(Err(err)) => {
            tracing::error!(%err, "MCP events query failed");
            return ReadOutcome::Internal("event query failed".into());
        }
        Err(join_err) => {
            tracing::error!(%join_err, "MCP events query task panicked");
            return ReadOutcome::Internal("event query task panicked".into());
        }
    };
    let events: Vec<_> = rows
        .into_iter()
        .map(super::super::server::WireHistoricalEvent::from_row)
        .collect();
    encode(&EventsBody { events }, "events")
}

// ── Logs ──────────────────────────────────────────────────────────

/// Wire body for both the `oxidhome://logs` resource read
/// and the `logs.query` tool (14.3b). Shared so both surfaces
/// serialise the same shape — a client reading the ledger
/// gets the same JSON whether they went through
/// `resources/read` or `tools/call`.
#[derive(Serialize)]
pub(super) struct LogsBody<'a> {
    pub(super) logs: &'a [crate::state::HistoricalLogEvent],
}

/// Keys `oxidhome://logs` recognizes. See [`EVENTS_KNOWN_KEYS`].
const LOGS_KNOWN_KEYS: &[&str] = &[
    "device",
    "instance",
    "level",
    "limit",
    "plugin",
    "since",
    "span_path_prefix",
    "target",
    "target_prefix",
    "until",
];

async fn logs_read(engine: Engine, raw_query: &str) -> ReadOutcome {
    let query = match parse_query(raw_query) {
        Ok(q) => q,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    if let Err(err) = reject_unknown(&query, LOGS_KNOWN_KEYS) {
        return ReadOutcome::InvalidParams(err);
    }
    let limit = match clamp_limit(&query, LOGS_QUERY_DEFAULT_LIMIT, LOGS_QUERY_MAX_LIMIT) {
        Ok(n) => n,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let since_ms = match parse_since(&query, "since") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let until_ms = match parse_since(&query, "until") {
        Ok(v) => v,
        Err(err) => return ReadOutcome::InvalidParams(err),
    };
    let min_level = match query.get("level").map(String::as_str) {
        Some("Trace") => Some(LogLevel::Trace),
        Some("Debug") => Some(LogLevel::Debug),
        Some("Info") => Some(LogLevel::Info),
        Some("Warn") => Some(LogLevel::Warn),
        Some("Error") => Some(LogLevel::Error),
        // A bogus level is a client bug. Round-1 F4 on PR
        // #121 routes this through `InvalidParams` (JSON-RPC
        // `-32602`) instead of `NotFound` — malformed input,
        // not a missing resource.
        Some(unknown) => {
            return ReadOutcome::InvalidParams(format!(
                "unknown level `{unknown}`; expected Trace|Debug|Info|Warn|Error",
            ));
        }
        None => None,
    };
    let log_query = LogQuery {
        since_ms,
        until_ms,
        min_level,
        instance_id: query.get("instance").cloned(),
        plugin_id: query.get("plugin").cloned(),
        device_id: query.get("device").cloned(),
        target: query.get("target").cloned(),
        target_prefix: query.get("target_prefix").cloned(),
        span_path_prefix: query.get("span_path_prefix").cloned(),
    };
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    // Round-1 F1 on PR #124: bound concurrent store-query
    // blocking tasks. See `events_read` for the rationale.
    let Ok(permit) = std::sync::Arc::clone(&STORE_QUERY_SEMAPHORE).try_acquire_owned() else {
        tracing::warn!(
            cap = STORE_QUERY_MAX,
            "MCP logs store-query saturated — refusing read",
        );
        return ReadOutcome::Busy("MCP store-query queue saturated; retry shortly".into());
    };
    let log_store = engine.log_store();
    let join = tokio::task::spawn_blocking(move || {
        let _guard = permit;
        log_store.query(&log_query, limit_usize)
    })
    .await;
    let rows = match join {
        Ok(Ok(rows)) => rows,
        Ok(Err(err)) => {
            tracing::error!(%err, "MCP logs query failed");
            return ReadOutcome::Internal("log query failed".into());
        }
        Err(join_err) => {
            tracing::error!(%join_err, "MCP logs query task panicked");
            return ReadOutcome::Internal("log query task panicked".into());
        }
    };
    encode(&LogsBody { logs: &rows }, "logs")
}

// ── Status ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusBody {
    version: &'static str,
    /// `true` iff the shared `SQLite` handle answered a ping.
    /// The REST `/api/v1/readyz` probe uses the same signal for
    /// its 200 vs. 503; keeping them aligned means an MCP agent
    /// and an orchestrator's HTTP probe agree on "up."
    ok: bool,
    /// Milliseconds since the Engine was constructed. Sourced
    /// from a monotonic clock (`Instant::elapsed`), so a
    /// wall-clock adjustment during the process's lifetime
    /// can't produce a negative or jumping value. Round-4 F3
    /// on PR #122; the design doc's `oxidhome://status`
    /// contract listed uptime among the required fields.
    uptime_ms: u64,
    installed_plugins: usize,
    running_instances: usize,
    devices: usize,
}

async fn status_read(engine: Engine) -> ReadOutcome {
    // `db_ping` grabs the shared `SQLite` mutex and waits on
    // whatever's holding it — same reason the events/logs
    // families run under `spawn_blocking` (round-2 F5 on PR
    // #122). Concurrent MCP status probes on a busy DB would
    // otherwise park the tokio worker for the ping's duration.
    let engine_for_ping = engine.clone();
    let ping_join = tokio::task::spawn_blocking(move || engine_for_ping.db_ping()).await;
    let ok = match ping_join {
        Ok(Ok(())) => true,
        Ok(Err(err)) => {
            tracing::warn!(target: "mcp.status", %err, "db ping failed while serving oxidhome://status");
            false
        }
        Err(join_err) => {
            tracing::error!(target: "mcp.status", %join_err, "db ping task panicked while serving oxidhome://status");
            return ReadOutcome::Internal("status db-ping task panicked".into());
        }
    };
    let body = StatusBody {
        version: env!("CARGO_PKG_VERSION"),
        ok,
        uptime_ms: engine.uptime_ms(),
        installed_plugins: engine.installed_plugins().list().len(),
        running_instances: engine.instances().list().len(),
        devices: engine.devices().list().len(),
    };
    encode(&body, "status")
}

// ── Blobs ─────────────────────────────────────────────────────────

/// Inline-response ceiling for a single `oxidhome://blobs/...`
/// read. Blobs are base64-encoded (`ceil(4/3 * raw)` bytes)
/// into the JSON-RPC response body, so a single request holds
/// two allocations briefly during processing (raw ≤ 4 MiB +
/// encoded ≤ ~5.4 MiB ≈ 9.4 MiB per slot) and ~5.4 MiB while
/// the response frame streams. 4 MiB matches typical
/// smart-home artifact sizes (a ~4 MP JPEG, a short WAV clip)
/// while keeping the aggregate memory bill in the two-digit
/// MiB range under the mount's concurrency caps.
///
/// Peak processing memory is bounded by
/// [`BLOB_CONCURRENT_READS`]; peak transmission memory is
/// bounded by
/// [`crate::api::mcp::server::PENDING_BODY_GATE`] (round-4 F1
/// on PR #122 attached the request permit to the response
/// body, so the slot doesn't release until the SSE frame is
/// fully sent).
const BLOB_INLINE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Concurrency cap on in-flight blob READ+ENCODE cycles.
/// Bounds the phase where raw bytes and the base64 string
/// coexist in memory (round-3 F1 on PR #122; math corrected
/// in round-4 F2).
///
/// - Per slot peak: `BLOB_INLINE_MAX_BYTES` (4 MiB) +
///   `ceil(4/3 * BLOB_INLINE_MAX_BYTES)` (~5.4 MiB) ≈ 9.4 MiB
///   during the `BASE64.encode(&bytes)` call where both live.
/// - 4 slots × 9.4 MiB ≈ 37 MiB processing peak.
///
/// The permit is a plain local binding in [`blob_read`] and
/// drops when the async function returns — right after
/// encoding finishes and the raw `Vec<u8>` has already been
/// dropped inside the blocking task. This gate does NOT bound
/// transmission memory; that's the mount's
/// [`crate::api::mcp::server::PENDING_BODY_GATE`]'s job.
const BLOB_CONCURRENT_READS: usize = 4;

/// Global semaphore backing [`BLOB_CONCURRENT_READS`]. Kept
/// `static` so the state doesn't have to thread through the
/// SDK's `ServerHandler` trait; the only touchpoint is
/// [`blob_read`].
static BLOB_READ_SEMAPHORE: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(BLOB_CONCURRENT_READS))
    });

/// Re-export of the blob store's per-mime cap so the local
/// projection math ([`BLOB_ENVELOPE_OVERHEAD_BYTES`] +
/// `MAX_BLOB_MIME_BYTES` + base64 body ≤ [`MAX_BLOB_BODY_BYTES`])
/// can name a single source of truth. The write-time
/// enforcement + SQL-side legacy filter live on the blob
/// store side (round-10 F1 on PR #122); this constant is
/// what MCP's projection uses so the two definitions can
/// never drift.
use crate::state::blobs::MAX_BLOB_MIME_BYTES;

/// Conservative headroom for the `BlobResourceContents` JSON
/// envelope + URI + JSON-RPC framing + SSE prefix around a
/// blob response body. Used by [`blob_read`] to project the
/// full serialized response against [`MAX_BLOB_BODY_BYTES`]
/// (round-9 F1 on PR #122).
///
/// Rough breakdown at the worst case:
///
/// - `BlobResourceContents` JSON keys + punctuation ≈ 60 B
/// - URI (`oxidhome://blobs/<instance>/<name>`): up to a few
///   hundred bytes; 512 B ceiling covers pathological names.
/// - `_meta`, JSON-RPC id + method + version wrapper ≈ 128 B.
/// - SSE `data:` prefix + trailing `\n\n` ≈ 8 B.
///
/// A 1024-byte budget covers all of the above with room to
/// spare. The projection is over-generous by design — we'd
/// rather refuse a borderline response with a clean 413 than
/// let one slip through and trip `PermitBody`'s stream
/// terminator.
const BLOB_ENVELOPE_OVERHEAD_BYTES: usize = 1024;

// Every branch in this function is a distinct failure mode
// (URI-decode error, unknown instance, unloaded instance,
// concurrency-cap saturation, store errors, oversized
// projected response). Splitting them into per-branch
// helpers would spread the outcome shape across the module
// without shortening any single decision — the function
// stays as one linear match-and-return so the audit /
// error mapping is easy to follow top-to-bottom.
#[allow(clippy::too_many_lines)]
async fn blob_read(engine: Engine, instance_id_raw: &str, name_raw: &str) -> ReadOutcome {
    // Round-2 F3 on PR #122: percent-decode the URI path
    // segments once before they hit the store. Blob names are
    // arbitrary human-readable strings ("front door.jpg",
    // "clip/segment-1.mp3"); a generic URI builder will encode
    // spaces as `%20` and `/` as `%2F`, and querying `SQLite`
    // for the raw encoded bytes returns nothing.
    let instance_id = match percent_decode_segment(instance_id_raw) {
        Ok(v) => v,
        Err(err) => {
            return ReadOutcome::InvalidParams(format!(
                "malformed `instance_id` segment `{instance_id_raw}`: {err}",
            ));
        }
    };
    let name = match percent_decode_segment(name_raw) {
        Ok(v) => v,
        Err(err) => {
            return ReadOutcome::InvalidParams(format!(
                "malformed `name` segment `{name_raw}`: {err}",
            ));
        }
    };
    // Resolve `installation_uuid` off the running instance's
    // handle — pinned by the supervisor after the first
    // successful load (round-2 F2 on PR #122). Pre-fix this
    // went through `InstalledPluginRegistry::get(plugin_id)`,
    // which has no row for dev / argv instances, so their
    // blobs were unreachable via MCP.
    let Some(handle) = engine.instances().get(&instance_id) else {
        return ReadOutcome::NotFound(format!("instance `{instance_id}` is not running"));
    };
    let Some(installation_uuid) = handle.installation_uuid().map(str::to_string) else {
        // Instance is still `Loading` — the supervisor hasn't
        // pinned the UUID yet. Treat as "not ready" via 404
        // rather than 5xx; the client's natural retry is to
        // wait for the state to advance and re-issue the read.
        return ReadOutcome::NotFound(format!(
            "instance `{instance_id}` is not yet loaded; retry once its state is `Running`"
        ));
    };
    // Acquire a processing slot BEFORE we start the read
    // (round-3 F1 on PR #122). Round-4 F2 on PR #122 swapped
    // `acquire_owned().await` (unbounded wait) for
    // `try_acquire_owned()` — a client that disconnects
    // mid-response causes axum to drop the request future,
    // but rmcp's handler task keeps running on its own tokio
    // task, so an `.await` here would let waiters pile up on
    // a client that repeatedly submits and disconnects.
    // Refusing immediately with `TooLarge` (client sees a
    // dedicated 413-shaped error and can retry) bounds the
    // handler-task count to the semaphore's own permit
    // count.
    let _permit = match std::sync::Arc::clone(&BLOB_READ_SEMAPHORE).try_acquire_owned() {
        Ok(p) => p,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            tracing::warn!(
                cap = BLOB_CONCURRENT_READS,
                "MCP blob concurrency cap reached — refusing read",
            );
            // Round-6 F4 on PR #122: `Busy` (503) not
            // `TooLarge` (413). The URI is fine; server is
            // just transiently saturated. Client should retry.
            return ReadOutcome::Busy(format!(
                "MCP blob concurrency cap reached ({BLOB_CONCURRENT_READS} in-flight reads); retry shortly"
            ));
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            // Semaphore is never closed in practice, but the
            // panic-free path still costs nothing.
            tracing::error!("MCP blob semaphore closed unexpectedly");
            return ReadOutcome::Internal("blob concurrency gate closed".into());
        }
    };
    // Round-2 F4 on PR #122: `read_with_info` returns bytes +
    // metadata belonging to the same blob version. Round-3
    // F3: base64-encode INSIDE the same blocking task so the
    // raw Vec drops before we hand back to the tokio worker
    // and the worker never sees CPU-bound encoding work.
    let blobs = engine.blobs();
    let uuid_for_task = installation_uuid.clone();
    let instance_for_task = instance_id.clone();
    let name_for_task = name.clone();
    let join = tokio::task::spawn_blocking(move || {
        let (info, bytes) = blobs.read_with_info(
            &uuid_for_task,
            &instance_for_task,
            &name_for_task,
            Some(BLOB_INLINE_MAX_BYTES),
        )?;
        // Encode + drop raw bytes here — before the return
        // hands control back to the async worker.
        let blob_b64 = BASE64.encode(&bytes);
        drop(bytes);
        Ok::<_, crate::state::blobs::BlobError>((info, blob_b64))
    })
    .await;
    match join {
        Ok(Ok((info, blob_b64))) => {
            // Round-6 F1 on PR #122: the store-side cap
            // ([`BLOB_INLINE_MAX_BYTES`]) already ceilings the
            // RAW blob at 4 MiB, so the encoded string can't
            // exceed `ceil(4/3 * 4 MiB)` ≈ 5.34 MiB — well
            // under [`MAX_BLOB_BODY_BYTES`]. Check anyway as
            // belt-and-suspenders so any future change to
            // `BLOB_INLINE_MAX_BYTES` trips this guard
            // (audited as 413) instead of the middleware's
            // stream-terminate path (looks like a network
            // error to the client). Round-8 F1 on PR #122
            // switched to `MAX_BLOB_BODY_BYTES` (which has no
            // escape-inflation headroom baked in — base64 has
            // no JSON-escape-worthy characters) so a valid
            // 3-MiB-raw blob doesn't hit the text cap.
            // Round-10 F1 on PR #122 moved the mime cap
            // upstream: `BlobStore::write` refuses over-cap
            // mimes, and `BlobStore::read_with_info`'s SQL
            // projects NULL for legacy rows whose mime
            // exceeds [`MAX_BLOB_MIME_BYTES`]. So by the
            // time `info.mime` reaches us it's already
            // known to fit — no per-read materialise-then-
            // check pass. Belt-and-suspenders: still assert
            // the invariant, so a future regression in the
            // store's SQL trips this instead of pushing the
            // response past `PermitBody`'s cap.
            let mime = info.mime;
            debug_assert!(
                mime.as_ref().is_none_or(|m| m.len() <= MAX_BLOB_MIME_BYTES),
                "read_with_info returned an over-cap mime; store invariant violated",
            );
            // Belt-and-suspenders against the transport cap:
            // base64 body + mime + URI + a conservative
            // envelope-framing budget must fit under
            // [`MAX_BLOB_BODY_BYTES`]. `blob_b64.len()` alone
            // is bounded by [`BLOB_INLINE_MAX_BYTES`] via the
            // store's `read_with_info`; this arithmetic
            // catches any future combination (e.g. a bumped
            // raw cap paired with the max mime) that would
            // slip past.
            let mime_len = mime.as_deref().map_or(0, str::len);
            let projected = blob_b64
                .len()
                .saturating_add(mime_len)
                .saturating_add(BLOB_ENVELOPE_OVERHEAD_BYTES);
            if projected > MAX_BLOB_BODY_BYTES {
                tracing::warn!(
                    b64 = blob_b64.len(),
                    mime = mime_len,
                    projected,
                    cap = MAX_BLOB_BODY_BYTES,
                    "MCP blob response projected size exceeds cap — refusing read",
                );
                return ReadOutcome::TooLarge(format!(
                    "blob response ({projected} B projected: {} b64 + {mime_len} mime + framing) \
                     exceeds the per-response cap ({MAX_BLOB_BODY_BYTES} B)",
                    blob_b64.len(),
                ));
            }
            ReadOutcome::OkBlob { blob_b64, mime }
        }
        Ok(Err(crate::state::blobs::BlobError::NotFound { what })) => {
            ReadOutcome::NotFound(format!("blob not found: {what}"))
        }
        Ok(Err(crate::state::blobs::BlobError::TooLarge {
            what,
            size_bytes,
            cap,
        })) => ReadOutcome::TooLarge(format!(
            "blob {what} is {size_bytes} bytes; the MCP inline cap is {cap}. \
             Reduce the blob size or fetch it via a plugin-owned tool that streams it."
        )),
        Ok(Err(err)) => {
            tracing::error!(%err, instance_id = %instance_id, name = %name, "MCP blob read failed");
            ReadOutcome::Internal("blob read failed".into())
        }
        Err(join_err) => {
            tracing::error!(%join_err, "MCP blob read task panicked");
            ReadOutcome::Internal("blob read task panicked".into())
        }
    }
}

/// Percent-decode one URI path segment, returning it as an
/// owned `String`. `serde_urlencoded` decodes `application/
/// x-www-form-urlencoded` (`+` → space); path segments follow
/// RFC 3986 where `+` is a literal `+`, not a space — the
/// query-string decoder is the wrong tool here. We hand-roll
/// the tiny subset we need instead.
///
/// Rules:
///
/// - `%HH` (two ASCII hex digits) → the byte `0xHH`.
/// - `+` → literal `+` (not space).
/// - Any other byte → itself.
///
/// The final byte sequence must be valid UTF-8 — a
/// percent-escape that resolves to a lone continuation byte
/// is rejected.
fn percent_decode_segment(raw: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let Some(pair) = bytes.get(i + 1..i + 3) else {
                    return Err("truncated %-escape".into());
                };
                let hi = decode_hex(pair[0])?;
                let lo = decode_hex(pair[1])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| format!("decoded bytes are not valid UTF-8: {e}"))
}

fn decode_hex(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!(
            "invalid hex digit `{}` in %-escape",
            other.escape_ascii()
        )),
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Parse `?key=value&key=value` into a `HashMap`, percent-decoding
/// values. `serde_urlencoded` is the same crate `axum`'s `Query`
/// extractor uses, so the decode rules are identical between our
/// REST and MCP surfaces (round-1 F3 on PR #121 — before the fix,
/// a URI like `oxidhome://logs?plugin=oxidhome_core%3A%3Aruntime`
/// queried `SQLite` for the raw `%3A%3A` bytes and matched nothing).
///
/// Duplicate keys keep the last value, matching the REST
/// `Query<HashMap<...>>` behavior — MCP clients should not depend
/// on either half of a duplicated key.
fn parse_query(raw: &str) -> Result<HashMap<String, String>, String> {
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(raw).map_err(|e| format!("malformed URI query: {e}"))?;
    let mut out = HashMap::with_capacity(pairs.len());
    for (k, v) in pairs {
        if k.is_empty() {
            continue;
        }
        out.insert(k, v);
    }
    Ok(out)
}

/// Refuse any key the family doesn't recognize. Rejecting
/// unknowns rather than silently ignoring them means a doc
/// change that renames a param surfaces immediately as a
/// 400 instead of quietly broadening the result set.
fn reject_unknown(query: &HashMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for k in query.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!(
                "unknown filter `{k}`; allowed: {}",
                allowed.join(", "),
            ));
        }
    }
    Ok(())
}

/// Parse a relative duration (e.g. `1h`, `30m`, `60s`, `2d`)
/// into an absolute epoch-ms timestamp — `now - duration`.
/// Returns `Ok(None)` when the key is absent, `Err` on any
/// malformed value.
fn parse_since(query: &HashMap<String, String>, key: &str) -> Result<Option<i64>, String> {
    let Some(raw) = query.get(key) else {
        return Ok(None);
    };
    let ms = parse_duration_ms(raw).map_err(|e| format!("invalid `{key}` value: {e}"))?;
    let now = now_unix_ms();
    Ok(Some(now.saturating_sub(ms)))
}

/// Duration grammar: `<digits><unit>` where unit is one ASCII
/// byte ∈ `{s, m, h, d}`. No compound values (`1h30m`) — the
/// design doc lists only single-unit examples and keeping it
/// simple keeps the surface predictable.
///
/// The percent-decoded query value can contain arbitrary UTF-8
/// (e.g. `?since=%C3%A9` decodes to `é`), so byte-index
/// splitting via `raw.len() - 1` would panic on a multi-byte
/// final `char`. Round-2 F1 on PR #121: split on the last
/// `char` boundary instead.
pub(super) fn parse_duration_ms(raw: &str) -> Result<i64, String> {
    // Isolate the unit as the last char; everything before it
    // is the digit portion. `char_indices` walks by scalar
    // value, so `raw[i..]` always lands on a UTF-8 boundary.
    let (unit_idx, unit_char) = raw
        .char_indices()
        .next_back()
        .ok_or_else(|| "empty duration".to_string())?;
    let unit = &raw[unit_idx..];
    let num = &raw[..unit_idx];
    // Refuse non-ASCII units up front so the error names the
    // bad byte cleanly instead of falling through into "not a
    // known unit."
    if !unit_char.is_ascii() {
        return Err(format!("`{raw}` — unknown unit `{unit}`; expected s|m|h|d"));
    }
    let n: i64 = num
        .parse()
        .map_err(|_| format!("`{raw}` — expected digits followed by s|m|h|d"))?;
    if n < 0 {
        return Err(format!("`{raw}` — duration must be non-negative"));
    }
    let per_unit_ms: i64 = match unit {
        "s" => 1_000,
        "m" => 60 * 1_000,
        "h" => 60 * 60 * 1_000,
        "d" => 24 * 60 * 60 * 1_000,
        other => {
            return Err(format!(
                "`{raw}` — unknown unit `{other}`; expected s|m|h|d"
            ));
        }
    };
    n.checked_mul(per_unit_ms)
        .ok_or_else(|| format!("`{raw}` — duration overflows i64 milliseconds"))
}

#[cfg(test)]
mod duration_tests {
    use super::parse_duration_ms;

    #[test]
    fn accepts_all_known_units() {
        assert_eq!(parse_duration_ms("30s").unwrap(), 30_000);
        assert_eq!(parse_duration_ms("5m").unwrap(), 300_000);
        assert_eq!(parse_duration_ms("2h").unwrap(), 7_200_000);
        assert_eq!(parse_duration_ms("1d").unwrap(), 86_400_000);
    }

    #[test]
    fn rejects_non_ascii_suffix_without_panicking() {
        // Percent-decoded `?since=%C3%A9` reaches this parser
        // as `é`. Pre-fix (round-2 F1 on PR #121), the byte-
        // index split panicked at `raw.len() - 1` because that
        // fell mid-way through `é`'s two UTF-8 bytes.
        let err = parse_duration_ms("é").expect_err("must reject non-ASCII unit");
        assert!(err.contains("é"), "error must name the bad unit; got {err}");
    }

    #[test]
    fn rejects_multi_byte_unit_after_digits() {
        // Same class of bug — `1é` used to panic at index 2.
        let err = parse_duration_ms("1é").expect_err("must reject non-ASCII unit");
        assert!(err.contains("é"), "error must name the bad unit; got {err}");
    }
}

#[cfg(test)]
mod parse_query_tests {
    use super::parse_query;

    /// The reason round-1 F3 was a bug: pre-fix, the hand-rolled
    /// parser stored the raw bytes verbatim. Any downstream `SQLite`
    /// comparison against the decoded value returned zero rows.
    /// This test locks in the fix directly — no integration
    /// scaffolding needed.
    #[test]
    fn percent_decodes_values() {
        let q = parse_query("plugin=oxidhome_core%3A%3Aruntime").expect("parse ok");
        assert_eq!(
            q.get("plugin").map(String::as_str),
            Some("oxidhome_core::runtime"),
            "value must be percent-decoded before storage lookup; got {q:?}",
        );
    }

    #[test]
    fn percent_decodes_keys_too() {
        // Round-trip protection: `serde_urlencoded` decodes keys as
        // well as values. `%74` = `t`, so `%74opic` should land as
        // the `topic` key.
        let q = parse_query("%74opic=alarm").expect("parse ok");
        assert_eq!(q.get("topic").map(String::as_str), Some("alarm"));
    }

    #[test]
    fn plus_decodes_to_space() {
        // `serde_urlencoded` follows the form-urlencoded rule where
        // `+` = SPACE. Matches axum's `Query` extractor exactly,
        // so an MCP client and a REST client see identical decode.
        let q = parse_query("target=one+two").expect("parse ok");
        assert_eq!(q.get("target").map(String::as_str), Some("one two"));
    }

    #[test]
    fn multiple_values_last_wins() {
        // Duplicate keys are silently collapsed to the last value —
        // documented in `parse_query`'s doc-comment. Test locks
        // that in so a future rewrite doesn't accidentally start
        // returning the first value or a Vec.
        let q = parse_query("device=a&device=b").expect("parse ok");
        assert_eq!(q.get("device").map(String::as_str), Some("b"));
    }

    #[test]
    fn empty_query_is_ok() {
        assert!(parse_query("").expect("parse ok").is_empty());
    }
}

#[cfg(test)]
mod percent_decode_tests {
    use super::percent_decode_segment;

    #[test]
    fn decodes_space_and_slash() {
        assert_eq!(
            percent_decode_segment("front%20door.jpg").unwrap(),
            "front door.jpg",
        );
        assert_eq!(
            percent_decode_segment("folder%2Fsnap.jpg").unwrap(),
            "folder/snap.jpg",
        );
    }

    #[test]
    fn plus_is_literal_not_space() {
        // RFC 3986 path segments: `+` is a literal `+`, not a
        // space. `serde_urlencoded` would decode this to a
        // space — that's why we hand-roll the segment decoder
        // instead of reusing it for blob paths.
        assert_eq!(percent_decode_segment("a+b").unwrap(), "a+b");
    }

    #[test]
    fn accepts_mixed_case_hex() {
        assert_eq!(percent_decode_segment("%3a%3A").unwrap(), "::");
    }

    #[test]
    fn rejects_truncated_escape() {
        assert!(percent_decode_segment("bad%2").is_err());
        assert!(percent_decode_segment("bad%").is_err());
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(percent_decode_segment("bad%GG").is_err());
    }

    #[test]
    fn rejects_invalid_utf8_result() {
        // `%FF` decoded is a lone byte that isn't valid UTF-8 —
        // makes the segment unusable as a `String` key on
        // downstream stores, so we reject at the decoder.
        assert!(percent_decode_segment("bad%FF").is_err());
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::{RESOURCE_BUSY_CODE, RESOURCE_TOO_LARGE_CODE, ReadOutcome};

    /// Round-3 F4 on PR #122: `ReadOutcome::TooLarge` maps to a
    /// dedicated JSON-RPC error code (not the -32602
    /// `INVALID_PARAMS` used for malformed input) and is
    /// audited as HTTP 413 ("Payload Too Large"). Locks in
    /// both wire mapping (client sees the right code) and
    /// audit mapping (operator's ledger scan can tell "too big
    /// to serve" apart from "bad input").
    #[test]
    fn too_large_maps_to_413_and_dedicated_code() {
        let outcome = ReadOutcome::TooLarge("blob too big".into());
        assert_eq!(outcome.status(), 413);
        assert_eq!(outcome.decision(), "deny");
        // `required_scope` is `Some` only for `Denied`.
        assert!(outcome.required_scope().is_none());

        let err = outcome
            .into_result("oxidhome://blobs/foo/bar")
            .expect_err("TooLarge must surface as an Err");
        assert_eq!(err.code, RESOURCE_TOO_LARGE_CODE);
        assert!(
            err.message.contains("blob too big"),
            "reason must reach the caller: {err:?}",
        );
    }

    /// Round-6 F4 on PR #122: `ReadOutcome::Busy` is
    /// deliberately distinct from `TooLarge`. Saturation of a
    /// concurrency semaphore is a transient overload, so the
    /// client sees `RESOURCE_BUSY_CODE` (retry) and the audit
    /// ledger records HTTP 503, not 413.
    #[test]
    fn busy_maps_to_503_and_dedicated_code() {
        let outcome = ReadOutcome::Busy("too many concurrent reads".into());
        assert_eq!(outcome.status(), 503);
        // Round-7 F3 on PR #122: 503 is a server failure, not
        // an authorization denial. Aligned with the REST auth
        // classifier's 5xx→"error" branch so operators can
        // filter transient overload apart from permission
        // problems on the same ledger.
        assert_eq!(outcome.decision(), "error");
        assert!(outcome.required_scope().is_none());

        let err = outcome
            .into_result("oxidhome://blobs/foo/bar")
            .expect_err("Busy must surface as an Err");
        assert_eq!(err.code, RESOURCE_BUSY_CODE);
        assert!(
            err.message.contains("too many concurrent reads"),
            "reason must reach the caller: {err:?}",
        );
    }

    /// Round-6 F1 on PR #122: `encode` refuses bodies past
    /// [`super::MAX_TEXT_BODY_BYTES`] BEFORE returning
    /// `OkText`, so the reviewer's inflation vector (inner JSON
    /// re-escaped by rmcp's outer envelope) can't push a
    /// nominal ceiling response past the transport cap.
    #[test]
    fn encode_refuses_oversize_body() {
        use serde::Serialize;
        // A tuple-struct wrapper around a `String` serializes
        // to `size + 2` bytes (opening/closing quotes).
        // Passing a raw string just past the cap generates a
        // body just past the cap without allocating hundreds
        // of MiB in the test itself.
        #[derive(Serialize)]
        struct Big<'a>(&'a str);
        let payload = "x".repeat(super::MAX_TEXT_BODY_BYTES + 4);
        let outcome = super::encode(&Big(&payload), "over-cap-test");
        assert!(
            matches!(&outcome, ReadOutcome::TooLarge(reason) if reason.contains("over-cap-test")),
            "expected TooLarge naming the resource; got wrong outcome variant",
        );
        // And the outcome maps to the 413 audit status +
        // dedicated JSON-RPC code end-to-end.
        assert_eq!(outcome.status(), 413);
        let err = outcome
            .into_result("oxidhome://events")
            .expect_err("must surface as Err");
        assert_eq!(err.code, RESOURCE_TOO_LARGE_CODE);
    }

    /// Round-7 F2 on PR #122: `CappedWriter` refuses to grow
    /// past its cap and reports `WriteZero` on the first
    /// over-cap write. That's the mechanism that keeps
    /// `serde_json::to_writer` from allocating the entire
    /// response before the encode helper's gate can see it —
    /// an unbounded per-row field can no longer let an
    /// oversize body reach the `guard_body_size` shape.
    #[test]
    fn capped_writer_refuses_past_cap() {
        use std::io::Write as _;
        let mut w = super::CappedWriter::with_cap(8);
        w.write_all(b"12345").expect("under cap");
        // 5 + 4 > 8 → refused, and no bytes appended.
        let err = w.write_all(b"6789").expect_err("past cap");
        assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(
            w.into_string().expect("valid utf8"),
            "12345",
            "no bytes may be appended after the write that hit the cap",
        );
    }

    /// Round-8 F1 on PR #122: the blob cap must comfortably
    /// hold the base64 encoding of the maximum raw blob the
    /// store admits. Base64 inflates raw bytes by a factor
    /// of `ceil(4/3)` (padded to a multiple of 4). A 4 MiB
    /// raw blob encodes to ~5.34 MiB — [`MAX_BLOB_BODY_BYTES`]
    /// (5.5 MiB) must fit that, or else valid blobs allowed
    /// by [`BLOB_INLINE_MAX_BYTES`] get refused after the
    /// full read + encode has already run.
    ///
    /// Boundary check: encoded size of `BLOB_INLINE_MAX_BYTES`
    /// **plus** the max mime **plus** the envelope budget must
    /// fit under the blob-response cap, and the blob-response
    /// cap must fit under the transport-level cap.
    ///
    /// Round-9 F1 on PR #122 added the mime + envelope terms —
    /// pre-fix, only the base64 body was checked, so a plugin
    /// with an over-long mime could push a valid 4 MiB blob
    /// past the transport ceiling and get truncated mid-stream.
    #[test]
    fn blob_cap_fits_max_raw_blob_encoded() {
        let raw =
            usize::try_from(super::BLOB_INLINE_MAX_BYTES).expect("cap fits in usize on this arch");
        // base64 (no-newlines, padded) length formula:
        // `4 * ceil(raw / 3)`
        let encoded = 4 * raw.div_ceil(3);
        let projected = encoded + super::MAX_BLOB_MIME_BYTES + super::BLOB_ENVELOPE_OVERHEAD_BYTES;
        assert!(
            projected <= super::MAX_BLOB_BODY_BYTES,
            "projected {projected} B (base64 {encoded} + mime {} + envelope {}) \
             must fit under blob cap {} B (raw {raw} B)",
            super::MAX_BLOB_MIME_BYTES,
            super::BLOB_ENVELOPE_OVERHEAD_BYTES,
            super::MAX_BLOB_BODY_BYTES,
        );
        // And the blob cap itself must fit under the
        // transport-level ceiling (base64 has no
        // JSON-escape inflation, so no headroom multiplier).
        let transport = usize::try_from(crate::api::mcp::server::MAX_RESPONSE_BODY_BYTES)
            .expect("transport cap fits in usize on this arch");
        assert!(
            super::MAX_BLOB_BODY_BYTES < transport,
            "blob cap ({}) must fit under the transport cap ({transport})",
            super::MAX_BLOB_BODY_BYTES,
        );
    }
}

fn parse_opt_u64(query: &HashMap<String, String>, key: &str) -> Result<Option<u64>, String> {
    match query.get(key) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("invalid `{key}` value `{raw}`; expected unsigned integer")),
    }
}

fn clamp_limit(query: &HashMap<String, String>, default: u32, max: u32) -> Result<u32, String> {
    let Some(raw) = query.get("limit") else {
        return Ok(default);
    };
    let n: u32 = raw
        .parse()
        .map_err(|_| format!("invalid `limit` value `{raw}`; expected unsigned integer"))?;
    Ok(n.clamp(1, max))
}

/// Pre-serialization ceiling on a resource-read body — the
/// JSON string this handler hands to rmcp as the
/// [`ResourceContents::text`] payload. Rmcp then embeds that
/// string in an outer JSON-RPC envelope (which re-escapes every
/// `"`, `\`, and control byte in our JSON), and wraps the whole
/// thing in SSE framing before it hits the wire.
///
/// Pre-serialization ceiling for **text** resource bodies —
/// JSON we hand to rmcp as the [`ResourceContents::text`]
/// payload. The transport-level ceiling
/// ([`crate::api::mcp::server::MAX_RESPONSE_BODY_BYTES`]) is
/// 8 MiB. This cap is set to `3.5 MiB` so worst-case escape
/// inflation stays under the transport cap:
///
/// - A byte that becomes `\uXXXX` after JSON escape (control
///   char, some non-ASCII) inflates 1 → 6, but such bytes
///   are rare in practice.
/// - The realistic worst case is `"` → `\"` and `\` → `\\`
///   (1 → 2, i.e. `2×`) on a quote/backslash-heavy body.
/// - `3.5 MiB × 2` = 7 MiB, leaves ~1 MiB headroom for the
///   JSON-RPC envelope + SSE framing under the 8 MiB
///   transport ceiling.
///
/// Round-7 F1 on PR #122 lowered this from 6 MiB after the
/// reviewer showed a 6 MiB escape-heavy body could inflate
/// past 8 MiB and force [`crate::api::mcp::server::PermitBody`]
/// to truncate a response that had already been audited as
/// a success.
const MAX_TEXT_BODY_BYTES: usize = 3_670_016; // 3.5 * 1024 * 1024

/// Pre-serialization ceiling for **blob** resource bodies —
/// the base64-encoded string we hand to rmcp as the
/// [`ResourceContents::blob`] payload. Distinct from
/// [`MAX_TEXT_BODY_BYTES`] because base64's alphabet
/// (`A-Za-z0-9+/=`) contains ZERO JSON-escape-worthy
/// characters, so the outer JSON-RPC envelope inflates a
/// base64 string 1× — no factor to reserve headroom for.
///
/// Sized to comfortably fit the store-side cap
/// [`BLOB_INLINE_MAX_BYTES`] (4 MiB raw → `ceil(4/3 * 4 MiB)`
/// ≈ 5.34 MiB base64) plus a small margin for the JSON-RPC
/// envelope and SSE framing under the 8 MiB transport
/// ceiling. Round-8 F1 on PR #122 split this out of
/// [`MAX_TEXT_BODY_BYTES`] — pre-fix, a valid 3 MiB blob
/// (base64 ≈ 4 MiB) hit the text cap and was refused with
/// 413, contradicting the advertised 4 MiB blob range.
const MAX_BLOB_BODY_BYTES: usize = 5_767_168; // 5.5 * 1024 * 1024

fn encode<T: Serialize>(value: &T, what: &'static str) -> ReadOutcome {
    // Round-7 F2 on PR #122: `serde_json::to_string` allocates
    // the ENTIRE body before we can measure it — so a single
    // unbounded field on one row (a plugin's structured log
    // `fields` blob, a custom event payload) can consume
    // arbitrary memory even though the completed body would
    // then be refused. `serde_json::to_writer` on a
    // [`CappedWriter`] fails at the exact byte the cap is
    // reached, before more bytes are appended.
    //
    // The writer's buffer is what ends up in `OkText` — we
    // don't re-allocate after the cap check, and the peak
    // memory this handler holds is bounded by
    // [`MAX_TEXT_BODY_BYTES`] + 1 byte (the byte that
    // tripped the cap).
    let mut writer = CappedWriter::with_cap(MAX_TEXT_BODY_BYTES);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => match writer.into_string() {
            Ok(body) => ReadOutcome::OkText {
                body,
                mime: "application/json",
            },
            Err(err) => {
                tracing::error!(%err, what, "MCP resource body was not valid UTF-8");
                ReadOutcome::Internal(format!("failed to serialize {what}"))
            }
        },
        Err(err) if err.io_error_kind() == Some(std::io::ErrorKind::WriteZero) => {
            tracing::warn!(
                what,
                cap = MAX_TEXT_BODY_BYTES,
                "MCP resource body exceeded pre-serialization cap — refusing read",
            );
            ReadOutcome::TooLarge(format!(
                "MCP `{what}` body exceeds the per-response cap ({MAX_TEXT_BODY_BYTES} bytes). \
                 Narrow the query (smaller `limit`, tighter filter) and retry.",
            ))
        }
        Err(err) => {
            tracing::error!(%err, what, "MCP resource serialization failed");
            ReadOutcome::Internal(format!("failed to serialize {what}"))
        }
    }
}

/// Round-1 F2 on PR #124: tools/call reuse of the capped
/// serialiser. The tool path needs the parsed [`JsonValue`]
/// for `CallToolResult.structuredContent`, whereas
/// [`encode`] delivers a raw JSON `String` bound for
/// [`ResourceContents::text`]. `encode_body_capped` runs the
/// same [`CappedWriter`]-bounded serialisation and returns
/// one of three named shapes so the tool layer can map
/// them to its own outcome enum without opening this
/// module's `ReadOutcome` (which carries resource-side
/// semantics the tool layer doesn't want).
pub(super) enum EncodedBody {
    Value(serde_json::Value),
    /// Body exceeded [`MAX_TEXT_BODY_BYTES`]; the reason
    /// string is caller-facing and names the tool.
    TooLarge(String),
    /// Serialisation failed for a reason other than the cap
    /// (bad UTF-8, serde error). The reason is caller-facing
    /// enough to identify the tool but hides the internal
    /// error surface.
    SerializeFailed(String),
}

pub(super) fn encode_body_capped<T: Serialize>(value: &T, what: &'static str) -> EncodedBody {
    let mut writer = CappedWriter::with_cap(MAX_TEXT_BODY_BYTES);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => {
            let bytes = writer.into_bytes();
            // Parse-back to a `JsonValue`. Peak memory during
            // this call is `bytes.len() + tree size` ≈ 2 ×
            // MAX_TEXT_BODY_BYTES (7 MiB). Well under the
            // mount's 128 MiB `PENDING_BODY_GATE * MAX` bound.
            match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => EncodedBody::Value(v),
                Err(err) => {
                    tracing::error!(%err, what, "MCP tool body parse-back failed");
                    EncodedBody::SerializeFailed(format!("failed to re-parse {what}"))
                }
            }
        }
        Err(err) if err.io_error_kind() == Some(std::io::ErrorKind::WriteZero) => {
            tracing::warn!(
                what,
                cap = MAX_TEXT_BODY_BYTES,
                "MCP tool body exceeded pre-serialization cap — refusing call",
            );
            EncodedBody::TooLarge(format!(
                "MCP `{what}` body exceeds the per-response cap ({MAX_TEXT_BODY_BYTES} bytes). \
                 Narrow the query (smaller `limit`, tighter filter) and retry.",
            ))
        }
        Err(err) => {
            tracing::error!(%err, what, "MCP tool serialization failed");
            EncodedBody::SerializeFailed(format!("failed to serialize {what}"))
        }
    }
}

/// [`std::io::Write`] that refuses to grow past a byte
/// ceiling — the exact machinery `encode` uses to keep an
/// oversize row from allocating hundreds of MiB before the
/// pre-serialization gate can see it (round-7 F2 on PR #122).
/// The first write past the cap returns
/// [`std::io::ErrorKind::WriteZero`], which `serde_json`
/// propagates as an I/O error; the caller detects that kind
/// and surfaces a clean [`ReadOutcome::TooLarge`].
struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
}

impl CappedWriter {
    fn with_cap(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
        }
    }

    fn into_string(self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.buf)
    }

    /// Return the raw bytes without a UTF-8 check. Callers
    /// that immediately parse the buffer as JSON
    /// (`serde_json::from_slice`) can skip the UTF-8 hop —
    /// `serde_json` validates encoding itself.
    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(chunk.len()) > self.cap {
            // Signal "would grow past the cap" without
            // partially appending — `serde_json::to_writer`
            // treats `WriteZero` as a fatal error and stops
            // serializing, so no additional bytes accumulate.
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "resource body would exceed MAX_TEXT_BODY_BYTES",
            ));
        }
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
