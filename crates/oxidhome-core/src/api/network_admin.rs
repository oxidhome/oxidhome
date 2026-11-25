//! Phase 8: operator surfaces for TLS certificate pins
//! ([`crate::state::TlsPinStore`]).
//!
//! - `oxidhome tls-pin list [<instance>]` / `oxidhome tls-pin reset
//!   <instance> [<host> [<port>]]` / `reset --all` — offline, under the
//!   exclusive state-dir lock, like the `token` commands; a reset leaves a
//!   two-phase `LOCAL` audit row (actor `cli`).
//! - `GET /api/v1/network/tls-pins[?instance_id=…]` (`instances:list`) and
//!   `DELETE /api/v1/network/tls-pins?instance_id=…[&host=…[&port=…]]` (or `?all=true`)
//!   (owner token, `policy.manage`), and the Connect `NetworkService`.
//! - MCP lists them (`oxidhome://network/tls-pins`), read-only.
//!
//! And for plugins' network grants (Phase 8.5), [`change_network_grant`]
//! behind `PUT` / `DELETE /api/v1/plugins/{plugin_id}/network-grant`, the
//! Connect `SetPluginNetworkGrant` / `ResetPluginNetworkGrant`, the MCP
//! `plugins.set_network_grant` / `plugins.reset_network_grant` tools
//! (all `policy.manage`, the owner token), and
//! [`set_network_grant_offline`] behind the offline `oxidhome plugin
//! grant`.

use oxidhome_manifest::NetworkRule;
use serde::Serialize;

use super::bootstrap::{audited, audited_call};
pub use crate::state::NetworkGrantError;
use crate::state::{
    AuditLog, Db, NetworkGrantChange, NetworkGrants, PinFilter, TlsPin, TlsPinStore,
};

/// Audit `path` prefix of a pin reset (`…:<scope>`, see
/// [`PinFilter::scope`]).
pub const AUDIT_PATH_RESET_TLS_PINS: &str = "cli.network.reset_tls_pins";

/// One pin as the JSON API and MCP render it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TlsPinView {
    /// Instance that made the request.
    pub instance_id: String,
    /// Host as the request named it.
    pub host: String,
    /// Port.
    pub port: u16,
    /// SHA-256 of the pinned leaf certificate, lowercase hex.
    pub sha256: String,
    /// When it was pinned, Unix milliseconds.
    pub pinned_ms: i64,
    /// The plugin installation whose instance made it.
    pub installation_uuid: String,
}

impl From<TlsPin> for TlsPinView {
    fn from(pin: TlsPin) -> Self {
        Self {
            instance_id: pin.key.instance_id,
            host: pin.key.host,
            port: pin.key.port,
            sha256: pin.fingerprint.to_hex(),
            pinned_ms: pin.pinned_ms,
            installation_uuid: pin.installation_uuid,
        }
    }
}

/// The filter of a reset: an instance (and maybe a host and port), or
/// `all` alone. A reset must say which, so a dropped or misspelled field
/// can't widen it to every pin.
///
/// # Errors
///
/// A message naming what is missing or contradictory.
pub fn reset_filter(filter: PinFilter, all: bool) -> Result<PinFilter, String> {
    let filter = filter.validated()?;
    match (filter.instance_id.is_some(), all) {
        (true, false) | (false, true) => Ok(filter),
        (false, false) => Err("name an instance, or reset all pins explicitly".into()),
        (true, true) => Err("`all` resets every pin; it takes no other filter".into()),
    }
}

/// Remove the pins `filter` selects, audited in `audit` as the CLI.
///
/// # Errors
///
/// A storage or audit failure.
pub fn reset_tls_pins(
    audit: &AuditLog,
    pins: &TlsPinStore,
    filter: &PinFilter,
) -> anyhow::Result<Vec<TlsPin>> {
    let path = format!("{AUDIT_PATH_RESET_TLS_PINS}:{}", filter.scope());
    audited(audit, "cli", "-", &path, || {
        pins.reset(filter)
            .map_err(|e| anyhow::anyhow!("removing TLS pins: {e}"))
    })
}

// ── Plugin network grants (Phase 8.5) ───────────────────────────────

/// Audit `path` of a network grant change:
/// `<surface>.plugin.network_grant.<set|reset>/<plugin_id>/<detail>`,
/// `/`-separated so the audit scrubber never reads the plugin id as a
/// `key: value` key (`com.example.secret:{…}` would mask the detail),
/// the detail being [`NetworkGrantChange::audit_detail`] (installation,
/// old and new granted rules).
pub const AUDIT_PATH_NETWORK_GRANT: &str = "plugin.network_grant";

/// Who asks for a grant change, for its audit row.
#[derive(Debug, Clone)]
pub struct GrantActor {
    /// `api`, `connect`, `mcp` or `cli`.
    pub surface: &'static str,
    /// The audit row's `actor_kind`.
    pub actor_kind: &'static str,
    /// The audit row's `token_id`: the caller's token, `-` for the CLI.
    pub token_id: String,
    /// The request's call id.
    pub call_id: Option<String>,
}

impl GrantActor {
    /// The actor of a request through `surface` (`api`, `connect`,
    /// `mcp`) under `ctx`.
    #[must_use]
    pub fn of(surface: &'static str, ctx: &crate::auth::InvocationContext) -> Self {
        Self {
            surface,
            actor_kind: ctx.root().kind().as_str(),
            token_id: ctx.root().audit_token_id().to_owned(),
            call_id: Some(ctx.call_id().to_owned()),
        }
    }
}

/// A grant change as every surface returns it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkGrantView {
    /// The plugin.
    pub plugin_id: String,
    /// Its network rules after the change, as the plugin listings show
    /// them.
    pub network: NetworkGrants,
    /// Instances restarted so they run under the new grant.
    pub restarted: Vec<String>,
    /// Instances that were running but didn't restart, with why: still
    /// stopping past the wait limit (they stop, and pick the grant up
    /// when started again), or the start failed.
    pub not_restarted: Vec<NotRestarted>,
}

/// One instance a grant change didn't restart.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NotRestarted {
    /// The instance.
    pub instance_id: String,
    /// Why.
    pub reason: String,
}

/// Parse the rules of a grant request, in manifest syntax.
///
/// # Errors
///
/// The first rule that doesn't parse, with why.
pub fn parse_grant_rules(rules: &[String]) -> Result<Vec<NetworkRule>, String> {
    rules
        .iter()
        .map(|r| {
            r.parse::<NetworkRule>()
                .map_err(|e| format!("rule `{r}` is not a network rule: {e}"))
        })
        .collect()
}

fn audit_path(by: &GrantActor, plugin_id: &str, reset: bool, detail: &str) -> String {
    let verb = if reset { "reset" } else { "set" };
    format!(
        "{}.{AUDIT_PATH_NETWORK_GRANT}.{verb}/{plugin_id}/{detail}",
        by.surface
    )
}

/// Set (or with `rules = None` reset to the manifest's request) the
/// network grant of installed plugin `plugin_id`, then, when that
/// changes the effective rules, restart its running instances so they
/// run under it at once.
///
/// Runs on its own task, so a caller that goes away (a client
/// disconnect) can't leave the grant stored and its instances
/// stopped. Holds the plugin's lifecycle lock throughout: no install,
/// uninstall or start interleaves. The grant is checked first (a
/// refusal leaves no row), then stored under a two-phase audit row
/// carrying the old and new grant. Restarting rather than swapping the
/// policy in place closes the sockets, HTTP connections and remembered
/// name resolutions the old grant allowed.
///
/// # Errors
///
/// [`NetworkGrantError`]: not installed, a rule outside the request,
/// too many rules, or the store or audit failed.
pub async fn change_network_grant(
    engine: crate::Engine,
    by: GrantActor,
    plugin_id: String,
    rules: Option<Vec<NetworkRule>>,
) -> Result<NetworkGrantView, NetworkGrantError> {
    let task_plugin_id = plugin_id.clone();
    tokio::spawn(async move {
        let lock = engine.plugin_lifecycle_lock(&plugin_id);
        let _guard = lock.lock().await;
        let registry = engine.installed_plugins();
        let row = registry
            .get(&plugin_id)
            .ok_or_else(|| NetworkGrantError::NotInstalled(plugin_id.clone()))?;
        // Checked before the audit intent, so a refusal writes no row
        // (the request's own row records it).
        let new = crate::state::narrowed_network_grant(&row.requested_network, rules.as_deref())?;
        let detail = NetworkGrantChange {
            installation_uuid: std::sync::Arc::clone(&row.installation_uuid),
            old: row.granted_capabilities.network.clone(),
            network: NetworkGrants::new(&row.requested_network, &new),
        }
        .audit_detail();
        let path = audit_path(&by, &plugin_id, rules.is_none(), &detail);
        let audit = engine.audit_log();
        let id = plugin_id.clone();
        let change = tokio::task::spawn_blocking(move || {
            let mut refused = None;
            let out = audited_call(
                &audit,
                by.actor_kind,
                &by.token_id,
                &path,
                by.call_id.as_deref(),
                || {
                    // The same inputs as the check above, so the row,
                    // the store and the answer agree.
                    registry
                        .set_network_grant(&id, rules.as_deref())
                        .map_err(|e| {
                            let msg = e.to_string();
                            refused = Some(e);
                            anyhow::anyhow!(msg)
                        })
                },
            );
            match (out, refused) {
                (Ok(change), _) => Ok(change),
                (Err(_), Some(e)) => Err(e),
                (Err(e), None) => Err(NetworkGrantError::Unavailable(id, format!("{e:#}"))),
            }
        })
        .await
        .map_err(|e| NetworkGrantError::Unavailable(plugin_id.clone(), e.to_string()))??;
        tracing::warn!(
            target: "host.network",
            plugin_id = %plugin_id,
            granted = change.network.granted.len(),
            effective = change.network.effective.len(),
            "plugin network grant changed",
        );
        // Only a change to what instances get needs a restart.
        let before = NetworkGrants::new(&row.requested_network, &row.granted_capabilities.network);
        let (restarted, not_restarted) = if same_rules(&before.effective, &change.network.effective)
        {
            // Nothing to restart, but an instance an earlier change
            // still waits on is still running under the old rules.
            (Vec::new(), still_stopping(&engine, &plugin_id))
        } else {
            restart_instances(&engine, &plugin_id, &row).await
        };
        Ok(NetworkGrantView {
            plugin_id,
            network: change.network,
            restarted,
            not_restarted,
        })
    })
    .await
    .map_err(|e| {
        NetworkGrantError::Unavailable(task_plugin_id, format!("grant task failed: {e}"))
    })?
}

/// Whether two effective rule lists grant the same, ignoring order and
/// case (the policy compares names case-insensitively).
fn same_rules(a: &[NetworkRule], b: &[NetworkRule]) -> bool {
    let canonical = |rules: &[NetworkRule]| {
        let mut out: Vec<String> = rules
            .iter()
            .map(|r| r.to_string().to_ascii_lowercase())
            .collect();
        out.sort();
        out.dedup();
        out
    };
    canonical(a) == canonical(b)
}

/// Top-level instances of `plugin_id` asked to stop that haven't been
/// reaped yet.
fn still_stopping(engine: &crate::Engine, plugin_id: &str) -> Vec<NotRestarted> {
    engine
        .instances()
        .list()
        .into_iter()
        .filter(|h| {
            h.plugin_id() == plugin_id && h.parent_instance_id().is_none() && h.stop_requested()
        })
        .map(|h| NotRestarted {
            instance_id: h.instance_id().to_owned(),
            reason: "still stopping; start it again once stopped".to_owned(),
        })
        .collect()
}

/// What a grant change found an instance doing before it stopped it.
enum Before {
    /// Running (or loading): restart it with these config overrides.
    Running(Option<toml::Value>),
    /// Already asked to stop (an operator's stop in flight): leave it.
    Stopping,
    /// Already ended; waited for only so its sandboxes are gone.
    Ended,
}

/// How long a grant change waits for its restarted instances to run.
pub const RESTART_WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Stop the running top-level instances of `row`'s installation (their
/// script sandboxes stop with them) and start each again with the
/// config it had, waiting (at most [`RESTART_WAIT_LIMIT`], all
/// together) until they run. Called under the plugin's lifecycle lock.
///
/// An instance already asked to stop (an operator's stop in flight) is
/// left stopped. A parent that already ended is waited for too, so its
/// sandboxes, which its reaper stops, are gone before this returns, but
/// isn't started again.
async fn restart_instances(
    engine: &crate::Engine,
    plugin_id: &str,
    row: &crate::state::InstalledPlugin,
) -> (Vec<String>, Vec<NotRestarted>) {
    let handles: Vec<_> = engine
        .instances()
        .list()
        .into_iter()
        .filter(|h| {
            h.plugin_id() == plugin_id
                && h.parent_instance_id().is_none()
                && h.installation_uuid()
                    .is_none_or(|uuid| *uuid == *row.installation_uuid)
        })
        .collect();
    // Decided before this asks them to stop.
    let mut plan: std::collections::HashMap<String, Before> = handles
        .iter()
        .map(|h| {
            let before = if h.state().is_terminal() {
                Before::Ended
            } else if h.stop_requested() {
                Before::Stopping
            } else {
                Before::Running(h.start_overrides())
            };
            (h.instance_id().to_owned(), before)
        })
        .collect();
    let report = crate::runtime::stop_and_wait_reaped(handles, crate::STOP_WAIT_LIMIT).await;
    let mut not_restarted: Vec<NotRestarted> = report
        .still_stopping
        .into_iter()
        .map(|instance_id| NotRestarted {
            reason: match plan.remove(&instance_id) {
                Some(Before::Running(_)) => "still stopping; start it again once stopped",
                Some(Before::Stopping) => "was already stopping, and still is",
                Some(Before::Ended) | None => "had ended; its sandboxes are still stopping",
            }
            .to_owned(),
            instance_id,
        })
        .collect();
    // Start them all, then wait for them together, under one deadline
    // that covers the starts too, so one slow instance doesn't hold the
    // others down.
    let deadline = tokio::time::Instant::now() + RESTART_WAIT_LIMIT;
    let mut starting = Vec::new();
    for instance_id in report.stopped {
        let Some(Before::Running(config)) = plan.remove(&instance_id) else {
            continue;
        };
        let start = engine.start_installed_instance(
            row.path.clone(),
            instance_id.clone(),
            config,
            std::sync::Arc::clone(&row.installation_uuid),
        );
        match tokio::time::timeout_at(deadline, start).await {
            Ok(Ok(handle)) => starting.push(handle),
            Ok(Err(err)) => not_restarted.push(NotRestarted {
                instance_id,
                reason: format!("restart failed: {err:#}"),
            }),
            Err(_) => not_restarted.push(NotRestarted {
                instance_id,
                reason: format!(
                    "not started {} s after the stop; start it again",
                    RESTART_WAIT_LIMIT.as_secs()
                ),
            }),
        }
    }
    let (mut restarted, failed) = wait_running(starting, deadline).await;
    not_restarted.extend(failed);
    restarted.sort();
    not_restarted.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    (restarted, not_restarted)
}

/// Wait for `starting` to run, together, until `deadline`:
/// the ones that did, and the ones that failed or are still starting.
async fn wait_running(
    starting: Vec<crate::runtime::InstanceHandle>,
    deadline: tokio::time::Instant,
) -> (Vec<String>, Vec<NotRestarted>) {
    let mut not_restarted = Vec::new();
    let mut waits = tokio::task::JoinSet::new();
    for handle in starting {
        waits.spawn(async move {
            let id = handle.instance_id().to_owned();
            match tokio::time::timeout_at(deadline, handle.wait_for_running()).await {
                Ok(Ok(())) => (id, Ok(())),
                Ok(Err(err)) => (id, Err(format!("restart failed: {err:#}"))),
                Err(_) => (
                    id,
                    Err(format!(
                        "not running {} s after the restart; still starting",
                        RESTART_WAIT_LIMIT.as_secs()
                    )),
                ),
            }
        });
    }
    let mut restarted = Vec::new();
    while let Some(joined) = waits.join_next().await {
        match joined {
            Ok((instance_id, Ok(()))) => restarted.push(instance_id),
            Ok((instance_id, Err(reason))) => {
                tracing::error!(
                    target: "host.network",
                    instance_id = %instance_id,
                    reason = %reason,
                    "restart after a network grant change didn't reach running",
                );
                not_restarted.push(NotRestarted {
                    instance_id,
                    reason,
                });
            }
            Err(err) => {
                tracing::error!(target: "host.network", error = %err, "restart wait task failed");
            }
        }
    }
    (restarted, not_restarted)
}

/// The offline `oxidhome plugin grant`: set (or with `rules = None`
/// reset) the network grant of installed plugin `plugin_id` under a
/// `cli` audit row carrying the old and new grant. Nothing runs while
/// the daemon is stopped; its next start loads the new grant.
///
/// # Errors
///
/// As [`crate::state::plan_network_grant_offline`], or the store or
/// audit failed.
pub fn set_network_grant_offline(
    plugins_root: &std::path::Path,
    audit: &AuditLog,
    db: &Db,
    plugin_id: &str,
    rules: Option<&[NetworkRule]>,
) -> anyhow::Result<NetworkGrantChange> {
    // Planned first, so a refusal writes no row and the row carries
    // the change. The daemon is stopped and the lock held, so nothing
    // changes in between.
    let plan = crate::state::plan_network_grant_offline(plugins_root, db, plugin_id, rules)?;
    let by = GrantActor {
        surface: "cli",
        actor_kind: "cli",
        token_id: "-".to_owned(),
        call_id: None,
    };
    let path = audit_path(&by, plugin_id, rules.is_none(), &plan.change.audit_detail());
    audited(audit, "cli", "-", &path, || Ok(plan.commit(db)?))?;
    Ok(plan.change)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit scrubber masks `key: value` pairs under sensitive-looking
    /// keys; a plugin id that looks like one must not hide the grant.
    #[test]
    fn a_sensitive_looking_plugin_id_keeps_the_audit_detail() {
        let by = GrantActor {
            surface: "api",
            actor_kind: "api",
            token_id: "t".to_owned(),
            call_id: None,
        };
        let detail = serde_json::json!({
            "installation": "inst-0123",
            "old": ["https://api.example.com"],
            "new": [],
        })
        .to_string();
        for id in ["com.example.secret", "acme.api_token", "x.password"] {
            let path = audit_path(&by, id, false, &detail);
            assert_eq!(crate::redact::scrub_text(&path), path, "{id}");
        }
        // A rule naming a sensitive-looking host keeps its port.
        let rule = |r: &str| r.parse::<NetworkRule>().unwrap();
        let change = NetworkGrantChange {
            installation_uuid: "inst-0123".into(),
            old: vec![rule("tcp://secrets.lan:*")],
            network: NetworkGrants::new(
                &[rule("tcp://secrets.lan:*")],
                &[rule("tcp://secrets.lan:1883")],
            ),
        };
        let path = audit_path(&by, "x.y", false, &change.audit_detail());
        assert_eq!(crate::redact::scrub_text(&path), path);
        let detail: serde_json::Value =
            serde_json::from_str(path.splitn(3, '/').nth(2).unwrap()).unwrap();
        assert_eq!(
            detail,
            serde_json::json!({
                "installation": "inst-0123",
                "old": [rule("tcp://secrets.lan:*").to_string()],
                "new": ["tcp://secrets.lan:1883"],
            })
        );
    }
}
