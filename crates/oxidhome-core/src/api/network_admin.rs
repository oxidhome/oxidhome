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
/// `<surface>.plugin.network_grant.<set|reset>:<plugin_id>:<detail>`,
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
            actor_kind: "api",
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
        "{}.{AUDIT_PATH_NETWORK_GRANT}.{verb}:{plugin_id}:{detail}",
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
                    registry.set_network_grant(&id, Some(&new)).map_err(|e| {
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
        let (restarted, not_restarted) = if before.effective == change.network.effective {
            (Vec::new(), Vec::new())
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

/// Stop the running top-level instances of `row`'s installation (their
/// script sandboxes stop with them) and start each again with the
/// config it had. Called under the plugin's lifecycle lock.
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
                && !h.state().is_terminal()
                && h.installation_uuid()
                    .is_none_or(|uuid| *uuid == *row.installation_uuid)
        })
        .collect();
    let overrides: std::collections::HashMap<String, Option<toml::Value>> = handles
        .iter()
        .map(|h| (h.instance_id().to_owned(), h.start_overrides()))
        .collect();
    let report = crate::runtime::stop_and_wait_reaped(handles, crate::STOP_WAIT_LIMIT).await;
    let mut not_restarted: Vec<NotRestarted> = report
        .still_stopping
        .into_iter()
        .map(|instance_id| NotRestarted {
            instance_id,
            reason: "still stopping; start it again once stopped".to_owned(),
        })
        .collect();
    let mut restarted = Vec::new();
    for instance_id in report.stopped {
        let config = overrides.get(&instance_id).cloned().flatten();
        match engine
            .start_installed_instance(
                row.path.clone(),
                instance_id.clone(),
                config,
                std::sync::Arc::clone(&row.installation_uuid),
            )
            .await
        {
            Ok(_) => restarted.push(instance_id),
            Err(err) => {
                tracing::error!(
                    target: "host.network",
                    instance_id = %instance_id,
                    error = %format!("{err:#}"),
                    "restart after a network grant change failed",
                );
                not_restarted.push(NotRestarted {
                    instance_id,
                    reason: format!("restart failed: {err:#}"),
                });
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
