//! H6 slice 5: the owner's deny lists over plugins
//! ([`crate::state::PluginDenyStore`]).
//!
//! [`change_plugin_deny`] sits behind `PUT` / `DELETE
//! /api/v1/plugins/{plugin_id}/deny`, the Connect `SetPluginDeny` /
//! `ResetPluginDeny`, and the MCP `plugins.set_deny` /
//! `plugins.reset_deny` tools; [`set_plugin_deny_offline`] behind the
//! offline `oxidhome plugin deny`. All `policy.manage` (the owner
//! token). Reading the list is `GET /api/v1/plugins/{plugin_id}/deny` /
//! `GetPluginDeny` (`policy.manage` too: the list says what the owner
//! fenced off).
//!
//! A list is keyed by plugin id and may name a plugin that isn't
//! installed; uninstalling the plugin deletes it. The key `*` is the
//! global list, which applies to every plugin. A list applies to the next decision of every running
//! instance: no restart.

use serde::Serialize;

use super::bootstrap::{audited, audited_call};
use super::network_admin::GrantActor;
use super::token_admin::{AdminError, SelectorSpec};
use crate::auth::DenyRule;
use crate::state::plugin_deny::is_deny_key;
use crate::state::{AuditLog, PluginDenyError, PluginDenyStore};

/// Audit `path` of a deny list change:
/// `<surface>.plugin.deny.<set|reset>/<plugin_id>/<detail>`, the detail
/// being the old and new list as JSON.
pub const AUDIT_PATH_PLUGIN_DENY: &str = "plugin.deny";

/// A plugin's deny list as every surface returns it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PluginDenyView {
    /// The plugin.
    pub plugin_id: String,
    /// Its deny entries (empty: none), as token listings show them.
    pub deny: Vec<serde_json::Value>,
}

impl PluginDenyView {
    fn new(plugin_id: String, rules: &[DenyRule]) -> Self {
        Self {
            plugin_id,
            deny: rules.iter().map(DenyRule::to_json).collect(),
        }
    }
}

/// Why a deny list change was refused.
#[derive(Debug, thiserror::Error)]
pub enum PluginDenyAdminError {
    /// The request is malformed: a 400 / `invalid_argument` /
    /// `invalid_params`.
    #[error("{0}")]
    Invalid(String),
    /// Too many plugins with a list: a 409 / `failed_precondition`.
    #[error("{0}")]
    Full(String),
    /// Storing or auditing failed.
    #[error("storing failed: {0}")]
    Store(String),
}

impl From<PluginDenyError> for PluginDenyAdminError {
    fn from(e: PluginDenyError) -> Self {
        match e {
            e @ (PluginDenyError::BadPluginId(_) | PluginDenyError::TooManyEntries) => {
                Self::Invalid(e.to_string())
            }
            e @ PluginDenyError::TooManyLists => Self::Full(e.to_string()),
            PluginDenyError::Sqlite(e) => Self::Store(e.to_string()),
        }
    }
}

/// The deny entries `specs` ask for, each restricted to the actions a
/// plugin takes (`service.call`, `state.read`, `blob.read`,
/// `event.subscribe`; `*` means those).
///
/// # Errors
///
/// A malformed entry, or one naming an action a plugin doesn't take.
pub fn plugin_deny_rules(specs: &[SelectorSpec]) -> Result<Vec<DenyRule>, PluginDenyAdminError> {
    if specs.len() > crate::state::plugin_deny::MAX_PLUGIN_DENY_ENTRIES {
        return Err(PluginDenyError::TooManyEntries.into());
    }
    let rules = super::token_admin::deny_rules(specs).map_err(|e| match e {
        AdminError::Invalid(m) => PluginDenyAdminError::Invalid(m),
        other => PluginDenyAdminError::Store(other.to_string()),
    })?;
    specs
        .iter()
        .zip(rules)
        .map(|(spec, rule)| {
            crate::auth::restrict_to_plugin_actions(&spec.actions, rule).ok_or_else(|| {
                PluginDenyAdminError::Invalid(
                    "a plugin deny entry can only name service.call, state.read, blob.read and \
                     event.subscribe"
                        .into(),
                )
            })
        })
        .collect()
}

fn audit_path(by: &GrantActor, plugin_id: &str, old: &[DenyRule], new: &[DenyRule]) -> String {
    let verb = if new.is_empty() { "reset" } else { "set" };
    let json = |rules: &[DenyRule]| {
        serde_json::Value::Array(rules.iter().map(DenyRule::to_json).collect())
    };
    let detail = serde_json::json!({"old": json(old), "new": json(new)});
    format!(
        "{}.{AUDIT_PATH_PLUGIN_DENY}.{verb}/{plugin_id}/{detail}",
        by.surface
    )
}

/// The deny list of `plugin_id` (empty when none).
///
/// # Errors
///
/// `plugin_id` is neither a plugin id nor `*`.
pub fn plugin_deny(
    store: &PluginDenyStore,
    plugin_id: String,
) -> Result<PluginDenyView, PluginDenyAdminError> {
    if !is_deny_key(&plugin_id) {
        return Err(PluginDenyError::BadPluginId(plugin_id).into());
    }
    let rules = store.get(&plugin_id);
    Ok(PluginDenyView::new(
        plugin_id,
        rules.as_deref().unwrap_or_default(),
    ))
}

/// Replace the deny list of `plugin_id` with `specs` (`None` or an empty
/// list removes it), under a two-phase audit row carrying the old and
/// new list. Applies to the next plugin decision; nothing restarts.
///
/// # Errors
///
/// [`PluginDenyAdminError`]: a malformed entry or plugin id, too many
/// entries or lists, or the store or audit failed.
pub async fn change_plugin_deny(
    engine: crate::Engine,
    by: GrantActor,
    plugin_id: String,
    specs: Option<Vec<SelectorSpec>>,
) -> Result<PluginDenyView, PluginDenyAdminError> {
    let rules = plugin_deny_rules(specs.as_deref().unwrap_or_default())?;
    if !is_deny_key(&plugin_id) {
        return Err(PluginDenyError::BadPluginId(plugin_id).into());
    }
    // Its own task: a client going away can't cut the write short
    // between the audit intent and its outcome.
    tokio::task::spawn_blocking(move || {
        let store = engine.plugin_denies();
        change_in(&engine.audit_log(), &store, &by, &plugin_id, rules)
    })
    .await
    .map_err(|e| PluginDenyAdminError::Store(format!("deny task failed: {e}")))?
}

fn change_in(
    audit: &AuditLog,
    store: &PluginDenyStore,
    by: &GrantActor,
    plugin_id: &str,
    rules: Vec<DenyRule>,
) -> Result<PluginDenyView, PluginDenyAdminError> {
    let view = PluginDenyView::new(plugin_id.to_owned(), &rules);
    let mut refused = None;
    // The old list, the audit row and the write under one writer lock:
    // the row names the list the change replaced.
    let new = rules.clone();
    let out = store.change(plugin_id, rules, |old, commit| {
        let path = audit_path(by, plugin_id, old.unwrap_or_default(), &new);
        audited_call(
            audit,
            by.actor_kind,
            &by.token_id,
            &path,
            by.call_id.as_deref(),
            || {
                commit().map_err(|e| {
                    let msg = e.to_string();
                    refused = Some(e);
                    anyhow::anyhow!(msg)
                })
            },
        )
    })?;
    match (out, refused) {
        (Ok(()), _) => {
            tracing::warn!(
                target: "auth.plugin",
                plugin_id = %plugin_id,
                entries = view.deny.len(),
                "plugin deny list changed",
            );
            Ok(view)
        }
        (Err(_), Some(e)) => Err(e.into()),
        (Err(e), None) => Err(PluginDenyAdminError::Store(format!("{e:#}"))),
    }
}

/// Delete `plugin_id`'s deny list once the plugin is uninstalled, so a
/// reinstall starts with none. Audited as
/// `uninstall.plugin.deny.reset/<plugin_id>/<detail>` under the
/// uninstall's caller (`ctx`; the host when there is none). With
/// `expected`, only that list (the one read before the tombstone) is
/// deleted: a list the owner set for a reinstall in between stays. No
/// list, no row.
///
/// # Errors
///
/// Storing or auditing failed; the list then still applies until the
/// next start removes it ([`crate::Engine`] startup).
pub(crate) fn forget_on_uninstall(
    audit: &AuditLog,
    store: &PluginDenyStore,
    ctx: Option<&crate::auth::InvocationContext>,
    plugin_id: &str,
    expected: Option<&crate::state::PluginDenyList>,
) -> anyhow::Result<()> {
    let by = match ctx {
        Some(ctx) => GrantActor::of("uninstall", ctx),
        None => GrantActor {
            surface: "uninstall",
            actor_kind: "host",
            token_id: "-".to_owned(),
            call_id: None,
        },
    };
    store.change(plugin_id, Vec::new(), |old, commit| {
        let Some(old) = old else {
            return Ok(());
        };
        if expected.is_some_and(|e| !std::ptr::eq(e.as_ptr(), old.as_ptr())) {
            return Ok(());
        }
        let path = audit_path(&by, plugin_id, old, &[]);
        audited_call(
            audit,
            by.actor_kind,
            &by.token_id,
            &path,
            by.call_id.as_deref(),
            || Ok(commit()?),
        )
    })?
}

/// `oxidhome plugin deny`: replace the deny list of `plugin_id` in the
/// offline `store` (`None` or empty removes it), audited as the CLI.
/// The daemon loads it when it next starts.
///
/// # Errors
///
/// A malformed entry or plugin id, too many entries or lists, or the
/// store or audit failed.
pub fn set_plugin_deny_offline(
    audit: &AuditLog,
    store: &PluginDenyStore,
    plugin_id: &str,
    specs: Option<&[SelectorSpec]>,
) -> anyhow::Result<PluginDenyView> {
    let rules = plugin_deny_rules(specs.unwrap_or_default())?;
    if !is_deny_key(plugin_id) {
        return Err(PluginDenyError::BadPluginId(plugin_id.to_owned()).into());
    }
    let by = GrantActor {
        surface: "cli",
        actor_kind: "cli",
        token_id: "-".to_owned(),
        call_id: None,
    };
    let view = PluginDenyView::new(plugin_id.to_owned(), &rules);
    let new = rules.clone();
    store.change(plugin_id, rules, |old, commit| {
        let path = audit_path(&by, plugin_id, old.unwrap_or_default(), &new);
        audited(audit, "cli", "-", &path, || Ok(commit()?))
    })??;
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(actions: &[&str], category: Option<&[&str]>) -> SelectorSpec {
        SelectorSpec {
            actions: actions.iter().map(|a| (*a).to_owned()).collect(),
            category: category.map(|c| c.iter().map(|x| (*x).to_owned()).collect()),
            devices: None,
            services: None,
        }
    }

    #[test]
    fn entries_keep_to_plugin_actions() {
        let rules = plugin_deny_rules(&[spec(&["*"], Some(&["lock"]))]).unwrap();
        assert_eq!(
            rules[0].actions,
            crate::auth::ActionSet::of(&[
                crate::auth::Action::StateRead,
                crate::auth::Action::BlobRead,
                crate::auth::Action::EventSubscribe,
            ])
        );
        for bad in [
            spec(&["device.command"], None),
            spec(&["state.read", "host.logs"], None),
        ] {
            assert!(matches!(
                plugin_deny_rules(&[bad]),
                Err(PluginDenyAdminError::Invalid(_))
            ));
        }
    }

    /// The audit scrubber masks `key: value` pairs; a plugin id that
    /// looks like a secret's key must not hide the list.
    #[test]
    fn a_sensitive_looking_plugin_id_keeps_the_audit_detail() {
        let by = GrantActor {
            surface: "api",
            actor_kind: "api",
            token_id: "t".to_owned(),
            call_id: None,
        };
        let rules = plugin_deny_rules(&[spec(&["state.read"], Some(&["lock"]))]).unwrap();
        for id in ["com.example.secret", "acme.api_token"] {
            let path = audit_path(&by, id, &[], &rules);
            assert_eq!(crate::redact::scrub_text(&path), path, "{id}");
        }
    }
}
