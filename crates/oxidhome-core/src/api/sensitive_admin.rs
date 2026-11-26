//! H6 slice 2: operator tooling for sensitive categories.
//!
//! - `oxidhome token list` — every token with its owner flag, scopes
//!   and sensitive grants.
//! - `oxidhome token grant-sensitive <token-id> <category>
//!   [--device <id>]...` / `revoke-sensitive <token-id> <category>` —
//!   edit a token's explicit sensitive grants
//!   ([`crate::auth::SensitiveGrant`]).
//! - `oxidhome device set-category <device-id> <category>|--clear` —
//!   the operator's category raise (also `PUT
//!   /api/v1/devices/{id}/category` for the owner token).
//!
//! Like `recover-admin-token`, the CLI forms run offline: they take the
//! exclusive state-dir lock, so they refuse while the daemon or an
//! `mcp-stdio` session is up. Each change leaves a two-phase `LOCAL`
//! audit row (actor `cli`).
//!
//! [`sensitive_access_report`] is the startup check: it names every
//! live non-owner token whose `*`, `devices:command` or `blobs:read`
//! scope spans sensitive categories (lock, opener and alarm
//! commands, camera bytes) that its grants, or its roles' grants,
//! don't fully cover.

use std::path::Path;

use anyhow::Context;

use super::bootstrap::{AUDIT_METHOD_LOCAL, audited};
use crate::auth::{
    DeviceCategory, SensitiveCategory, SensitiveGrant, SensitiveSet, TokenPolicy, parse_policy,
};
use crate::state::{AuditLog, DeviceMetaRow, TokenRecord, TokenStore};

/// Audit `path` prefix of a sensitive grant (`…:<category>`).
pub const AUDIT_PATH_GRANT_SENSITIVE: &str = "cli.auth.grant_sensitive";
/// Audit `path` prefix of a sensitive revoke (`…:<category>`).
pub const AUDIT_PATH_REVOKE_SENSITIVE: &str = "cli.auth.revoke_sensitive";
/// Audit `path` prefix of a category override (`…:<category|clear>`).
/// The row's `token_id` column holds the device id.
pub const AUDIT_PATH_DEVICE_CATEGORY: &str = "cli.device.category";

/// Longest device pattern a grant may carry, in bytes.
const MAX_DEVICE_PATTERN_LEN: usize = 64;
/// Most device patterns one grant may carry.
const MAX_DEVICE_PATTERNS: usize = 64;

/// One live token whose broad scopes span sensitive categories its
/// grants don't fully cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveGap {
    /// Token id.
    pub token_id: String,
    /// Token label.
    pub label: String,
    /// Categories its scopes span that its grants (or its roles'
    /// grants) don't fully cover.
    pub missing: SensitiveSet,
}

/// Which sensitive categories `scopes` would reach if a scope alone
/// were enough.
fn reached_by(scopes: &[String]) -> SensitiveSet {
    let has = |s: &str| scopes.iter().any(|x| x == "*" || x == s);
    let mut set = SensitiveSet::empty();
    if has("devices:command") {
        for c in [
            SensitiveCategory::Lock,
            SensitiveCategory::Opener,
            SensitiveCategory::Alarm,
        ] {
            set.insert(c);
        }
    }
    if has("blobs:read") {
        set.insert(SensitiveCategory::Camera);
    }
    set
}

/// The tokens [`sensitive_access_report`] would name, from records.
/// `role_sensitive` maps a role id to the sensitive categories its
/// definition grants on every device; a token holding such a role is
/// covered for them.
#[must_use]
pub fn sensitive_gaps<S: std::hash::BuildHasher>(
    records: &[TokenRecord],
    role_sensitive: &std::collections::HashMap<String, SensitiveSet, S>,
) -> Vec<SensitiveGap> {
    records
        .iter()
        .filter(|r| r.revoked_ms.is_none() && !r.owner)
        .filter_map(|r| {
            let policy = parse_policy(&r.scope_json)?;
            // The devices its commands can reach: the token's
            // `device.send_command` allowlist, if it has one.
            let command_devices = policy
                .constraints
                .get("device.send_command")
                .and_then(|c| c.devices.as_deref());
            let covered = |c: SensitiveCategory| {
                if policy
                    .roles
                    .iter()
                    .any(|id| role_sensitive.get(id).is_some_and(|s| s.contains(c)))
                {
                    return true;
                }
                let grants = policy.sensitive.iter().filter(|g| g.category == c);
                if grants.clone().any(|g| g.devices.is_none()) {
                    return true;
                }
                // Command grants that together cover every allowlist
                // pattern cover everything the token reaches.
                let granted: Vec<String> =
                    grants.filter_map(|g| g.devices.clone()).flatten().collect();
                // No allowlist: the token reaches every device id.
                let every = ["dev-*".to_owned()];
                let allowed: &[String] = command_devices.unwrap_or(&every);
                c.guards_commands() && allowed.iter().all(|a| pattern_covers(&granted, a))
            };
            let reached = reached_by(&policy.scopes);
            let missing: SensitiveSet = reached
                .iter()
                .filter(|c| !(c.guards_commands() && command_devices.is_some_and(<[_]>::is_empty)))
                .filter(|c| !covered(*c))
                .collect();
            (!missing.is_empty()).then(|| SensitiveGap {
                token_id: r.id.clone(),
                label: r.label.clone(),
                missing,
            })
        })
        .collect()
}

/// `true` when some pattern in `granted` matches every id `pattern`
/// can: the same pattern, or a `prefix*` that `pattern` starts with.
/// Both sides are read in the device-id space, so `*` and `dev-*`
/// match the same ids.
fn pattern_covers(granted: &[String], pattern: &str) -> bool {
    let pattern = in_id_space(pattern);
    granted.iter().any(|g| {
        let g = in_id_space(g);
        g == pattern
            || g.strip_suffix('*')
                .is_some_and(|prefix| pattern.starts_with(prefix))
    })
}

/// `pattern` as the device ids it can match: a `prefix*` whose prefix
/// every id starts with (`*`, `d*`, ... `dev-*`) is `dev-*`.
fn in_id_space(pattern: &str) -> &str {
    match pattern.strip_suffix('*') {
        Some(prefix) if "dev-".starts_with(prefix) => "dev-*",
        _ => pattern,
    }
}

/// Startup check: log at `warn` every live non-owner token whose
/// `*` / `devices:command` / `blobs:read` scope spans locks, openers,
/// alarms or camera bytes that its grants don't fully cover, and how
/// to grant them. Returns what it logged.
pub fn sensitive_access_report(tokens: &TokenStore) -> Vec<SensitiveGap> {
    let records = match tokens.list() {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(target: "auth.sensitive", error = %err, "listing tokens for the sensitive-access check failed");
            return Vec::new();
        }
    };
    let role_sensitive = match tokens.roles() {
        Ok(roles) => roles
            .into_iter()
            .filter_map(|r| {
                let def = r.def()?;
                Some((r.id, def.sensitive.into_iter().collect::<SensitiveSet>()))
            })
            .collect(),
        Err(err) => {
            tracing::error!(target: "auth.sensitive", error = %err, "listing roles for the sensitive-access check failed");
            std::collections::HashMap::<String, SensitiveSet>::new()
        }
    };
    let gaps = sensitive_gaps(&records, &role_sensitive);
    if !records.is_empty() && !records.iter().any(|r| r.owner && r.revoked_ms.is_none()) {
        tracing::warn!(
            target: "auth.sensitive",
            "no live owner token: nothing holds sensitive categories by default; mint one \
             offline with `oxidhome recover-admin-token` (it revokes the current admin \
             tokens) or grant categories with `oxidhome token grant-sensitive`",
        );
    }
    for gap in &gaps {
        tracing::warn!(
            target: "auth.sensitive",
            token_id = %gap.token_id,
            label = %gap.label,
            missing = %gap.missing.to_csv(),
            "token's broad scopes span sensitive categories its grants don't fully cover \
             (lock, opener and alarm commands and camera bytes need an explicit grant); grant \
             with `oxidhome token grant-sensitive <token-id> <category>`",
        );
    }
    gaps
}

fn live_policy(tokens: &TokenStore, token_id: &str) -> anyhow::Result<TokenPolicy> {
    let rec = tokens
        .get(token_id)
        .context("reading the token")?
        .filter(|r| r.revoked_ms.is_none())
        .ok_or_else(|| anyhow::anyhow!("no live token `{token_id}`"))?;
    if rec.owner {
        anyhow::bail!(
            "token `{token_id}` is the owner token: it holds every sensitive category and its \
             grants can't be edited; rotate it with `oxidhome recover-admin-token`"
        );
    }
    parse_policy(&rec.scope_json).ok_or_else(|| {
        anyhow::anyhow!(
            "token `{token_id}` has a policy the host can't parse (it is treated as deny-all); \
             refusing to rewrite it"
        )
    })
}

pub(crate) fn check_devices(devices: &[String]) -> anyhow::Result<()> {
    if devices.len() > MAX_DEVICE_PATTERNS {
        anyhow::bail!("at most {MAX_DEVICE_PATTERNS} --device patterns");
    }
    for d in devices {
        if !crate::state::is_device_pattern(d) || d.len() > MAX_DEVICE_PATTERN_LEN {
            anyhow::bail!(
                "device pattern {d:?} must be a device id (dev-<16 hex>) or a `prefix*` of one \
                 (omit --device to grant every device)"
            );
        }
    }
    Ok(())
}

/// `policy` with `category` granted: on every device (`devices` empty)
/// or added to the category's device list. A category already granted
/// on every device stays that way.
#[must_use]
pub fn with_grant(
    mut policy: TokenPolicy,
    category: SensitiveCategory,
    devices: &[String],
) -> TokenPolicy {
    let existing: Vec<SensitiveGrant> = policy
        .sensitive
        .iter()
        .filter(|g| g.category == category)
        .cloned()
        .collect();
    policy.sensitive.retain(|g| g.category != category);
    let all = devices.is_empty() || existing.iter().any(|g| g.devices.is_none());
    let grant = if all {
        SensitiveGrant::all(category)
    } else {
        let mut list: Vec<String> = existing
            .into_iter()
            .flat_map(|g| g.devices.unwrap_or_default())
            .chain(devices.iter().cloned())
            .collect();
        list.sort();
        list.dedup();
        SensitiveGrant {
            category,
            devices: Some(list),
        }
    };
    policy.sensitive.push(grant);
    policy.sensitive.sort_by_key(|g| g.category);
    policy
}

/// Grant `category` to `token_id` (every device, or the `devices`
/// patterns). Returns the policy as stored.
///
/// # Errors
///
/// Unknown or revoked token, an unparseable stored policy, a bad
/// device pattern, or a storage / audit failure.
pub fn grant_sensitive(
    tokens: &TokenStore,
    audit: &AuditLog,
    token_id: &str,
    category: SensitiveCategory,
    devices: &[String],
) -> anyhow::Result<TokenPolicy> {
    check_devices(devices)?;
    let policy = with_grant(live_policy(tokens, token_id)?, category, devices);
    // The merged list, not just this call's patterns, stays in bounds.
    for grant in &policy.sensitive {
        if let Some(list) = &grant.devices {
            check_devices(list)?;
        }
    }
    let path = format!("{AUDIT_PATH_GRANT_SENSITIVE}:{}", category.as_str());
    audited(audit, "cli", token_id, &path, || {
        store(tokens, token_id, &policy)?;
        Ok(())
    })?;
    tracing::warn!(
        target: "auth.sensitive",
        token_id,
        category = category.as_str(),
        devices = ?devices,
        "sensitive grant added",
    );
    Ok(policy)
}

/// Remove every grant of `category` from `token_id`. Returns the policy
/// as stored.
///
/// # Errors
///
/// As [`grant_sensitive`].
pub fn revoke_sensitive(
    tokens: &TokenStore,
    audit: &AuditLog,
    token_id: &str,
    category: SensitiveCategory,
) -> anyhow::Result<TokenPolicy> {
    let mut policy = live_policy(tokens, token_id)?;
    policy.sensitive.retain(|g| g.category != category);
    let path = format!("{AUDIT_PATH_REVOKE_SENSITIVE}:{}", category.as_str());
    audited(audit, "cli", token_id, &path, || {
        store(tokens, token_id, &policy)?;
        Ok(())
    })?;
    Ok(policy)
}

fn store(tokens: &TokenStore, token_id: &str, policy: &TokenPolicy) -> anyhow::Result<()> {
    if tokens
        .set_policy(token_id, &policy.to_json())
        .context("storing the token policy")?
    {
        Ok(())
    } else {
        anyhow::bail!("token `{token_id}` was revoked meanwhile")
    }
}

/// The stores the offline `token` / `device` / `tls-pin` commands touch, opened
/// straight on the database: no engine, so listing tokens or raising
/// a category doesn't run engine startup (device-state revision bump,
/// pending-command resolution) while the daemon is stopped.
pub struct OfflineStores {
    /// The token table.
    pub tokens: TokenStore,
    /// The audit ledger.
    pub audit: crate::state::AuditLog,
    /// The `device_meta` table.
    pub devices: crate::state::DeviceMetaStore,
    /// The `network_tls_pin` table (Phase 8.2).
    pub tls_pins: crate::state::TlsPinStore,
    /// The database itself, for tables without a store. Private, so
    /// no handle outlives the state-dir lock: see [`Self::db`].
    db: std::sync::Arc<crate::state::Db>,
}

impl OfflineStores {
    /// The database itself, for tables without a store
    /// (`plugin_installation`), borrowed for the callback.
    #[must_use]
    pub fn db(&self) -> &crate::state::Db {
        &self.db
    }
}

/// Run `op` against the stores of the database under `state_dir`,
/// holding the exclusive state-dir lock (the daemon must be stopped).
///
/// # Errors
///
/// No database, the lock is held, the database won't open, or `op`
/// failed.
pub fn with_offline_stores<T>(
    state_dir: &Path,
    op: impl FnOnce(&OfflineStores) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let (_lock, db) = open_offline(state_dir)?;
    let db = std::sync::Arc::new(db);
    let stores = OfflineStores {
        tokens: TokenStore::new(std::sync::Arc::clone(&db)),
        audit: crate::state::AuditLog::new(std::sync::Arc::clone(&db)),
        devices: crate::state::DeviceMetaStore::open(std::sync::Arc::clone(&db))
            .context("reading device_meta")?,
        tls_pins: crate::state::TlsPinStore::open(std::sync::Arc::clone(&db))
            .context("reading TLS pins")?,
        db,
    };
    op(&stores)
}

/// Run `op` against the bare database under `state_dir`, with the same
/// lock and schema check as [`with_offline_stores`] but no stores
/// loaded: for read-only listings that have none (`oxidhome plugin
/// list`).
///
/// # Errors
///
/// No database, the lock is held, the database won't open, or `op`
/// failed.
pub fn with_offline_db<T>(
    state_dir: &Path,
    op: impl FnOnce(&crate::state::Db) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let (_lock, db) = open_offline(state_dir)?;
    op(&db)
}

/// Take the exclusive state-dir lock, check the schema, and open the
/// database. The guard must outlive every use of the handle.
fn open_offline(state_dir: &Path) -> anyhow::Result<(std::fs::File, crate::state::Db)> {
    if !state_dir.join(crate::state::db::DB_FILE_NAME).exists() {
        anyhow::bail!(
            "no oxidhome database under {} (set $OXIDHOME_STATE_DIR to the daemon's state dir)",
            state_dir.display(),
        );
    }
    let lock = crate::exclusive_lock::acquire_state_dir_lock(state_dir)
        .context("this command needs exclusive access — stop the daemon first")?;
    // Migrations are the daemon's to run: refuse a database at any
    // other schema version before opening it.
    let path = state_dir.join(crate::state::db::DB_FILE_NAME);
    let version: i64 =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .and_then(|c| c.pragma_query_value(None, "user_version", |r| r.get(0)))
            .with_context(|| format!("reading the schema version of {}", path.display()))?;
    if version != crate::state::db::schema_version() {
        anyhow::bail!(
            "the database is at schema {version}, this binary expects {}; start the daemon \
             once to upgrade it, stop it, then run this command again",
            crate::state::db::schema_version(),
        );
    }
    let db = crate::state::Db::open_file(state_dir)
        .with_context(|| format!("opening the database under {}", state_dir.display()))?;
    Ok((lock, db))
}

/// Set (or with `None` clear) the operator's category raise for
/// `device_id` in `devices`, audited in `audit`. The owner recorded
/// with it comes from the device's persisted state or events. Returns
/// the stored row.
///
/// # Errors
///
/// A malformed device id, or a storage / audit failure.
pub fn set_device_category(
    audit: &crate::state::AuditLog,
    devices: &crate::state::DeviceMetaStore,
    device_id: &str,
    category: Option<DeviceCategory>,
) -> anyhow::Result<DeviceMetaRow> {
    if !crate::state::is_device_id(device_id) {
        anyhow::bail!("`{device_id}` is not a device id (expected `dev-` and 16 hex digits)");
    }
    let path = format!(
        "{AUDIT_PATH_DEVICE_CATEGORY}:{}",
        category.map_or("clear", DeviceCategory::as_str)
    );
    audited(audit, "cli", device_id, &path, || {
        devices
            .set_override(device_id, category, None)
            .context("storing the category override")
    })
}

/// `method` of every row this module writes.
pub const AUDIT_METHOD: &str = AUDIT_METHOD_LOCAL;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuditQuery, Db};
    use std::sync::Arc;

    fn stores() -> (TokenStore, AuditLog) {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        (TokenStore::new(Arc::clone(&db)), AuditLog::new(db))
    }

    #[test]
    fn grant_and_revoke_round_trip_through_the_store() {
        let (tokens, audit) = stores();
        let t = tokens.create("ha", br#"["*"]"#).unwrap();
        let p = grant_sensitive(&tokens, &audit, &t.id, SensitiveCategory::Lock, &[]).unwrap();
        assert_eq!(
            p.sensitive,
            vec![SensitiveGrant::all(SensitiveCategory::Lock)]
        );
        let stored = parse_policy(&tokens.get(&t.id).unwrap().unwrap().scope_json).unwrap();
        assert_eq!(stored, p);
        assert_eq!(stored.scopes, vec!["*".to_string()]);

        let p = grant_sensitive(
            &tokens,
            &audit,
            &t.id,
            SensitiveCategory::Opener,
            &["dev-00000000000000aa".into()],
        )
        .unwrap();
        assert_eq!(p.sensitive.len(), 2);

        let p = revoke_sensitive(&tokens, &audit, &t.id, SensitiveCategory::Lock).unwrap();
        assert_eq!(p.sensitive.len(), 1);
        assert_eq!(p.sensitive[0].category, SensitiveCategory::Opener);

        let rows = audit.query(&AuditQuery::default(), 10).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|r| r.method == AUDIT_METHOD && r.decision == "allow")
        );
        assert!(
            rows.iter()
                .any(|r| r.path == "cli.auth.grant_sensitive:lock")
        );
    }

    /// Repeated grants can't grow a device list past the cap.
    #[test]
    fn merged_device_lists_stay_capped() {
        let (tokens, audit) = stores();
        let t = tokens.create("ha", br#"["*"]"#).unwrap();
        let first: Vec<String> = (0..MAX_DEVICE_PATTERNS)
            .map(|i| format!("dev-{i:016x}"))
            .collect();
        grant_sensitive(&tokens, &audit, &t.id, SensitiveCategory::Lock, &first).unwrap();
        let more = vec!["dev-ffffffffffffffff".to_owned()];
        assert!(grant_sensitive(&tokens, &audit, &t.id, SensitiveCategory::Lock, &more).is_err());
    }

    /// The owner's grants aren't editable: it holds every category.
    #[test]
    fn owner_grants_are_refused_before_any_audit_row() {
        let (tokens, audit) = stores();
        let owner = TokenStore::generate();
        assert!(
            tokens
                .insert_owner_if_empty(&owner, "admin", br#"["*"]"#)
                .unwrap()
        );
        assert!(grant_sensitive(&tokens, &audit, &owner.id, SensitiveCategory::Lock, &[]).is_err());
        assert!(revoke_sensitive(&tokens, &audit, &owner.id, SensitiveCategory::Lock).is_err());
        assert_eq!(audit.query(&AuditQuery::default(), 10).unwrap().len(), 0);
    }

    #[test]
    fn grants_merge_device_lists_and_never_narrow_an_all_grant() {
        let base = TokenPolicy::default();
        let p = with_grant(base, SensitiveCategory::Lock, &["dev-b".into()]);
        let p = with_grant(
            p,
            SensitiveCategory::Lock,
            &["dev-a".into(), "dev-b".into()],
        );
        assert_eq!(
            p.sensitive,
            vec![SensitiveGrant {
                category: SensitiveCategory::Lock,
                devices: Some(vec!["dev-a".into(), "dev-b".into()]),
            }]
        );
        let p = with_grant(p, SensitiveCategory::Lock, &[]);
        let p = with_grant(p, SensitiveCategory::Lock, &["dev-c".into()]);
        assert_eq!(
            p.sensitive,
            vec![SensitiveGrant::all(SensitiveCategory::Lock)]
        );
    }

    #[test]
    fn refuses_revoked_unparseable_and_bad_patterns() {
        let (tokens, audit) = stores();
        let t = tokens.create("x", br#"["*"]"#).unwrap();
        assert!(
            grant_sensitive(
                &tokens,
                &audit,
                &t.id,
                SensitiveCategory::Lock,
                &["*".into()]
            )
            .is_err()
        );
        // A truncated literal can never match; its prefix form can.
        let lock = SensitiveCategory::Lock;
        assert!(grant_sensitive(&tokens, &audit, &t.id, lock, &["dev-ab12".into()]).is_err());
        assert!(grant_sensitive(&tokens, &audit, &t.id, lock, &["dev-ab12*".into()]).is_ok());
        assert!(grant_sensitive(&tokens, &audit, &t.id, lock, &["dev-XY*".into()]).is_err());
        tokens.revoke(&t.id).unwrap();
        assert!(grant_sensitive(&tokens, &audit, &t.id, SensitiveCategory::Lock, &[]).is_err());
        let bad = tokens.create("bad", b"not json").unwrap();
        assert!(grant_sensitive(&tokens, &audit, &bad.id, SensitiveCategory::Lock, &[]).is_err());
        assert!(
            grant_sensitive(&tokens, &audit, "tok-missing", SensitiveCategory::Lock, &[]).is_err()
        );
    }

    #[test]
    fn startup_report_names_wildcard_tokens_without_grants() {
        let (tokens, audit) = stores();
        let wildcard = tokens.create("ha", br#"["*"]"#).unwrap();
        let reader = tokens.create("ro", br#"["devices:list"]"#).unwrap();
        let cam = tokens.create("cam", br#"["blobs:read"]"#).unwrap();
        let revoked = tokens.create("old", br#"["*"]"#).unwrap();
        tokens.revoke(&revoked.id).unwrap();
        grant_sensitive(&tokens, &audit, &cam.id, SensitiveCategory::Camera, &[]).unwrap();

        let gaps = sensitive_access_report(&tokens);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].token_id, wildcard.id);
        assert_eq!(gaps[0].missing.to_csv(), "lock,opener,alarm,camera");
        assert!(gaps.iter().all(|g| g.token_id != reader.id));

        // A device-narrowed grant still leaves the category reported.
        grant_sensitive(
            &tokens,
            &audit,
            &wildcard.id,
            SensitiveCategory::Lock,
            &["dev-1*".into()],
        )
        .unwrap();
        let gaps = sensitive_access_report(&tokens);
        assert!(gaps[0].missing.contains(SensitiveCategory::Lock));
    }

    /// A token that can only command some devices is fully covered by
    /// a grant naming those devices.
    #[test]
    fn a_grant_matching_the_command_allowlist_closes_the_gap() {
        let (tokens, audit) = stores();
        let t = tokens
            .create(
                "door",
                br#"{"scopes":["devices:command"],"constraints":{"device.send_command":{"devices":["dev-00000000000000aa"]}}}"#,
            )
            .unwrap();
        let gaps = sensitive_access_report(&tokens);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        grant_sensitive(
            &tokens,
            &audit,
            &t.id,
            SensitiveCategory::Lock,
            &["dev-00000000000000aa".into()],
        )
        .unwrap();
        let gaps = sensitive_access_report(&tokens);
        assert!(
            !gaps[0].missing.contains(SensitiveCategory::Lock),
            "{gaps:?}"
        );
        assert!(gaps[0].missing.contains(SensitiveCategory::Opener));

        // A wider prefix grant covers a narrower allowlist pattern.
        let wide = tokens
            .create(
                "wide",
                br#"{"scopes":["devices:command"],"constraints":{"device.send_command":{"devices":["dev-ab12*"]}}}"#,
            )
            .unwrap();
        grant_sensitive(
            &tokens,
            &audit,
            &wide.id,
            SensitiveCategory::Lock,
            &["dev-ab*".into()],
        )
        .unwrap();
        let gaps = sensitive_access_report(&tokens);
        let gap = gaps
            .iter()
            .find(|g| g.token_id == wide.id)
            .expect("opener still missing");
        assert!(!gap.missing.contains(SensitiveCategory::Lock), "{gap:?}");

        // Without an allowlist, a `dev-*` grant covers every device.
        let all = tokens.create("all", br#"["devices:command"]"#).unwrap();
        grant_sensitive(
            &tokens,
            &audit,
            &all.id,
            SensitiveCategory::Lock,
            &["dev-*".into()],
        )
        .unwrap();
        let gaps = sensitive_access_report(&tokens);
        let gap = gaps
            .iter()
            .find(|g| g.token_id == all.id)
            .expect("opener still missing");
        assert!(!gap.missing.contains(SensitiveCategory::Lock), "{gap:?}");

        // An explicit `*` allowlist is the same id space as `dev-*`.
        let star = tokens
            .create(
                "star",
                br#"{"scopes":["devices:command"],"constraints":{"device.send_command":{"devices":["*"]}}}"#,
            )
            .unwrap();
        grant_sensitive(
            &tokens,
            &audit,
            &star.id,
            SensitiveCategory::Lock,
            &["dev-*".into()],
        )
        .unwrap();
        let gaps = sensitive_access_report(&tokens);
        let gap = gaps
            .iter()
            .find(|g| g.token_id == star.id)
            .expect("opener still missing");
        assert!(!gap.missing.contains(SensitiveCategory::Lock), "{gap:?}");

        // An empty allowlist reaches no device at all.
        let none = tokens
            .create(
                "none",
                br#"{"scopes":["devices:command"],"constraints":{"device.send_command":{"devices":[]}}}"#,
            )
            .unwrap();
        let gaps = sensitive_access_report(&tokens);
        assert!(gaps.iter().all(|g| g.token_id != none.id), "{gaps:?}");
    }
}
