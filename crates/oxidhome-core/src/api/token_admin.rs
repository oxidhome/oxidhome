//! H6 slice 3: minting and listing tokens by role.
//!
//! One validation and one storage path for every surface that mints a
//! token:
//!
//! - `oxidhome token create <label> --role <role> ...` (offline CLI);
//! - `POST /api/v1/tokens` and Connect `TokensService.CreateToken`,
//!   which [`crate::auth::authorize()`] allows for `token.manage`, i.e.
//!   for the owner token only. MCP has no mint tool: M7 keeps
//!   credentials out of MCP responses.
//!
//! Listing (`oxidhome token list`, `GET /api/v1/tokens`, Connect
//! `TokensService.ListTokens`, MCP `tokens.list`) goes through
//! [`summaries`]. No surface ever returns a secret other than the one
//! it just minted, and the store keeps only its hash.
//!
//! A minted token is never the owner: `owner` is not an assignable
//! role, and only the first-run bootstrap and `recover-admin-token`
//! mint the owner. Each mint leaves a two-phase audit row whose
//! `token_id` is the new token and whose `path` is
//! `<surface>.auth.mint:<roles or "scopes">`.

use serde::{Deserialize, Serialize};

use super::bootstrap::{ADMIN_TOKEN_LABEL, audited_call};
use super::sensitive_admin::check_devices;
use crate::auth::{
    Action, ActionSet, DenyRule, DeviceCategory, Role, SensitiveCategory, SensitiveGrant,
    TokenPolicy, parse_policy,
};
use crate::state::{AuditLog, TokenRecord, TokenStore};

/// Audit `path` suffix of a mint (`<surface>.auth.mint:<roles>`).
pub const AUDIT_PATH_MINT: &str = "auth.mint";

/// Longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
/// Most entries in each list of a mint request.
pub const MAX_LIST: usize = 32;

/// What to mint. Shared by every surface; the JSON form is the body of
/// `POST /api/v1/tokens`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRequest {
    /// Operator-facing name. Not `admin`, which `recover-admin-token`
    /// revokes.
    pub label: String,
    /// Role presets (`admin`, `resident`, `guest`, `dashboard`,
    /// `monitor`, `assistant`).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Flat scopes (`devices:read`, ..., or `*`), on top of the roles.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Sensitive categories (`lock`, `opener`, `alarm`, `camera`),
    /// granted on every device. For a grant narrowed to devices, leave
    /// the category out here and add it with `oxidhome token
    /// grant-sensitive <id> <category> --device <dev-id>`.
    #[serde(default)]
    pub sensitive: Vec<String>,
    /// The token's deny list.
    #[serde(default)]
    pub deny: Vec<DenySpec>,
}

/// One deny entry of a [`MintRequest`]: the wire shape of a
/// [`DenyRule`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenySpec {
    /// Action names (`device.command`) or `*`.
    pub actions: Vec<String>,
    /// Device categories; absent for every resource.
    #[serde(default)]
    pub category: Option<Vec<String>>,
    /// Device ids or `prefix*` patterns; absent for every device.
    #[serde(default)]
    pub devices: Option<Vec<String>>,
}

/// Why a mint was refused.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    /// The request is malformed: a 400 / `invalid_argument` /
    /// `invalid_params`, with this message.
    #[error("{0}")]
    Invalid(String),
    /// The token couldn't be stored or audited.
    #[error("storing the token failed: {0}")]
    Store(String),
}

fn invalid(msg: impl Into<String>) -> MintError {
    MintError::Invalid(msg.into())
}

/// A freshly minted token: the only copy of its secret. Its `Debug`
/// masks the secret.
pub struct Minted {
    /// The new token's id.
    pub token_id: String,
    /// The bearer secret. Shown once; the host keeps only its hash.
    pub secret: String,
    /// The stored policy, as listed.
    pub summary: TokenSummary,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted")
            .field("token_id", &self.token_id)
            .field("secret", &crate::redact::REDACTED)
            .field("summary", &self.summary)
            .finish()
    }
}

/// Every scope name a token can hold, and `*`.
fn known_scope(name: &str) -> bool {
    name == "*"
        || Action::ALL
            .iter()
            .filter_map(|a| a.legacy_scope())
            .any(|s| s.name() == name)
}

fn check_len<T>(what: &str, list: &[T]) -> Result<(), MintError> {
    if list.len() > MAX_LIST {
        return Err(invalid(format!("at most {MAX_LIST} {what}")));
    }
    Ok(())
}

/// Validate `req` and build the policy it stores.
///
/// # Errors
///
/// [`MintError::Invalid`] naming the first problem.
pub fn build_policy(req: &MintRequest) -> Result<TokenPolicy, MintError> {
    let label = req.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err(invalid(format!(
            "`label` must be 1 to {MAX_LABEL_CHARS} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(invalid("`label` must not contain control characters"));
    }
    if label == ADMIN_TOKEN_LABEL {
        return Err(invalid(
            "`admin` is reserved for the owner token (`recover-admin-token` revokes tokens \
             with that label); pick another label",
        ));
    }
    check_len("roles", &req.roles)?;
    check_len("scopes", &req.scopes)?;
    check_len("sensitive categories", &req.sensitive)?;
    check_len("deny entries", &req.deny)?;
    if req.roles.is_empty() && req.scopes.is_empty() {
        return Err(invalid("name at least one role or scope"));
    }
    let mut roles = Vec::new();
    for name in &req.roles {
        let role: Role = name.parse().map_err(|e| invalid(format!("{e}")))?;
        if !role.assignable() {
            return Err(invalid(
                "`owner` is not assignable: the owner is the bootstrap / recovered token",
            ));
        }
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    let mut scopes = Vec::new();
    for scope in &req.scopes {
        if !known_scope(scope) {
            return Err(invalid(format!("unknown scope `{scope}`")));
        }
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    let mut sensitive: Vec<SensitiveGrant> = Vec::new();
    for name in &req.sensitive {
        let category: SensitiveCategory = name.parse().map_err(|e| invalid(format!("{e}")))?;
        if !sensitive.iter().any(|g| g.category == category) {
            sensitive.push(SensitiveGrant::all(category));
        }
    }
    sensitive.sort_by_key(|g| g.category);
    let deny = req
        .deny
        .iter()
        .map(deny_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let policy = TokenPolicy {
        scopes,
        sensitive,
        roles,
        deny,
        ..TokenPolicy::default()
    };
    // What is stored must read back as itself: the bearer middleware
    // treats an unparseable policy as deny-all.
    if parse_policy(&policy.to_json()).as_ref() != Some(&policy) {
        return Err(invalid("the policy does not round-trip"));
    }
    Ok(policy)
}

fn deny_rule(spec: &DenySpec) -> Result<DenyRule, MintError> {
    if spec.actions.is_empty() {
        return Err(invalid("a deny entry needs at least one action (or `*`)"));
    }
    let actions = ActionSet::parse(spec.actions.iter().map(String::as_str))
        .map_err(|e| invalid(format!("{e}")))?;
    let categories = match &spec.category {
        None => None,
        Some(list) if list.is_empty() => {
            return Err(invalid("a deny entry's `category` must not be empty"));
        }
        Some(list) => Some(
            list.iter()
                .map(|c| c.parse::<DeviceCategory>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid(format!("{e}")))?,
        ),
    };
    let devices = match &spec.devices {
        None => None,
        Some(list) if list.is_empty() => {
            return Err(invalid("a deny entry's `devices` must not be empty"));
        }
        Some(list) => {
            check_devices(list).map_err(|e| invalid(format!("{e:#}")))?;
            Some(list.clone())
        }
    };
    Ok(DenyRule {
        actions,
        categories,
        devices,
    })
}

/// Mint a token for `req`, audited as `surface` (`cli`, `api`,
/// `connect`, `mcp`) with `actor_kind` in the row. Blocking.
///
/// # Errors
///
/// [`MintError::Invalid`] for a bad request; [`MintError::Store`] when
/// the row or its audit couldn't be written.
pub fn mint(
    tokens: &TokenStore,
    audit: &AuditLog,
    surface: &str,
    actor_kind: &str,
    call_id: Option<&str>,
    req: &MintRequest,
) -> Result<Minted, MintError> {
    let policy = build_policy(req)?;
    let label = req.label.trim();
    let issued = TokenStore::generate();
    let what = if policy.roles.is_empty() {
        "scopes".to_owned()
    } else {
        policy
            .roles
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let path = format!("{surface}.{AUDIT_PATH_MINT}:{what}");
    audited_call(audit, actor_kind, &issued.id, &path, call_id, || {
        tokens
            .insert(&issued, label, &policy.to_json())
            .map_err(anyhow::Error::from)
    })
    .map_err(|e| MintError::Store(format!("{e:#}")))?;
    tracing::warn!(
        target: "auth.token",
        token_id = %issued.id,
        label,
        surface,
        roles = %what,
        "token minted",
    );
    let record = tokens
        .get(&issued.id)
        .ok()
        .flatten()
        .ok_or_else(|| MintError::Store("the new token is not readable".into()))?;
    Ok(Minted {
        token_id: issued.id,
        secret: issued.plaintext,
        summary: TokenSummary::of(&record),
    })
}

/// One token as listed: never its secret or hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenSummary {
    /// Token id.
    pub token_id: String,
    /// Label.
    pub label: String,
    /// `true` for the bootstrap / recovered owner token.
    pub owner: bool,
    /// `true` once revoked.
    pub revoked: bool,
    /// Role names; `["owner"]` for the owner.
    pub roles: Vec<String>,
    /// Flat scopes.
    pub scopes: Vec<String>,
    /// Sensitive grants: `lock`, or `camera[dev-a1* dev-b2*]` when
    /// narrowed to devices. Every category for the owner.
    pub sensitive: Vec<String>,
    /// Deny entries, as `actions@categories[devices]`.
    pub deny: Vec<String>,
    /// Creation time, Unix ms.
    pub created_ms: i64,
    /// Last use, Unix ms (coarse, see `LAST_USED_RESOLUTION_MS`).
    pub last_used_ms: Option<i64>,
    /// `false` when the stored policy doesn't parse: the token is
    /// deny-all.
    pub policy_valid: bool,
}

impl TokenSummary {
    /// The summary of one stored token.
    #[must_use]
    pub fn of(record: &TokenRecord) -> Self {
        let policy = parse_policy(&record.scope_json);
        let policy_valid = policy.is_some();
        let policy = policy.unwrap_or_default();
        let mut roles: Vec<String> = policy.roles.iter().map(|r| r.as_str().into()).collect();
        let sensitive = if record.owner {
            roles.insert(0, Role::Owner.as_str().into());
            SensitiveCategory::ALL
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect()
        } else {
            policy
                .sensitive
                .iter()
                .map(|g| match &g.devices {
                    None => g.category.as_str().to_owned(),
                    Some(d) => format!("{}[{}]", g.category.as_str(), d.join(" ")),
                })
                .collect()
        };
        Self {
            token_id: record.id.clone(),
            label: record.label.clone(),
            owner: record.owner,
            revoked: record.revoked_ms.is_some(),
            roles,
            scopes: policy.scopes,
            sensitive,
            deny: policy.deny.iter().map(DenyRule::describe).collect(),
            created_ms: record.created_ms,
            last_used_ms: record.last_used_ms,
            policy_valid,
        }
    }
}

/// Every token, oldest first. Blocking.
///
/// # Errors
///
/// The store's read error.
pub fn summaries(tokens: &TokenStore) -> Result<Vec<TokenSummary>, crate::state::TokenError> {
    Ok(tokens.list()?.iter().map(TokenSummary::of).collect())
}

/// One role preset as listed by `oxidhome token roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleSummary {
    /// Role name.
    pub role: &'static str,
    /// What it grants, in one line.
    pub description: &'static str,
    /// Actions its grants name.
    pub actions: Vec<&'static str>,
    /// `false` for `owner`.
    pub assignable: bool,
}

/// Every role preset.
#[must_use]
pub fn roles() -> Vec<RoleSummary> {
    Role::ALL
        .iter()
        .map(|r| RoleSummary {
            role: r.as_str(),
            description: r.description(),
            actions: r.actions().iter().map(Action::as_str).collect(),
            assignable: r.assignable(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuditQuery, Db};
    use std::sync::Arc;

    fn stores() -> (TokenStore, AuditLog) {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        (TokenStore::new(Arc::clone(&db)), AuditLog::new(db))
    }

    fn req(label: &str, roles: &[&str]) -> MintRequest {
        MintRequest {
            label: label.into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            ..MintRequest::default()
        }
    }

    #[test]
    fn mint_stores_a_role_token_that_verifies() {
        let (tokens, audit) = stores();
        let mut r = req("kitchen tablet", &["dashboard"]);
        r.deny = vec![DenySpec {
            actions: vec!["device.command".into()],
            category: None,
            devices: Some(vec!["dev-a1*".into()]),
        }];
        r.sensitive = vec!["camera".into()];
        let m = mint(&tokens, &audit, "cli", "cli", None, &r).expect("mint");
        let rec = tokens.verify(&m.secret).expect("verifies");
        assert_eq!(rec.id, m.token_id);
        assert!(!rec.owner);
        let policy = parse_policy(&rec.scope_json).expect("parses");
        assert_eq!(policy.roles, vec![Role::Dashboard]);
        assert_eq!(policy.scopes, Vec::<String>::new());
        assert_eq!(m.summary.roles, vec!["dashboard"]);
        assert_eq!(m.summary.deny, vec!["device.command[dev-a1*]"]);
        assert_eq!(m.summary.sensitive, vec!["camera"]);
        let rows = audit.query(&AuditQuery::default(), 10).expect("audit");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_id, m.token_id);
        assert_eq!(rows[0].path, "cli.auth.mint:dashboard");
        assert_eq!(rows[0].decision, "allow");
    }

    #[test]
    fn bad_requests_are_refused_before_anything_is_stored() {
        let (tokens, audit) = stores();
        let cases: Vec<(MintRequest, &str)> = vec![
            (req("", &["monitor"]), "label"),
            (req("admin", &["monitor"]), "reserved"),
            (req("a\nb", &["monitor"]), "control"),
            (req("x", &[]), "at least one role or scope"),
            (req("x", &["owner"]), "not assignable"),
            (req("x", &["root"]), "unknown role"),
            (
                MintRequest {
                    scopes: vec!["devices:*".into()],
                    ..req("x", &[])
                },
                "unknown scope",
            ),
            (
                MintRequest {
                    sensitive: vec!["door".into()],
                    ..req("x", &["resident"])
                },
                "unknown category",
            ),
            (
                MintRequest {
                    deny: vec![DenySpec::default()],
                    ..req("x", &["resident"])
                },
                "at least one action",
            ),
            (
                MintRequest {
                    deny: vec![DenySpec {
                        actions: vec!["*".into()],
                        category: Some(vec![]),
                        devices: None,
                    }],
                    ..req("x", &["resident"])
                },
                "must not be empty",
            ),
            (
                MintRequest {
                    deny: vec![DenySpec {
                        actions: vec!["*".into()],
                        category: None,
                        devices: Some(vec!["kitchen".into()]),
                    }],
                    ..req("x", &["resident"])
                },
                "device pattern",
            ),
        ];
        for (r, needle) in cases {
            let err = mint(&tokens, &audit, "cli", "cli", None, &r).expect_err("refused");
            assert!(
                matches!(&err, MintError::Invalid(m) if m.contains(needle)),
                "{r:?}: {err}"
            );
        }
        assert_eq!(tokens.count().unwrap(), 0);
        assert_eq!(audit.count().unwrap(), 0);
    }

    #[test]
    fn summaries_show_the_owner_and_unparseable_policies() {
        let (tokens, _) = stores();
        let issued = TokenStore::generate();
        assert!(
            tokens
                .insert_owner_if_empty(&issued, "admin", br#"["*"]"#)
                .unwrap()
        );
        tokens.create("broken", b"{").unwrap();
        let list = summaries(&tokens).unwrap();
        assert_eq!(list[0].roles, vec!["owner"]);
        assert_eq!(list[0].sensitive.len(), SensitiveCategory::ALL.len());
        assert!(list[0].policy_valid);
        assert!(!list[1].policy_valid);
        assert_eq!(list[1].roles, Vec::<String>::new());
    }

    #[test]
    fn roles_listing_marks_owner_unassignable() {
        let r = roles();
        assert_eq!(r.len(), Role::ALL.len());
        assert!(!r[0].assignable);
        assert!(
            r.iter()
                .skip(1)
                .all(|r| r.assignable && !r.actions.is_empty())
        );
    }
}
