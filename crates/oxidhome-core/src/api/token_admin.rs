//! Roles, and minting and listing tokens by role.
//!
//! One validation and one storage path for every surface:
//!
//! - roles: `oxidhome role list|create|update|delete` (offline CLI),
//!   `GET`/`POST /api/v1/roles`, `PUT`/`DELETE /api/v1/roles/{name}`
//!   and Connect `RolesService`, which [`crate::auth::authorize()`]
//!   allows for `policy.manage`, i.e. for the owner token only;
//! - tokens: `oxidhome token create <label> --role <name> ...`
//!   (offline CLI), `POST /api/v1/tokens` and Connect
//!   `TokensService.CreateToken` (`token.manage`, the owner only). MCP
//!   has no mint tool: M7 keeps credentials out of MCP responses.
//!
//! Listing tokens (`oxidhome token list`, `GET /api/v1/tokens`,
//! Connect `TokensService.ListTokens`, MCP `tokens.list`) goes through
//! [`summaries`]. No surface ever returns a secret other than the one
//! it just minted, and the store keeps only its hash.
//!
//! A token holds its roles by name, so a role edit applies to it from
//! its next request on; a role that live tokens hold can't be deleted.
//! The built-in roles can't be created, edited or deleted. A minted
//! token is never the owner: `owner` is not a role, and only the
//! first-run bootstrap and `recover-admin-token` mint the owner. Every
//! mint and role write leaves a two-phase audit row:
//! `<surface>.auth.mint:<roles>` with the new token's id,
//! `<surface>.auth.role.<create|update|delete>:<name>` with the role's.

use serde::{Deserialize, Serialize};

use super::bootstrap::{ADMIN_TOKEN_LABEL, audited_call};
use crate::auth::role::{OWNER_LABEL, builtin, builtins, is_role_name};
use crate::auth::{GrantWire, RoleDef, RoleGrant};
use crate::state::{AuditLog, TokenRecord, TokenStore};

/// Audit `path` suffix of a mint (`<surface>.auth.mint:<roles>`).
pub const AUDIT_PATH_MINT: &str = "auth.mint";

/// Longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
/// Most roles on a token, and most grants in a role.
pub const MAX_LIST: usize = 32;
pub use crate::state::auth_role::MAX_ROLES;

/// What to mint. Shared by every surface; the JSON form is the body of
/// `POST /api/v1/tokens`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRequest {
    /// Operator-facing name. Not `admin`, which `recover-admin-token`
    /// revokes.
    pub label: String,
    /// Names of the roles the token holds: built-in or custom.
    pub roles: Vec<String>,
}

/// Why a token or role request was refused.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The request is malformed: a 400 / `invalid_argument` /
    /// `invalid_params`, with this message.
    #[error("{0}")]
    Invalid(String),
    /// The token or role couldn't be stored or audited.
    #[error("storing failed: {0}")]
    Store(String),
    /// No role has this name: a 404 / `not_found`.
    #[error("no role named `{0}`")]
    NotFound(String),
    /// The role name is taken: a 409 / `already_exists`.
    #[error("{0}")]
    Exists(String),
    /// A role write conflicts with what is stored (live tokens hold
    /// the role, or the role limit is reached): a 409 /
    /// `failed_precondition`.
    #[error("{0}")]
    Conflict(String),
}

impl From<crate::state::RoleError> for AdminError {
    fn from(err: crate::state::RoleError) -> Self {
        use crate::state::RoleError;
        match err {
            RoleError::NotFound(name) => Self::NotFound(name),
            e @ RoleError::Exists(_) => Self::Exists(e.to_string()),
            e @ (RoleError::InUse { .. } | RoleError::Full) => Self::Conflict(e.to_string()),
            RoleError::Sqlite(e) => Self::Store(e.to_string()),
        }
    }
}

fn invalid(msg: impl Into<String>) -> AdminError {
    AdminError::Invalid(msg.into())
}

/// A freshly minted token: the only copy of its secret. Its `Debug`
/// masks the secret.
pub struct Minted {
    /// The new token's id.
    pub token_id: String,
    /// The bearer secret. Shown once; the host keeps only its hash.
    pub secret: String,
    /// The stored token, as listed.
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

/// Validate a mint request: its trimmed label and its roles, deduped,
/// each built in or stored.
fn check_mint(tokens: &TokenStore, req: &MintRequest) -> Result<Vec<String>, AdminError> {
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
    if req.roles.is_empty() || req.roles.len() > MAX_LIST {
        return Err(invalid(format!("name 1 to {MAX_LIST} roles")));
    }
    let mut roles: Vec<String> = Vec::new();
    for name in &req.roles {
        if name == OWNER_LABEL {
            return Err(invalid(
                "`owner` is not assignable: the owner is the bootstrap / recovered token",
            ));
        }
        if !roles.contains(name) {
            roles.push(name.clone());
        }
    }
    let custom: Vec<String> = roles
        .iter()
        .filter(|r| builtin(r).is_none())
        .cloned()
        .collect();
    let stored = tokens.roles_by_name(&custom)?;
    if let Some(missing) = custom
        .iter()
        .find(|n| !stored.iter().any(|r| &r.name == *n))
    {
        return Err(invalid(format!("unknown role `{missing}`")));
    }
    Ok(roles)
}

/// Mint a token holding `req.roles`. `surface` names the audit path's
/// origin (`cli`, `api`, `connect`) with `actor_kind` in the row.
/// Blocking.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a bad request; [`AdminError::Store`] when
/// the row or its audit couldn't be written.
pub fn mint(
    tokens: &TokenStore,
    audit: &AuditLog,
    surface: &str,
    actor_kind: &str,
    call_id: Option<&str>,
    req: &MintRequest,
) -> Result<Minted, AdminError> {
    let roles = check_mint(tokens, req)?;
    let label = req.label.trim();
    let issued = TokenStore::generate();
    let what = roles.join(",");
    let path = format!("{surface}.{AUDIT_PATH_MINT}:{what}");
    let mut vanished = None;
    let record = audited_call(
        audit,
        actor_kind,
        &issued.id,
        &path,
        call_id,
        || match tokens.insert_with_roles(&issued, label, &roles)? {
            Ok(record) => Ok(record),
            Err(name) => {
                vanished = Some(name);
                anyhow::bail!("role deleted while minting")
            }
        },
    );
    if let Some(name) = vanished {
        return Err(invalid(format!("unknown role `{name}`")));
    }
    let record = record.map_err(|e| AdminError::Store(format!("{e:#}")))?;
    tracing::warn!(
        target: "auth.token",
        token_id = %issued.id,
        label,
        surface,
        roles = %what,
        "token minted",
    );
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
    /// `true` for the bootstrap / recovered owner token, which may do
    /// everything.
    pub owner: bool,
    /// `true` once revoked.
    pub revoked: bool,
    /// Names of the roles the token holds.
    pub roles: Vec<String>,
    /// Creation time, Unix ms.
    pub created_ms: i64,
    /// Last use, Unix ms (coarse, see `LAST_USED_RESOLUTION_MS`).
    pub last_used_ms: Option<i64>,
}

impl TokenSummary {
    /// The summary of one stored token.
    #[must_use]
    pub fn of(record: &TokenRecord) -> Self {
        Self {
            token_id: record.id.clone(),
            label: record.label.clone(),
            owner: record.owner,
            revoked: record.revoked_ms.is_some(),
            roles: record.roles.clone(),
            created_ms: record.created_ms,
            last_used_ms: record.last_used_ms,
        }
    }
}

/// Every token, oldest first. Blocking.
///
/// # Errors
///
/// The store's read error.
pub fn summaries(tokens: &TokenStore) -> Result<Vec<TokenSummary>, AdminError> {
    Ok(tokens
        .list()
        .map_err(|e| AdminError::Store(e.to_string()))?
        .iter()
        .map(TokenSummary::of)
        .collect())
}

/// A role as created on every surface: the body of `POST
/// /api/v1/roles`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRole {
    /// Unique name: 1–32 of `a-z0-9-_`, starting with a letter, not
    /// `owner` or a built-in role's.
    pub name: String,
    /// What the role grants.
    pub grants: Vec<GrantWire>,
}

/// A role's new grants: the body of `PUT /api/v1/roles/{name}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleUpdate {
    /// What the role grants.
    pub grants: Vec<GrantWire>,
}

/// Validate `grants` into the definition stored for a role.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming the first problem.
pub fn build_role(grants: &[GrantWire]) -> Result<Vec<u8>, AdminError> {
    if grants.len() > MAX_LIST {
        return Err(invalid(format!("at most {MAX_LIST} grants")));
    }
    let def = RoleDef::from_wire("", grants.to_vec()).map_err(|e| invalid(e.to_string()))?;
    Ok(def.definition_json())
}

/// A custom role name, not a built-in one's.
fn check_role_name(name: &str) -> Result<(), AdminError> {
    if builtin(name).is_some() {
        return Err(invalid(format!("`{name}` is a built-in role")));
    }
    if is_role_name(name) {
        Ok(())
    } else {
        Err(invalid(format!(
            "role name `{name}` must be 1 to 32 of a-z, 0-9, `-`, `_`, start with a letter, \
             and not be `{OWNER_LABEL}`"
        )))
    }
}

/// One role as listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleSummary {
    /// Name.
    pub name: String,
    /// `true` for a built-in role.
    pub builtin: bool,
    /// Grants, as `actions[@categories][ [devices]]`.
    pub grants: Vec<String>,
    /// Ids of the live tokens holding the role.
    pub tokens: Vec<String>,
    /// Created, Unix ms; `None` for a built-in role.
    pub created_ms: Option<i64>,
    /// Last edited, Unix ms; `None` for a built-in role.
    pub updated_ms: Option<i64>,
}

impl RoleSummary {
    fn of(record: &crate::state::RoleRecord, tokens: Vec<String>) -> Self {
        Self {
            name: record.name.clone(),
            builtin: false,
            grants: describe(record.def().as_ref()),
            tokens,
            created_ms: Some(record.created_ms),
            updated_ms: Some(record.updated_ms),
        }
    }
}

fn describe(def: Option<&RoleDef>) -> Vec<String> {
    def.map_or_else(Vec::new, |d| {
        d.grants.iter().map(RoleGrant::describe).collect()
    })
}

/// Every role: the built-in ones, then the custom ones by name.
/// Blocking.
///
/// # Errors
///
/// [`AdminError::Store`] on a read failure.
pub fn role_summaries(tokens: &TokenStore) -> Result<Vec<RoleSummary>, AdminError> {
    let mut out = builtins()
        .iter()
        .map(|r| {
            Ok(RoleSummary {
                name: r.name.clone(),
                builtin: true,
                grants: describe(Some(r)),
                tokens: tokens.role_holders(&r.name)?,
                created_ms: None,
                updated_ms: None,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    for r in tokens.roles()? {
        let held = tokens.role_holders(&r.name)?;
        out.push(RoleSummary::of(&r, held));
    }
    Ok(out)
}

/// Who writes a role, for its audit row.
#[derive(Debug, Clone, Copy)]
pub struct Audited<'a> {
    /// `cli`, `api`, `connect`.
    pub surface: &'a str,
    /// The audit row's `actor_kind`.
    pub actor_kind: &'a str,
    /// The request's call id, on network writes.
    pub call_id: Option<&'a str>,
}

fn audit_role<T>(
    audit: &AuditLog,
    by: Audited<'_>,
    verb: &str,
    name: &str,
    op: impl FnOnce() -> Result<T, AdminError>,
) -> Result<T, AdminError> {
    let path = format!("{}.auth.role.{verb}:{name}", by.surface);
    let mut refused = None;
    let out = audited_call(audit, by.actor_kind, name, &path, by.call_id, || {
        op().map_err(|e| {
            let msg = e.to_string();
            refused = Some(e);
            anyhow::anyhow!(msg)
        })
    });
    match (out, refused) {
        (Ok(v), _) => {
            tracing::warn!(target: "auth.role", role = name, surface = by.surface, verb, "role written");
            Ok(v)
        }
        (Err(_), Some(e)) => Err(e),
        (Err(e), None) => Err(AdminError::Store(format!("{e:#}"))),
    }
}

/// Create a role. Blocking.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a bad name or definition,
/// [`AdminError::Exists`] for a taken name, [`AdminError::Store`].
pub fn create_role(
    tokens: &TokenStore,
    audit: &AuditLog,
    by: Audited<'_>,
    req: &NewRole,
) -> Result<RoleSummary, AdminError> {
    check_role_name(&req.name)?;
    let json = build_role(&req.grants)?;
    let record = audit_role(audit, by, "create", &req.name, || {
        Ok(tokens.create_role(&req.name, &json)?)
    })?;
    Ok(RoleSummary::of(&record, Vec::new()))
}

/// Replace a role's grants; every token holding it sees them from its
/// next request on. Blocking.
///
/// # Errors
///
/// [`AdminError::Invalid`], [`AdminError::NotFound`],
/// [`AdminError::Store`].
pub fn update_role(
    tokens: &TokenStore,
    audit: &AuditLog,
    by: Audited<'_>,
    name: &str,
    grants: &[GrantWire],
) -> Result<RoleSummary, AdminError> {
    // Checked before the audit row: the name lands in its path.
    check_role_name(name)?;
    let json = build_role(grants)?;
    let (record, held) = audit_role(audit, by, "update", name, || {
        Ok(tokens.update_role(name, &json)?)
    })?;
    Ok(RoleSummary::of(&record, held))
}

/// Delete a role. Refused while live tokens hold it. Blocking.
///
/// # Errors
///
/// [`AdminError::NotFound`], [`AdminError::Conflict`] (held),
/// [`AdminError::Store`].
pub fn delete_role(
    tokens: &TokenStore,
    audit: &AuditLog,
    by: Audited<'_>,
    name: &str,
) -> Result<RoleSummary, AdminError> {
    check_role_name(name)?;
    let record = audit_role(audit, by, "delete", name, || Ok(tokens.delete_role(name)?))?;
    Ok(RoleSummary::of(&record, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuditQuery, Db};
    use std::sync::Arc;

    fn stores() -> (TokenStore, AuditLog) {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let tokens = TokenStore::new(Arc::clone(&db));
        tokens
            .create_role("dashboard", br#"[{"actions":["device.read"]}]"#)
            .unwrap();
        (tokens, AuditLog::new(db))
    }

    fn req(label: &str, roles: &[&str]) -> MintRequest {
        MintRequest {
            label: label.into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    fn grants(json: &str) -> Vec<GrantWire> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn mint_stores_a_role_token_that_verifies() {
        let (tokens, audit) = stores();
        let m = mint(
            &tokens,
            &audit,
            "cli",
            "cli",
            None,
            &req("kitchen tablet", &["dashboard", "guest", "dashboard"]),
        )
        .expect("mint");
        let rec = tokens.verify(&m.secret).expect("verifies");
        assert_eq!(rec.id, m.token_id);
        assert!(!rec.owner);
        assert_eq!(rec.roles, vec!["dashboard", "guest"]);
        assert_eq!(m.summary.roles, vec!["dashboard", "guest"]);
        let rows = audit.query(&AuditQuery::default(), 10).expect("audit");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_id, m.token_id);
        assert_eq!(rows[0].path, "cli.auth.mint:dashboard,guest");
        assert_eq!(rows[0].decision, "allow");
    }

    #[test]
    fn bad_requests_are_refused_before_anything_is_stored() {
        let (tokens, audit) = stores();
        for (r, needle) in [
            (req("", &["guest"]), "label"),
            (req("admin", &["guest"]), "reserved"),
            (req("bad\nlabel", &["guest"]), "control"),
            (req("x", &[]), "roles"),
            (req("x", &["owner"]), "not assignable"),
            (req("x", &["nope"]), "unknown role"),
        ] {
            let err = mint(&tokens, &audit, "cli", "cli", None, &r).expect_err(needle);
            assert!(
                matches!(&err, AdminError::Invalid(m) if m.contains(needle)),
                "{needle}: {err}"
            );
        }
        assert!(
            serde_json::from_str::<MintRequest>(r#"{"label":"x","roles":[],"scopes":[]}"#).is_err()
        );
        assert_eq!(tokens.count().unwrap(), 0);
        assert_eq!(audit.query(&AuditQuery::default(), 10).unwrap().len(), 0);
    }

    #[test]
    fn summaries_show_the_owner() {
        let (tokens, _) = stores();
        let issued = TokenStore::generate();
        assert!(tokens.insert_owner_if_empty(&issued, "admin").unwrap());
        let list = summaries(&tokens).unwrap();
        assert!(list[0].owner);
        assert_eq!(list[0].roles, Vec::<String>::new());
    }

    #[test]
    fn roles_are_validated_written_audited_and_listed() {
        let (tokens, audit) = stores();
        let by = Audited {
            surface: "cli",
            actor_kind: "cli",
            call_id: None,
        };
        let new = NewRole {
            name: "tablet".into(),
            grants: grants(
                r#"[{"actions":["device.read","device.command"],"category":["light","lock"]}]"#,
            ),
        };
        assert!(serde_json::from_str::<NewRole>(r#"{"name":"x","grants":[],"deny":[]}"#).is_err());
        let r = create_role(&tokens, &audit, by, &new).unwrap();
        assert_eq!(r.grants, vec!["device.read,device.command@light,lock"]);
        assert!(matches!(
            create_role(&tokens, &audit, by, &new),
            Err(AdminError::Exists(_))
        ));
        for (name, bad, needle) in [
            ("owner", "[]", "role name"),
            ("Bad Name", "[]", "role name"),
            ("member", "[]", "built-in"),
            ("x", r#"[{"actions":["token.manage"]}]"#, "owner's alone"),
            (
                "x",
                r#"[{"actions":["host.status"],"category":["lock"]}]"#,
                "can't be narrowed",
            ),
            (
                "x",
                r#"[{"actions":["device.read"],"devices":["lamp"]}]"#,
                "device id",
            ),
            (
                "x",
                r#"[{"actions":["device.read"],"category":["door"]}]"#,
                "unknown",
            ),
        ] {
            let req = NewRole {
                name: name.into(),
                grants: grants(bad),
            };
            let err = create_role(&tokens, &audit, by, &req).expect_err(bad);
            assert!(
                matches!(&err, AdminError::Invalid(m) if m.contains(needle)),
                "{name} {bad}: {err}"
            );
        }

        let m = mint(
            &tokens,
            &audit,
            "cli",
            "cli",
            None,
            &req("hall", &["tablet"]),
        )
        .unwrap();
        let listed = role_summaries(&tokens).unwrap();
        assert_eq!(
            listed.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["admin", "member", "guest", "agent", "dashboard", "tablet"]
        );
        let tablet = listed.iter().find(|r| r.name == "tablet").unwrap();
        assert_eq!(tablet.tokens, vec![m.token_id.clone()]);

        let edit = grants(r#"[{"actions":["device.list"]}]"#);
        let r = update_role(&tokens, &audit, by, "tablet", &edit).unwrap();
        assert_eq!(r.grants, vec!["device.list"]);
        assert!(matches!(
            update_role(&tokens, &audit, by, "nope", &edit),
            Err(AdminError::NotFound(_))
        ));
        assert!(matches!(
            delete_role(&tokens, &audit, by, "tablet"),
            Err(AdminError::Conflict(_))
        ));
        tokens.revoke(&m.token_id).unwrap();
        delete_role(&tokens, &audit, by, "tablet").unwrap();

        let paths: Vec<String> = audit
            .query(&AuditQuery::default(), 50)
            .unwrap()
            .into_iter()
            .filter(|r| r.decision == "allow")
            .map(|r| r.path)
            .collect();
        for p in [
            "cli.auth.role.create:tablet",
            "cli.auth.role.update:tablet",
            "cli.auth.role.delete:tablet",
        ] {
            assert!(paths.iter().any(|x| x == p), "{p}: {paths:?}");
        }
    }
}
