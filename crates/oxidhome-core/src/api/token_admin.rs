//! H6 slice 3: owner-defined roles, and minting and listing tokens by
//! role.
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
//! A token references its roles by id, so a role edit applies to it
//! from its next request on. Deleting a role that live tokens hold is
//! refused unless forced; a forced delete leaves references that grant
//! nothing. A minted token is never the owner: `owner` is not a role,
//! and only the first-run bootstrap and `recover-admin-token` mint the
//! owner. Every mint and role write leaves a two-phase audit row:
//! `<surface>.auth.mint:<roles or "scopes">` with the new token's id,
//! `<surface>.auth.role.<create|update|delete>:<name>` with the role's.

use serde::{Deserialize, Serialize};

use super::bootstrap::{ADMIN_TOKEN_LABEL, audited_call};
use super::sensitive_admin::check_devices;
use crate::auth::role::{
    NARROWABLE, OWNER_LABEL, SCOPED, SERVICE_NARROWABLE, is_role_name, is_service_pattern,
};
use crate::auth::{
    Action, ActionSet, DenyRule, DeviceCategory, RoleDef, RoleGrant, SensitiveCategory,
    SensitiveGrant, TokenPolicy, parse_policy,
};
use crate::state::{AuditLog, TokenRecord, TokenStore};

/// Audit `path` suffix of a mint (`<surface>.auth.mint:<roles>`).
pub const AUDIT_PATH_MINT: &str = "auth.mint";

/// Longest label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
/// Most entries in each list of a mint request or role definition.
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
    /// Names of owner-defined roles.
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
    pub deny: Vec<SelectorSpec>,
}

/// One grant or deny entry: the wire shape of a [`RoleGrant`] or a
/// [`DenyRule`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorSpec {
    /// Action names (`device.command`) or `*`.
    pub actions: Vec<String>,
    /// Device categories; absent for every resource.
    #[serde(default)]
    pub category: Option<Vec<String>>,
    /// Device ids or `prefix*` patterns; absent for every device.
    #[serde(default)]
    pub devices: Option<Vec<String>>,
    /// Service patterns (`<plugin>` or `<plugin>/<local-id>`, each half
    /// literal or `prefix*`) for `service.call`; not combined with
    /// `category` or `devices`.
    #[serde(default)]
    pub services: Option<Vec<String>>,
}

/// Why a mint was refused.
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

fn check_len<T>(what: &str, list: &[T]) -> Result<(), AdminError> {
    if list.len() > MAX_LIST {
        return Err(invalid(format!("at most {MAX_LIST} {what}")));
    }
    Ok(())
}

/// Validate `req` and build the policy it stores, resolving each role
/// name to its id with `role_id`.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming the first problem.
pub fn build_policy(
    req: &MintRequest,
    mut role_id: impl FnMut(&str) -> Result<Option<String>, AdminError>,
) -> Result<TokenPolicy, AdminError> {
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
    let mut roles: Vec<String> = Vec::new();
    for name in &req.roles {
        if name == OWNER_LABEL {
            return Err(invalid(
                "`owner` is not assignable: the owner is the bootstrap / recovered token",
            ));
        }
        let Some(id) = role_id(name)? else {
            return Err(invalid(format!("unknown role `{name}`")));
        };
        if !roles.contains(&id) {
            roles.push(id);
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
    let deny = deny_rules(&req.deny)?;
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

fn deny_rules(specs: &[SelectorSpec]) -> Result<Vec<DenyRule>, AdminError> {
    check_len("deny entries", specs)?;
    specs
        .iter()
        .map(|spec| {
            let (actions, categories, devices, services) = selector(spec, "deny")?;
            let wildcard = spec.actions.iter().any(|a| a == "*");
            let to_devices = categories.is_some() || devices.is_some();
            // A narrowed `*` means what the selector can match; a named
            // action it can never match is refused.
            let actions =
                crate::auth::role::deny_actions(actions, wildcard, services.is_some(), to_devices)
                    .ok_or_else(|| {
                        invalid(if services.is_some() {
                            "a deny entry narrowed to services can only name service.call"
                        } else {
                            "a deny entry narrowed to devices can't name service.call (narrow it \
                             with `services` instead)"
                        })
                    })?;
            Ok(DenyRule {
                actions,
                categories,
                devices,
                services,
            })
        })
        .collect()
}

type Selector = crate::auth::role::SelectorParts;

/// Validate one grant or deny entry (`what` names it in errors).
fn selector(spec: &SelectorSpec, what: &str) -> Result<Selector, AdminError> {
    if spec.actions.is_empty() {
        return Err(invalid(format!(
            "a {what} entry needs at least one action (or `*`)"
        )));
    }
    check_len("actions", &spec.actions)?;
    let actions = ActionSet::parse(spec.actions.iter().map(String::as_str))
        .map_err(|e| invalid(format!("{e}")))?;
    let categories = match &spec.category {
        None => None,
        Some(list) if list.is_empty() => {
            return Err(invalid(format!(
                "a {what} entry's `category` must not be empty"
            )));
        }
        Some(list) => {
            check_len("categories", list)?;
            let mut parsed = Vec::with_capacity(list.len());
            for c in list {
                let c = c
                    .parse::<DeviceCategory>()
                    .map_err(|e| invalid(format!("{e}")))?;
                if !parsed.contains(&c) {
                    parsed.push(c);
                }
            }
            Some(parsed)
        }
    };
    let devices = match &spec.devices {
        None => None,
        Some(list) if list.is_empty() => {
            return Err(invalid(format!(
                "a {what} entry's `devices` must not be empty"
            )));
        }
        Some(list) => {
            check_devices(list).map_err(|e| invalid(format!("{e:#}")))?;
            Some(list.clone())
        }
    };
    let services = match &spec.services {
        None => None,
        Some(list) if list.is_empty() => {
            return Err(invalid(format!(
                "a {what} entry's `services` must not be empty"
            )));
        }
        Some(_) if categories.is_some() || devices.is_some() => {
            return Err(invalid(format!(
                "a {what} entry narrows to devices (`category`, `devices`) or to `services`, \
                 not both"
            )));
        }
        Some(list) => {
            check_len("services", list)?;
            if let Some(bad) = list.iter().find(|p| !is_service_pattern(p)) {
                return Err(invalid(format!(
                    "service pattern `{bad}` must be `<plugin>` or `<plugin>/<local-id>`, each \
                     half literal or ending in a single `*`, the plugin half in plugin-id \
                     characters (`a-z`, `0-9`, `.`, `-`)"
                )));
            }
            Some(list.clone())
        }
    };
    Ok((actions, categories, devices, services))
}

/// Mint a token for `req`, audited as `surface` (`cli`, `api`,
/// `connect`, `mcp`) with `actor_kind` in the row. Blocking.
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
    let mut resolved = std::collections::HashMap::new();
    let policy = build_policy(req, |name| {
        let id = tokens.role_by_name(name)?.map(|r| r.id);
        if let Some(id) = &id {
            resolved.insert(id.clone(), name.to_owned());
        }
        Ok(id)
    })?;
    let label = req.label.trim();
    let issued = TokenStore::generate();
    let mut names: Vec<&str> = Vec::new();
    for name in &req.roles {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    let what = if names.is_empty() {
        "scopes".to_owned()
    } else {
        names.join(",")
    };
    let path = format!("{surface}.{AUDIT_PATH_MINT}:{what}");
    let mut vanished = None;
    let record = audited_call(
        audit,
        actor_kind,
        &issued.id,
        &path,
        call_id,
        || match tokens.insert_with_roles(&issued, label, &policy.to_json(), &policy.roles)? {
            Ok(record) => Ok(record),
            Err(id) => {
                vanished = resolved.get(&id).cloned();
                anyhow::bail!("role deleted while minting")
            }
        },
    );
    if let Some(name) = vanished {
        return Err(AdminError::Invalid(format!("unknown role `{name}`")));
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
        // From the names resolved for the insert: nothing fallible
        // stands between the stored token and its secret's delivery.
        summary: TokenSummary::of(&record, &resolved),
    })
}

/// `role id -> name` for every stored role.
fn role_names(
    tokens: &TokenStore,
) -> Result<std::collections::HashMap<String, String>, AdminError> {
    Ok(tokens
        .roles()?
        .into_iter()
        .map(|r| (r.id, r.name))
        .collect())
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
    /// Role names (`<id> (deleted)` for a role deleted since);
    /// `["owner"]` for the owner.
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
    /// The summary of one stored token; `role_names` maps role ids to
    /// names.
    #[must_use]
    pub fn of(
        record: &TokenRecord,
        role_names: &std::collections::HashMap<String, String>,
    ) -> Self {
        let policy = parse_policy(&record.scope_json);
        let policy_valid = policy.is_some();
        let policy = policy.unwrap_or_default();
        let mut roles: Vec<String> = policy
            .roles
            .iter()
            .map(|id| {
                role_names
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| format!("{id} (deleted)"))
            })
            .collect();
        let sensitive = if record.owner {
            roles.insert(0, OWNER_LABEL.into());
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
pub fn summaries(tokens: &TokenStore) -> Result<Vec<TokenSummary>, AdminError> {
    let names = role_names(tokens)?;
    Ok(tokens
        .list()
        .map_err(|e| AdminError::Store(e.to_string()))?
        .iter()
        .map(|r| TokenSummary::of(r, &names))
        .collect())
}

/// A role definition as given on every surface (the body of
/// `POST /api/v1/roles` minus `name`, and of `PUT /api/v1/roles/{name}`).
/// Only a JSON object: a struct would otherwise also accept an array,
/// and `[]` must not quietly clear a role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleSpec {
    /// What the role grants. Actions are those a scope can grant (`*`
    /// for all of them), optionally narrowed to device categories and
    /// device ids.
    pub grants: Vec<SelectorSpec>,
    /// Sensitive categories the role grants, on every device.
    pub sensitive: Vec<String>,
    /// What the role denies, whatever grants it.
    pub deny: Vec<SelectorSpec>,
}

/// [`RoleSpec`]'s object form: typed, so unknown and duplicate fields
/// are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleSpecObject {
    #[serde(default)]
    grants: Vec<SelectorSpec>,
    #[serde(default)]
    sensitive: Vec<String>,
    #[serde(default)]
    deny: Vec<SelectorSpec>,
}

/// [`NewRole`]'s object form.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRoleObject {
    name: String,
    #[serde(default)]
    grants: Vec<SelectorSpec>,
    #[serde(default)]
    sensitive: Vec<String>,
    #[serde(default)]
    deny: Vec<SelectorSpec>,
}

/// Deserialize `T` from a JSON object only: a derived struct would
/// also accept an array, and `[]` must not quietly clear a role.
fn from_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectOnly<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectOnly<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(ObjectOnly(std::marker::PhantomData))
}

impl<'de> Deserialize<'de> for RoleSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let o: RoleSpecObject = from_object(deserializer)?;
        Ok(Self {
            grants: o.grants,
            sensitive: o.sensitive,
            deny: o.deny,
        })
    }
}

/// `POST /api/v1/roles`: a name and a definition, in one object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewRole {
    /// Unique name: 1–32 of `a-z0-9-_`, starting with a letter, not
    /// `owner`.
    pub name: String,
    /// The definition.
    pub spec: RoleSpec,
}

impl<'de> Deserialize<'de> for NewRole {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let o: NewRoleObject = from_object(deserializer)?;
        Ok(Self {
            name: o.name,
            spec: RoleSpec {
                grants: o.grants,
                sensitive: o.sensitive,
                deny: o.deny,
            },
        })
    }
}

/// Validate `spec` into the definition stored for a role.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming the first problem.
pub fn build_role(spec: &RoleSpec) -> Result<Vec<u8>, AdminError> {
    check_len("grants", &spec.grants)?;
    check_len("sensitive categories", &spec.sensitive)?;
    let mut grants = Vec::with_capacity(spec.grants.len());
    for g in &spec.grants {
        let (actions, categories, devices, services) = selector(g, "grant")?;
        let wildcard = g.actions.iter().any(|a| a == "*");
        let narrowed = categories.is_some() || devices.is_some();
        if narrowed && !wildcard && !NARROWABLE.contains_all(actions) {
            let names = actions.without(NARROWABLE).names().join(", ");
            return Err(invalid(format!(
                "a grant narrowed to devices can only name device.list, device.read and \
                 device.command, not {names}"
            )));
        }
        if services.is_some() && !wildcard && !SERVICE_NARROWABLE.contains_all(actions) {
            let names = actions.without(SERVICE_NARROWABLE).names().join(", ");
            return Err(invalid(format!(
                "a grant narrowed to services can only name service.call, not {names}"
            )));
        }
        let actions = if wildcard {
            actions.intersection(if services.is_some() {
                SERVICE_NARROWABLE
            } else if narrowed {
                NARROWABLE
            } else {
                SCOPED
            })
        } else if SCOPED.contains_all(actions) {
            actions
        } else {
            let names = actions.without(SCOPED).names().join(", ");
            return Err(invalid(format!(
                "a role can't grant {names}: no scope grants it (the owner holds \
                 token.manage and policy.manage; plugins' manifests govern state.read)"
            )));
        };
        grants.push(RoleGrant {
            actions,
            categories,
            devices,
            services,
        });
    }
    let mut sensitive: Vec<SensitiveCategory> = Vec::new();
    for name in &spec.sensitive {
        let c: SensitiveCategory = name.parse().map_err(|e| invalid(format!("{e}")))?;
        if !sensitive.contains(&c) {
            sensitive.push(c);
        }
    }
    sensitive.sort();
    let def = RoleDef {
        id: String::new(),
        name: String::new(),
        grants,
        sensitive,
        deny: deny_rules(&spec.deny)?,
    };
    let json = def.definition_json();
    if RoleDef::parse("", "", &json).as_ref() != Some(&def) {
        return Err(invalid("the role definition does not round-trip"));
    }
    Ok(json)
}

fn check_role_name(name: &str) -> Result<(), AdminError> {
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
    /// Stable id, what token policies reference.
    pub role_id: String,
    /// Name.
    pub name: String,
    /// Grants, as `actions@categories[devices]`.
    pub grants: Vec<String>,
    /// Sensitive categories.
    pub sensitive: Vec<String>,
    /// Denies, as `actions@categories[devices]`.
    pub deny: Vec<String>,
    /// Ids of the live tokens holding the role.
    pub tokens: Vec<String>,
    /// Created, Unix ms.
    pub created_ms: i64,
    /// Last edited, Unix ms.
    pub updated_ms: i64,
    /// `false` when the stored definition doesn't parse: the role
    /// grants nothing.
    pub definition_valid: bool,
}

impl RoleSummary {
    fn of(record: &crate::state::RoleRecord, tokens: Vec<String>) -> Self {
        let def = record.def();
        let definition_valid = def.is_some();
        let def = def.unwrap_or_else(|| RoleDef {
            id: record.id.clone(),
            name: record.name.clone(),
            grants: Vec::new(),
            sensitive: Vec::new(),
            deny: Vec::new(),
        });
        Self {
            role_id: record.id.clone(),
            name: record.name.clone(),
            grants: def.grants.iter().map(RoleGrant::describe).collect(),
            sensitive: def
                .sensitive
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect(),
            deny: def.deny.iter().map(DenyRule::describe).collect(),
            tokens,
            created_ms: record.created_ms,
            updated_ms: record.updated_ms,
            definition_valid,
        }
    }
}

/// Every role, by name. Blocking.
///
/// # Errors
///
/// [`AdminError::Store`] on a read failure.
pub fn role_summaries(tokens: &TokenStore) -> Result<Vec<RoleSummary>, AdminError> {
    tokens
        .roles()?
        .iter()
        .map(|r| Ok(RoleSummary::of(r, tokens.role_holders(&r.id)?)))
        .collect()
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
    subject: &str,
    op: impl FnOnce() -> Result<T, AdminError>,
) -> Result<T, AdminError> {
    let path = format!("{}.auth.role.{verb}:{name}", by.surface);
    let mut refused = None;
    let out = audited_call(audit, by.actor_kind, subject, &path, by.call_id, || {
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
/// [`AdminError::Conflict`] for a taken name, [`AdminError::Store`].
pub fn create_role(
    tokens: &TokenStore,
    audit: &AuditLog,
    by: Audited<'_>,
    req: &NewRole,
) -> Result<RoleSummary, AdminError> {
    check_role_name(&req.name)?;
    let json = build_role(&req.spec)?;
    let record = audit_role(audit, by, "create", &req.name, &req.name, || {
        Ok(tokens.create_role(&req.name, &json)?)
    })?;
    Ok(RoleSummary::of(&record, Vec::new()))
}

/// Replace a role's definition; every token holding it sees the new
/// definition from its next request on. Blocking.
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
    spec: &RoleSpec,
) -> Result<RoleSummary, AdminError> {
    // Checked before the audit row: the name lands in its path.
    check_role_name(name)?;
    let json = build_role(spec)?;
    let (record, held) = audit_role(audit, by, "update", name, name, || {
        Ok(tokens.update_role(name, &json)?)
    })?;
    Ok(RoleSummary::of(&record, held))
}

/// Delete a role. Refused while live tokens hold it unless `force`;
/// then those tokens keep a reference that grants nothing. Returns the
/// deleted role (with the tokens that held it). Blocking.
///
/// # Errors
///
/// [`AdminError::NotFound`], [`AdminError::Conflict`] (held, not
/// forced), [`AdminError::Store`].
pub fn delete_role(
    tokens: &TokenStore,
    audit: &AuditLog,
    by: Audited<'_>,
    name: &str,
    force: bool,
) -> Result<RoleSummary, AdminError> {
    check_role_name(name)?;
    let verb = if force { "delete-forced" } else { "delete" };
    let (record, held) = audit_role(audit, by, verb, name, name, || {
        Ok(tokens.delete_role(name, force)?)
    })?;
    Ok(RoleSummary::of(&record, held))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuditQuery, Db};
    use std::sync::Arc;

    fn stores() -> (TokenStore, AuditLog) {
        let db = Arc::new(Db::open_in_memory().expect("db"));
        let tokens = TokenStore::new(Arc::clone(&db));
        for name in ["dashboard", "monitor", "resident"] {
            tokens
                .create_role(name, br#"{"grants":[{"actions":["device.read"]}]}"#)
                .unwrap();
        }
        (tokens, AuditLog::new(db))
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
        r.deny = vec![SelectorSpec {
            actions: vec!["device.command".into()],
            category: None,
            devices: Some(vec!["dev-a1*".into()]),
            services: None,
        }];
        r.sensitive = vec!["camera".into()];
        let m = mint(&tokens, &audit, "cli", "cli", None, &r).expect("mint");
        let rec = tokens.verify(&m.secret).expect("verifies");
        assert_eq!(rec.id, m.token_id);
        assert!(!rec.owner);
        let policy = parse_policy(&rec.scope_json).expect("parses");
        let dashboard = tokens.role_by_name("dashboard").unwrap().unwrap();
        assert_eq!(policy.roles, vec![dashboard.id]);
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
                    deny: vec![SelectorSpec::default()],
                    ..req("x", &["resident"])
                },
                "at least one action",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["*".into()],
                        category: Some(vec![]),
                        devices: None,
                        services: None,
                    }],
                    ..req("x", &["resident"])
                },
                "must not be empty",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["*".into()],
                        category: None,
                        devices: Some(vec!["kitchen".into()]),
                        services: None,
                    }],
                    ..req("x", &["resident"])
                },
                "device pattern",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["*".into()],
                        category: Some(vec!["light".into(); MAX_LIST + 1]),
                        devices: None,
                        services: None,
                    }],
                    ..req("x", &["resident"])
                },
                "at most 32 categories",
            ),
        ];
        for (r, needle) in cases {
            let err = mint(&tokens, &audit, "cli", "cli", None, &r).expect_err("refused");
            assert!(
                matches!(&err, AdminError::Invalid(m) if m.contains(needle)),
                "{r:?}: {err}"
            );
        }
        assert_eq!(tokens.count().unwrap(), 0);
        assert_eq!(audit.count().unwrap(), 0);
    }

    /// H6 slice 4: a `services` selector names only `service.call`,
    /// stands alone and names well-formed patterns.
    #[test]
    fn service_selectors_are_validated() {
        let (tokens, audit) = stores();
        let cases: Vec<(MintRequest, &str)> = vec![
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["device.read".into()],
                        category: None,
                        devices: None,
                        services: Some(vec!["acme.notify".into()]),
                    }],
                    ..req("x", &["resident"])
                },
                "can only name service.call",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["service.call".into()],
                        category: Some(vec!["lock".into()]),
                        devices: None,
                        services: Some(vec!["acme.notify".into()]),
                    }],
                    ..req("x", &["resident"])
                },
                "not both",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["service.call".into()],
                        category: None,
                        devices: None,
                        services: Some(vec!["acme/x*y".into()]),
                    }],
                    ..req("x", &["resident"])
                },
                "service pattern",
            ),
            (
                MintRequest {
                    deny: vec![SelectorSpec {
                        actions: vec!["service.call".into()],
                        category: Some(vec!["lock".into()]),
                        devices: None,
                        services: None,
                    }],
                    ..req("x", &["resident"])
                },
                "can't name service.call",
            ),
        ];
        for (r, needle) in cases {
            let err = mint(&tokens, &audit, "cli", "cli", None, &r).expect_err("refused");
            assert!(
                matches!(&err, AdminError::Invalid(m) if m.contains(needle)),
                "{r:?}: {err}"
            );
        }
        let ok = MintRequest {
            deny: vec![SelectorSpec {
                actions: vec!["*".into()],
                category: None,
                devices: None,
                services: Some(vec!["zwave.*/door".into()]),
            }],
            ..req("x", &["resident"])
        };
        let m = mint(&tokens, &audit, "cli", "cli", None, &ok).expect("minted");
        assert_eq!(m.summary.deny, vec!["service.call{zwave.*/door}"]);
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
    #[allow(clippy::too_many_lines)]
    fn roles_are_validated_written_audited_and_listed() {
        let (tokens, audit) = stores();
        let by = Audited {
            surface: "cli",
            actor_kind: "cli",
            call_id: None,
        };
        let spec: RoleSpec = serde_json::from_str(
            r#"{"grants":[{"actions":["device.read","device.command"],"category":["light"]}],
                "sensitive":["lock"],"deny":[{"actions":["device.command"],"category":["alarm"]}]}"#,
        )
        .unwrap();
        let new = NewRole {
            name: "tablet".into(),
            spec: spec.clone(),
        };
        // An array is not a definition; a repeated field is refused.
        assert!(serde_json::from_str::<RoleSpec>("[]").is_err());
        assert!(serde_json::from_str::<NewRole>("[]").is_err());
        assert!(serde_json::from_str::<RoleSpec>(r#"{"deny":[],"deny":[]}"#).is_err());
        assert!(RoleDef::parse("role-0000000000000001", "x", b"[]").is_none());
        assert!(matches!(
            update_role(
                &tokens,
                &audit,
                by,
                "oxh_Not-A-Role-Name",
                &RoleSpec::default()
            ),
            Err(AdminError::Invalid(_))
        ));
        // The flattened body still refuses unknown fields.
        assert!(serde_json::from_str::<NewRole>(r#"{"name":"x","extra":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<NewRole>(r#"{"name":"x","sensitive":["lock"]}"#)
                .unwrap()
                .spec
                .sensitive,
            vec!["lock"]
        );
        let r = create_role(&tokens, &audit, by, &new).unwrap();
        assert_eq!(r.grants, vec!["device.read,device.command@light"]);
        assert_eq!(r.sensitive, vec!["lock"]);
        assert_eq!(r.deny, vec!["device.command@alarm"]);
        assert!(matches!(
            create_role(&tokens, &audit, by, &new),
            Err(AdminError::Exists(_))
        ));
        for (name, bad, needle) in [
            ("owner", "{}", "role name"),
            ("Bad Name", "{}", "role name"),
            (
                "x",
                r#"{"grants":[{"actions":["token.manage"]}]}"#,
                "can't grant token.manage",
            ),
            (
                "x",
                r#"{"grants":[{"actions":["state.read"]}]}"#,
                "can't grant state.read",
            ),
            (
                "x",
                r#"{"grants":[{"actions":["device.read"],"services":["acme.notify"]}]}"#,
                "can only name service.call",
            ),
            (
                "x",
                r#"{"grants":[{"actions":["service.call"],"services":[]}]}"#,
                "must not be empty",
            ),
            ("x", r#"{"sensitive":["door"]}"#, "unknown"),
            (
                "x",
                r#"{"grants":[{"actions":["blob.read"],"category":["camera"]}]}"#,
                "can only name device.list",
            ),
            (
                "x",
                r#"{"grants":[{"actions":["device.read"],"devices":["lamp"]}]}"#,
                "device pattern",
            ),
        ] {
            let req = NewRole {
                name: name.into(),
                spec: serde_json::from_str(bad).unwrap(),
            };
            let err = create_role(&tokens, &audit, by, &req).expect_err(bad);
            assert!(
                matches!(&err, AdminError::Invalid(m) if m.contains(needle)),
                "{name} {bad}: {err}"
            );
        }

        let mut mint_req = req("hall", &["tablet"]);
        mint_req.scopes = vec!["status:read".into()];
        let m = mint(&tokens, &audit, "cli", "cli", None, &mint_req).unwrap();
        assert_eq!(m.summary.roles, vec!["tablet"]);
        let listed = role_summaries(&tokens).unwrap();
        let tablet = listed.iter().find(|r| r.name == "tablet").unwrap();
        assert_eq!(tablet.tokens, vec![m.token_id.clone()]);

        let edit: RoleSpec =
            serde_json::from_str(r#"{"grants":[{"actions":["device.list"]}]}"#).unwrap();
        let r = update_role(&tokens, &audit, by, "tablet", &edit).unwrap();
        assert_eq!(r.grants, vec!["device.list"]);
        assert!(matches!(
            update_role(&tokens, &audit, by, "nope", &edit),
            Err(AdminError::NotFound(_))
        ));
        assert!(matches!(
            delete_role(&tokens, &audit, by, "tablet", false),
            Err(AdminError::Conflict(_))
        ));
        let gone = delete_role(&tokens, &audit, by, "tablet", true).unwrap();
        assert_eq!(gone.tokens, vec![m.token_id.clone()]);
        let list = summaries(&tokens).unwrap();
        let t = list.iter().find(|t| t.token_id == m.token_id).unwrap();
        assert!(t.roles[0].ends_with("(deleted)"), "{:?}", t.roles);

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
            "cli.auth.role.delete-forced:tablet",
        ] {
            assert!(paths.iter().any(|x| x == p), "{p}: {paths:?}");
        }
    }
}
