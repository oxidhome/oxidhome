//! H6 slice 3: owner-defined roles, the `auth_role` table
//! (migration 23).
//!
//! A role is a name plus a definition (grants, sensitive categories,
//! denies; see [`crate::auth::RoleDef`]). Token policies reference a
//! role by its id, so editing a role applies to every token holding it
//! from the next request on. A role
//! that live tokens still reference is deleted only when forced; the
//! dangling references then grant nothing.
//!
//! The store is `TokenStore`'s: roles and tokens share the auth
//! domain, its database handle and its `synchronous = FULL` writes.

use rusqlite::{OptionalExtension, params};
use thiserror::Error;

use super::TokenStore;
use super::auth_token::{generate_secret, now_ms};
use crate::auth::{RoleDef, parse_policy};

/// One stored role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRecord {
    /// `role-<16 hex>`.
    pub id: String,
    /// Unique name.
    pub name: String,
    /// The definition JSON (see [`RoleDef::parse`]).
    pub definition: Vec<u8>,
    /// Created, unix ms.
    pub created_ms: i64,
    /// Last edited, unix ms.
    pub updated_ms: i64,
}

impl RoleRecord {
    /// The parsed definition; `None` (the role grants nothing) when the
    /// stored JSON is malformed.
    #[must_use]
    pub fn def(&self) -> Option<RoleDef> {
        RoleDef::parse(&self.id, &self.name, &self.definition)
    }
}

/// Why a role write failed.
#[derive(Debug, Error)]
pub enum RoleError {
    /// The database failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Another role already has the name.
    #[error("a role named `{0}` already exists")]
    Exists(String),
    /// The host already stores [`MAX_ROLES`] roles.
    #[error("at most {MAX_ROLES} roles")]
    Full,
    /// No role has the name.
    #[error("no role named `{0}`")]
    NotFound(String),
    /// Live tokens still hold the role; delete with `force`.
    #[error("role `{name}` is held by {} live token(s) ({}); delete with force to leave them without it", tokens.len(), tokens.join(", "))]
    InUse {
        /// The role.
        name: String,
        /// Ids of the live tokens holding it.
        tokens: Vec<String>,
    },
}

impl From<super::TokenError> for RoleError {
    fn from(err: super::TokenError) -> Self {
        match err {
            super::TokenError::Sqlite(e) => Self::Sqlite(e),
            other => Self::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::other(other.to_string()),
            ))),
        }
    }
}

/// Most roles the host stores.
pub const MAX_ROLES: usize = 64;

const SELECT: &str = "SELECT id, name, definition, created_ms, updated_ms FROM auth_role";

fn row_to_role(row: &rusqlite::Row<'_>) -> rusqlite::Result<RoleRecord> {
    Ok(RoleRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        definition: row.get(2)?,
        created_ms: row.get(3)?,
        updated_ms: row.get(4)?,
    })
}

fn mint_role_id() -> String {
    let bytes = generate_secret();
    let mut id = String::from("role-");
    for b in &bytes[..8] {
        use std::fmt::Write as _;
        let _ = write!(id, "{b:02x}");
    }
    id
}

/// Ids of the live tokens whose policy references `role_id`.
fn holders(conn: &rusqlite::Connection, role_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT id, scope_json FROM auth_token WHERE revoked_ms IS NULL")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, scope_json) = row?;
        if parse_policy(&scope_json).is_some_and(|p| p.roles.iter().any(|r| r == role_id)) {
            out.push(id);
        }
    }
    Ok(out)
}

impl TokenStore {
    /// Every role, by name.
    ///
    /// # Errors
    ///
    /// On database failure.
    pub fn roles(&self) -> Result<Vec<RoleRecord>, RoleError> {
        self.db.read(|conn| -> Result<Vec<RoleRecord>, RoleError> {
            let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY name"))?;
            let rows = stmt.query_map([], row_to_role)?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// The role named `name`.
    ///
    /// # Errors
    ///
    /// On database failure.
    pub fn role_by_name(&self, name: &str) -> Result<Option<RoleRecord>, RoleError> {
        let name = name.to_owned();
        self.db
            .read(move |conn| -> Result<Option<RoleRecord>, RoleError> {
                Ok(conn
                    .query_row(&format!("{SELECT} WHERE name = ?1"), [&name], row_to_role)
                    .optional()?)
            })
    }

    /// The roles among `ids` that still exist, in `ids` order. A
    /// deleted id is skipped. Read on every request of a token that
    /// holds roles.
    ///
    /// # Errors
    ///
    /// On database failure.
    pub fn roles_by_id(&self, ids: &[String]) -> Result<Vec<RoleRecord>, RoleError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        self.db
            .read(move |conn| -> Result<Vec<RoleRecord>, RoleError> {
                let mut stmt = conn.prepare(&format!("{SELECT} WHERE id = ?1"))?;
                let mut out = Vec::with_capacity(ids.len());
                for id in &ids {
                    if let Some(r) = stmt.query_row([id], row_to_role).optional()? {
                        out.push(r);
                    }
                }
                Ok(out)
            })
    }

    /// Ids of the live tokens holding `role_id`.
    ///
    /// # Errors
    ///
    /// On database failure.
    pub fn role_holders(&self, role_id: &str) -> Result<Vec<String>, RoleError> {
        let role_id = role_id.to_owned();
        self.db
            .read(move |conn| -> Result<Vec<String>, RoleError> { Ok(holders(conn, &role_id)?) })
    }

    /// Store a new role. The caller validated `name` and `definition`.
    ///
    /// # Errors
    ///
    /// [`RoleError::Exists`] for a taken name, [`RoleError::Full`];
    /// on database failure.
    pub fn create_role(&self, name: &str, definition: &[u8]) -> Result<RoleRecord, RoleError> {
        let now = now_ms();
        let record = RoleRecord {
            id: mint_role_id(),
            name: name.to_owned(),
            definition: definition.to_vec(),
            created_ms: now,
            updated_ms: now,
        };
        let row = record.clone();
        self.durable_write(
            move |conn| -> Result<Result<(), RoleError>, super::TokenError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let taken: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM auth_role WHERE name = ?1)",
                    [&row.name],
                    |r| r.get(0),
                )?;
                if taken {
                    return Ok(Err(RoleError::Exists(row.name)));
                }
                let count: i64 =
                    tx.query_row("SELECT COUNT(*) FROM auth_role", [], |r| r.get(0))?;
                if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_ROLES {
                    return Ok(Err(RoleError::Full));
                }
                tx.execute(
                    "INSERT INTO auth_role (id, name, definition, created_ms, updated_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        row.id,
                        row.name,
                        row.definition,
                        row.created_ms,
                        row.updated_ms
                    ],
                )?;
                tx.commit()?;
                Ok(Ok(()))
            },
        )??;
        Ok(record)
    }

    /// Replace the definition of the role named `name`. Every token
    /// holding it sees the new definition from its next request on.
    /// Returns the role and the live tokens holding it, read in the
    /// same transaction.
    ///
    /// # Errors
    ///
    /// [`RoleError::NotFound`]; on database failure.
    pub fn update_role(
        &self,
        name: &str,
        definition: &[u8],
    ) -> Result<(RoleRecord, Vec<String>), RoleError> {
        let name = name.to_owned();
        let definition = definition.to_vec();
        let now = now_ms();
        self.durable_write(
            move |conn| -> Result<Result<(RoleRecord, Vec<String>), RoleError>, super::TokenError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let n = tx.execute(
                    "UPDATE auth_role SET definition = ?1, updated_ms = ?2 WHERE name = ?3",
                    params![definition, now, name],
                )?;
                if n == 0 {
                    return Ok(Err(RoleError::NotFound(name)));
                }
                let role =
                    tx.query_row(&format!("{SELECT} WHERE name = ?1"), [&name], row_to_role)?;
                let tokens = holders(&tx, &role.id)?;
                tx.commit()?;
                Ok(Ok((role, tokens)))
            },
        )?
    }

    /// Delete the role named `name`. Refused while live tokens hold it
    /// unless `force`; returns the ids of the tokens that held it (now
    /// dangling references, which grant nothing).
    ///
    /// # Errors
    ///
    /// [`RoleError::NotFound`], [`RoleError::InUse`]; on database
    /// failure.
    pub fn delete_role(
        &self,
        name: &str,
        force: bool,
    ) -> Result<(RoleRecord, Vec<String>), RoleError> {
        let name = name.to_owned();
        self.durable_write(
            move |conn| -> Result<Result<(RoleRecord, Vec<String>), RoleError>, super::TokenError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let Some(role) = tx
                    .query_row(&format!("{SELECT} WHERE name = ?1"), [&name], row_to_role)
                    .optional()?
                else {
                    return Ok(Err(RoleError::NotFound(name)));
                };
                let tokens = holders(&tx, &role.id)?;
                if !tokens.is_empty() && !force {
                    return Ok(Err(RoleError::InUse { name, tokens }));
                }
                tx.execute("DELETE FROM auth_role WHERE id = ?1", [&role.id])?;
                tx.commit()?;
                Ok(Ok((role, tokens)))
            },
        )?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::state::Db;

    fn store() -> TokenStore {
        TokenStore::new(Arc::new(Db::open_in_memory().expect("db")))
    }

    #[test]
    fn roles_create_update_delete() {
        let tokens = store();
        let def = br#"{"grants":[{"actions":["device.read"]}]}"#;
        let role = tokens.create_role("tablet", def).unwrap();
        assert!(crate::auth::role::is_role_id(&role.id));
        assert!(matches!(
            tokens.create_role("tablet", def),
            Err(RoleError::Exists(_))
        ));
        let holder = tokens
            .create(
                "t",
                format!(r#"{{"scopes":[],"roles":["{}"]}}"#, role.id).as_bytes(),
            )
            .unwrap();
        assert_eq!(
            tokens.role_holders(&role.id).unwrap(),
            vec![holder.id.clone()]
        );

        let (edited, held) = tokens
            .update_role("tablet", br#"{"grants":[{"actions":["device.list"]}]}"#)
            .unwrap();
        assert_eq!(held, vec![holder.id.clone()]);
        assert_eq!(edited.id, role.id);
        let found = tokens
            .roles_by_id(&[role.id.clone(), "role-ffffffffffffffff".into()])
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].def().unwrap().grants[0].actions.names(),
            vec!["device.list"]
        );

        assert!(matches!(
            tokens.delete_role("tablet", false),
            Err(RoleError::InUse { .. })
        ));
        // A mint revalidates its roles in its own transaction.
        let issued = TokenStore::generate();
        assert_eq!(
            tokens
                .insert_with_roles(&issued, "late", b"{}", &["role-ffffffffffffffff".into()])
                .unwrap()
                .unwrap_err(),
            "role-ffffffffffffffff"
        );
        assert!(tokens.list().unwrap().iter().all(|t| t.id != issued.id));
        let (_, held) = tokens.delete_role("tablet", true).unwrap();
        assert_eq!(held, vec![holder.id]);
        assert_eq!(tokens.roles_by_id(&[role.id]).unwrap(), Vec::new());
        assert!(matches!(
            tokens.delete_role("tablet", true),
            Err(RoleError::NotFound(_))
        ));
        assert!(matches!(
            tokens.update_role("tablet", b"{}"),
            Err(RoleError::NotFound(_))
        ));
    }
}
