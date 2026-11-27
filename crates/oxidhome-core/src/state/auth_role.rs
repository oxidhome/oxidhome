//! Custom roles, the `auth_role` table.
//!
//! A role is a name plus a definition (a list of grants; see
//! [`crate::auth::RoleDef`]). Tokens hold roles by name, so editing a
//! role applies to every token holding it from the next request on. A
//! role that live tokens hold can't be deleted. The built-in roles
//! (`crate::auth::role::builtin`) are not stored.
//!
//! The store is `TokenStore`'s: roles and tokens share the auth
//! domain, its database handle and its `synchronous = FULL` writes.

use rusqlite::{OptionalExtension, params};
use thiserror::Error;

use super::TokenStore;
use super::auth_token::{now_ms, parse_roles};
use crate::auth::RoleDef;

/// One stored role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRecord {
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
        RoleDef::parse(&self.name, &self.definition)
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
    /// Live tokens still hold the role.
    #[error("role `{name}` is held by {} live token(s) ({}); revoke them first", tokens.len(), tokens.join(", "))]
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

/// Most custom roles the host stores.
pub const MAX_ROLES: usize = 64;

const SELECT: &str = "SELECT name, definition, created_ms, updated_ms FROM auth_role";

fn row_to_role(row: &rusqlite::Row<'_>) -> rusqlite::Result<RoleRecord> {
    Ok(RoleRecord {
        name: row.get(0)?,
        definition: row.get(1)?,
        created_ms: row.get(2)?,
        updated_ms: row.get(3)?,
    })
}

/// Ids of the live tokens holding the role `name`.
fn holders(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT id, roles FROM auth_token WHERE revoked_ms IS NULL")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, roles) = row?;
        if parse_roles(&roles).iter().any(|r| r == name) {
            out.push(id);
        }
    }
    Ok(out)
}

impl TokenStore {
    /// Every custom role, by name.
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

    /// The custom roles among `names` that exist, in `names` order.
    /// Read on every request of a token that holds custom roles.
    ///
    /// # Errors
    ///
    /// On database failure.
    pub fn roles_by_name(&self, names: &[String]) -> Result<Vec<RoleRecord>, RoleError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let names = names.to_vec();
        self.db
            .read(move |conn| -> Result<Vec<RoleRecord>, RoleError> {
                let mut stmt = conn.prepare(&format!("{SELECT} WHERE name = ?1"))?;
                let mut out = Vec::with_capacity(names.len());
                for name in &names {
                    if let Some(r) = stmt.query_row([name], row_to_role).optional()? {
                        out.push(r);
                    }
                }
                Ok(out)
            })
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
                    "INSERT INTO auth_role (name, definition, created_ms, updated_ms) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![row.name, row.definition, row.created_ms, row.updated_ms],
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
                let tokens = holders(&tx, &name)?;
                tx.commit()?;
                Ok(Ok((role, tokens)))
            },
        )?
    }

    /// Delete the role named `name`. Refused while live tokens hold it.
    ///
    /// # Errors
    ///
    /// [`RoleError::NotFound`], [`RoleError::InUse`]; on database
    /// failure.
    pub fn delete_role(&self, name: &str) -> Result<RoleRecord, RoleError> {
        let name = name.to_owned();
        self.durable_write(
            move |conn| -> Result<Result<RoleRecord, RoleError>, super::TokenError> {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let Some(role) = tx
                    .query_row(&format!("{SELECT} WHERE name = ?1"), [&name], row_to_role)
                    .optional()?
                else {
                    return Ok(Err(RoleError::NotFound(name)));
                };
                let tokens = holders(&tx, &name)?;
                if !tokens.is_empty() {
                    return Ok(Err(RoleError::InUse { name, tokens }));
                }
                tx.execute("DELETE FROM auth_role WHERE name = ?1", [&name])?;
                tx.commit()?;
                Ok(Ok(role))
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
        let def = br#"[{"actions":["device.read"]}]"#;
        tokens.create_role("tablet", def).unwrap();
        assert!(matches!(
            tokens.create_role("tablet", def),
            Err(RoleError::Exists(_))
        ));
        let holder = tokens.create("t", &["tablet"]).unwrap();

        let (_, held) = tokens
            .update_role("tablet", br#"[{"actions":["device.list"]}]"#)
            .unwrap();
        assert_eq!(held, vec![holder.id.clone()]);
        let found = tokens
            .roles_by_name(&["tablet".into(), "gone".into()])
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].def().unwrap().grants[0].actions.names(),
            vec!["device.list"]
        );

        assert!(matches!(
            tokens.delete_role("tablet"),
            Err(RoleError::InUse { .. })
        ));
        // A mint revalidates its custom roles in its own transaction.
        let issued = TokenStore::generate();
        assert_eq!(
            tokens
                .insert_with_roles(&issued, "late", &["member".into(), "gone".into()])
                .unwrap()
                .unwrap_err(),
            "gone"
        );
        assert!(tokens.list().unwrap().iter().all(|t| t.id != issued.id));
        tokens.revoke(&holder.id).unwrap();
        tokens.delete_role("tablet").unwrap();
        assert_eq!(
            tokens.roles_by_name(&["tablet".into()]).unwrap(),
            Vec::new()
        );
        assert!(matches!(
            tokens.delete_role("tablet"),
            Err(RoleError::NotFound(_))
        ));
        assert!(matches!(
            tokens.update_role("tablet", b"[]"),
            Err(RoleError::NotFound(_))
        ));
    }
}
