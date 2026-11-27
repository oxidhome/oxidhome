//! Offline operator tooling: the stores the `oxidhome token`, `role`,
//! `device`, `plugin` and `tls-pin` commands open while the daemon is
//! stopped, and the device category raise.
//!
//! - `oxidhome device set-category <device-id> <category>|--clear` —
//!   the operator's category raise (also `PUT
//!   /api/v1/devices/{id}/category` for the owner token).
//!
//! Like `recover-admin-token`, the CLI forms run offline: they take the
//! exclusive state-dir lock, so they refuse while the daemon or an
//! `mcp-stdio` session is up. Each change leaves a two-phase `LOCAL`
//! audit row (actor `cli`).

use std::path::Path;

use anyhow::Context;

use super::bootstrap::{AUDIT_METHOD_LOCAL, audited};
use crate::auth::DeviceCategory;
use crate::state::{DeviceMetaRow, TokenStore};

/// Audit `path` prefix of a category override (`…:<category|clear>`).
/// The row's `token_id` column holds the device id.
pub const AUDIT_PATH_DEVICE_CATEGORY: &str = "cli.device.category";

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
