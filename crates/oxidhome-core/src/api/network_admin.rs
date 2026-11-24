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

use serde::Serialize;

use super::bootstrap::audited;
use crate::state::{AuditLog, PinFilter, TlsPin, TlsPinStore};

/// Audit `path` prefix of a pin reset (`…:<instance|*>`).
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
}

impl From<TlsPin> for TlsPinView {
    fn from(pin: TlsPin) -> Self {
        Self {
            instance_id: pin.key.instance_id,
            host: pin.key.host,
            port: pin.key.port,
            sha256: pin.fingerprint.to_hex(),
            pinned_ms: pin.pinned_ms,
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
    let path = format!(
        "{AUDIT_PATH_RESET_TLS_PINS}:{}",
        filter.instance_id.as_deref().unwrap_or("*")
    );
    audited(audit, "cli", "-", &path, || {
        pins.reset(filter)
            .map_err(|e| anyhow::anyhow!("removing TLS pins: {e}"))
    })
}
