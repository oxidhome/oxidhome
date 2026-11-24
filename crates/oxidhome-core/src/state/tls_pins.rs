//! Trust-on-first-use certificate pins for LAN devices (Phase 8): the
//! `network_tls_pin` table.
//!
//! A streaming instance's `https://` request to a *private* or
//! *link-local* address whose certificate the system roots don't vouch
//! for (a camera or plug with a self-signed certificate) is accepted once
//! and its leaf certificate's SHA-256 recorded here, keyed by
//! `(instance, host, port)` as the request named them. Later requests to
//! the same key must present the same certificate; anything else is
//! refused (`TLS-certificate-error`) and audited. The operator resets a
//! pin (`oxidhome tls-pin reset`, `DELETE /api/v1/network/tls-pins`, the
//! Connect `ResetTlsPins`) when a device's certificate legitimately
//! changes; the next request pins again.
//!
//! The table is small and bounded ([`MAX_PINS_PER_INSTANCE`],
//! [`MAX_PINS_TOTAL`]) and loaded into memory at open; a check reads only
//! memory. A new pin commits to `SQLite` before it is published in
//! memory, and before the request that created it is sent.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rusqlite::params;

use super::db::Db;
use super::event_log::now_unix_ms;

/// Most pins one instance may hold.
pub const MAX_PINS_PER_INSTANCE: usize = 256;
/// Most pins the host holds in all (instance ids are cheap).
pub const MAX_PINS_TOTAL: usize = 4096;
/// Longest host a pin may name, in bytes (a DNS name or an IP literal).
const MAX_HOST_LEN: usize = 253;

/// Which certificate a key is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// SHA-256 of a DER certificate.
    #[must_use]
    pub fn of_der(der: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(der).into())
    }

    /// Lowercase hex, as shown to operators.
    #[must_use]
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self(out))
    }
}

/// `(instance, host, port)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PinKey {
    /// Instance id.
    pub instance_id: String,
    /// Host as the request named it, lowercase, without a trailing dot
    /// (or an IP literal without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
}

/// One pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPin {
    /// The pinned key.
    pub key: PinKey,
    /// SHA-256 of the pinned leaf certificate.
    pub fingerprint: Fingerprint,
    /// When it was pinned (Unix ms).
    pub pinned_ms: i64,
}

/// The outcome of [`TlsPinStore::check_or_pin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// The certificate matches the key's pin.
    Matches,
    /// The key had no pin; this certificate is now pinned.
    Pinned,
    /// The key is pinned to another certificate.
    Mismatch(Fingerprint),
    /// No pin, and the instance or the host is at its pin cap.
    Full,
}

/// Which pins a listing or reset selects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinFilter {
    /// Only this instance's pins.
    pub instance_id: Option<String>,
    /// Only pins for this host (with `instance_id`).
    pub host: Option<String>,
    /// Only pins for this port (with `host`).
    pub port: Option<u16>,
}

impl PinFilter {
    fn matches(&self, key: &PinKey) -> bool {
        self.instance_id
            .as_ref()
            .is_none_or(|i| *i == key.instance_id)
            && self.host.as_ref().is_none_or(|h| *h == key.host)
            && self.port.is_none_or(|p| p == key.port)
    }

    /// The filter, after checking that a host comes with an instance and
    /// a port with a host, so a reset can't be broader than it reads.
    ///
    /// # Errors
    ///
    /// A message naming what is missing.
    pub fn validated(self) -> Result<Self, String> {
        if self.host.is_some() && self.instance_id.is_none() {
            return Err("a host needs an instance id".into());
        }
        if self.port.is_some() && self.host.is_none() {
            return Err("a port needs a host".into());
        }
        if self.host.as_ref().is_some_and(|h| h.len() > MAX_HOST_LEN) {
            return Err("host is too long".into());
        }
        Ok(Self {
            host: self.host.map(|h| normalize_host(&h)),
            ..self
        })
    }
}

/// Lowercase, without a trailing dot or IPv6 brackets.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The `network_tls_pin` table plus its in-memory copy. One per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct TlsPinStore {
    db: Option<Arc<Db>>,
    pins: RwLock<BTreeMap<PinKey, (Fingerprint, i64)>>,
    /// Serializes writers through commit and publication.
    writer: Mutex<()>,
}

impl Default for TlsPinStore {
    fn default() -> Self {
        Self::detached()
    }
}

impl TlsPinStore {
    /// A store with no database: pins live for the process only.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            db: None,
            pins: RwLock::new(BTreeMap::new()),
            writer: Mutex::new(()),
        }
    }

    /// Load every pin from `db`. Rows that don't decode are skipped
    /// (and logged): a lost pin re-pins, it never trusts more.
    ///
    /// # Errors
    ///
    /// `SQLite` errors reading the table.
    pub fn open(db: Arc<Db>) -> Result<Self, rusqlite::Error> {
        let pins = db.read(|conn| -> Result<_, rusqlite::Error> {
            let mut stmt = conn.prepare(
                "SELECT instance_id, host, port, sha256, pinned_ms FROM network_tls_pin",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?;
            let mut out = BTreeMap::new();
            for row in rows {
                let (instance_id, host, port, sha, pinned_ms) = row?;
                if let (Ok(port), Some(fp)) = (u16::try_from(port), Fingerprint::from_hex(&sha)) {
                    out.insert(
                        PinKey {
                            instance_id,
                            host,
                            port,
                        },
                        (fp, pinned_ms),
                    );
                } else {
                    tracing::warn!(
                        target: "host.network",
                        instance_id = %instance_id,
                        host = %host,
                        "skipping a malformed TLS pin row",
                    );
                }
            }
            Ok(out)
        })?;
        Ok(Self {
            db: Some(db),
            pins: RwLock::new(pins),
            writer: Mutex::new(()),
        })
    }

    /// Compare `fingerprint` with `key`'s pin, pinning it when there is
    /// none. Blocking (a new pin is a durable `SQLite` write).
    ///
    /// # Errors
    ///
    /// `SQLite` errors storing a new pin; the certificate is then not
    /// trusted.
    pub fn check_or_pin(
        &self,
        key: &PinKey,
        fingerprint: Fingerprint,
    ) -> Result<PinCheck, rusqlite::Error> {
        if let Some(check) = self.check(key, fingerprint) {
            return Ok(check);
        }
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        // Re-check under the writer: a concurrent request may have pinned.
        if let Some(check) = self.check(key, fingerprint) {
            return Ok(check);
        }
        {
            let pins = self.pins.read().unwrap_or_else(PoisonError::into_inner);
            let owned = pins
                .keys()
                .filter(|k| k.instance_id == key.instance_id)
                .count();
            if pins.len() >= MAX_PINS_TOTAL || owned >= MAX_PINS_PER_INSTANCE {
                return Ok(PinCheck::Full);
            }
        }
        let now = now_unix_ms();
        if let Some(db) = &self.db {
            db.write(|conn| {
                conn.execute(
                    "INSERT INTO network_tls_pin (instance_id, host, port, sha256, pinned_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        key.instance_id,
                        key.host,
                        i64::from(key.port),
                        fingerprint.to_hex(),
                        now
                    ],
                )
            })?;
        }
        self.pins
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), (fingerprint, now));
        Ok(PinCheck::Pinned)
    }

    fn check(&self, key: &PinKey, fingerprint: Fingerprint) -> Option<PinCheck> {
        let pins = self.pins.read().unwrap_or_else(PoisonError::into_inner);
        pins.get(key).map(|(pinned, _)| {
            if *pinned == fingerprint {
                PinCheck::Matches
            } else {
                PinCheck::Mismatch(*pinned)
            }
        })
    }

    /// The pins `filter` selects, ordered by instance, host and port.
    #[must_use]
    pub fn list(&self, filter: &PinFilter) -> Vec<TlsPin> {
        self.pins
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(key, _)| filter.matches(key))
            .map(|(key, (fingerprint, pinned_ms))| TlsPin {
                key: key.clone(),
                fingerprint: *fingerprint,
                pinned_ms: *pinned_ms,
            })
            .collect()
    }

    /// Remove the pins `filter` selects (an empty filter removes every
    /// pin); returns what was removed. The next request to a removed key
    /// pins again.
    ///
    /// # Errors
    ///
    /// `SQLite` errors; memory is then unchanged.
    pub fn reset(&self, filter: &PinFilter) -> Result<Vec<TlsPin>, rusqlite::Error> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let removed = self.list(filter);
        if removed.is_empty() {
            return Ok(removed);
        }
        if let Some(db) = &self.db {
            db.write(|conn| -> Result<(), rusqlite::Error> {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare(
                        "DELETE FROM network_tls_pin \
                         WHERE instance_id = ?1 AND host = ?2 AND port = ?3",
                    )?;
                    for pin in &removed {
                        stmt.execute(params![
                            pin.key.instance_id,
                            pin.key.host,
                            i64::from(pin.key.port)
                        ])?;
                    }
                }
                tx.commit()
            })?;
        }
        let mut pins = self.pins.write().unwrap_or_else(PoisonError::into_inner);
        for pin in &removed {
            pins.remove(&pin.key);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(instance: &str, host: &str, port: u16) -> PinKey {
        PinKey {
            instance_id: instance.into(),
            host: host.into(),
            port,
        }
    }

    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }

    #[test]
    fn first_use_pins_then_matches_or_mismatches() {
        let store = TlsPinStore::open(Arc::new(Db::open_in_memory().unwrap())).unwrap();
        let k = key("cam", "192.168.1.20", 443);
        assert_eq!(store.check_or_pin(&k, fp(1)).unwrap(), PinCheck::Pinned);
        assert_eq!(store.check_or_pin(&k, fp(1)).unwrap(), PinCheck::Matches);
        assert_eq!(
            store.check_or_pin(&k, fp(2)).unwrap(),
            PinCheck::Mismatch(fp(1))
        );
        // Another port is another key.
        assert_eq!(
            store
                .check_or_pin(&key("cam", "192.168.1.20", 8443), fp(2))
                .unwrap(),
            PinCheck::Pinned
        );
    }

    #[test]
    fn pins_survive_reopen_and_reset_by_filter() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let store = TlsPinStore::open(Arc::clone(&db)).unwrap();
        store
            .check_or_pin(&key("a", "cam.lan", 443), fp(1))
            .unwrap();
        store
            .check_or_pin(&key("a", "cam.lan", 8443), fp(2))
            .unwrap();
        store
            .check_or_pin(&key("b", "cam.lan", 443), fp(3))
            .unwrap();
        let reopened = TlsPinStore::open(Arc::clone(&db)).unwrap();
        assert_eq!(reopened.list(&PinFilter::default()).len(), 3);

        let one = PinFilter {
            instance_id: Some("a".into()),
            host: Some("CAM.lan.".into()),
            port: Some(8443),
        }
        .validated()
        .unwrap();
        let removed = reopened.reset(&one).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].fingerprint, fp(2));
        let instance_a = PinFilter {
            instance_id: Some("a".into()),
            ..PinFilter::default()
        };
        assert_eq!(reopened.list(&instance_a).len(), 1);
        assert_eq!(reopened.reset(&instance_a).unwrap().len(), 1);
        assert_eq!(
            TlsPinStore::open(db)
                .unwrap()
                .list(&PinFilter::default())
                .len(),
            1
        );
    }

    #[test]
    fn filters_need_their_parents() {
        assert!(
            PinFilter {
                host: Some("x".into()),
                ..PinFilter::default()
            }
            .validated()
            .is_err()
        );
        assert!(
            PinFilter {
                instance_id: Some("a".into()),
                port: Some(1),
                ..PinFilter::default()
            }
            .validated()
            .is_err()
        );
    }

    #[test]
    fn pins_are_capped_per_instance() {
        let store = TlsPinStore::detached();
        for port in 0..u16::try_from(MAX_PINS_PER_INSTANCE).unwrap() {
            assert_eq!(
                store.check_or_pin(&key("a", "h", port), fp(1)).unwrap(),
                PinCheck::Pinned
            );
        }
        assert_eq!(
            store.check_or_pin(&key("a", "h", 9999), fp(1)).unwrap(),
            PinCheck::Full
        );
        // Existing keys still check.
        assert_eq!(
            store.check_or_pin(&key("a", "h", 0), fp(1)).unwrap(),
            PinCheck::Matches
        );
        assert_eq!(
            store.check_or_pin(&key("b", "h", 0), fp(1)).unwrap(),
            PinCheck::Pinned
        );
    }

    #[test]
    fn fingerprints_round_trip_hex() {
        let f = Fingerprint::of_der(b"cert");
        assert_eq!(Fingerprint::from_hex(&f.to_hex()), Some(f));
        assert_eq!(Fingerprint::from_hex("zz"), None);
    }
}
