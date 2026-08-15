//! C6: short-lived HMAC-signed tickets that let a sandboxed
//! iframe authenticate to `GET /api/v1/plugins/{plugin_id}/ui/frame`.
//!
//! # Why tickets exist
//!
//! `/ui/frame` is loaded as an iframe subresource by the
//! sandboxed wrapper page at `/ui`. Browsers deliberately do
//! **not** propagate the parent page's `Authorization: Bearer …`
//! header into subresource navigations, so the frame endpoint
//! can't reuse the bearer that gated the wrapper. Cookies
//! would be one option (the deployment model is a single
//! daemon origin, so cookie scope is fine), but cookies
//! require the operator to configure `Secure` / `SameSite`
//! and pay attention to CSRF once we grow write endpoints.
//!
//! A short-lived, plugin-id-bound, path-embedded ticket is
//! narrower: it authorises exactly one thing (`GET /ui/frame`
//! for exactly this `plugin_id`), for a small time window, with
//! no ambient authority. Ticket verification runs in the
//! frame handler itself — the bearer-token layer never sees
//! `/ui/frame` requests, so there's no risk of an
//! Authorization-less request tripping the anonymous-probe
//! audit code path.
//!
//! # Format
//!
//! On the wire:
//! ```text
//! <expiry_ms>~<plugin_id>~<hmac_hex>
//! ```
//!
//! - `expiry_ms` — decimal milliseconds since Unix epoch after
//!   which the ticket is refused.
//! - `plugin_id` — the plugin the ticket authorises. Bound to
//!   the URL path segment so a ticket for plugin A can't
//!   unlock plugin B's frame.
//! - `hmac_hex` — 128-bit prefix of HMAC-SHA256 keyed on the
//!   per-process
//!   [`Engine::ui_ticket_secret`](crate::Engine::ui_ticket_secret),
//!   over the payload `"<expiry_ms>~<plugin_id>"`. The `~`
//!   delimiter never appears in `plugin_id` (reverse-DNS
//!   `[a-z0-9.-]+`) so plain string parsing is unambiguous.
//!
//! # Lifetime
//!
//! `TICKET_TTL` is 5 minutes — long enough for a browser to
//! finish loading the iframe and any deferred subresources,
//! short enough that a leaked wrapper URL doesn't grant
//! open-ended access. The bearer that fetched `/ui` is the
//! long-lived credential; the ticket is a ~5-minute
//! delegation. A daemon restart rotates the secret and
//! invalidates every outstanding ticket.

use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

/// C6: how long a `/ui` mint remains valid. 5 minutes
/// covers a user opening the wrapper, the browser fetching
/// the iframe, and any deferred subresource loads inside
/// the sandbox — well past the "load and settle" window a
/// legitimate UI needs.
pub(crate) const TICKET_TTL: Duration = Duration::from_mins(5);

/// C6: outcome of [`verify`]. The frame handler maps `Bad`
/// to `400 Bad Request` (malformed ticket the client
/// supplied), `Expired` to `401 Unauthorized` (the natural
/// "auth required" fit — the client can retry by re-fetching
/// `/ui` to mint a fresh ticket), and `WrongPlugin` to
/// `404 Not Found` (indistinguishable from a nonexistent
/// plugin, avoiding an enumeration oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketError {
    /// Shape / decoding / MAC mismatch.
    Bad,
    /// MAC verifies but `expiry_ms` is in the past.
    Expired,
    /// MAC verifies and the ticket is fresh, but the
    /// `plugin_id` baked into the ticket doesn't match the
    /// URL path segment.
    WrongPlugin,
}

/// Sign a fresh ticket for `plugin_id` with expiry `now +
/// TICKET_TTL`. Called by the `/ui` handler after the
/// bearer + `plugins:ui` scope check succeeds.
pub(crate) fn issue(secret: &[u8; 32], plugin_id: &str, now: SystemTime) -> String {
    let expiry_ms = now
        .checked_add(TICKET_TTL)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let payload = format!("{expiry_ms}~{plugin_id}");
    let mac = hmac_sha256(secret, payload.as_bytes());
    let mut hex = String::with_capacity(32);
    for b in &mac[..16] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!("{payload}~{hex}")
}

/// Verify a ticket the frame handler received in `?tk=…`
/// against the per-process secret and `expected_plugin_id`
/// (from the URL path).
pub(crate) fn verify(
    secret: &[u8; 32],
    raw: &str,
    expected_plugin_id: &str,
    now: SystemTime,
) -> Result<(), TicketError> {
    let parts: Vec<&str> = raw.split('~').collect();
    if parts.len() != 3 {
        return Err(TicketError::Bad);
    }
    let (expiry_ms_str, plugin_id, mac_hex) = (parts[0], parts[1], parts[2]);
    if expiry_ms_str.is_empty() || plugin_id.is_empty() || mac_hex.len() != 32 {
        return Err(TicketError::Bad);
    }
    let expiry_ms: u64 = expiry_ms_str.parse().map_err(|_| TicketError::Bad)?;
    // MAC first — even a wrong-plugin or expired ticket must
    // present a valid signature, otherwise attackers can
    // enumerate accepted plugin ids or probe the clock.
    let payload = format!("{expiry_ms_str}~{plugin_id}");
    let expected = hmac_sha256(secret, payload.as_bytes());
    let mut supplied = [0u8; 16];
    for (i, chunk) in mac_hex.as_bytes().chunks(2).enumerate() {
        supplied[i] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| TicketError::Bad)?,
            16,
        )
        .map_err(|_| TicketError::Bad)?;
    }
    if !constant_time_eq(&expected[..16], &supplied) {
        return Err(TicketError::Bad);
    }
    if plugin_id != expected_plugin_id {
        return Err(TicketError::WrongPlugin);
    }
    let now_ms = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    if now_ms >= expiry_ms {
        return Err(TicketError::Expired);
    }
    Ok(())
}

/// HMAC-SHA256 — hand-rolled on top of the existing `sha2`
/// dep, same as `state::device_state::hmac_sha256`. Only
/// ~15 lines; not worth adding the `hmac` crate for one
/// additional call site.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k_padded = [0u8; BLOCK];
    k_padded[..key.len()].copy_from_slice(key);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k_padded[i];
        opad[i] ^= k_padded[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        [0x5a; 32]
    }

    #[test]
    fn issued_ticket_verifies_for_same_plugin_id() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", now);
        verify(&secret(), &t, "com.example.foo", now).expect("fresh ticket verifies");
    }

    #[test]
    fn ticket_rejects_wrong_plugin() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", now);
        assert_eq!(
            verify(&secret(), &t, "com.example.bar", now),
            Err(TicketError::WrongPlugin),
        );
    }

    #[test]
    fn ticket_rejects_expired() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", issued_at);
        let later = issued_at + TICKET_TTL + Duration::from_secs(1);
        assert_eq!(
            verify(&secret(), &t, "com.example.foo", later),
            Err(TicketError::Expired),
        );
    }

    #[test]
    fn ticket_rejects_tampered_mac() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", now);
        // Flip one hex char in the mac suffix.
        let mut chars: Vec<char> = t.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            verify(&secret(), &tampered, "com.example.foo", now),
            Err(TicketError::Bad),
        );
    }

    #[test]
    fn ticket_rejects_wrong_secret() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", now);
        let other_secret = [0xa5; 32];
        assert_eq!(
            verify(&other_secret, &t, "com.example.foo", now),
            Err(TicketError::Bad),
        );
    }

    #[test]
    fn ticket_rejects_malformed_shapes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(verify(&secret(), "", "id", now), Err(TicketError::Bad));
        assert_eq!(verify(&secret(), "a~b", "id", now), Err(TicketError::Bad));
        assert_eq!(
            verify(
                &secret(),
                "notdigits~id~00000000000000000000000000000000",
                "id",
                now
            ),
            Err(TicketError::Bad),
        );
        assert_eq!(
            verify(&secret(), "1~id~short", "id", now),
            Err(TicketError::Bad),
        );
    }
}
