//! C6: short-lived HMAC-signed tickets that let a browser
//! load the sandboxed plugin UI *without* an
//! `Authorization: Bearer …` header on the wrapper or
//! frame requests.
//!
//! # Why tickets exist — browser flow
//!
//! The operator's dashboard app (which holds the bearer)
//! calls `POST /api/v1/plugins/{plugin_id}/ui-session` and
//! receives `{"url": ".../ui?tk=<t>", ...}`. The dashboard
//! renders that URL as an iframe `src` (or opens it in a
//! new tab). Browsers do **not** attach the parent page's
//! `Authorization` header to iframe subresource
//! navigations or to top-level document navigations, so
//! the wrapper endpoint at `/ui` must not require a
//! bearer — it authenticates by the ticket embedded in
//! its own URL instead. The wrapper page then reuses the
//! same ticket as the iframe `src` for `/ui/frame`.
//!
//! Round-2 (C6 review round-1, finding 1): pre-fix, `/ui`
//! itself sat behind bearer middleware, so a real browser
//! navigating to a plugin UI got 401. The old integration
//! test hid this by manually adding the header to a
//! `oneshot` request. The current shape splits the
//! bearer-gated JSON minting endpoint from the public
//! ticket-gated wrapper.
//!
//! # Format
//!
//! On the wire:
//! ```text
//! <expiry_ms>~<plugin_id>~<installation_uuid>~<hmac_hex>
//! ```
//!
//! - `expiry_ms` — decimal milliseconds since Unix epoch.
//! - `plugin_id` — reverse-DNS, no `~`.
//! - `installation_uuid` — the specific installation of
//!   `plugin_id` this ticket authorises. Round-2 finding 2:
//!   pre-fix, tickets bound only `plugin_id`; an
//!   uninstall + reinstall under the same id (different
//!   `installation_uuid`) let an old ticket authorise the
//!   *replacement* package's UI. Binding to
//!   `installation_uuid` and comparing at verify time
//!   makes cross-reinstall tickets fail closed.
//! - `hmac_hex` — 128-bit prefix of HMAC-SHA256 keyed on
//!   the per-process
//!   [`Engine::ui_ticket_secret`](crate::Engine::ui_ticket_secret),
//!   over the payload
//!   `"<expiry_ms>~<plugin_id>~<installation_uuid>"`.
//!
//! Ticket length is bounded (see [`MAX_TICKET_LEN`]) so
//! the public verifier can't be pushed into a big
//! allocation by a query string full of separators
//! (round-2 finding 3).
//!
//! # Lifetime
//!
//! `TICKET_TTL` is 5 minutes — long enough for a browser
//! to open the wrapper, load the iframe, and settle;
//! short enough that a leaked URL doesn't grant open-ended
//! access. A daemon restart rotates the secret and
//! invalidates every outstanding ticket.

use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

/// C6: how long a `/ui-session` mint remains valid.
pub(crate) const TICKET_TTL: Duration = Duration::from_mins(5);

/// C6 round-2 finding 3: hard upper bound on the raw
/// ticket length the public frame handler will attempt to
/// parse. Real tickets are well under this — 20 (expiry
/// digits) + typical `plugin_id` (~40) + 32 (UUID hex) +
/// 32 (mac hex) + 3 delimiters ≈ 130 chars. 512 is
/// comfortable headroom without letting an attacker
/// coerce a per-request `String::new` + Vec growth by
/// stuffing the query with separator-heavy garbage.
pub(crate) const MAX_TICKET_LEN: usize = 512;

/// C6: outcome of [`verify`]. The frame handler maps `Bad`
/// to `400 Bad Request` (client bug — refetch
/// `/ui-session`), `Expired` to `401 Unauthorized`
/// (natural retry-with-fresh-ticket signal), and
/// `WrongPlugin` to `404 Not Found` (indistinguishable
/// from a nonexistent plugin, so cross-plugin ticket
/// misuse can't enumerate installed ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketError {
    /// Shape / decoding / MAC mismatch, or ticket too long.
    Bad,
    /// MAC verifies but `expiry_ms` is in the past.
    Expired,
    /// MAC verifies and the ticket is fresh, but its
    /// `(plugin_id, installation_uuid)` pair doesn't match
    /// what the caller passed. Covers both cross-plugin
    /// ticket use AND the uninstall + reinstall race
    /// (same `plugin_id`, different `installation_uuid`).
    WrongPlugin,
}

/// Sign a fresh ticket for `plugin_id` @ `installation_uuid`
/// with expiry `now + TICKET_TTL`. Called by the
/// authenticated `/ui-session` handler after the
/// bearer + `plugins:ui` scope check succeeds.
pub(crate) fn issue(
    secret: &[u8; 32],
    plugin_id: &str,
    installation_uuid: &str,
    now: SystemTime,
) -> String {
    let expiry_ms = now
        .checked_add(TICKET_TTL)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let payload = format!("{expiry_ms}~{plugin_id}~{installation_uuid}");
    let mac = hmac_sha256(secret, payload.as_bytes());
    let mut hex = String::with_capacity(32);
    for b in &mac[..16] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!("{payload}~{hex}")
}

/// Verify a ticket the wrapper / frame handler received in
/// `?tk=…` against the per-process secret,
/// `expected_plugin_id` (from the URL path), and
/// `expected_installation_uuid` (looked up from the
/// current registry row).
pub(crate) fn verify(
    secret: &[u8; 32],
    raw: &str,
    expected_plugin_id: &str,
    expected_installation_uuid: &str,
    now: SystemTime,
) -> Result<(), TicketError> {
    // Round-2 finding 3: cap raw length first. Parsing an
    // over-long ticket allocates nothing beyond the check.
    if raw.len() > MAX_TICKET_LEN {
        return Err(TicketError::Bad);
    }
    // Round-2 finding 3: parse without collecting every
    // `~`-separated segment. `rsplit_once` peels the mac
    // suffix in O(1); the remaining `<expiry>~<id>~<uuid>`
    // splits into exactly three pieces via `splitn(3, '~')`.
    let (payload, mac_hex) = raw.rsplit_once('~').ok_or(TicketError::Bad)?;
    let mut parts = payload.splitn(3, '~');
    let expiry_ms_str = parts.next().ok_or(TicketError::Bad)?;
    let plugin_id = parts.next().ok_or(TicketError::Bad)?;
    let installation_uuid = parts.next().ok_or(TicketError::Bad)?;
    if parts.next().is_some()
        || expiry_ms_str.is_empty()
        || plugin_id.is_empty()
        || installation_uuid.is_empty()
        || mac_hex.len() != 32
    {
        return Err(TicketError::Bad);
    }
    let expiry_ms: u64 = expiry_ms_str.parse().map_err(|_| TicketError::Bad)?;
    // MAC first — even a wrong-plugin or expired ticket
    // must present a valid signature, otherwise attackers
    // can enumerate accepted `(plugin_id, uuid)` tuples or
    // probe the clock.
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
    if plugin_id != expected_plugin_id || installation_uuid != expected_installation_uuid {
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
/// dep, same as `state::device_state::hmac_sha256`.
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
    fn issued_ticket_verifies_for_same_id_and_uuid() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", now);
        verify(&secret(), &t, "com.example.foo", "inst-uuid-1", now)
            .expect("fresh ticket verifies");
    }

    /// Round-2 finding 2: a ticket for the same
    /// `plugin_id` under a *different* `installation_uuid`
    /// (uninstall + reinstall race) is rejected as
    /// `WrongPlugin`.
    #[test]
    fn ticket_rejects_wrong_installation_uuid() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", now);
        assert_eq!(
            verify(&secret(), &t, "com.example.foo", "inst-uuid-2", now),
            Err(TicketError::WrongPlugin),
        );
    }

    #[test]
    fn ticket_rejects_wrong_plugin() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", now);
        assert_eq!(
            verify(&secret(), &t, "com.example.bar", "inst-uuid-1", now),
            Err(TicketError::WrongPlugin),
        );
    }

    #[test]
    fn ticket_rejects_expired() {
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", issued_at);
        let later = issued_at + TICKET_TTL + Duration::from_secs(1);
        assert_eq!(
            verify(&secret(), &t, "com.example.foo", "inst-uuid-1", later),
            Err(TicketError::Expired),
        );
    }

    #[test]
    fn ticket_rejects_tampered_mac() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", now);
        let mut chars: Vec<char> = t.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            verify(&secret(), &tampered, "com.example.foo", "inst-uuid-1", now),
            Err(TicketError::Bad),
        );
    }

    #[test]
    fn ticket_rejects_wrong_secret() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t = issue(&secret(), "com.example.foo", "inst-uuid-1", now);
        let other_secret = [0xa5; 32];
        assert_eq!(
            verify(&other_secret, &t, "com.example.foo", "inst-uuid-1", now),
            Err(TicketError::Bad),
        );
    }

    #[test]
    fn ticket_rejects_malformed_shapes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            verify(&secret(), "", "id", "uuid", now),
            Err(TicketError::Bad),
        );
        assert_eq!(
            verify(&secret(), "a~b", "id", "uuid", now),
            Err(TicketError::Bad),
        );
        // Missing installation_uuid segment (old 3-part
        // shape from round-1) → Bad.
        assert_eq!(
            verify(
                &secret(),
                "1~id~00000000000000000000000000000000",
                "id",
                "uuid",
                now,
            ),
            Err(TicketError::Bad),
        );
        assert_eq!(
            verify(&secret(), "1~id~uuid~short", "id", "uuid", now),
            Err(TicketError::Bad),
        );
    }

    /// Round-2 finding 3: a ticket longer than
    /// `MAX_TICKET_LEN` is rejected without allocation.
    #[test]
    fn ticket_rejects_over_max_length() {
        let mut oversized = "1~id~uuid~".to_string();
        oversized.push_str(&"~".repeat(MAX_TICKET_LEN));
        assert_eq!(
            verify(&secret(), &oversized, "id", "uuid", SystemTime::UNIX_EPOCH),
            Err(TicketError::Bad),
        );
    }

    /// A payload that would explode a naive `split` into a
    /// huge Vec still exits fast: the length cap fires
    /// before any parsing runs.
    #[test]
    fn separator_heavy_ticket_does_not_amplify_allocation() {
        let long = "~".repeat(MAX_TICKET_LEN + 1);
        assert_eq!(
            verify(&secret(), &long, "id", "uuid", SystemTime::UNIX_EPOCH),
            Err(TicketError::Bad),
        );
    }
}
