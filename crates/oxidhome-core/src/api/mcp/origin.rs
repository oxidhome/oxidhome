//! Origin allow-list middleware for the MCP mount.
//!
//! PR #119 round-2 F2 — the MCP transport spec ([Security
//! considerations][spec]) requires the server to validate the
//! `Origin` request header on every streamable-HTTP call to
//! prevent DNS-rebinding attacks: a malicious page in the
//! victim's browser resolves an attacker-controlled hostname to
//! the operator's loopback IP and then rides the browser's
//! ambient authority to talk to their local MCP hub.
//!
//! # Policy (14.1)
//!
//! - Non-browser clients (curl, agent HTTP libraries, our own
//!   integration tests) don't send `Origin`. Those pass — the
//!   attack requires a browser as the confused deputy.
//! - Browser clients always send `Origin`; we allow only the
//!   loopback family (`http://localhost*`, `http://127.0.0.1*`,
//!   `http://[::1]*`, and their `https://` variants). A hub
//!   binds to loopback by default, so any legitimate browser
//!   client is same-origin (or a locally-served UI).
//! - Anything else → 403 Forbidden.
//!
//! When 14.4 lands bearer auth, missing-`Origin`-with-no-token
//! becomes 401 anyway. This layer is scoped to the DNS-rebind
//! attack surface: it never grants access — only denies clearly
//! wrong ones.
//!
//! [spec]:
//!   https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Middleware: reject requests whose `Origin` header (if any)
/// isn't a loopback address. Callers with no `Origin` pass
/// through — see the module doc.
pub(super) async fn require_local_origin(request: Request, next: Next) -> Response {
    let Some(origin) = request.headers().get(header::ORIGIN) else {
        return next.run(request).await;
    };
    let Ok(origin) = origin.to_str() else {
        // Non-ASCII / malformed Origin header — no legitimate
        // browser sends this; treat as attacker-shaped.
        return (StatusCode::FORBIDDEN, "Invalid Origin header").into_response();
    };
    if is_loopback_origin(origin) {
        next.run(request).await
    } else {
        tracing::warn!(
            origin = %origin,
            "MCP request rejected: Origin not in loopback allow-list",
        );
        (StatusCode::FORBIDDEN, "Origin not allowed").into_response()
    }
}

/// Loopback-family `Origin` matcher. Accepts:
///
/// - `http://localhost` / `http://localhost:<port>`
/// - `http://127.0.0.1` / `http://127.0.0.1:<port>`
/// - `http://[::1]` / `http://[::1]:<port>`
/// - the same three with `https://`
///
/// Rejects everything else, including subdomains like
/// `attacker.localhost` (must be an exact host match after the
/// scheme).
fn is_loopback_origin(origin: &str) -> bool {
    // Split scheme://host[:port] into scheme + rest.
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if scheme != "http" && scheme != "https" {
        return false;
    }
    // Origin has no path per spec; still guard against a
    // trailing `/` that some libraries include.
    let rest = rest.split_once('/').map_or(rest, |(head, _)| head);

    // IPv6-literal Origin is `[::1][:port]`; split on the
    // closing bracket first.
    if let Some(rest) = rest.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host != "::1" {
            return false;
        }
        return tail.is_empty() || tail.starts_with(':');
    }

    // IPv4 / hostname: strip an optional `:port`.
    let host = rest.split_once(':').map_or(rest, |(head, _)| head);
    matches!(host, "localhost" | "127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::is_loopback_origin;

    #[test]
    fn loopback_hosts_pass_with_and_without_port() {
        for allowed in [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://[::1]",
            "http://[::1]:8443",
            "https://localhost:443",
        ] {
            assert!(
                is_loopback_origin(allowed),
                "expected loopback allow: {allowed}",
            );
        }
    }

    #[test]
    fn non_loopback_hosts_are_rejected() {
        for denied in [
            "http://attacker.example",
            "http://attacker.example:8080",
            "https://evil.com",
            // Subdomain of localhost is a well-known
            // DNS-rebinding trick — reject.
            "http://attacker.localhost",
            // Malformed / no scheme.
            "localhost:8080",
            // Wrong scheme.
            "ftp://localhost",
            // IPv6 with a non-loopback host inside brackets.
            "http://[2001:db8::1]",
        ] {
            assert!(
                !is_loopback_origin(denied),
                "expected loopback deny: {denied}",
            );
        }
    }
}
