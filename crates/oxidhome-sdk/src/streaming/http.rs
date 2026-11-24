//! A blocking HTTP client over `wasi:http`.
//!
//! ```no_run
//! use oxidhome_sdk::streaming::http::Request;
//!
//! let response = Request::get("https://camera.lan:10443/status")
//!     .header("accept", "application/json")
//!     .timeout(std::time::Duration::from_secs(5))
//!     .send()?;
//! if response.status() == 200 {
//!     let text = response.text().unwrap_or_default();
//!     oxidhome_sdk::tracing::info!(%text, "camera status");
//! }
//! # Ok::<(), oxidhome_sdk::streaming::http::Error>(())
//! ```
//!
//! [`Request::send`] blocks until the whole response body has arrived (or
//! a limit or timeout ends the request), so call it from `init`, a
//! command or a service call, not from a tight `tick`.
//!
//! - **Limits.** Bodies over [`Request::max_body`] (1 MiB by default) end
//!   the request with [`Error::BodyTooLarge`]. [`Request::timeout`] (30 s
//!   by default) bounds connecting, waiting for the response head, and
//!   each gap between body chunks.
//! - **Redirects.** `301`, `302`, `303`, `307` and `308` with a
//!   `Location` are followed, at most [`MAX_REDIRECTS`] times (fewer with
//!   [`Request::max_redirects`]). Each hop is a new request that the host
//!   checks against the instance's network rules again. A redirect from
//!   `https` to `http` is refused ([`Error::InsecureRedirect`]); a
//!   redirect to another origin drops `authorization`, `cookie` and
//!   `proxy-authorization` (other headers, such as an API key header,
//!   are kept: set [`Request::max_redirects`] to `0` to follow redirects
//!   yourself). `303`, and `301` / `302` after a `POST`, continue as a
//!   `GET` without a body.
//! - **HTTPS.** The host verifies certificates against the system's
//!   roots. A device on the LAN (a private or link-local address) with a
//!   self-signed certificate is trusted on first use: the host pins the
//!   certificate it sees first and refuses any other until the operator
//!   resets the pin.

use std::time::Duration;

use crate::bindings::wasi::http::outgoing_handler;
use crate::bindings::wasi::http::types::{
    ErrorCode, Fields, FutureIncomingResponse, IncomingBody, IncomingResponse,
    Method as WasiMethod, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
};
use crate::bindings::wasi::io::streams::{OutputStream, StreamError};

/// Most redirects one [`Request::send`] follows.
pub const MAX_REDIRECTS: u8 = 5;
/// Default [`Request::max_body`]: 1 MiB.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;
/// Default [`Request::timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest write `wasi:io` takes at once.
const WRITE_CHUNK: usize = 4096;
/// Largest read asked of the response stream at once.
const READ_CHUNK: u64 = 64 * 1024;
/// Headers dropped when a redirect leaves the origin.
const CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "cookie", "proxy-authorization"];

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL isn't `http(s)://host[:port][/path][?query]`.
    #[error("invalid URL `{0}`")]
    InvalidUrl(String),
    /// The host refused or failed the request. `HTTP-request-denied`
    /// means no network rule allows it ([`Error::is_denied`]).
    #[error("HTTP request failed: {0:?}")]
    Http(ErrorCode),
    /// The request couldn't be built or its body written.
    #[error("{0}")]
    Request(String),
    /// The response body is larger than [`Request::max_body`].
    #[error("response body exceeds {limit} bytes")]
    BodyTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// More redirects than [`Request::max_redirects`].
    #[error("more than {limit} redirects")]
    TooManyRedirects {
        /// The limit that was exceeded.
        limit: u8,
    },
    /// An `https` response redirected to `http`.
    #[error("refusing to follow an https redirect to plain http: `{0}`")]
    InsecureRedirect(String),
}

impl Error {
    /// Whether the host refused the request because no network rule
    /// allows it.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Error::Http(ErrorCode::HttpRequestDenied))
    }
}

/// An HTTP method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `PATCH`
    Patch,
    /// `OPTIONS`
    Options,
    /// Any other token, e.g. `"PROPFIND"`.
    Other(String),
}

impl Method {
    fn to_wasi(&self) -> WasiMethod {
        match self {
            Method::Get => WasiMethod::Get,
            Method::Head => WasiMethod::Head,
            Method::Post => WasiMethod::Post,
            Method::Put => WasiMethod::Put,
            Method::Delete => WasiMethod::Delete,
            Method::Patch => WasiMethod::Patch,
            Method::Options => WasiMethod::Options,
            Method::Other(m) => WasiMethod::Other(m.clone()),
        }
    }
}

/// A request to send. Build it with [`Request::get`] / [`Request::new`]
/// and the setters, then [`Request::send`] it.
#[derive(Debug, Clone)]
pub struct Request {
    method: Method,
    url: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    timeout: Duration,
    max_body: usize,
    max_redirects: u8,
}

impl Request {
    /// A request with `method` to `url`.
    #[must_use]
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
            max_redirects: MAX_REDIRECTS,
        }
    }

    /// A `GET` request.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }

    /// A `POST` request.
    #[must_use]
    pub fn post(url: impl Into<String>) -> Self {
        Self::new(Method::Post, url)
    }

    /// A `PUT` request.
    #[must_use]
    pub fn put(url: impl Into<String>) -> Self {
        Self::new(Method::Put, url)
    }

    /// A `DELETE` request.
    #[must_use]
    pub fn delete(url: impl Into<String>) -> Self {
        Self::new(Method::Delete, url)
    }

    /// Add a header (names are case-insensitive; repeats are kept).
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers
            .push((name.into().to_ascii_lowercase(), value.into()));
        self
    }

    /// The request body; `content-length` is set from it.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Bound connecting, the wait for the response head, and each gap
    /// between body chunks (each separately).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Largest response body accepted, in bytes.
    #[must_use]
    pub fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// Most redirects followed, at most [`MAX_REDIRECTS`]; `0` returns
    /// the redirect response itself.
    #[must_use]
    pub fn max_redirects(mut self, hops: u8) -> Self {
        self.max_redirects = hops.min(MAX_REDIRECTS);
        self
    }

    /// Send the request, following redirects, and read the response.
    ///
    /// # Errors
    ///
    /// See [`Error`]; a request no network rule allows fails with
    /// [`Error::Http`] (`HTTP-request-denied`).
    pub fn send(self) -> Result<Response, Error> {
        let mut current = self;
        let mut url = Url::parse(&current.url)?;
        let mut hops = 0u8;
        loop {
            let head = current.start(&url)?;
            let location = match redirect_location(head.status, &head.headers) {
                Some(location) if current.max_redirects > 0 => location,
                // The final response: only its body is read.
                _ => return head.read(current.max_body, &url),
            };
            if hops >= current.max_redirects {
                return Err(Error::TooManyRedirects {
                    limit: current.max_redirects,
                });
            }
            hops += 1;
            let next = url.join(&location)?;
            if url.https && !next.https {
                return Err(Error::InsecureRedirect(next.to_string()));
            }
            current.follow(head.status, &url, &next);
            // The redirect's own body is dropped unread.
            drop(head);
            url = next;
        }
    }

    /// Adjust method, body and headers for a redirect with `status` from
    /// `from` to `to`.
    fn follow(&mut self, status: u16, from: &Url, to: &Url) {
        let keeps_method = matches!(status, 307 | 308)
            || (matches!(status, 301 | 302) && self.method != Method::Post);
        if !keeps_method {
            if self.method != Method::Head {
                self.method = Method::Get;
            }
            self.body.clear();
            // Headers describing the dropped body go with it.
            self.headers.retain(|(name, _)| {
                !name.starts_with("content-") && name != "digest" && name != "repr-digest"
            });
        }
        if !from.same_origin(to) {
            self.headers
                .retain(|(name, _)| !CREDENTIAL_HEADERS.contains(&name.as_str()));
        }
        self.url = to.to_string();
    }

    /// Send one request and wait for the response head.
    fn start(&self, url: &Url) -> Result<Head, Error> {
        let headers = Fields::new();
        for (name, value) in &self.headers {
            if name == "content-length" {
                continue;
            }
            headers
                .append(name, value)
                .map_err(|e| Error::Request(format!("header `{name}`: {e:?}")))?;
        }
        // An empty POST / PUT / PATCH still says so: some servers refuse a
        // chunked request without a length (`411`).
        if !self.body.is_empty()
            || matches!(self.method, Method::Post | Method::Put | Method::Patch)
        {
            headers
                .append("content-length", self.body.len().to_string().as_bytes())
                .map_err(|e| Error::Request(format!("content-length: {e:?}")))?;
        }
        let request = OutgoingRequest::new(headers);
        let fail = |what: &str| Error::Request(format!("invalid {what}"));
        request
            .set_method(&self.method.to_wasi())
            .map_err(|()| fail("method"))?;
        request
            .set_scheme(Some(if url.https {
                &Scheme::Https
            } else {
                &Scheme::Http
            }))
            .map_err(|()| fail("scheme"))?;
        request
            .set_authority(Some(&url.authority))
            .map_err(|()| fail("authority"))?;
        request
            .set_path_with_query(Some(&url.path_and_query))
            .map_err(|()| fail("path"))?;
        let options = RequestOptions::new();
        let nanos = u64::try_from(self.timeout.as_nanos()).unwrap_or(u64::MAX);
        let _ = options.set_connect_timeout(Some(nanos));
        let _ = options.set_first_byte_timeout(Some(nanos));
        let _ = options.set_between_bytes_timeout(Some(nanos));

        let outgoing = request.body().map_err(|()| fail("body"))?;
        let pending = outgoing_handler::handle(request, Some(options)).map_err(Error::Http)?;
        // Written after `handle`: the host buffers one chunk, so a body
        // written before the request starts would never drain.
        // A failed or cut-short write leaves the body unfinished, which
        // fails the request, so the response below says why
        // (`HTTP-request-denied`, a TLS error) or carries what the server
        // answered anyway (a `413` mid-upload); the write error itself
        // adds nothing.
        let written = outgoing
            .write()
            .map_err(|()| fail("body stream"))
            .and_then(|stream| write_body(&stream, &self.body, &pending));
        if let Ok(true) = written {
            let _ = OutgoingBody::finish(outgoing, None);
        } else {
            // Unfinished: ends the request instead of leaving the host
            // waiting for the rest of the body.
            drop(outgoing);
        }

        pending.subscribe().block();
        let response = pending
            .get()
            .ok_or_else(|| Error::Request("response not ready".into()))?
            .map_err(|()| Error::Request("response already taken".into()))?
            .map_err(Error::Http)?;
        let status = response.status();
        let headers = {
            let fields = response.headers();
            fields.entries()
        };
        let incoming = response
            .consume()
            .map_err(|()| Error::Request("response body already taken".into()))?;
        Ok(Head {
            status,
            headers,
            incoming,
            _response: response,
        })
    }
}

/// A response head, its body not read yet.
struct Head {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    // Dropped before the response it came from.
    incoming: IncomingBody,
    _response: IncomingResponse,
}

impl Head {
    /// Read the body (at most `max_body` bytes) into a [`Response`].
    fn read(self, max_body: usize, url: &Url) -> Result<Response, Error> {
        let Head {
            status,
            headers,
            incoming,
            _response,
        } = self;
        let body = read_body(incoming, max_body)?;
        Ok(Response {
            status,
            headers,
            body,
            url: url.to_string(),
        })
    }
}

/// Write `body` and flush it. Returns `false` when the response arrived
/// first: a server that answers mid-upload and stops reading would
/// otherwise block the write for good.
fn write_body(
    stream: &OutputStream,
    body: &[u8],
    pending: &FutureIncomingResponse,
) -> Result<bool, Error> {
    let failed = |e: StreamError| Error::Request(format!("writing the body: {e:?}"));
    let writable = stream.subscribe();
    let answered = pending.subscribe();
    let mut rest = body;
    let mut flushed = false;
    loop {
        let room = stream.check_write().map_err(failed)?;
        if room == 0 {
            if crate::bindings::wasi::io::poll::poll(&[&writable, &answered]).contains(&1) {
                return Ok(false);
            }
            continue;
        }
        if rest.is_empty() {
            // `check-write` is 0 until a flush completes.
            if flushed {
                return Ok(true);
            }
            stream.flush().map_err(failed)?;
            flushed = true;
            continue;
        }
        let n = usize::try_from(room)
            .unwrap_or(usize::MAX)
            .min(rest.len())
            .min(WRITE_CHUNK);
        stream.write(&rest[..n]).map_err(failed)?;
        rest = &rest[n..];
    }
}

/// Read a whole response body, refusing more than `max_body` bytes.
fn read_body(incoming: IncomingBody, max_body: usize) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    {
        let stream = incoming
            .stream()
            .map_err(|()| Error::Request("response stream already taken".into()))?;
        loop {
            let room = max_body.saturating_sub(body.len()) as u64 + 1;
            match stream.blocking_read(room.min(READ_CHUNK)) {
                Ok(chunk) => {
                    // Checked before growing the buffer.
                    if chunk.len() > max_body - body.len() {
                        return Err(Error::BodyTooLarge { limit: max_body });
                    }
                    body.extend_from_slice(&chunk);
                }
                Err(StreamError::Closed) => break,
                Err(StreamError::LastOperationFailed(e)) => {
                    return Err(
                        match crate::bindings::wasi::http::types::http_error_code(&e) {
                            Some(code) => Error::Http(code),
                            None => Error::Request(e.to_debug_string()),
                        },
                    );
                }
            }
        }
    }
    drop(IncomingBody::finish(incoming));
    Ok(body)
}

fn redirect_location(status: u16, headers: &[(String, Vec<u8>)]) -> Option<String> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("location"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .map(str::to_owned)
}

/// A response with its whole body.
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    url: String,
}

impl Response {
    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The first value of header `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Every header, in the order received.
    #[must_use]
    pub fn headers(&self) -> &[(String, Vec<u8>)] {
        &self.headers
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body, taken.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// The body as UTF-8.
    ///
    /// # Errors
    ///
    /// When it isn't valid UTF-8.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// The body parsed as JSON.
    ///
    /// # Errors
    ///
    /// When it isn't JSON of type `T`.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// The URL that answered, after redirects.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// An absolute `http(s)` URL, split the way `wasi:http` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    https: bool,
    /// `host[:port]`, as written (brackets kept for IPv6).
    authority: String,
    /// Starts with `/`; the fragment removed.
    path_and_query: String,
}

impl Url {
    fn parse(raw: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidUrl(raw.to_owned());
        let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
        let https = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err(invalid());
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty()
            || authority.contains('@')
            || authority
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(invalid());
        }
        let path_and_query = if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        };
        if path_and_query
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(invalid());
        }
        Ok(Self {
            https,
            authority: authority.to_owned(),
            path_and_query,
        })
    }

    /// Resolve a `Location` against this URL (RFC 3986 §5.2, for the
    /// forms servers send).
    fn join(&self, location: &str) -> Result<Self, Error> {
        let location = location.trim();
        // Absolute when a scheme comes before any `/`, `?` or `#`; only
        // `http(s)://` ones are followed (`parse` refuses the rest).
        let head = location.split(['/', '?', '#']).next().unwrap_or_default();
        if let Some((scheme, _)) = head.split_once(':') {
            let is_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if is_scheme {
                return Self::parse(location).map(Self::without_dot_segments);
            }
        }
        let scheme = if self.https { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Self::parse(&format!("{scheme}://{rest}")).map(Self::without_dot_segments);
        }
        let location = location.split('#').next().unwrap_or_default();
        let (base_path, _) = self
            .path_and_query
            .split_once('?')
            .unwrap_or((&self.path_and_query, ""));
        let target = if location.is_empty() {
            self.path_and_query.clone()
        } else if location.starts_with('/') {
            location.to_owned()
        } else if location.starts_with('?') {
            format!("{base_path}{location}")
        } else {
            let dir = &base_path[..=base_path.rfind('/').unwrap_or(0)];
            format!("{dir}{location}")
        };
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_owned(), Some(q)),
            None => (target.clone(), None),
        };
        let path = remove_dot_segments(&path);
        let path_and_query = match query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        Self::parse(&format!("{scheme}://{}{path_and_query}", self.authority))
    }

    /// This URL with `.` and `..` segments resolved (RFC 3986 §5.2.4).
    fn without_dot_segments(mut self) -> Self {
        let (path, query) = match self.path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (self.path_and_query.as_str(), None),
        };
        let path = remove_dot_segments(path);
        self.path_and_query = match query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        self
    }

    fn same_origin(&self, other: &Self) -> bool {
        let (host, port) = self.origin();
        self.https == other.https && port.is_some() && (host, port) == other.origin()
    }

    /// Host (lowercase; an IP literal in one spelling) and effective port.
    fn origin(&self) -> (String, Option<u16>) {
        let (host, port) = match self.authority.rfind(']') {
            Some(close) => {
                let (host, rest) = self.authority.split_at(close + 1);
                (host, rest.strip_prefix(':'))
            }
            None => match self.authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (self.authority.as_str(), None),
            },
        };
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let host = bare
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| bare.to_ascii_lowercase(), |ip| ip.to_string());
        // Numeric, so `:0443` is `:443`; `None` (never the same origin)
        // for a port that doesn't parse.
        let port = match port {
            None => Some(if self.https { 443 } else { 80 }),
            Some(port) => port.parse().ok(),
        };
        (host, port)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.authority, self.path_and_query)
    }
}

/// RFC 3986 §5.2.4, on an absolute path.
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    let mut trailing_slash = false;
    for (i, segment) in segments.iter().enumerate() {
        match *segment {
            "." => trailing_slash = i == last,
            ".." => {
                out.pop();
                trailing_slash = i == last;
            }
            s => {
                out.push(s);
                trailing_slash = false;
            }
        }
    }
    let mut joined = format!("/{}", out.join("/"));
    if trailing_slash && !joined.ends_with('/') {
        joined.push('/');
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    #[test]
    fn urls_split_into_wasi_parts() {
        let u = url("https://cam.lan:10443/a/b?x=1#frag");
        assert!(u.https);
        assert_eq!(u.authority, "cam.lan:10443");
        assert_eq!(u.path_and_query, "/a/b?x=1");
        assert_eq!(url("http://h").path_and_query, "/");
        assert_eq!(url("http://h?q").path_and_query, "/?q");
        assert_eq!(url("HTTP://[::1]:80/").authority, "[::1]:80");
        for bad in [
            "ftp://h/",
            "h/path",
            "http:///x",
            "http://user@h/",
            "http://h /",
            "http://h/a b",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn locations_resolve_against_the_current_url() {
        let base = url("https://cam.lan/api/v1/status?x=1");
        for (location, expected) in [
            ("https://other.example/x", "https://other.example/x"),
            ("//other.example/y", "https://other.example/y"),
            ("/root", "https://cam.lan/root"),
            ("next", "https://cam.lan/api/v1/next"),
            ("../v2/s", "https://cam.lan/api/v2/s"),
            ("./", "https://cam.lan/api/v1/"),
            ("?y=2", "https://cam.lan/api/v1/status?y=2"),
            ("/a/./b/../c#f", "https://cam.lan/a/c"),
            ("http://cam.lan/plain", "http://cam.lan/plain"),
            (
                "next?return=https://cam.lan/s",
                "https://cam.lan/api/v1/next?return=https://cam.lan/s",
            ),
        ] {
            assert_eq!(base.join(location).expect(location).to_string(), expected);
        }
        for (location, expected) in [
            ("https://cam.lan/api/../status", "https://cam.lan/status"),
            ("//cam.lan/a/./b/../c?q=../x", "https://cam.lan/a/c?q=../x"),
        ] {
            assert_eq!(base.join(location).expect(location).to_string(), expected);
        }
        for location in ["mailto:help@example.org", "ftp://cam.lan/x", "https:x"] {
            assert!(base.join(location).is_err(), "{location}");
        }
    }

    #[test]
    fn origins_compare_with_default_ports() {
        assert!(url("https://h/a").same_origin(&url("https://H:443/b")));
        assert!(!url("https://h/a").same_origin(&url("http://h/a")));
        assert!(!url("https://h/a").same_origin(&url("https://h:8443/a")));
        assert!(url("http://[::1]/").same_origin(&url("http://[::1]:80/")));
        assert!(url("https://[fd00::1]/a").same_origin(&url("https://[fd00:0:0:0:0:0:0:1]:443/b")));
        assert!(url("https://h:0443/a").same_origin(&url("https://h/b")));
        assert!(!url("https://h:x/a").same_origin(&url("https://h:x/b")));
    }

    #[test]
    fn redirects_rewrite_method_body_and_credentials() {
        let from = url("https://a.example/x");
        let same = url("https://a.example/y");
        let other = url("https://b.example/y");
        let post = || {
            Request::post("https://a.example/x")
                .header("Authorization", "secret")
                .header("content-type", "text/plain")
                .header("Content-Encoding", "identity")
                .body("hi")
        };

        let mut r = post();
        r.follow(303, &from, &same);
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.body, Vec::<u8>::new());
        assert_eq!(r.headers.len(), 1, "{:?}", r.headers);

        let mut r = post();
        r.follow(307, &from, &other);
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.body, b"hi");
        assert!(r.headers.iter().all(|(n, _)| n != "authorization"));
        assert_eq!(r.url, "https://b.example/y");

        let mut r = Request::new(Method::Head, "https://a.example/x");
        r.follow(302, &from, &same);
        assert_eq!(r.method, Method::Head);

        // Only a POST becomes a GET on 301 / 302; other writes keep
        // their method and body.
        let mut r = post();
        r.follow(301, &from, &same);
        assert_eq!(r.method, Method::Get);
        let mut r = Request::put("https://a.example/x").body("on");
        r.follow(302, &from, &same);
        assert_eq!(r.method, Method::Put);
        assert_eq!(r.body, b"on");
    }

    #[test]
    fn redirect_limits_are_clamped() {
        assert_eq!(Request::get("http://h").max_redirects(50).max_redirects, 5);
        assert_eq!(Request::get("http://h").max_redirects(2).max_redirects, 2);
    }
}
