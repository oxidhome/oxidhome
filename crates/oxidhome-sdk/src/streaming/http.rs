//! A blocking HTTP client over `wasi:http`.
//!
//! ```no_run
//! use std::time::Duration;
//! use oxidhome_sdk::streaming::http::Request;
//!
//! let response = Request::get("https://camera.lan:10443/status")
//!     .header("accept", "application/json")
//!     .timeout(Duration::from_secs(5))
//!     .total_timeout(Duration::from_secs(10))
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
//! command or a service call, not from a tight `tick`. It sends the
//! whole request body before reading the response body: an exchange
//! that streams both ways at once needs `wasi:http` directly.
//!
//! [`Request::send_streaming`] returns once the response head has
//! arrived, with a [`BodyReader`] that reads the body without blocking:
//! for bodies that don't end (a multipart camera stream, MJPEG,
//! server-sent events, a long poll) or that are read a little each
//! `tick`. A plugin that keeps the reader between calls is ticked early
//! when more of the body arrives (see the readiness wakeups in
//! [`crate::streaming`]).
//!
//! - **Timeouts.** [`Request::timeout`] (30 s by default) bounds
//!   connecting, waiting for the response head, and each gap between
//!   body chunks, each on its own: a server that trickles its body keeps
//!   [`Request::send`] busy for as long as it trickles.
//!   [`Request::total_timeout`] bounds the whole exchange, redirects
//!   included ([`Error::TotalTimeout`]); with
//!   [`Request::send_streaming`], everything up to the response head.
//!   Set it on calls from `tick` or a command: a call blocked inside the
//!   host is out of the liveness watchdog's reach.
//! - **Limits.** Bodies over [`Request::max_body`] (1 MiB by default) end
//!   the request with [`Error::BodyTooLarge`]. The host caps a request's
//!   headers at [`MAX_HEADER_BYTES`]; more fails it with
//!   [`Error::Request`].
//! - **Headers.** [`FORBIDDEN_HEADERS`] (hop-by-hop headers and `host`,
//!   which the host sets), `content-length` (set from the body) and `te`
//!   (valid only with `connection: te`) are dropped by
//!   [`Request::header`], so a header list copied from a
//!   packet capture can be sent as is.
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
//! - **Sent or not.** [`Error::may_have_reached_server`] tells a failure
//!   where nothing reached the server (an invalid request, no network
//!   rule allowing it, a failed lookup, connect or TLS handshake) from
//!   one where the server may have received the request and acted on it,
//!   as a command's outcome needs (an error, or unknown).
//! - **HTTPS.** The host verifies certificates against the system's
//!   roots. A local device (a private, link-local or loopback address)
//!   with a self-signed certificate is trusted on first use: the host pins the
//!   certificate it sees first and refuses any other until the operator
//!   resets the pin.

use std::time::{Duration, Instant};

use crate::bindings::wasi::clocks::monotonic_clock;
use crate::bindings::wasi::http::outgoing_handler;
use crate::bindings::wasi::http::types::{
    ErrorCode, Fields, FutureIncomingResponse, IncomingBody, IncomingResponse,
    Method as WasiMethod, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
};
use crate::bindings::wasi::io::poll::{Pollable, poll};
use crate::bindings::wasi::io::streams::{InputStream, OutputStream, StreamError};

/// Most redirects one [`Request::send`] follows.
pub const MAX_REDIRECTS: u8 = 5;
/// Default [`Request::max_body`]: 1 MiB.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;
/// Default [`Request::timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The host's budget for a request's headers: each name once and every
/// value, plus a few dozen bytes of bookkeeping for each, so the headers
/// that fit are somewhat less than this.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Headers `wasi:http` refuses from a plugin: hop-by-hop headers, and
/// `host`, which the host sets from the URL. [`Request::header`] drops
/// them (and `content-length`, which is set from the body, and `te`,
/// which is only valid with a `connection: te`).
pub const FORBIDDEN_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
    "http2-settings",
];
/// Largest write `wasi:io` takes at once.
const WRITE_CHUNK: usize = 4096;
/// Largest read asked of the response stream at once.
const READ_CHUNK: u64 = 64 * 1024;
/// Headers dropped when a redirect leaves the origin.
const CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "cookie", "proxy-authorization"];
/// Most of a [`Request::total_timeout`]'s remainder the host's connect
/// timeout leaves unused, so a server that can't be reached fails as
/// `connection-timeout` (nothing sent) before the total timeout (maybe
/// sent) ends the request.
const CONNECT_MARGIN: Duration = Duration::from_millis(500);

/// Why a request failed. [`Error::may_have_reached_server`] tells
/// whether the server may have received it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL isn't `http(s)://host[:port][/path][?query]`.
    #[error("invalid URL `{0}`")]
    InvalidUrl(String),
    /// The host refused or failed the request. `HTTP-request-denied`
    /// means no network rule allows it ([`Error::is_denied`]).
    #[error("HTTP request failed: {0:?}")]
    Http(ErrorCode),
    /// The request couldn't be built: a header the host refuses (invalid,
    /// or over [`MAX_HEADER_BYTES`] in all), or another invalid part.
    /// Nothing was sent.
    #[error("{0}")]
    Request(String),
    /// The response body is larger than [`Request::max_body`].
    #[error("response body exceeds {limit} bytes")]
    BodyTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// [`Request::total_timeout`] ran out.
    #[error("the exchange took longer than {limit:?}")]
    TotalTimeout {
        /// The limit that was exceeded.
        limit: Duration,
        /// Whether the request had been handed to the host by then (it
        /// may have reached the server).
        dispatched: bool,
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
    /// A redirect's `Location` isn't an `http(s)` URL.
    #[error("refusing to follow a redirect to `{0}`")]
    InvalidRedirect(String),
    /// The request a redirect pointed to failed (`error` says how): no
    /// response came from it. The servers before it did answer.
    #[error("after {hops} redirect(s): {error}")]
    AfterRedirect {
        /// Redirects followed before the failed request.
        hops: u8,
        /// Why that request failed.
        #[source]
        error: Box<Error>,
    },
}

impl Error {
    /// Whether the host refused the request because no network rule
    /// allows it.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        match self {
            Error::Http(ErrorCode::HttpRequestDenied) => true,
            Error::AfterRedirect { error, .. } => error.is_denied(),
            _ => false,
        }
    }

    /// Whether a server may have received the request (and acted on it).
    ///
    /// `false` only when nothing went out: the URL or request was
    /// invalid, no network rule allows it, or the name lookup, the
    /// connect or the TLS handshake failed (including a connection cut
    /// during the handshake, which the host reports as
    /// `TLS-protocol-error`). Any failure after that may have come after
    /// the server read the request, and so may a [`Error::TotalTimeout`]
    /// once the request was dispatched.
    /// After a redirect it is always `true`: an earlier request reached
    /// its server.
    #[must_use]
    pub fn may_have_reached_server(&self) -> bool {
        match self {
            Error::InvalidUrl(_) | Error::Request(_) => false,
            Error::Http(code) => !nothing_sent(code),
            Error::TotalTimeout { dispatched, .. } => *dispatched,
            Error::BodyTooLarge { .. }
            | Error::TooManyRedirects { .. }
            | Error::InsecureRedirect(_)
            | Error::InvalidRedirect(_)
            | Error::AfterRedirect { .. } => true,
        }
    }
}

/// Whether the host fails a request with `code` only before any of it
/// is sent.
fn nothing_sent(code: &ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::DnsTimeout
            | ErrorCode::DnsError(_)
            | ErrorCode::DestinationNotFound
            | ErrorCode::DestinationUnavailable
            | ErrorCode::DestinationIpProhibited
            | ErrorCode::DestinationIpUnroutable
            | ErrorCode::ConnectionRefused
            | ErrorCode::ConnectionTimeout
            | ErrorCode::ConnectionLimitReached
            | ErrorCode::TlsProtocolError
            | ErrorCode::TlsCertificateError
            | ErrorCode::TlsAlertReceived(_)
            | ErrorCode::HttpRequestDenied
            | ErrorCode::HttpRequestMethodInvalid
            | ErrorCode::HttpRequestUriInvalid
            | ErrorCode::HttpRequestUriTooLong
            | ErrorCode::HttpRequestHeaderSectionSize(_)
            | ErrorCode::HttpRequestHeaderSize(_)
    )
}

/// A failure the host reports oddly (a response gone missing): treated
/// as possibly sent.
fn internal(what: &str) -> Error {
    Error::Http(ErrorCode::InternalError(Some(what.to_owned())))
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

/// When a [`Request::total_timeout`] runs out.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    at: Instant,
    limit: Duration,
}

impl Deadline {
    /// `limit` from now; none for a limit too far out to represent.
    fn after(limit: Option<Duration>) -> Option<Self> {
        let limit = limit?;
        Some(Self {
            at: Instant::now().checked_add(limit)?,
            limit,
        })
    }

    /// The error once the deadline has passed, after the request was
    /// handed to the host.
    fn expired(self) -> Error {
        Error::TotalTimeout {
            limit: self.limit,
            dispatched: true,
        }
    }

    /// The time left; an error once there is none.
    fn left(self) -> Result<Duration, Error> {
        let left = self.at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(self.expired())
        } else {
            Ok(left)
        }
    }

    /// Its timer, started now: one per exchange, shared by every phase.
    fn timer(self) -> Expiry {
        let left = self.at.saturating_duration_since(Instant::now());
        Expiry {
            timer: monotonic_clock::subscribe_duration(nanos(left)),
            deadline: self,
        }
    }
}

/// A deadline's timer. The deadline has passed once either the timer
/// fired or the clock says so: a test host's virtual clock moves the
/// clock without the timers, and the other way round.
struct Expiry {
    timer: Pollable,
    deadline: Deadline,
}

impl Expiry {
    /// An error once the deadline has passed.
    fn check(&self) -> Result<(), Error> {
        if self.timer.ready() {
            return Err(self.deadline.expired());
        }
        self.deadline.left().map(drop)
    }

    /// The time left before the request is handed to the host; an
    /// error (nothing sent) once there is none.
    fn left_before_dispatch(&self) -> Result<Duration, Error> {
        let not_sent = Error::TotalTimeout {
            limit: self.deadline.limit,
            dispatched: false,
        };
        if self.timer.ready() {
            return Err(not_sent);
        }
        self.deadline.left().map_err(|_| not_sent)
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Wait until `ready` is; an error if `expiry` passes first, or with it.
fn wait(ready: &Pollable, expiry: Option<&Expiry>) -> Result<(), Error> {
    let Some(expiry) = expiry else {
        ready.block();
        return Ok(());
    };
    // The timer's own wake-up counts: asking it again may not see it.
    if poll(&[ready, &expiry.timer]).contains(&1) {
        return Err(expiry.deadline.expired());
    }
    expiry.check()
}

/// A request to send. Build it with [`Request::get`] / [`Request::new`]
/// and the setters, then [`Request::send`] it.
///
/// `Debug` shows header names and the body's length, never their values.
#[derive(Clone)]
pub struct Request {
    method: Method,
    url: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    timeout: Duration,
    total_timeout: Option<Duration>,
    max_body: usize,
    max_redirects: u8,
    /// Header names a `connection` header nominated as hop-by-hop.
    connection_options: Vec<String>,
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
            total_timeout: None,
            max_body: DEFAULT_MAX_BODY,
            max_redirects: MAX_REDIRECTS,
            connection_options: Vec::new(),
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
    /// [`FORBIDDEN_HEADERS`], `content-length` and `te` are dropped, and
    /// so are the headers a `connection` header names (before or after
    /// it), which belong to the connection they were captured on.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        if name == "connection" {
            let options = String::from_utf8_lossy(&value).to_ascii_lowercase();
            for option in options.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                self.headers.retain(|(n, _)| n != option);
                self.connection_options.push(option.to_owned());
            }
            return self;
        }
        // `te` too: it needs a `connection: te`, which is dropped.
        if !matches!(name.as_str(), "content-length" | "te")
            && !FORBIDDEN_HEADERS.contains(&name.as_str())
            && !self.connection_options.contains(&name)
        {
            self.headers.push((name, value));
        }
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

    /// Bound the whole exchange, from the call to [`Request::send`] until
    /// the body has arrived (redirects included), or until the response
    /// head has arrived for [`Request::send_streaming`]. None by default.
    ///
    /// The host's connect timeout is then kept up to 10 % (at most
    /// 500 ms) short of the time left, so a server that can't be reached
    /// fails as `connection-timeout` (nothing sent) rather than as
    /// [`Error::TotalTimeout`] (maybe sent).
    #[must_use]
    pub fn total_timeout(mut self, limit: Duration) -> Self {
        self.total_timeout = Some(limit);
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
        let max_body = self.max_body;
        let expiry = Deadline::after(self.total_timeout).map(Deadline::timer);
        let (head, url) = self.exchange(expiry.as_ref())?;
        let Head {
            status,
            headers,
            incoming,
            _response,
            _upload,
        } = head;
        let body = read_body(incoming, max_body, expiry.as_ref())?;
        Ok(Response {
            status,
            headers,
            body,
            url: url.to_string(),
        })
    }

    /// Send the request, following redirects, and return once the
    /// response head has arrived; read the body with the returned
    /// [`BodyReader`]. [`Request::max_body`] doesn't apply.
    ///
    /// A request body is still sent first: when the server answers with
    /// a `1xx` / `2xx` before it has read it all, this keeps sending and
    /// returns once the upload has ended (finished, or cut short by the
    /// server).
    ///
    /// The response holds one of the instance's concurrent HTTP requests
    /// until it is dropped.
    ///
    /// # Errors
    ///
    /// As [`Request::send`], except [`Error::BodyTooLarge`].
    pub fn send_streaming(self) -> Result<StreamingResponse, Error> {
        let expiry = Deadline::after(self.total_timeout).map(Deadline::timer);
        let (head, url) = self.exchange(expiry.as_ref())?;
        let Head {
            status,
            headers,
            incoming,
            _response: response,
            _upload: upload,
        } = head;
        let stream = incoming
            .stream()
            .map_err(|()| internal("response stream already taken"))?;
        Ok(StreamingResponse {
            status,
            headers,
            url: url.to_string(),
            body: BodyReader {
                ready: stream.subscribe(),
                stream,
                _incoming: incoming,
                _response: response,
                _upload: upload,
                ended: false,
            },
        })
    }

    /// Send the request, following redirects, until a response that
    /// isn't one to follow; return its head and URL.
    fn exchange(mut self, expiry: Option<&Expiry>) -> Result<(Head, Url), Error> {
        let mut url = Url::parse(&self.url)?;
        let mut hops = 0u8;
        loop {
            let head = self.start(&url, expiry).map_err(|error| {
                if hops == 0 {
                    error
                } else {
                    Error::AfterRedirect {
                        hops,
                        error: Box::new(error),
                    }
                }
            })?;
            let location = match redirect_location(head.status, &head.headers) {
                Some(location) if self.max_redirects > 0 => location,
                // The final response.
                _ => return Ok((head, url)),
            };
            if hops >= self.max_redirects {
                return Err(Error::TooManyRedirects {
                    limit: self.max_redirects,
                });
            }
            hops += 1;
            let next = url.join(&location?).map_err(|err| match err {
                Error::InvalidUrl(location) => Error::InvalidRedirect(location),
                other => other,
            })?;
            if url.https && !next.https {
                return Err(Error::InsecureRedirect(next.to_string()));
            }
            self.follow(head.status, &url, &next);
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
    fn start(&self, url: &Url, expiry: Option<&Expiry>) -> Result<Head, Error> {
        let headers = Fields::new();
        for (name, value) in &self.headers {
            headers.append(name, value).map_err(|e| {
                Error::Request(format!(
                    "header `{name}`: {e:?} (an invalid name or value, or more than \
                     {MAX_HEADER_BYTES} bytes of headers)"
                ))
            })?;
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
        // The total timeout bounds the rest itself; only the connect
        // timeout is kept inside it (see `CONNECT_MARGIN`).
        let connect = match expiry {
            None => self.timeout,
            Some(expiry) => {
                let left = expiry.left_before_dispatch()?;
                self.timeout
                    .min(left.saturating_sub((left / 10).min(CONNECT_MARGIN)))
            }
        };
        let options = RequestOptions::new();
        let _ = options.set_connect_timeout(Some(nanos(connect)));
        let _ = options.set_first_byte_timeout(Some(nanos(self.timeout)));
        let _ = options.set_between_bytes_timeout(Some(nanos(self.timeout)));

        let outgoing = request.body().map_err(|()| fail("body"))?;
        let pending = outgoing_handler::handle(request, Some(options)).map_err(Error::Http)?;
        // Written after `handle`: the host buffers one chunk, so a body
        // written before the request starts would never drain.
        // A failed or cut-short write leaves the body unfinished, which
        // fails the request, so the response below says why
        // (`HTTP-request-denied`, a TLS error) or carries what the server
        // answered anyway (a `413` mid-upload); the write error itself
        // adds nothing.
        let written = match outgoing.write() {
            Ok(stream) => write_body(&stream, &self.body, &pending, self.timeout, expiry)?,
            Err(()) => Written::Broken(None),
        };
        let (early, upload) = match written {
            Written::All(early) => {
                let _ = OutgoingBody::finish(outgoing, None);
                (early, None)
            }
            // Refused mid-upload: the unfinished body stays open until
            // the response body is read, since dropping it aborts the
            // exchange.
            Written::Refused(response) => (Some(response), Some(outgoing)),
            // Dropped unfinished: ends the request instead of leaving the
            // host waiting for the rest of the body.
            // A response taken before it broke is still the answer.
            Written::Broken(early) => (early, None),
        };

        let response = match early {
            Some(response) => response,
            None => take_response(&pending, expiry)?,
        };
        let status = response.status();
        let headers = {
            let fields = response.headers();
            fields.entries()
        };
        let incoming = response
            .consume()
            .map_err(|()| internal("response body already taken"))?;
        Ok(Head {
            status,
            headers,
            incoming,
            _response: response,
            _upload: upload,
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
    /// An upload the server answered before it finished.
    _upload: Option<OutgoingBody>,
}

/// Wait (until `expiry`, if any) for the response and take it.
fn take_response(
    pending: &FutureIncomingResponse,
    expiry: Option<&Expiry>,
) -> Result<IncomingResponse, Error> {
    wait(&pending.subscribe(), expiry)?;
    pending
        .get()
        .ok_or_else(|| internal("response not ready"))?
        .map_err(|()| internal("response already taken"))?
        .map_err(Error::Http)
}

/// How an upload ended.
enum Written {
    /// Whole body sent, with the response if it came first.
    All(Option<IncomingResponse>),
    /// The server refused (`3xx` and up) mid-upload; the rest is not sent.
    Refused(IncomingResponse),
    /// The body stream failed: the response (taken already, or still
    /// pending) says why.
    Broken(Option<IncomingResponse>),
}

/// Write `body` and flush it, before `expiry` if any. A response that
/// arrives while the write is blocked is taken: a refusal (`413`) stops
/// the upload, since such a server may never read the rest; an early
/// `1xx`/`2xx` doesn't, since such a server may still be reading it, but
/// once answered, the upload must keep moving: `timeout` without
/// progress fails it.
///
/// An `Err` is the request's outcome (the host's error code, the stall).
fn write_body(
    stream: &OutputStream,
    body: &[u8],
    pending: &FutureIncomingResponse,
    timeout: Duration,
    expiry: Option<&Expiry>,
) -> Result<Written, Error> {
    let writable = stream.subscribe();
    let answered = pending.subscribe();
    let mut early = None;
    let mut rest = body;
    let mut flushed = false;
    loop {
        // Checked before every write: a server that keeps reading would
        // otherwise never reach the wait below.
        if let Some(expiry) = expiry {
            expiry.check()?;
        }
        let Ok(room) = stream.check_write() else {
            return Ok(Written::Broken(early));
        };
        if room == 0 {
            // Once answered, the stall timer instead of the response.
            let stall = early
                .is_some()
                .then(|| monotonic_clock::subscribe_duration(nanos(timeout)));
            let mut waits = vec![&writable, stall.as_ref().unwrap_or(&answered)];
            waits.extend(expiry.map(|e| &e.timer));
            let ready = poll(&waits);
            // The deadline first: nothing that came with it counts.
            if let Some(expiry) = expiry {
                if ready.contains(&2) {
                    return Err(expiry.deadline.expired());
                }
                expiry.check()?;
            }
            match early {
                // A response first, even with room to write again: a
                // refusal ends the upload.
                None if ready.contains(&1) => {
                    let response = take_response(pending, None)?;
                    if response.status() >= 300 {
                        return Ok(Written::Refused(response));
                    }
                    early = Some(response);
                }
                Some(_) if !ready.contains(&0) && ready.contains(&1) => {
                    return Err(Error::Http(ErrorCode::ConnectionWriteTimeout));
                }
                _ => {}
            }
            continue;
        }
        if rest.is_empty() {
            // `check-write` is 0 until a flush completes.
            if flushed {
                return Ok(Written::All(early));
            }
            if stream.flush().is_err() {
                return Ok(Written::Broken(early));
            }
            flushed = true;
            continue;
        }
        let n = usize::try_from(room)
            .unwrap_or(usize::MAX)
            .min(rest.len())
            .min(WRITE_CHUNK);
        if stream.write(&rest[..n]).is_err() {
            return Ok(Written::Broken(early));
        }
        rest = &rest[n..];
    }
}

/// The error a failed response-body read reports.
fn read_error(err: &crate::bindings::wasi::io::error::Error) -> Error {
    match crate::bindings::wasi::http::types::http_error_code(err) {
        Some(code) => Error::Http(code),
        None => Error::Http(ErrorCode::InternalError(Some(err.to_debug_string()))),
    }
}

/// Read a whole response body, refusing more than `max_body` bytes,
/// before `expiry` if any.
fn read_body(
    incoming: IncomingBody,
    max_body: usize,
    expiry: Option<&Expiry>,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    {
        let stream = incoming
            .stream()
            .map_err(|()| internal("response stream already taken"))?;
        let ready = stream.subscribe();
        loop {
            // Checked before every read: a server that keeps a little
            // data ready would otherwise never reach the wait below.
            if let Some(expiry) = expiry {
                expiry.check()?;
            }
            let room = max_body.saturating_sub(body.len()) as u64 + 1;
            match stream.read(room.min(READ_CHUNK)) {
                Ok(chunk) if chunk.is_empty() => match expiry {
                    Some(expiry) => {
                        if !poll(&[&ready, &expiry.timer]).contains(&0) {
                            return Err(expiry.deadline.expired());
                        }
                    }
                    None => ready.block(),
                },
                Ok(chunk) => {
                    // Checked before growing the buffer.
                    if chunk.len() > max_body - body.len() {
                        return Err(Error::BodyTooLarge { limit: max_body });
                    }
                    body.extend_from_slice(&chunk);
                }
                Err(StreamError::Closed) => break,
                Err(StreamError::LastOperationFailed(e)) => return Err(read_error(&e)),
            }
        }
    }
    drop(IncomingBody::finish(incoming));
    Ok(body)
}

/// The `Location` of a redirect response; an error for one that isn't
/// UTF-8.
fn redirect_location(status: u16, headers: &[(String, Vec<u8>)]) -> Option<Result<String, Error>> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = find_header(headers, "location")?;
    Some(
        std::str::from_utf8(location)
            .map(str::to_owned)
            .map_err(|_| {
                Error::InvalidRedirect(redact_userinfo(&String::from_utf8_lossy(location)))
            }),
    )
}

/// The first value of header `name` (case-insensitive) in `headers`.
fn find_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// A response with its whole body.
///
/// `Debug` shows header names and the body's length, never their values.
#[derive(Clone)]
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
        find_header(&self.headers, name)
    }

    /// Every header; the values of a repeated name come together.
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

/// A response whose body is read as it arrives, from
/// [`Request::send_streaming`].
///
/// `Debug` shows header names, never their values.
pub struct StreamingResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    url: String,
    body: BodyReader,
}

impl StreamingResponse {
    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The first value of header `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        find_header(&self.headers, name)
    }

    /// Every header; the values of a repeated name come together.
    #[must_use]
    pub fn headers(&self) -> &[(String, Vec<u8>)] {
        &self.headers
    }

    /// The URL that answered, after redirects.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The body.
    pub fn body(&mut self) -> &mut BodyReader {
        &mut self.body
    }

    /// The body, taken.
    #[must_use]
    pub fn into_body(self) -> BodyReader {
        self.body
    }
}

/// A response body read as it arrives. Dropping it ends the exchange.
///
/// [`Request::timeout`] still bounds each gap between body chunks: after
/// that long without data, a read fails with `connection-read-timeout`.
/// A reader the plugin keeps between calls wakes it early when it has
/// something to read, including its end: drop the reader once it has
/// ended, or the plugin keeps being woken.
pub struct BodyReader {
    // Fields drop in order: the pollable before its stream, the stream
    // before the body it came from, the body before its response.
    ready: Pollable,
    stream: InputStream,
    _incoming: IncomingBody,
    _response: IncomingResponse,
    /// An upload the server answered before it finished.
    _upload: Option<OutgoingBody>,
    ended: bool,
}

impl BodyReader {
    /// What has arrived, at most `max` bytes, without waiting: empty when
    /// nothing has yet, `None` once the body has ended.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] when the body failed (the connection was cut, or
    /// [`Request::timeout`] passed without data); the body has ended then.
    pub fn read(&mut self, max: usize) -> Result<Option<Vec<u8>>, Error> {
        if self.ended {
            return Ok(None);
        }
        match self.stream.read(u64::try_from(max).unwrap_or(u64::MAX)) {
            Ok(chunk) => Ok(Some(chunk)),
            Err(StreamError::Closed) => {
                self.ended = true;
                Ok(None)
            }
            Err(StreamError::LastOperationFailed(e)) => {
                self.ended = true;
                Err(read_error(&e))
            }
        }
    }

    /// As [`BodyReader::read`], but wait until something has arrived (or
    /// the body has ended or failed). [`Request::timeout`] bounds the wait.
    ///
    /// # Errors
    ///
    /// As [`BodyReader::read`].
    pub fn read_blocking(&mut self, max: usize) -> Result<Option<Vec<u8>>, Error> {
        loop {
            match self.read(max)? {
                Some(chunk) if chunk.is_empty() && max > 0 => self.ready.block(),
                other => return Ok(other),
            }
        }
    }

    /// A pollable that is ready when [`BodyReader::read`] has something to
    /// return: data, the end, or an error. For waiting on several things
    /// at once with [`poll`].
    #[must_use]
    pub fn pollable(&self) -> &Pollable {
        &self.ready
    }

    /// Whether the body has ended (or failed): [`BodyReader::read`]
    /// returns `None` from now on.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.ended
    }
}

/// Header names only: values may be credentials (`authorization`,
/// `set-cookie`).
struct HeaderNames<'a>(&'a [(String, Vec<u8>)]);

impl std::fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(n, _)| n))
            .finish()
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &redact_userinfo(&self.url))
            .field("headers", &HeaderNames(&self.headers))
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .field("total_timeout", &self.total_timeout)
            .field("max_body", &self.max_body)
            .field("max_redirects", &self.max_redirects)
            // Not `connection_options`: they come from a header value.
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for StreamingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingResponse")
            .field("status", &self.status)
            .field("headers", &HeaderNames(&self.headers))
            .field("url", &self.url)
            .field("body", &self.body)
            .finish()
    }
}

impl std::fmt::Debug for BodyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyReader")
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &HeaderNames(&self.headers))
            .field("body_len", &self.body.len())
            .field("url", &self.url)
            .finish()
    }
}

/// `raw` with any `user:password@` in its authority replaced by `***@`.
fn redact_userinfo(raw: &str) -> String {
    // After a scheme-relative `//`, or a `scheme://` that comes before
    // any path, query or fragment (a `://` in a query is not a scheme).
    let head = raw.find(['/', '?', '#']).unwrap_or(raw.len());
    let start = if raw.starts_with("//") {
        2
    } else if raw[..head].ends_with(':') && raw[head..].starts_with("//") {
        head + 2
    } else {
        0
    };
    let end = raw[start..]
        .find(['/', '?', '#'])
        .map_or(raw.len(), |i| start + i);
    match raw[start..end].rfind('@') {
        Some(at) => format!("{}***{}", &raw[..start], &raw[start + at..]),
        None => raw.to_owned(),
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
        let invalid = || Error::InvalidUrl(redact_userinfo(raw));
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
        if !plain_authority(authority) {
            return Err(invalid());
        }
        let path_and_query = if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        };
        if !plain_path_and_query(&path_and_query) {
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
        // Before the dot segments go: a bad segment they remove is still
        // a bad `Location`.
        if !plain_path_and_query(&target) {
            return Err(Error::InvalidUrl(redact_userinfo(location)));
        }
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

/// Whether `authority` is `host[:port]` as the host takes it: a host
/// without userinfo, whitespace or brackets, or a bracketed IPv6
/// address; a port of 1–5 digits that fits a `u16`. Checked here so a
/// bad `Location` is [`Error::InvalidRedirect`] rather than a failure at
/// the host after earlier hops went out.
fn plain_authority(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return false;
        };
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after {
            "" => (inner, None),
            _ => match after.strip_prefix(':') {
                Some(port) => (inner, Some(port)),
                None => return false,
            },
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let host_ok = !host.is_empty()
        && (authority.starts_with('[')
            // RFC 3986 `reg-name` without percent-encoding (`http`
            // refuses `%` there): unreserved and sub-delims.
            || host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b)
            }));
    let port_ok = port.is_none_or(|p| {
        (1..=5).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok()
    });
    host_ok && port_ok
}

/// Whether the host takes `path_and_query` as is (`http`'s rules): no
/// whitespace or control characters anywhere, no `<`, `>` or `` ` `` in
/// the path, no `"`, `<` or `>` in the query. Checked here for the same
/// reason as [`plain_authority`].
fn plain_path_and_query(path_and_query: &str) -> bool {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let plain = |b: u8| !b.is_ascii_whitespace() && !b.is_ascii_control();
    path.bytes()
        .all(|b| plain(b) && !matches!(b, b'<' | b'>' | b'`'))
        && query
            .bytes()
            .all(|b| plain(b) && !matches!(b, b'"' | b'<' | b'>'))
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
    // A final `.` / `..` leaves an empty last segment (a trailing `/`),
    // kept even after another empty one: `/a//.` is `/a//`.
    if trailing_slash {
        out.push("");
    }
    format!("/{}", out.join("/"))
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
        // `http` takes these as they are.
        assert_eq!(url("http://h/{\"a\"}?x={}").path_and_query, "/{\"a\"}?x={}");
        assert_eq!(url("HTTP://[::1]:80/").authority, "[::1]:80");
        for bad in [
            "ftp://h/",
            "h/path",
            "http:///x",
            "http://user@h/",
            "http://h /",
            "http://h/a b",
            "http://h:abc/",
            "http://h:99999/",
            "http://h:/",
            "http://h:+80/",
            "http://camera]/",
            "http://[::1]abc/",
            "http://[nope]/",
            "http://h:1:2/",
            "http://cam|era/",
            "http://cam%20era/",
            "http://h/bad<path",
            "http://h/a`b",
            "http://h/?q=\"x\"",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_and_errors_hide_credentials() {
        let request = Request::get("https://u:pw@cam.lan/x")
            .header("Authorization", "Bearer s3cret")
            .body("token=s3cret");
        let shown = format!("{request:?}");
        assert!(
            !shown.contains("s3cret") && !shown.contains("pw"),
            "{shown}"
        );
        assert!(shown.contains("authorization"), "{shown}");
        let err = Url::parse("https://u:pw@cam.lan/x").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidUrl(u) if u == "https://***@cam.lan/x"),
            "{err:?}"
        );
        assert_eq!(redact_userinfo("http://cam.lan/a@b"), "http://cam.lan/a@b");
        assert_eq!(redact_userinfo("//u:pw@cam.lan/live"), "//***@cam.lan/live");
        let shown = format!("{:?}", Request::get("//u:pw@cam.lan/live"));
        assert!(!shown.contains("pw"), "{shown}");
        // A `://` in the query is not a scheme.
        assert_eq!(
            redact_userinfo("//u:pw@cam.lan/login?next=https://x"),
            "//***@cam.lan/login?next=https://x"
        );
        assert_eq!(
            redact_userinfo("u:pw@cam.lan/login?next=https://x"),
            "***@cam.lan/login?next=https://x"
        );
        assert_eq!(
            redact_userinfo("https://u:pw@cam.lan/login?next=https://v:x@y"),
            "https://***@cam.lan/login?next=https://v:x@y"
        );
        let err = Url::parse("//u:pw@cam.lan/login?next=https://x").unwrap_err();
        assert!(!format!("{err:?}").contains("pw"), "{err:?}");
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
            ("/a//.", "https://cam.lan/a//"),
            ("/a/b/..", "https://cam.lan/a/"),
            ("/..", "https://cam.lan/"),
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
        for location in [
            "mailto:help@example.org",
            "ftp://cam.lan/x",
            "https:x",
            "/bad<path/../next",
            "https://cam.lan/bad<path/../next",
        ] {
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
    fn hop_by_hop_and_host_set_headers_are_dropped() {
        let mut request = Request::get("http://h");
        for name in FORBIDDEN_HEADERS {
            request = request.header(name.to_ascii_uppercase(), "x");
        }
        let request = request
            .header("Content-Length", "3")
            .header("TE", "trailers")
            .header("X-Before", "1")
            .header("Connection", "X-Before, x-after, token=s3cret")
            .header("X-After", "2")
            .header("Authorization", "Basic x");
        let names: Vec<&str> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["authorization"]);
        assert!(!format!("{request:?}").contains("s3cret"));
    }

    #[test]
    fn errors_tell_whether_the_request_may_have_gone_out() {
        for not_sent in [
            Error::InvalidUrl("x".into()),
            Error::Request("header".into()),
            Error::Http(ErrorCode::HttpRequestDenied),
            Error::Http(ErrorCode::ConnectionRefused),
            Error::Http(ErrorCode::ConnectionTimeout),
            Error::Http(ErrorCode::TlsProtocolError),
            Error::Http(ErrorCode::TlsCertificateError),
            Error::Http(ErrorCode::DnsTimeout),
            Error::TotalTimeout {
                limit: Duration::ZERO,
                dispatched: false,
            },
        ] {
            assert!(!not_sent.may_have_reached_server(), "{not_sent:?}");
        }
        for maybe in [
            Error::Http(ErrorCode::ConnectionTerminated),
            Error::Http(ErrorCode::ConnectionReadTimeout),
            Error::Http(ErrorCode::HttpResponseTimeout),
            Error::Http(ErrorCode::HttpProtocolError),
            Error::Http(ErrorCode::InternalError(None)),
            Error::TotalTimeout {
                limit: Duration::from_secs(1),
                dispatched: true,
            },
            Error::BodyTooLarge { limit: 1 },
            Error::InvalidRedirect("mailto:x".into()),
        ] {
            assert!(maybe.may_have_reached_server(), "{maybe:?}");
        }
        // The hop before reached its server, whatever stopped this one.
        let denied = Error::AfterRedirect {
            hops: 1,
            error: Box::new(Error::Http(ErrorCode::HttpRequestDenied)),
        };
        assert!(denied.may_have_reached_server());
        assert!(denied.is_denied());
        assert!(!Error::Http(ErrorCode::ConnectionRefused).is_denied());
        assert_eq!(
            denied.to_string(),
            "after 1 redirect(s): HTTP request failed: ErrorCode::HttpRequestDenied"
        );
    }

    #[test]
    fn total_timeouts_beyond_the_clock_are_none() {
        assert!(Deadline::after(None).is_none());
        assert!(Deadline::after(Some(Duration::MAX)).is_none());
        let deadline = Deadline::after(Some(Duration::from_secs(60))).expect("deadline");
        assert!(deadline.left().is_ok());
        let past = Deadline::after(Some(Duration::ZERO)).expect("deadline");
        assert!(matches!(
            past.left(),
            Err(Error::TotalTimeout { limit, dispatched: true }) if limit.is_zero()
        ));
    }

    #[test]
    fn only_redirects_with_a_location_are_followed() {
        let headers = |v: &[u8]| vec![("Location".to_owned(), v.to_vec())];
        assert!(redirect_location(200, &headers(b"/x")).is_none());
        assert!(redirect_location(302, &[]).is_none());
        assert!(matches!(redirect_location(302, &headers(b"/x")), Some(Ok(l)) if l == "/x"));
        assert!(matches!(
            redirect_location(307, &headers(b"/\xff")),
            Some(Err(Error::InvalidRedirect(_)))
        ));
        assert!(matches!(
            redirect_location(302, &headers(b"https://u:secret@cam.lan/\xff")),
            Some(Err(Error::InvalidRedirect(l))) if !l.contains("secret")
        ));
    }

    #[test]
    fn redirect_limits_are_clamped() {
        assert_eq!(Request::get("http://h").max_redirects(50).max_redirects, 5);
        assert_eq!(Request::get("http://h").max_redirects(2).max_redirects, 2);
    }
}
