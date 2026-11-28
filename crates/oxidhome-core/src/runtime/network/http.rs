//! Outgoing `wasi:http` for streaming instances.
//!
//! `wasmtime-wasi-http` handles the `wasi:http` resources; sending is
//! ours ([`HttpHooks`]). For each request the host:
//!
//! 1. takes one of the instance's HTTP request permits, held until the
//!    response body is done;
//! 2. resolves the request's host itself (a name must match a name rule)
//!    and checks every address with the instance's [`NetworkPolicy`]
//!    (`tcp` / `any` rules for `http://`, `https` / `any` for `https://`);
//! 3. connects to the first allowed address — the one it checked, with
//!    no second lookup;
//! 4. for `https://`, runs the TLS handshake for the host the request
//!    named ([`super::tls`]), refusing (and auditing) a LAN device whose
//!    certificate doesn't match its pin;
//! 5. sends the request over HTTP/1.1.
//!
//! `wasi:http` doesn't follow redirects: a 3xx goes back to the plugin,
//! and following it is a new request that runs these steps again.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::uri::Scheme;
use http_body_util::BodyExt;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::sockets::network::ErrorCode as SocketErrorCode;
use wasmtime_wasi_http::RequestOptions as RequestOptionsResource;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::outgoing_handler;
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode as HttpErrorCode;
use wasmtime_wasi_http::p2::body::HostFutureTrailers;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, HostOutgoingRequest};
use wasmtime_wasi_http::{Error, RequestOptions, WasiBody, WasiHttpHooks};

use super::policy::{Denial, NetworkPolicy, Use};
use super::tls::{Connected, TlsClient};

/// What the HTTP connection runs over: plain TCP or TLS.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// Connect timeout when the plugin sets none.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Time to the response head when the plugin sets none.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest gap between response body frames when the plugin sets none.
const BETWEEN_BYTES_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest single write to an outgoing body; each body buffers at most
/// one such chunk on the host.
const BODY_CHUNK_SIZE: usize = 16 * 1024;

/// `wasi:http` from `wasmtime-wasi-http`, with `outgoing-handler#handle`
/// replaced by one that also frees the `request-options` it was given:
/// `wasmtime-wasi-http` 50 reads the owned handle and leaves it in the
/// table, so every request with options would leak an entry.
pub(super) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<crate::runtime::state::PluginState>,
) -> anyhow::Result<()> {
    use wasmtime_wasi_http::WasiHttpView as _;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(linker)?;
    linker.allow_shadowing(true);
    let shadowed = linker.instance(OUTGOING_HANDLER).and_then(|mut instance| {
        instance.func_wrap(
            "handle",
            |mut store: wasmtime::StoreContextMut<'_, crate::runtime::state::PluginState>,
             (request, options): (
                Resource<HostOutgoingRequest>,
                Option<Resource<RequestOptionsResource>>,
            )| {
                let mut view = store.data_mut().http();
                // WIT: no path-with-query means an empty one; upstream
                // would fail to build the URI without a path.
                if let Ok(req) = view.table.get_mut(&request)
                    && req.path_with_query.is_none()
                {
                    req.path_with_query = Some("/".to_owned());
                }
                let options_rep = options.as_ref().map(Resource::rep);
                let result = outgoing_handler::Host::handle(&mut view, request, options);
                if let Some(rep) = options_rep {
                    // Already gone if upstream ever deletes it itself.
                    let _ = view
                        .table
                        .delete(Resource::<RequestOptionsResource>::new_own(rep));
                }
                let result: Result<Resource<HostFutureIncomingResponse>, HttpErrorCode> =
                    match result {
                        Ok(response) => Ok(response),
                        Err(err) => Err(err.downcast()?),
                    };
                Ok((result,))
            },
        )
    });
    let limited = shadowed.and_then(|()| limit_request_setters(linker));
    linker.allow_shadowing(false);
    limited?;
    Ok(())
}

/// The `outgoing-handler` interface `wasmtime-wasi-http` links.
const OUTGOING_HANDLER: &str = "wasi:http/outgoing-handler@0.2.12";
/// The `types` interface `wasmtime-wasi-http` links.
const HTTP_TYPES: &str = "wasi:http/types@0.2.12";
/// Longest custom method name a request may set.
const MAX_METHOD_LEN: usize = 64;
/// Longest authority a request may set.
const MAX_AUTHORITY_LEN: usize = 512;
/// Longest path-with-query a request may set.
const MAX_PATH_LEN: usize = 8 * 1024;
/// Largest response head (headers, counting each name per value) the
/// host keeps; also hyper's read-buffer cap.
const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Most bytes one `fields` map may hold (upstream's default is 128 KiB).
/// The SDK copies it as `streaming::http::MAX_HEADER_BYTES`; a unit test
/// keeps the two equal.
pub(crate) const FIELD_SIZE_LIMIT: usize = 16 * 1024;
/// Longest header name a guest may set. Upstream charges a repeated
/// name once against [`FIELD_SIZE_LIMIT`] but copies it for every value
/// when listing or encoding the map; capping the name bounds that.
const MAX_FIELD_NAME_LEN: usize = 256;

/// `fields` constructors and mutators, wrapped to refuse header names over
/// [`MAX_FIELD_NAME_LEN`] (`invalid-syntax`), and to fail a map over
/// [`FIELD_SIZE_LIMIT`] (or over `http`'s entry cap) with
/// `invalid-syntax` where upstream traps.
fn limit_field_names(
    types: &mut wasmtime::component::LinkerInstance<'_, crate::runtime::state::PluginState>,
) -> wasmtime::Result<()> {
    use wasmtime_wasi_http::FieldMap;
    use wasmtime_wasi_http::WasiHttpView as _;
    use wasmtime_wasi_http::p2::bindings::http::types::{HeaderError, HostFields};
    type Store<'a> = wasmtime::StoreContextMut<'a, crate::runtime::state::PluginState>;
    fn lift<T>(
        result: wasmtime_wasi_http::p2::HeaderResult<T>,
    ) -> wasmtime::Result<(Result<T, HeaderError>,)> {
        Ok((match result {
            Ok(value) => Ok(value),
            Err(err) => Err(header_error(err)?),
        },))
    }
    let too_long = |name: &str| name.len() > MAX_FIELD_NAME_LEN;

    types.func_wrap(
        "[static]fields.from-list",
        move |mut store: Store<'_>, (entries,): (Vec<(String, Vec<u8>)>,)| {
            if entries.iter().any(|(name, _)| too_long(name)) {
                return Ok((Err(HeaderError::InvalidSyntax),));
            }
            lift(HostFields::from_list(&mut store.data_mut().http(), entries))
        },
    )?;
    types.func_wrap(
        "[method]fields.set",
        move |mut store: Store<'_>,
              (fields, name, values): (Resource<FieldMap>, String, Vec<Vec<u8>>)| {
            if too_long(&name) {
                return Ok((Err(HeaderError::InvalidSyntax),));
            }
            lift(HostFields::set(
                &mut store.data_mut().http(),
                fields,
                name,
                values,
            ))
        },
    )?;
    types.func_wrap(
        "[method]fields.append",
        move |mut store: Store<'_>,
              (fields, name, value): (Resource<FieldMap>, String, Vec<u8>)| {
            if too_long(&name) {
                return Ok((Err(HeaderError::InvalidSyntax),));
            }
            lift(HostFields::append(
                &mut store.data_mut().http(),
                fields,
                name,
                value,
            ))
        },
    )?;
    Ok(())
}

/// The guest-facing code for a failed `fields` call; a trap only for
/// what isn't the guest's doing (a missing table entry).
fn header_error(
    err: wasmtime_wasi_http::p2::HeaderError,
) -> wasmtime::Result<wasmtime_wasi_http::p2::bindings::http::types::HeaderError> {
    use wasmtime_wasi_http::FieldMapError;
    use wasmtime_wasi_http::p2::bindings::http::types::HeaderError;
    let err = match err.downcast() {
        Ok(code) => return Ok(code),
        Err(err) => err,
    };
    // Upstream traps on these: a plugin building headers from
    // operator config would die on a long value instead of failing
    // the request.
    match err.downcast_ref::<FieldMapError>() {
        Some(FieldMapError::TotalSizeTooBig | FieldMapError::TooManyFields) => {
            Ok(HeaderError::InvalidSyntax)
        }
        _ => Err(err),
    }
}

/// The `outgoing-request` setters `wasmtime-wasi-http` stores without a
/// length limit, wrapped to refuse oversized values: a request that is
/// never sent would otherwise hold guest-sized strings in host memory.
fn limit_request_setters(
    linker: &mut wasmtime::component::Linker<crate::runtime::state::PluginState>,
) -> wasmtime::Result<()> {
    use wasmtime_wasi_http::WasiHttpView as _;
    use wasmtime_wasi_http::p2::bindings::http::types::{HostOutgoingRequest as Setters, Method};
    type Store<'a> = wasmtime::StoreContextMut<'a, crate::runtime::state::PluginState>;
    type Request = Resource<HostOutgoingRequest>;

    let mut types = linker.instance(HTTP_TYPES)?;
    limit_field_names(&mut types)?;
    // Upstream `get` returns `none` for a pending entry even after the
    // request finished, until the guest polls a subscription; a plugin
    // that just calls `get` each tick would never see its response.
    // Poll once, without waiting, first.
    types.func_wrap(
        "[method]future-incoming-response.get",
        |mut store: Store<'_>, (response,): (Resource<HostFutureIncomingResponse>,)| {
            use futures_util::FutureExt as _;
            use wasmtime_wasi::p2::Pollable as _;
            let mut view = store.data_mut().http();
            let entry = view.table.get_mut(&response)?;
            if matches!(entry, HostFutureIncomingResponse::Pending(_)) {
                let _ = entry.ready().now_or_never();
            }
            Ok((
                wasmtime_wasi_http::p2::bindings::http::types::HostFutureIncomingResponse::get(
                    &mut view, response,
                )?,
            ))
        },
    )?;
    // Same for `future-trailers.get`.
    types.func_wrap(
        "[method]future-trailers.get",
        |mut store: Store<'_>, (trailers,): (Resource<HostFutureTrailers>,)| {
            use futures_util::FutureExt as _;
            use wasmtime_wasi::p2::Pollable as _;
            let mut view = store.data_mut().http();
            let entry = view.table.get_mut(&trailers)?;
            if matches!(entry, HostFutureTrailers::Waiting(_)) {
                let _ = entry.ready().now_or_never();
            }
            Ok((
                wasmtime_wasi_http::p2::bindings::http::types::HostFutureTrailers::get(
                    &mut view, trailers,
                )?,
            ))
        },
    )?;
    types.func_wrap(
        "[method]outgoing-request.set-method",
        |mut store: Store<'_>, (request, method): (Request, Method)| {
            if matches!(&method, Method::Other(m) if m.len() > MAX_METHOD_LEN) {
                return Ok((Err(()),));
            }
            Ok((Setters::set_method(
                &mut store.data_mut().http(),
                request,
                method,
            )?,))
        },
    )?;
    types.func_wrap(
        "[method]outgoing-request.set-authority",
        |mut store: Store<'_>, (request, authority): (Request, Option<String>)| {
            if authority
                .as_ref()
                .is_some_and(|a| a.len() > MAX_AUTHORITY_LEN)
            {
                return Ok((Err(()),));
            }
            Ok((Setters::set_authority(
                &mut store.data_mut().http(),
                request,
                authority,
            )?,))
        },
    )?;
    types.func_wrap(
        "[method]outgoing-request.set-path-with-query",
        |mut store: Store<'_>, (request, path): (Request, Option<String>)| {
            if path.as_ref().is_some_and(|p| p.len() > MAX_PATH_LEN) {
                return Ok((Err(()),));
            }
            Ok((Setters::set_path_with_query(
                &mut store.data_mut().http(),
                request,
                path,
            )?,))
        },
    )?;
    Ok(())
}

/// The future `send_request` returns: the response plus a future that
/// drives the connection until the response body is done.
type SendFuture = Box<
    dyn Future<
            Output = Result<
                (
                    http::Response<WasiBody>,
                    Box<dyn Future<Output = Result<(), Error>> + Send>,
                ),
                Error,
            >,
        > + Send,
>;

/// `wasmtime-wasi-http` hooks for one streaming instance.
pub(crate) struct HttpHooks {
    policy: Arc<NetworkPolicy>,
    tls: Arc<TlsClient>,
}

impl HttpHooks {
    pub(crate) fn new(policy: Arc<NetworkPolicy>, tls: Arc<TlsClient>) -> Self {
        Self { policy, tls }
    }
}

impl WasiHttpHooks for HttpHooks {
    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        options: Option<RequestOptions>,
        fut: Box<dyn Future<Output = Result<(), Error>> + Send>,
    ) -> SendFuture {
        // Request-body errors reach the plugin through the body stream;
        // nothing here needs them.
        drop(fut);
        // Admitted here, before `wasmtime-wasi-http` spawns the send, so
        // requests over the limit fail at once instead of queueing with
        // their headers and body.
        let Ok(permit) = Arc::clone(&self.policy.http_requests).try_acquire_owned() else {
            drop(request);
            return Box::new(std::future::ready(Err(Error::ConnectionLimitReached)));
        };
        let policy = Arc::clone(&self.policy);
        let tls = Arc::clone(&self.tls);
        // Sent on a spawned task: carry the invocation for audit rows.
        let ctx = crate::auth::invocation::current();
        Box::new(super::in_invocation(ctx, async move {
            send(policy, tls, permit, request, options).await
        }))
    }

    fn p2_outgoing_body_chunk_size(&mut self) -> usize {
        BODY_CHUNK_SIZE
    }

    fn p2_outgoing_body_buffer_chunks(&mut self) -> usize {
        1
    }

    /// A failed TCP connect sent nothing, so its code must not be one a
    /// cut after the request went out also has: upstream maps a reset
    /// to `connection-terminated`.
    fn p2_error_from_connect(&mut self, err: &std::io::Error) -> HttpErrorCode {
        connect_error(err)
    }
}

/// The `wasi:http` code of a failed TCP connect (see
/// [`HttpHooks::p2_error_from_connect`]).
fn connect_error(err: &std::io::Error) -> HttpErrorCode {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown => {
            HttpErrorCode::DestinationUnavailable
        }
        ErrorKind::TimedOut => HttpErrorCode::ConnectionTimeout,
        _ if address_family_unsupported(err) => HttpErrorCode::DestinationUnavailable,
        _ => HttpErrorCode::ConnectionRefused,
    }
}

/// Whether the host can't use the destination's address family, as
/// upstream tells it apart.
fn address_family_unsupported(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EAFNOSUPPORT)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

fn dns_error(code: SocketErrorCode) -> Error {
    match code {
        // Resolved only to addresses the rules refuse (already audited).
        SocketErrorCode::AccessDenied => Error::HttpRequestDenied,
        SocketErrorCode::TemporaryResolverFailure => Error::DnsTimeout,
        _ => Error::DnsError {
            rcode: Some(format!("{code:?}")),
            info_code: None,
        },
    }
}

/// The addresses `host:port` may be reached at, in resolver order.
/// Every one has passed the policy; connecting tries them in turn.
async fn checked_addresses(
    policy: &Arc<NetworkPolicy>,
    using: Use,
    target: &str,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, Error> {
    let (candidates, name_rules) = if let Ok(ip) = host.parse::<IpAddr>() {
        (vec![ip], None)
    } else {
        let rules = policy.name_rules(host, &[using]).map_err(|denial| {
            policy.audit_denial("http", target, &denial);
            Error::HttpRequestDenied
        })?;
        let permits = super::sockets::lookup_permits(policy).map_err(dns_error)?;
        let addrs = super::sockets::resolve(
            policy,
            permits,
            host,
            &rules,
            "http",
            target,
            Some((using, port)),
        )
        .await
        .map_err(dns_error)?;
        (addrs, Some(rules))
    };
    let mut denial = None;
    let mut allowed = Vec::new();
    for ip in candidates {
        let addr = SocketAddr::new(ip, port);
        match policy.check_addr(using, addr, name_rules.as_deref()) {
            Ok(()) => allowed.push(addr),
            Err(d) => denial = denial.or(Some(d)),
        }
    }
    if allowed.is_empty() {
        let denial = denial.unwrap_or_else(|| Denial::ResolvedRefused(host.to_owned()));
        policy.audit_denial("http", target, &denial);
        return Err(Error::HttpRequestDenied);
    }
    Ok(allowed)
}

/// TLS handshake for `host` on `stream`, by `deadline`; refuses (and
/// audits) a certificate that doesn't match its pin.
async fn secure(
    policy: &Arc<NetworkPolicy>,
    client: &TlsClient,
    stream: tokio::net::TcpStream,
    target: &str,
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<Box<dyn Io>, Error> {
    let peer = stream.peer_addr().map_err(Error::Connect)?;
    let connected = tokio::time::timeout_at(
        deadline,
        super::tls::connect(client, policy, target, stream, peer, host, port),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)??;
    match connected {
        Connected::Stream(stream) => Ok(stream),
        Connected::Refused(denial) => {
            policy.audit_denial("tls", target, &Denial::Tls(denial.to_string()));
            Err(Error::TlsCertificateError)
        }
    }
}

/// HTTP/1.1 handshake on `stream`, by `deadline`.
async fn handshake(
    stream: Box<dyn Io>,
    deadline: tokio::time::Instant,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<WasiBody>,
        hyper::client::conn::http1::Connection<TokioIo<Box<dyn Io>>, WasiBody>,
    ),
    Error,
> {
    tokio::time::timeout_at(
        deadline,
        hyper::client::conn::http1::Builder::new()
            // Bounds the response head the parser buffers.
            .max_buf_size(MAX_RESPONSE_HEAD)
            .handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)?
    .map_err(Error::from)
}

/// Response headers stay in host memory as long as the plugin keeps the
/// response; refuse a head over [`MAX_RESPONSE_HEAD`], counting each
/// name once per value.
fn check_response_head(headers: &http::HeaderMap) -> Result<(), Error> {
    let head: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum();
    if head > MAX_RESPONSE_HEAD {
        return Err(Error::HttpResponseHeaderSectionSize(
            u32::try_from(head).ok(),
        ));
    }
    Ok(())
}

/// Maps a hyper error, reporting a response head that overflowed the
/// parser's buffer as a header-section size error.
fn hyper_error(err: hyper::Error) -> Error {
    if err.is_parse_too_large() {
        Error::HttpResponseHeaderSectionSize(None)
    } else {
        Error::from(err)
    }
}

/// Connect to each checked address in turn, within one deadline;
/// never a fresh lookup.
async fn connect_any(
    addrs: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, Error> {
    let mut last_error = None;
    let count = addrs.len();
    for (i, addr) in addrs.into_iter().enumerate() {
        // An equal share of what's left, so a stalled address can't use
        // up the time the next ones need.
        let left = u32::try_from(count - i).unwrap_or(u32::MAX).max(1);
        let attempt = deadline.saturating_duration_since(tokio::time::Instant::now()) / left;
        match tokio::time::timeout(attempt, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(Error::Connect(err)),
            Err(_) => last_error = Some(Error::ConnectionTimeout),
        }
    }
    Err(last_error.unwrap_or(Error::ConnectionTimeout))
}

/// `authority` exactly as `host[:port]`: nothing hidden after a
/// bracketed IPv6 literal, and a bracket holding an IPv6 address, so the
/// `Host` header names what the policy checked.
fn plain_authority(authority: &http::uri::Authority) -> bool {
    let raw = authority.as_str();
    let host = authority.host();
    if host.starts_with('[') {
        let inner = host.trim_start_matches('[').trim_end_matches(']');
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
    }
    match raw.strip_prefix(host) {
        Some("") => true,
        Some(rest) => rest.strip_prefix(':').is_some_and(|p| {
            !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit())
        }),
        None => false,
    }
}

async fn send(
    policy: Arc<NetworkPolicy>,
    tls_client: Arc<TlsClient>,
    permit: tokio::sync::OwnedSemaphorePermit,
    mut request: http::Request<WasiBody>,
    options: Option<RequestOptions>,
) -> Result<
    (
        http::Response<WasiBody>,
        Box<dyn Future<Output = Result<(), Error>> + Send>,
    ),
    Error,
> {
    // No tunnels: a `CONNECT` would go out with a path as its target.
    if request.method() == http::Method::CONNECT {
        return Err(Error::HttpRequestMethodInvalid);
    }
    let uri = request.uri().clone();
    let authority = uri.authority().ok_or(Error::HttpRequestUriInvalid)?;
    // Userinfo would reach the `Host` header and the audit row; the
    // checked host and port are all a request may carry.
    if authority.as_str().contains('@') || !plain_authority(authority) {
        return Err(Error::HttpRequestUriInvalid);
    }
    let tls = uri.scheme() == Some(&Scheme::HTTPS);
    let (using, default_port, scheme) = if tls {
        (Use::Https, 443, "https")
    } else {
        (Use::Http, 80, "http")
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = authority.port_u16().unwrap_or(default_port);
    let target = format!("{scheme}://{authority}");

    let options = options.unwrap_or_default();
    let connect_timeout = options.connect_timeout.unwrap_or(CONNECT_TIMEOUT);
    let first_byte_timeout = options.first_byte_timeout.unwrap_or(FIRST_BYTE_TIMEOUT);
    let between_bytes_timeout = options
        .between_bytes_timeout
        .unwrap_or(BETWEEN_BYTES_TIMEOUT)
        .max(Duration::from_millis(1));
    // One connect deadline covers the lookup, every address tried, the
    // TLS handshake and the HTTP handshake.
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let addrs = tokio::time::timeout_at(
        deadline,
        checked_addresses(&policy, using, &target, &host, port),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)??;

    let stream = connect_any(addrs, deadline).await?;
    let stream: Box<dyn Io> = if tls {
        secure(&policy, &tls_client, stream, &target, &host, port, deadline).await?
    } else {
        Box::new(stream)
    };
    let (mut sender, conn) = handshake(stream, deadline).await?;

    // The request line carries only the path; the authority went into
    // the `Host` header (`wasmtime-wasi-http` sets it).
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            uri.path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str),
        )
        .build()
        .map_err(|_| Error::HttpRequestUriInvalid)?;

    let send = async move {
        let response = tokio::time::timeout(first_byte_timeout, sender.send_request(request))
            .await
            .map_err(|_| Error::ConnectionReadTimeout)?
            .map_err(hyper_error)?;
        check_response_head(response.headers())?;
        let mut timeout = tokio::time::interval(between_bytes_timeout);
        timeout.reset();
        Ok::<_, Error>(response.map(|incoming| IncomingBody { incoming, timeout }))
    };
    let mut send = pin!(send);
    let mut conn = Some(conn);
    // Wait for the response head while driving the connection.
    let response = std::future::poll_fn(|cx| match send.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => {
            let Some(c) = conn.as_mut() else {
                return Poll::Pending;
            };
            let done = ready!(Pin::new(c).poll(cx));
            conn = None;
            match done {
                Ok(()) => send.as_mut().poll(cx),
                Err(err) => Poll::Ready(Err(hyper_error(err))),
            }
        }
    })
    .await?;
    let io = async move {
        // The permit lives as long as the connection.
        let _permit = permit;
        match conn {
            None => Ok(()),
            Some(conn) => conn.await.map_err(|err| {
                if err.is_timeout() {
                    Error::HttpResponseTimeout
                } else {
                    hyper_error(err)
                }
            }),
        }
    };
    Ok((
        response.map(BodyExt::boxed_unsync),
        Box::new(io) as Box<dyn Future<Output = Result<(), Error>> + Send>,
    ))
}

/// A response body that fails if no frame arrives within the
/// between-bytes timeout.
struct IncomingBody {
    incoming: hyper::body::Incoming,
    timeout: tokio::time::Interval,
}

impl http_body::Body for IncomingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        match Pin::new(&mut self.incoming).poll_frame(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(if err.is_timeout() {
                Error::HttpResponseTimeout
            } else {
                Error::from(err)
            }))),
            Poll::Ready(Some(Ok(frame))) => {
                self.timeout.reset();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => {
                ready!(self.timeout.poll_tick(cx));
                Poll::Ready(Some(Err(Error::ConnectionReadTimeout)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.incoming.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::plain_authority;

    fn plain(s: &str) -> bool {
        plain_authority(&s.parse().expect("authority"))
    }

    /// The SDK documents the host's header budget as a constant of its
    /// own (no WIT carries it); it must not drift from the host's.
    #[test]
    fn the_sdk_header_budget_is_the_hosts() {
        assert_eq!(
            oxidhome_sdk::streaming::http::MAX_HEADER_BYTES,
            super::FIELD_SIZE_LIMIT
        );
    }

    /// A request that runs out the SDK's default total timeout must
    /// return before the per-call watchdog traps the call.
    #[test]
    fn the_sdk_total_timeout_ends_before_the_watchdog() {
        assert!(
            oxidhome_sdk::streaming::http::DEFAULT_TOTAL_TIMEOUT
                < crate::runtime::watchdog::WATCHDOG_DEFAULT
        );
    }

    #[test]
    fn oversized_header_maps_fail_instead_of_trapping() {
        use wasmtime_wasi_http::FieldMapError;
        use wasmtime_wasi_http::p2::HeaderError;
        use wasmtime_wasi_http::p2::bindings::http::types::HeaderError as Code;
        for err in [FieldMapError::TotalSizeTooBig, FieldMapError::TooManyFields] {
            assert!(matches!(
                super::header_error(HeaderError::from(err)),
                Ok(Code::InvalidSyntax)
            ));
        }
        assert!(matches!(
            super::header_error(HeaderError::from(FieldMapError::Forbidden)),
            Ok(Code::Forbidden)
        ));
        assert!(
            super::header_error(HeaderError::trap(wasmtime::format_err!("missing entry"))).is_err()
        );
    }

    #[test]
    fn a_failed_connect_never_looks_like_a_cut_after_sending() {
        use std::io::{Error, ErrorKind};
        use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionRefused,
            ErrorKind::Other,
        ] {
            assert!(matches!(
                super::connect_error(&Error::from(kind)),
                ErrorCode::ConnectionRefused
            ));
        }
        assert!(matches!(
            super::connect_error(&Error::from(ErrorKind::TimedOut)),
            ErrorCode::ConnectionTimeout
        ));
        assert!(matches!(
            super::connect_error(&Error::from(ErrorKind::HostUnreachable)),
            ErrorCode::DestinationUnavailable
        ));
        #[cfg(unix)]
        assert!(matches!(
            super::connect_error(&Error::from_raw_os_error(libc::EAFNOSUPPORT)),
            ErrorCode::DestinationUnavailable
        ));
    }

    #[test]
    fn response_heads_are_bounded_per_value() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-small", http::HeaderValue::from_static("1"));
        assert!(super::check_response_head(&headers).is_ok());
        let name = http::HeaderName::from_bytes(&[b'x'; 200]).unwrap();
        for _ in 0..400 {
            headers.append(name.clone(), http::HeaderValue::from_static("v"));
        }
        assert!(super::check_response_head(&headers).is_err());
    }

    #[test]
    fn authority_must_be_exactly_host_and_port() {
        for ok in [
            "example.com",
            "example.com:8080",
            "127.0.0.1:80",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(plain(ok), "{ok}");
        }
        for bad in ["[::1]x", "[::1]x:80", "[v1.x]:80", "[::1]:", "example.com:"] {
            if let Ok(a) = bad.parse::<http::uri::Authority>() {
                assert!(!plain_authority(&a), "{bad}");
            }
        }
    }
}
