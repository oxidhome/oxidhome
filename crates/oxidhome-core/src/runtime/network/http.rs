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
//! 3. refuses `https://` — TLS isn't implemented yet;
//! 4. connects to the first allowed address — the one it checked, with
//!    no second lookup — and sends the request over HTTP/1.1.
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
use wasmtime_wasi::p2::bindings::sockets::network::ErrorCode as SocketErrorCode;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::{Error, RequestOptions, WasiBody, WasiHttpHooks};

use super::policy::{Denial, NetworkPolicy, Use};

/// Connect timeout when the plugin sets none.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Time to the response head when the plugin sets none.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest gap between response body frames when the plugin sets none.
const BETWEEN_BYTES_TIMEOUT: Duration = Duration::from_secs(60);

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
}

impl HttpHooks {
    pub(crate) fn new(policy: Arc<NetworkPolicy>) -> Self {
        Self { policy }
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
        let policy = Arc::clone(&self.policy);
        Box::new(async move { send(policy, request, options).await })
    }
}

fn dns_error(code: SocketErrorCode) -> Error {
    match code {
        SocketErrorCode::TemporaryResolverFailure => Error::DnsTimeout,
        _ => Error::DnsError {
            rcode: Some(format!("{code:?}")),
            info_code: None,
        },
    }
}

/// Pick the address to connect to for `host:port`.
async fn checked_address(
    policy: &Arc<NetworkPolicy>,
    using: Use,
    target: &str,
    host: &str,
    port: u16,
) -> Result<SocketAddr, Error> {
    let (candidates, name_rules) = if let Ok(ip) = host.parse::<IpAddr>() {
        (vec![ip], None)
    } else {
        let rules = policy.name_rules(host, &[using]).map_err(|denial| {
            policy.audit_denial("http", target, &denial);
            Error::HttpRequestDenied
        })?;
        let addrs = super::sockets::resolve(policy, host, &rules, "http")
            .await
            .map_err(dns_error)?;
        (addrs, Some(rules))
    };
    let mut denial = None;
    for ip in candidates {
        let addr = SocketAddr::new(ip, port);
        match policy.check_addr(using, addr, name_rules.as_deref()) {
            Ok(()) => return Ok(addr),
            Err(d) => denial = denial.or(Some(d)),
        }
    }
    let denial = denial.unwrap_or_else(|| Denial::ResolvedRefused(host.to_owned()));
    policy.audit_denial("http", target, &denial);
    Err(Error::HttpRequestDenied)
}

async fn send(
    policy: Arc<NetworkPolicy>,
    mut request: http::Request<WasiBody>,
    options: Option<RequestOptions>,
) -> Result<
    (
        http::Response<WasiBody>,
        Box<dyn Future<Output = Result<(), Error>> + Send>,
    ),
    Error,
> {
    let uri = request.uri().clone();
    let authority = uri.authority().ok_or(Error::HttpRequestUriInvalid)?;
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

    let permit = Arc::clone(&policy.http_requests)
        .try_acquire_owned()
        .map_err(|_| Error::ConnectionLimitReached)?;
    let addr = checked_address(&policy, using, &target, &host, port).await?;
    if tls {
        // Checked first, so a target the rules don't allow is refused
        // (and audited) as such.
        return Err(Error::InternalError(Some(
            "https is not supported by this host yet; only http:// requests are sent".into(),
        )));
    }

    let options = options.unwrap_or_default();
    let connect_timeout = options.connect_timeout.unwrap_or(CONNECT_TIMEOUT);
    let first_byte_timeout = options.first_byte_timeout.unwrap_or(FIRST_BYTE_TIMEOUT);
    let between_bytes_timeout = options
        .between_bytes_timeout
        .unwrap_or(BETWEEN_BYTES_TIMEOUT)
        .max(Duration::from_millis(1));

    let stream = tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| Error::ConnectionTimeout)?
        .map_err(Error::Connect)?;
    let (mut sender, conn) = tokio::time::timeout(
        connect_timeout,
        hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)??;

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
            .map_err(Error::from)?;
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
                Err(err) => Poll::Ready(Err(Error::from(err))),
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
                    Error::from(err)
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
