//! TLS for outgoing `https://` requests of streaming instances.
//!
//! - **Stack.** rustls with the `ring` provider, TLS 1.3 and 1.2. Server
//!   certificates are verified against the operating system's roots
//!   (`rustls-native-certs`, loaded once, on the first `https://`
//!   request); no bundled root list.
//! - **Names.** SNI and certificate name checks use the host the request
//!   named, never the address it was resolved to; an IP-literal host is
//!   checked against the certificate's IP addresses and sends no SNI.
//! - **Trust on first use.** When the connected address is *private* or
//!   *link-local* and the roots don't vouch for the certificate (a device
//!   with a self-signed certificate), the handshake still proves the
//!   server holds the leaf certificate's key, and the leaf's SHA-256 is
//!   checked against the instance's pin for `(host, port)` in the
//!   [`TlsPinStore`]: no pin pins it, the same certificate passes, any
//!   other is refused and audited. Public addresses, and NAT64 addresses
//!   (which may translate to public servers), never get this. A pinned
//!   key also refuses a different certificate the roots do vouch for,
//!   whatever address the name now resolves to.
//!   Nothing of the request is sent before that check.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use wasmtime_wasi_http::Error;

use super::policy::NetworkPolicy;
use crate::native_policy::endpoint::{AddressClass, classify};
use crate::state::tls_pins::{Fingerprint, PinCheck, PinKey, TlsPinStore};

/// The system roots, once loaded: `None` when the system has none usable.
#[derive(Debug, Clone)]
enum Roots {
    Loading,
    Loaded(Option<Arc<WebPkiServerVerifier>>),
}

/// Host-wide TLS client state: the root verifier (built on first use) and
/// the pin store. One per [`Engine`](crate::Engine).
pub(crate) struct TlsClient {
    provider: Arc<CryptoProvider>,
    /// `None` when the system has no usable roots: only pinned LAN
    /// devices can then be reached.
    /// `Some` once loaded. One detached blocking job loads it; requests
    /// wait on the channel, so one that gives up holds no thread.
    roots: Arc<tokio::sync::watch::Sender<Roots>>,
    roots_started: AtomicBool,
    extra_roots: Vec<CertificateDer<'static>>,
    pins: Arc<TlsPinStore>,
    /// Test hook: also trust loopback servers on first use.
    tofu_loopback: bool,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("extra_roots", &self.extra_roots.len())
            .field("tofu_loopback", &self.tofu_loopback)
            .finish_non_exhaustive()
    }
}

impl TlsClient {
    /// A client verifying against the system roots, with `pins`.
    #[must_use]
    pub(crate) fn new(pins: Arc<TlsPinStore>) -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            roots: Arc::new(tokio::sync::watch::Sender::new(Roots::Loading)),
            roots_started: AtomicBool::new(false),
            extra_roots: Vec::new(),
            pins,
            tofu_loopback: false,
        }
    }

    /// Test hook: add the DER certificates `roots` to the system roots,
    /// and with `tofu_loopback` treat loopback servers like LAN devices
    /// for trust on first use. Not for production.
    #[must_use]
    pub(crate) fn for_tests(
        pins: Arc<TlsPinStore>,
        roots: Vec<Vec<u8>>,
        tofu_loopback: bool,
    ) -> Self {
        Self {
            extra_roots: roots.into_iter().map(CertificateDer::from).collect(),
            tofu_loopback,
            ..Self::new(pins)
        }
    }

    /// The pin store.
    #[must_use]
    pub(crate) fn pins(&self) -> &Arc<TlsPinStore> {
        &self.pins
    }

    async fn root_verifier(&self) -> Option<Arc<WebPkiServerVerifier>> {
        let mut loaded = self.roots.subscribe();
        if !self.roots_started.swap(true, Ordering::AcqRel) {
            let roots = Arc::clone(&self.roots);
            let extra = self.extra_roots.clone();
            let provider = Arc::clone(&self.provider);
            // Detached: a request that stops waiting neither stops nor
            // repeats the load.
            drop(tokio::task::spawn_blocking(move || {
                roots.send_replace(Roots::Loaded(build_root_verifier(&provider, extra)));
            }));
        }
        match &*loaded
            .wait_for(|roots| matches!(roots, Roots::Loaded(_)))
            .await
            .ok()?
        {
            Roots::Loaded(verifier) => verifier.clone(),
            Roots::Loading => None,
        }
    }

    /// Whether a server at `addr` may be trusted on first use.
    fn tofu_allowed(&self, addr: SocketAddr) -> bool {
        let ip = addr.ip().to_canonical();
        if is_nat64(ip) {
            return false;
        }
        match classify(ip) {
            AddressClass::Private | AddressClass::LinkLocal => true,
            AddressClass::Loopback => self.tofu_loopback,
            AddressClass::Public | AddressClass::Forbidden => false,
        }
    }
}

/// `64:ff9b::/96` (RFC 6052) and `64:ff9b:1::/48` (RFC 8215): a
/// translator may map these to any IPv4 server, public ones included.
fn is_nat64(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x64 && s[1] == 0xff9b && (s[2] == 1 || s[2..6] == [0, 0, 0, 0])
        }
        IpAddr::V4(_) => false,
    }
}

fn build_root_verifier(
    provider: &Arc<CryptoProvider>,
    extra: Vec<CertificateDer<'static>>,
) -> Option<Arc<WebPkiServerVerifier>> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::warn!(
            target: "host.network",
            errors = native.errors.len(),
            "some system root certificates couldn't be loaded",
        );
    }
    let mut store = RootCertStore::empty();
    let (added, ignored) = store.add_parsable_certificates(native.certs.into_iter().chain(extra));
    if ignored > 0 {
        tracing::debug!(target: "host.network", ignored, "skipped unparsable root certificates");
    }
    if added == 0 {
        tracing::warn!(
            target: "host.network",
            "no system root certificates; https:// requests reach only pinned LAN devices",
        );
        return None;
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(store), Arc::clone(provider))
        .build()
        .map_err(|err| {
            tracing::warn!(target: "host.network", error = %err, "building the TLS root verifier failed");
        })
        .ok()
}

/// What the handshake's certificate check concluded.
#[derive(Debug, Clone, Copy)]
enum Trust {
    /// The roots vouch for it.
    Roots(Fingerprint),
    /// Not vouched for, but the server is on the LAN: check the pin.
    FirstUse(Fingerprint),
}

/// One connection's certificate verifier.
#[derive(Debug)]
struct Verifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    tofu: bool,
    trust: Mutex<Option<Trust>>,
    /// The leaf the server presented, whatever the verdict.
    seen: Mutex<Option<Fingerprint>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Fingerprint::of_der(end_entity));
        let verdict = match &self.roots {
            Some(roots) => {
                roots.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            )),
        };
        let trust = match verdict {
            Ok(verified) => {
                *self.trust.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some(Trust::Roots(Fingerprint::of_der(end_entity)));
                return Ok(verified);
            }
            Err(rustls::Error::InvalidCertificate(_)) if self.tofu => {
                Trust::FirstUse(Fingerprint::of_der(end_entity))
            }
            Err(err) => return Err(err),
        };
        *self.trust.lock().unwrap_or_else(PoisonError::into_inner) = Some(trust);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS-wrapped connection.
pub(super) type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// Why a TLS connection was refused by policy (pins), as opposed to
/// failing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum PinDenial {
    #[error(
        "the certificate (sha256 {seen}) differs from the one pinned on first use (sha256 \
         {pinned}); reset the pin if the device's certificate changed"
    )]
    Mismatch { seen: String, pinned: String },
    #[error("the instance or host holds the most TLS pins it may; reset unused pins")]
    Full,
    #[error("storing the certificate pin failed")]
    Store,
}

/// Outcome of [`connect`].
pub(super) enum Connected {
    /// Ready for HTTP.
    Stream(Box<TlsStream>),
    /// A pin refused the server; the caller audits it.
    Refused(PinDenial),
}

/// TLS handshake with the server on `stream` (connected to `peer`) for
/// `host:port` as the request named it (`target`), for `policy`'s
/// instance. A new pin is logged and audited here, even when the
/// request is abandoned meanwhile.
pub(super) async fn connect(
    client: &TlsClient,
    policy: &Arc<NetworkPolicy>,
    target: &str,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    host: &str,
    port: u16,
) -> Result<Connected, Error> {
    let server_name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => {
            ServerName::try_from(host.to_owned()).map_err(|_| Error::HttpRequestUriInvalid)?
        }
    };
    let verifier = Arc::new(Verifier {
        roots: client.root_verifier().await,
        provider: Arc::clone(&client.provider),
        tofu: client.tofu_allowed(peer),
        trust: Mutex::new(None),
        seen: Mutex::new(None),
    });
    let key = PinKey {
        instance_id: policy.instance_id().to_owned(),
        host: crate::state::tls_pins::normalize_host(host),
        port,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&client.provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::TlsProtocolError)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = match tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
    {
        Ok(tls) => tls,
        Err(err) => {
            // A pinned key presenting another certificate is a pin
            // refusal (audited), whatever else failed with it.
            let seen = *verifier.seen.lock().unwrap_or_else(PoisonError::into_inner);
            return match (seen, client.pins.pinned(&key)) {
                (Some(seen), Some(pinned)) if seen != pinned => {
                    Ok(Connected::Refused(PinDenial::Mismatch {
                        seen: seen.to_hex(),
                        pinned: pinned.to_hex(),
                    }))
                }
                _ => Err(tls_error(&err)),
            };
        }
    };
    let trust = *verifier
        .trust
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match trust {
        Some(Trust::Roots(seen)) => {
            // A pinned key stays pinned until the operator resets it,
            // whoever vouches for a replacement and wherever the name now
            // resolves.
            match client.pins.pinned(&key) {
                Some(pinned) if pinned != seen => Ok(Connected::Refused(PinDenial::Mismatch {
                    seen: seen.to_hex(),
                    pinned: pinned.to_hex(),
                })),
                _ => Ok(Connected::Stream(Box::new(tls))),
            }
        }
        Some(Trust::FirstUse(seen)) => {
            let pins = Arc::clone(&client.pins);
            let (policy, target) = (Arc::clone(policy), target.to_owned());
            // The audit row's caller: task-locals don't reach the
            // blocking thread.
            let ctx = crate::auth::invocation::current();
            // Pinned and audited together on the blocking thread, so a
            // request that times out meanwhile can't leave an unaudited pin.
            let check = tokio::task::spawn_blocking(move || {
                let check = pins.check_or_pin(&key, seen);
                if matches!(check, Ok(PinCheck::Pinned)) {
                    tracing::warn!(
                        target: "host.network",
                        instance_id = %key.instance_id,
                        host = %key.host,
                        port = key.port,
                        sha256 = %seen.to_hex(),
                        "trusting a certificate the system roots don't vouch for, on first use",
                    );
                    let audit = || policy.audit_pinned(&target, seen);
                    match ctx {
                        Some(ctx) => crate::auth::invocation::CURRENT.sync_scope(ctx, audit),
                        None => audit(),
                    }
                }
                check
            })
            .await
            .map_err(|_| Error::InternalError(Some("pin check failed".into())))?;
            match check {
                Ok(PinCheck::Matches | PinCheck::Pinned) => Ok(Connected::Stream(Box::new(tls))),
                Ok(PinCheck::Mismatch(pinned)) => Ok(Connected::Refused(PinDenial::Mismatch {
                    seen: seen.to_hex(),
                    pinned: pinned.to_hex(),
                })),
                Ok(PinCheck::Full) => Ok(Connected::Refused(PinDenial::Full)),
                Err(err) => {
                    tracing::error!(target: "host.network", error = %err, "storing a TLS pin failed");
                    Ok(Connected::Refused(PinDenial::Store))
                }
            }
        }
        // rustls always verifies the certificate before completing.
        None => Err(Error::TlsCertificateError),
    }
}

/// Map a handshake error to the `wasi:http` error code.
fn tls_error(err: &std::io::Error) -> Error {
    if let Some(err) = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        return match err {
            rustls::Error::InvalidCertificate(_) => Error::TlsCertificateError,
            rustls::Error::AlertReceived(alert) => Error::TlsAlertReceived {
                alert_id: Some(u8::from(*alert)),
                alert_message: None,
            },
            _ => Error::TlsProtocolError,
        };
    }
    match err.kind() {
        std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof => Error::ConnectionTerminated,
        _ => Error::TlsProtocolError,
    }
}
