//! Phase 8: network access of `streaming-plugin` instances.
//!
//! `examples/net-probe` runs a list of network operations on `init` and
//! stores each result; these tests point it at local servers and check
//! what the manifest's `[capabilities] network` rules let through, and
//! that each refusal leaves an audit `deny` row.

#[path = "support.rs"]
mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oxidhome_core::state::{AuditEntry, AuditQuery};
use oxidhome_test_host::wit::types::Value;
use oxidhome_test_host::{LoadOptions, TestHost, TestPluginInstance};
use support::{HELLO_WORLD, NET_PROBE, NETWORK_DISCOVERY, stage, stage_with};

/// A TCP server on loopback answering each connection once: a line
/// protocol (`ping` → `pong`) or, for an HTTP request, `respond`'s
/// reply to its path. Counts the connections it accepted.
struct TcpServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl TcpServer {
    fn line() -> Self {
        Self::start(|_| None)
    }

    fn http(respond: impl Fn(&str) -> String + Send + 'static) -> Self {
        Self::start(move |path| Some(respond(path)))
    }

    fn start(respond: impl Fn(&str) -> Option<String> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp server");
        let addr = listener.local_addr().expect("local addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    continue;
                }
                let path = first.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let reply = if first.starts_with("GET ") {
                    // Skip the headers.
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                        line.clear();
                    }
                    respond(&path).unwrap_or_default()
                } else {
                    "pong\n".to_owned()
                };
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
                drop(stream);
                let mut rest = Vec::new();
                let _ = reader
                    .get_mut()
                    .set_read_timeout(Some(Duration::from_millis(50)));
                let _ = reader.read_to_end(&mut rest);
            }
        });
        Self { addr, accepted }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// A UDP server on loopback answering each datagram with `pong`.
fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp server");
    let addr = socket.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((_, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(b"pong", from);
        }
    });
    addr
}

/// A UDP server on loopback that answers each datagram from a second
/// socket, i.e. from an address the client didn't send to.
fn udp_reply_from_elsewhere() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp server");
    let other = UdpSocket::bind("127.0.0.1:0").expect("bind udp reply socket");
    let addr = socket.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((_, from)) = socket.recv_from(&mut buf) {
            let _ = other.send_to(b"spoof", from);
        }
    });
    addr
}

/// `err` and its sources, `: `-joined.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut chain = err.to_string();
    let mut source = err.source();
    while let Some(e) = source {
        chain.push_str(": ");
        chain.push_str(&e.to_string());
        source = e.source();
    }
    chain
}

fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_redirect(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
}

/// Stage net-probe with these network rules.
fn probe_dir(rules: &[String]) -> support::TempDir {
    let rules: Vec<toml::Value> = rules.iter().cloned().map(toml::Value::String).collect();
    stage(NET_PROBE, |caps| {
        caps.insert("network".into(), toml::Value::Array(rules));
    })
}

/// Run `ops` in a net-probe instance with `rules`; the results, in order.
async fn probe(host: &TestHost, id: &str, rules: &[String], ops: &[String]) -> Vec<String> {
    let dir = probe_dir(rules);
    let mut overrides = toml::Table::new();
    overrides.insert("ops".into(), toml::Value::String(ops.join(";")));
    let mut instance = host
        .load_with(
            dir.path(),
            LoadOptions::new()
                .instance_id(id)
                .config(toml::Value::Table(overrides)),
        )
        .await
        .expect("load net-probe");
    instance.init().await.expect("init net-probe");
    results(&instance, ops.len())
}

fn results(instance: &TestPluginInstance, n: usize) -> Vec<String> {
    (0..n)
        .map(
            |i| match instance.storage().get(&format!("op/{i}")).expect("storage") {
                Some(Value::StringVal(s)) => s,
                other => panic!("op/{i}: {other:?}"),
            },
        )
        .collect()
}

/// Wait (bounded) for the deny-audit worker to write a `NET` row whose
/// path starts with `net.<op>/<instance>/` and contains `target`.
async fn wait_for_deny(host: &TestHost, op: &str, instance: &str, target: &str) -> AuditEntry {
    let prefix = format!("net.{op}/{instance}/");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = host
            .engine()
            .audit_log()
            .query(&AuditQuery::default(), 256)
            .expect("audit query");
        if let Some(row) = rows.iter().find(|r| {
            r.method == "NET"
                && r.decision == "deny"
                && r.path.starts_with(&prefix)
                && r.path.contains(target)
        }) {
            assert_eq!(row.required_scope.as_deref(), Some("network"));
            return row.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no NET deny row for {prefix}…{target}; rows: {rows:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_tcp_and_udp_reach_their_servers() {
    let host = TestHost::new().unwrap();
    let tcp = TcpServer::line();
    let udp = udp_echo();
    let results = probe(
        &host,
        "allowed",
        &[
            format!("tcp://127.0.0.1:{}", tcp.port()),
            format!("udp://127.0.0.1:{}", udp.port()),
        ],
        &[
            format!("tcp 127.0.0.1:{}", tcp.port()),
            format!("udp {udp}"),
        ],
    )
    .await;
    assert_eq!(
        results,
        vec!["ok:pong".to_owned(), format!("ok:pong@{udp}")]
    );
    assert_eq!(tcp.accepted(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn datagrams_from_unallowed_addresses_are_dropped() {
    let host = TestHost::new().unwrap();
    let server = udp_reply_from_elsewhere();
    let results = probe(
        &host,
        "spoof",
        &[format!("udp://127.0.0.1:{}", server.port())],
        &[format!("udp {server}")],
    )
    .await;
    // The send went out; the reply came from another port and never
    // reached the plugin, which gave up waiting.
    assert_eq!(results, vec!["err:WouldBlock".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn disallowed_host_port_and_proto_are_refused_and_audited() {
    let host = TestHost::new().unwrap();
    let allowed = TcpServer::line();
    let other = TcpServer::line();
    let udp = udp_echo();
    let results = probe(
        &host,
        "denied",
        &[format!("tcp://127.0.0.1:{}", allowed.port())],
        &[
            // Another port on the allowed address.
            format!("tcp 127.0.0.1:{}", other.port()),
            // The allowed port on another loopback address.
            format!("tcp 127.0.0.2:{}", allowed.port()),
            // UDP isn't covered by a `tcp` rule.
            format!("udp {udp}"),
            // Broadcast is never allowed.
            "udp 255.255.255.255:9999".to_owned(),
            // The cloud metadata address.
            "tcp 169.254.169.254:80".to_owned(),
        ],
    )
    .await;
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result, "err:PermissionDenied", "op {i}: {results:?}");
    }
    assert_eq!(
        other.accepted(),
        0,
        "the refused connect must not reach the server"
    );

    let row = wait_for_deny(
        &host,
        "connect",
        "denied",
        &format!("127.0.0.1:{}", other.port()),
    )
    .await;
    assert!(
        row.domain_error
            .is_some_and(|e| e.contains("no network rule"))
    );
    wait_for_deny(
        &host,
        "connect",
        "denied",
        &format!("127.0.0.2:{}", allowed.port()),
    )
    .await;
    wait_for_deny(&host, "send", "denied", &udp.to_string()).await;
    wait_for_deny(&host, "send", "denied", "255.255.255.255:9999").await;
    wait_for_deny(&host, "connect", "denied", "169.254.169.254:80").await;
}

/// The policy is built from what the operator granted, not from what the
/// manifest requests: a grant narrowed to one port out of a requested
/// range allows only that port.
#[tokio::test(flavor = "multi_thread")]
async fn only_granted_rules_are_enforced_as_allowed() {
    let host = TestHost::new().unwrap();
    let granted = TcpServer::line();
    let withheld = TcpServer::line();
    let granted_rule = format!("tcp://127.0.0.1:{}", granted.port());
    let dir = probe_dir(&["tcp://127.0.0.0/8:*".to_owned()]);
    let grant = oxidhome_test_host::CapabilitiesSection {
        network: vec![granted_rule.parse().unwrap()],
        storage_quota_kb: 16,
        ..Default::default()
    };
    let mut overrides = toml::Table::new();
    overrides.insert(
        "ops".into(),
        toml::Value::String(format!(
            "tcp 127.0.0.1:{};tcp 127.0.0.1:{}",
            granted.port(),
            withheld.port()
        )),
    );
    let mut instance = host
        .load_with(
            dir.path(),
            LoadOptions::new()
                .instance_id("granted")
                .config(toml::Value::Table(overrides))
                .grant(grant),
        )
        .await
        .unwrap();
    instance.init().await.unwrap();
    assert_eq!(
        results(&instance, 2),
        vec!["ok:pong".to_owned(), "err:PermissionDenied".to_owned()]
    );
    assert_eq!(withheld.accepted(), 0);
    wait_for_deny(
        &host,
        "connect",
        "granted",
        &format!("127.0.0.1:{}", withheld.port()),
    )
    .await;
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().expect("ip literal")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_resolving_to_a_forbidden_address_is_refused() {
    // `localhost` answers loopback: a name rule never reaches it
    // (rebinding protection), and a name without a rule isn't looked up.
    let host = TestHost::new()
        .unwrap()
        .with_dns_overrides([("localhost", vec![ip("127.0.0.1")])]);
    let tcp = TcpServer::line();
    let web = TcpServer::http(|_| http_ok("secret"));
    let results = probe(
        &host,
        "rebind",
        &[
            format!("tcp://localhost:{}", tcp.port()),
            format!("tcp://localhost:{}", web.port()),
        ],
        &[
            format!("tcp localhost:{}", tcp.port()),
            "dns localhost".to_owned(),
            "dns unlisted.example.com".to_owned(),
            format!("http http://localhost:{}/", web.port()),
        ],
    )
    .await;
    for result in &results {
        assert!(result.starts_with("err:"), "{results:?}");
    }
    assert_eq!(tcp.accepted(), 0);
    assert_eq!(web.accepted(), 0);
    wait_for_deny(&host, "lookup", "rebind", "unlisted.example.com").await;
    // The refusal is a policy one, not a DNS failure: audited, and HTTP
    // reports it as denied.
    let row = wait_for_deny(&host, "lookup", "rebind", "localhost").await;
    assert!(
        row.domain_error
            .is_some_and(|e| e.contains("no network rule allows")),
        "rebinding refusal"
    );
    assert_eq!(results[3], "err:ErrorCode::HttpRequestDenied");
}

#[tokio::test(flavor = "multi_thread")]
async fn lookups_hand_over_only_the_answers_the_rules_allow() {
    let host = TestHost::new().unwrap().with_dns_overrides([
        ("camera.lan", vec![ip("192.168.1.20")]),
        ("api.example.com", vec![ip("1.1.1.1"), ip("192.168.1.30")]),
        ("rebind.example.com", vec![ip("192.168.1.21")]),
        ("metadata.google.internal", vec![ip("169.254.169.254")]),
    ]);
    let names = [
        "camera.lan",
        "api.example.com",
        "rebind.example.com",
        "metadata.google.internal",
        "missing.example.com",
    ];
    let rules: Vec<String> = names.iter().map(|n| format!("tcp://{n}:443")).collect();
    let ops: Vec<String> = names.iter().map(|n| format!("dns {n}")).collect();
    let results = probe(&host, "lookups", &rules, &ops).await;
    // A local-only name reaches the LAN; a public name keeps only its
    // public answers.
    assert_eq!(results[0], "ok:192.168.1.20", "{results:?}");
    assert_eq!(results[1], "ok:1.1.1.1", "{results:?}");
    // A public name answering only a LAN address, and a local-only name
    // answering link-local, are refused and audited.
    for (result, name) in results[2..4].iter().zip(&names[2..4]) {
        assert!(result.starts_with("err:"), "{results:?}");
        let row = wait_for_deny(&host, "lookup", "lookups", name).await;
        assert!(
            row.domain_error
                .is_some_and(|e| e.contains("no network rule allows")),
            "{name}"
        );
    }
    // A name the table doesn't list is unresolvable: a DNS failure, not
    // a policy refusal, and never sent to the machine's resolver.
    assert!(results[4].starts_with("err:"), "{results:?}");
    assert_ne!(results[4], results[2], "{results:?}");
    // Every queued denial is written before checking none names it.
    let engine = host.engine().clone();
    assert!(
        tokio::task::spawn_blocking(move || engine.drain_state_read_audit(Duration::from_secs(10)))
            .await
            .unwrap(),
        "deny-audit queue drained"
    );
    let rows = host
        .engine()
        .audit_log()
        .query(&AuditQuery::default(), 256)
        .expect("audit query");
    assert!(
        !rows.iter().any(|r| r.path.contains("missing.example.com")),
        "{rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn binds_go_only_to_the_unspecified_address_and_listen_is_refused() {
    let host = TestHost::new().unwrap();
    let results = probe(
        &host,
        "binds",
        &[],
        &[
            "bind 0.0.0.0:0".to_owned(),
            "bind 127.0.0.1:0".to_owned(),
            "listen 0.0.0.0:0".to_owned(),
            // Header names are capped (host memory), not a network op.
            "hdr 32".to_owned(),
            "hdr 300".to_owned(),
        ],
    )
    .await;
    assert_eq!(results[0], "ok:bound");
    assert_eq!(results[1], "err:PermissionDenied");
    assert!(results[2].starts_with("err:"), "{results:?}");
    assert_eq!(results[3], "ok:appended");
    assert_eq!(results[4], "err:HeaderError::InvalidSyntax");
    wait_for_deny(&host, "bind", "binds", "127.0.0.1:0").await;
    wait_for_deny(&host, "listen", "binds", "0.0.0.0").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http_requests_are_checked_on_every_hop() {
    let host = TestHost::new().unwrap();
    let forbidden = TcpServer::http(|_| http_ok("secret"));
    let forbidden_url = format!("http://127.0.0.1:{}/", forbidden.port());
    let allowed = TcpServer::http(move |path| match path {
        "/redirect" => http_redirect(&forbidden_url),
        // A head past the host's 64 KiB ceiling.
        "/bighead" => format!(
            "HTTP/1.1 200 OK\r\nx-big: {}\r\ncontent-length: 0\r\n\r\n",
            "a".repeat(70 * 1024)
        ),
        _ => http_ok("hello"),
    });
    let results = probe(
        &host,
        "http",
        &[format!("tcp://127.0.0.1:{}", allowed.port())],
        &[
            format!("http http://127.0.0.1:{}/ok", allowed.port()),
            // A plugin that only calls `get` (no pollable) gets its
            // response too.
            format!("httppoll http://127.0.0.1:{}/ok", allowed.port()),
            // No path set at all: sent as `/`.
            format!("http http://127.0.0.1:{}", allowed.port()),
            // The plugin follows the 302 itself; the second hop is a new
            // request, refused like any other.
            format!("http http://127.0.0.1:{}/redirect", allowed.port()),
            format!("http http://127.0.0.1:{}/", forbidden.port()),
            // HTTPS needs an `https` rule.
            format!("http https://127.0.0.1:{}/", allowed.port()),
            // Userinfo never reaches the wire.
            format!("http http://user:pw@127.0.0.1:{}/ok", allowed.port()),
            // Nor does an oversized path.
            format!(
                "http http://127.0.0.1:{}/{}",
                allowed.port(),
                "a".repeat(9000)
            ),
            format!("http http://127.0.0.1:{}/bighead", allowed.port()),
        ],
    )
    .await;
    assert_eq!(results[0], "ok:200:hello");
    assert_eq!(results[1], "ok:200:hello");
    assert_eq!(results[2], "ok:200:hello");
    assert_eq!(results[3], "err:ErrorCode::HttpRequestDenied");
    assert_eq!(results[4], "err:ErrorCode::HttpRequestDenied");
    assert_eq!(results[5], "err:ErrorCode::HttpRequestDenied");
    assert!(results[6].starts_with("err:"), "{results:?}");
    assert_eq!(results[7], "err:path");
    assert!(
        results[8].starts_with("err:ErrorCode::HttpResponseHeaderSectionSize"),
        "{results:?}"
    );
    // Only the four allowed requests and the redirecting hop reached it.
    assert_eq!(allowed.accepted(), 5);
    assert_eq!(
        forbidden.accepted(),
        0,
        "the redirect target must not be contacted"
    );
    wait_for_deny(
        &host,
        "http",
        "http",
        &format!("127.0.0.1:{}", forbidden.port()),
    )
    .await;
    wait_for_deny(&host, "http", "http", "https://").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_world_components_get_no_network_imports() {
    let host = TestHost::new().unwrap();
    // The same component, declared as a `plugin`-world plugin: the
    // linker has no `wasi:sockets` / `wasi:http`, so it can't load.
    let dir = stage_with(NET_PROBE, |manifest| {
        manifest
            .get_mut("plugin")
            .and_then(toml::Value::as_table_mut)
            .expect("[plugin]")
            .insert("world".into(), toml::Value::String("plugin".into()));
        manifest
            .get_mut("capabilities")
            .and_then(toml::Value::as_table_mut)
            .expect("[capabilities]")
            .insert("network".into(), toml::Value::Array(Vec::new()));
    });
    let err = match host.load(dir.path()).await {
        Ok(_) => panic!("a plugin-world instance must not link wasi:sockets"),
        Err(err) => error_chain(&err),
    };
    assert!(
        err.contains("wasi:sockets") || err.contains("wasi:http"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_manifests_need_the_streaming_export() {
    let host = TestHost::new().unwrap();
    // A `plugin`-world component under a streaming manifest: it would
    // get the network imports without implementing the world.
    let dir = stage_with(HELLO_WORLD, |manifest| {
        manifest
            .get_mut("plugin")
            .and_then(toml::Value::as_table_mut)
            .expect("[plugin]")
            .insert(
                "world".into(),
                toml::Value::String("streaming-plugin".into()),
            );
    });
    let err = match host.load(dir.path()).await {
        Ok(_) => panic!("a component without the streaming export must not load"),
        Err(err) => error_chain(&err),
    };
    assert!(err.contains("oxidhome:plugin/streaming@"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn network_discovery_example_publishes_replies() {
    let host = TestHost::new().unwrap();
    let allowed = udp_echo();
    let denied = udp_echo();
    let dir = stage(NETWORK_DISCOVERY, |caps| {
        caps.insert(
            "network".into(),
            toml::Value::Array(vec![toml::Value::String(format!(
                "udp://127.0.0.1:{}",
                allowed.port()
            ))]),
        );
    });
    let mut overrides = toml::Table::new();
    overrides.insert(
        "targets".into(),
        toml::Value::String(format!("{allowed},{denied}")),
    );
    let mut instance = host
        .load_with(
            dir.path(),
            LoadOptions::new()
                .instance_id("discovery")
                .config(toml::Value::Table(overrides)),
        )
        .await
        .unwrap();
    instance.init().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        instance.tick().await.unwrap();
        if matches!(
            instance.storage().get("replies").unwrap(),
            Some(Value::IntVal(1))
        ) {
            break;
        }
        assert!(Instant::now() < deadline, "no reply drained");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let replies: Vec<String> = instance
        .events()
        .unwrap()
        .into_iter()
        .filter(|e| e.topic == "network-discovery.reply")
        .filter_map(|e| match e.payload {
            oxidhome_test_host::wit::events::EventPayload::Custom(c) => Some(c.payload),
            _ => None,
        })
        .collect();
    assert_eq!(replies, vec![format!("{allowed} pong")]);
    wait_for_deny(&host, "send", "discovery", &denied.to_string()).await;
}

// ── HTTPS (Phase 8.2) ────────────────────────────────────────────

/// A certificate (DER chain head) and its key, made by `rcgen`.
struct Cert {
    der: Vec<u8>,
    key: Vec<u8>,
}

/// A CA and a leaf it signed for `127.0.0.1`.
fn ca_and_leaf() -> (Vec<u8>, Cert) {
    let (ca, issuer) = test_ca();
    (ca, leaf(&issuer, "127.0.0.1"))
}

/// A CA certificate (DER) and the issuer that signs with it.
fn test_ca() -> (Vec<u8>, rcgen::Issuer<'static, rcgen::KeyPair>) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "OxidHome test CA");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    (ca.der().to_vec(), rcgen::Issuer::new(ca_params, ca_key))
}

/// A leaf for `name` signed by `issuer`.
fn leaf(issuer: &rcgen::Issuer<'static, rcgen::KeyPair>, name: &str) -> Cert {
    let key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
        .expect("leaf params")
        .signed_by(&key, issuer)
        .expect("leaf cert");
    Cert {
        der: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

/// A self-signed certificate for `names`.
fn self_signed(names: &[&str]) -> Cert {
    let key = rcgen::KeyPair::generate().expect("key");
    let cert =
        rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
            .expect("params")
            .self_signed(&key)
            .expect("cert");
    Cert {
        der: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

/// A self-signed certificate for `name` that expired a year ago.
fn expired_self_signed(name: &str) -> Cert {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let cert = params.self_signed(&key).expect("cert");
    Cert {
        der: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

/// The certificate a [`TlsServer`] presents; swappable.
#[derive(Debug)]
struct CurrentCert(std::sync::Mutex<Arc<rustls::sign::CertifiedKey>>);

impl rustls::server::ResolvesServerCert for CurrentCert {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0.lock().unwrap()))
    }
}

fn certified(cert: &Cert) -> Arc<rustls::sign::CertifiedKey> {
    let provider = rustls::crypto::ring::default_provider();
    let key = provider
        .key_provider
        .load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.key.clone().into(),
        ))
        .expect("signing key");
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(cert.der.clone())],
        key,
    ))
}

/// An HTTPS server on loopback answering `respond(path)`, counting the
/// handshakes that completed.
struct TlsServer {
    addr: SocketAddr,
    cert: Arc<CurrentCert>,
    served: Arc<AtomicUsize>,
}

impl TlsServer {
    fn start(cert: &Cert, respond: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls server");
        let addr = listener.local_addr().expect("local addr");
        let current = Arc::new(CurrentCert(std::sync::Mutex::new(certified(cert))));
        let config =
            Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_cert_resolver(
                    Arc::clone(&current) as Arc<dyn rustls::server::ResolvesServerCert>
                ),
            );
        let served = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&served);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut reader = BufReader::new(&mut tls);
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() || first.is_empty() {
                    continue;
                }
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                drop(reader);
                count.fetch_add(1, Ordering::SeqCst);
                let path = first.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let _ = tls.write_all(respond(&path).as_bytes());
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        Self {
            addr,
            cert: current,
            served,
        }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    fn swap(&self, cert: &Cert) {
        *self.cert.0.lock().unwrap() = certified(cert);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn https_reaches_servers_the_roots_vouch_for() {
    let (ca, issuer) = test_ca();
    let host = TestHost::new().unwrap().with_tls_for_tests(vec![ca]);
    let server = TlsServer::start(&leaf(&issuer, "127.0.0.1"), |_| http_ok("secure"));
    // Signed by the trusted CA, for another name: only the name check
    // fails, and that is refused even where trust on first use applies.
    let wrong_name = TlsServer::start(&leaf(&issuer, "camera.example"), |_| http_ok("no"));
    // Self-signed but expired: refused, not pinned (a missing issuer
    // must be the certificate's only fault).
    let expired = TlsServer::start(&expired_self_signed("127.0.0.1"), |_| http_ok("no"));
    let results = probe(
        &host,
        "https",
        &[
            format!("https://127.0.0.1:{}", server.port()),
            format!("https://127.0.0.1:{}", wrong_name.port()),
            format!("https://127.0.0.1:{}", expired.port()),
        ],
        &[
            format!("get https://127.0.0.1:{}/ok", server.port()),
            format!("get https://127.0.0.1:{}/ok", wrong_name.port()),
            format!("get https://127.0.0.1:{}/ok", expired.port()),
        ],
    )
    .await;
    assert_eq!(results[0], "ok:200:secure");
    for refused in &results[1..] {
        assert_eq!(refused, "err:Http(ErrorCode::TlsCertificateError)");
    }
    assert_eq!(server.served(), 1);
    assert_eq!(wrong_name.served(), 0);
    assert_eq!(expired.served(), 0);
    assert_eq!(
        host.engine()
            .tls_pins()
            .list(&oxidhome_core::state::PinFilter::default()),
        Vec::new()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn https_by_name_checks_the_certificate_against_that_name() {
    // The name resolves to loopback, which only an IP rule reaches; the
    // name rule lets the host look it up. SNI and the certificate check
    // use the name the request used.
    let (ca, issuer) = test_ca();
    let host = TestHost::new()
        .unwrap()
        .with_tls_for_tests(vec![ca])
        .with_dns_overrides([
            ("camera.example", vec![ip("127.0.0.1")]),
            ("doorbell.example", vec![ip("127.0.0.1")]),
        ]);
    let server = TlsServer::start(&leaf(&issuer, "camera.example"), |_| http_ok("secure"));
    let port = server.port();
    let results = probe(
        &host,
        "by-name",
        &[
            format!("https://camera.example:{port}"),
            format!("https://doorbell.example:{port}"),
            format!("https://127.0.0.1:{port}"),
        ],
        &[
            format!("get https://camera.example:{port}/ok"),
            format!("get https://doorbell.example:{port}/ok"),
        ],
    )
    .await;
    assert_eq!(
        results,
        vec![
            "ok:200:secure".to_owned(),
            "err:Http(ErrorCode::TlsCertificateError)".to_owned()
        ]
    );
    assert_eq!(server.served(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ip_literal_request_pins_a_certificate_for_another_name() {
    // A device reached by IP whose self-signed certificate names
    // something else: only the name goes unchecked, and the pin binds
    // the leaf to that address and port.
    let host = TestHost::new().unwrap().with_tls_for_tests(Vec::new());
    let cert = self_signed(&["camera.lan"]);
    let server = TlsServer::start(&cert, |_| http_ok("frame"));
    let rule = format!("https://127.0.0.1:{}", server.port());
    let get = format!("get https://127.0.0.1:{}/snap", server.port());
    let results = probe(
        &host,
        "cam",
        std::slice::from_ref(&rule),
        &[get.clone(), get],
    )
    .await;
    assert_eq!(
        results,
        vec!["ok:200:frame".to_owned(), "ok:200:frame".to_owned()]
    );
    let pins = host
        .engine()
        .tls_pins()
        .list(&oxidhome_core::state::PinFilter::default());
    assert_eq!(pins.len(), 1, "{pins:?}");
    assert_eq!(pins[0].key.host, "127.0.0.1");
    assert_eq!(pins[0].key.port, server.port());
    assert_eq!(
        pins[0].fingerprint.to_hex(),
        oxidhome_core::state::Fingerprint::of_der(&cert.der).to_hex()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lan_certificates_are_pinned_on_first_use() {
    // Loopback is trusted on first use like a LAN address.
    let host = TestHost::new().unwrap().with_tls_for_tests(Vec::new());
    let first = self_signed(&["127.0.0.1"]);
    let server = TlsServer::start(&first, |_| http_ok("frame"));
    let rule = format!("https://127.0.0.1:{}", server.port());
    let get = format!("get https://127.0.0.1:{}/snap", server.port());
    let results = probe(
        &host,
        "cam",
        std::slice::from_ref(&rule),
        &[get.clone(), get.clone()],
    )
    .await;
    assert_eq!(
        results,
        vec!["ok:200:frame".to_owned(), "ok:200:frame".to_owned()]
    );
    let pins = host
        .engine()
        .tls_pins()
        .list(&oxidhome_core::state::PinFilter::default());
    assert_eq!(pins.len(), 1, "{pins:?}");
    assert_eq!(pins[0].key.instance_id, "cam");
    assert_eq!(pins[0].key.host, "127.0.0.1");
    assert_eq!(pins[0].key.port, server.port());

    // Another certificate at the same place is refused, before any
    // request bytes are sent, and audited.
    server.swap(&self_signed(&["127.0.0.1"]));
    let results = probe(
        &host,
        "cam",
        std::slice::from_ref(&rule),
        std::slice::from_ref(&get),
    )
    .await;
    assert_eq!(
        results,
        vec!["err:Http(ErrorCode::TlsCertificateError)".to_owned()]
    );
    assert_eq!(server.served(), 2);
    let row = wait_for_deny(&host, "tls", "cam", &format!("127.0.0.1:{}", server.port())).await;
    assert!(
        row.domain_error.is_some_and(|e| e.contains("pinned")),
        "domain_error"
    );

    // The operator resets the pin; the next request pins the new one.
    let removed = host
        .engine()
        .tls_pins()
        .reset(&oxidhome_core::state::PinFilter {
            instance_id: Some("cam".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(removed.len(), 1);
    let results = probe(&host, "cam", &[rule], &[get]).await;
    assert_eq!(results, vec!["ok:200:frame".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sdk_client_follows_redirects_without_downgrading() {
    let (ca, leaf) = ca_and_leaf();
    let host = TestHost::new().unwrap().with_tls_for_tests(vec![ca]);
    let plain = TcpServer::http(|_| http_ok("plain"));
    let plain_url = format!("http://127.0.0.1:{}/x", plain.port());
    let secure = TlsServer::start(&leaf, move |path| match path {
        "/down" => http_redirect(&plain_url),
        "/hop" => http_redirect("/ok"),
        _ => http_ok("secure"),
    });
    let hop = TcpServer::http(|path| match path {
        "/loop" => http_redirect("/loop"),
        _ => http_ok("hopped"),
    });
    let results = probe(
        &host,
        "redirects",
        &[
            format!("https://127.0.0.1:{}", secure.port()),
            format!("tcp://127.0.0.1:{}", plain.port()),
            format!("tcp://127.0.0.1:{}", hop.port()),
        ],
        &[
            format!("get https://127.0.0.1:{}/hop", secure.port()),
            format!("get https://127.0.0.1:{}/down", secure.port()),
            format!("get http://127.0.0.1:{}/loop", hop.port()),
        ],
    )
    .await;
    assert_eq!(results[0], "ok:200:secure");
    assert!(
        results[1].starts_with("err:InsecureRedirect"),
        "{results:?}"
    );
    assert_eq!(results[2], "err:TooManyRedirects { limit: 5 }");
    assert_eq!(plain.accepted(), 0, "https must not be downgraded");
    assert_eq!(hop.accepted(), 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pin_holds_against_a_root_vouched_replacement() {
    let (ca, issuer) = test_ca();
    let host = TestHost::new().unwrap().with_tls_for_tests(vec![ca]);
    let server = TlsServer::start(&leaf(&issuer, "127.0.0.1"), |_| http_ok("secure"));
    let key = oxidhome_core::state::PinKey {
        instance_id: "held".into(),
        host: "127.0.0.1".into(),
        port: server.port(),
    };
    host.engine()
        .tls_pins()
        .check_or_pin(
            &key,
            // A dev load's installation is its plugin id.
            "example.net-probe",
            oxidhome_core::state::Fingerprint::of_der(b"the device's old certificate"),
        )
        .unwrap();
    let results = probe(
        &host,
        "held",
        &[format!("https://127.0.0.1:{}", server.port())],
        &[format!("get https://127.0.0.1:{}/", server.port())],
    )
    .await;
    assert_eq!(results, ["err:Http(ErrorCode::TlsCertificateError)"]);
    assert_eq!(server.served(), 0);
    wait_for_deny(
        &host,
        "tls",
        "held",
        &format!("127.0.0.1:{}", server.port()),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_untrusted_certificate_is_audited_as_a_pin_mismatch() {
    // A certificate for another name fails verification whatever the
    // pin says, but against a pin that is the event the operator needs
    // to see.
    let (ca, issuer) = test_ca();
    let host = TestHost::new().unwrap().with_tls_for_tests(vec![ca]);
    let server = TlsServer::start(&leaf(&issuer, "camera.example"), |_| http_ok("no"));
    host.engine()
        .tls_pins()
        .check_or_pin(
            &oxidhome_core::state::PinKey {
                instance_id: "moved".into(),
                host: "127.0.0.1".into(),
                port: server.port(),
            },
            // A dev load's installation is its plugin id.
            "example.net-probe",
            oxidhome_core::state::Fingerprint::of_der(b"the device's old certificate"),
        )
        .unwrap();
    let results = probe(
        &host,
        "moved",
        &[format!("https://127.0.0.1:{}", server.port())],
        &[format!("get https://127.0.0.1:{}/", server.port())],
    )
    .await;
    assert_eq!(results, ["err:Http(ErrorCode::TlsCertificateError)"]);
    let row = wait_for_deny(
        &host,
        "tls",
        "moved",
        &format!("127.0.0.1:{}", server.port()),
    )
    .await;
    assert!(
        row.domain_error.is_some_and(|e| e.contains("pinned")),
        "domain_error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_refused_mid_way_returns_the_refusal() {
    // The server answers `413` after the request head and never reads the
    // body: the SDK must stop uploading and return the answer, not block.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    // When the refusal went out: the bound is measured from there, not
    // from staging the plugin (which may build it).
    let refused_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let refused = Arc::clone(&refused_at);
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
            line.clear();
        }
        let _ =
            stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 4\r\n\r\nbig!");
        *refused.lock().unwrap() = Some(Instant::now());
        // Hold the connection open, reading nothing.
        std::thread::sleep(Duration::from_secs(20));
        drop(stream);
    });
    let host = TestHost::new().unwrap();
    let results = probe(
        &host,
        "uploader",
        &[format!("tcp://127.0.0.1:{port}")],
        &[format!("post 16777216 http://127.0.0.1:{port}/upload")],
    )
    .await;
    assert_eq!(results, ["ok:413:big!"]);
    let since = refused_at.lock().unwrap().expect("refused").elapsed();
    assert!(since < Duration::from_secs(10), "{since:?}");
}
