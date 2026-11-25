//! `net-probe` — a `streaming-plugin` world test fixture.
//!
//! `init` runs the operations listed in the `ops` config field and stores
//! each result in plugin storage (`op/<index>` = `ok:<detail>` or
//! `err:<detail>`), so a host test can assert what the network policy let
//! through. See `manifest.toml` for the operation syntax.
//!
//! The `hold-*` operations keep their socket open. Each `tick` counts
//! itself (`ticks`) and drains the held sockets without blocking: the
//! number of messages read so far goes to `received` and the last one to
//! `last`, so a host test can see when, and how often, the host woke the
//! plugin for a reply.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use oxidhome_sdk::bindings::oxidhome::plugin::types::Value;
use oxidhome_sdk::host::{config, storage};
use oxidhome_sdk::streaming::discovery::{self, DiscoverySocket};
use oxidhome_sdk::streaming::wasi::http::outgoing_handler;
use oxidhome_sdk::streaming::wasi::http::types::{
    Fields, IncomingBody, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
};
use oxidhome_sdk::streaming::wasi::io::streams::StreamError;
use oxidhome_sdk::{Plugin, StreamingPlugin};

/// How long `udp` waits for a reply.
const UDP_WAIT: Duration = Duration::from_secs(2);
/// How long `httppoll` keeps calling `get`.
const POLL_WAIT: Duration = Duration::from_secs(5);
/// Most reads from one held socket per tick, so a busy peer can't keep a
/// tick running.
const MAX_READS_PER_TICK: usize = 256;
/// Most redirects `http` follows.
const MAX_REDIRECTS: usize = 3;

#[derive(Default)]
struct NetProbe {
    /// Sockets the `hold-*` operations keep open.
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpStream>,
    discovery: Vec<DiscoverySocket>,
    ticks: i64,
    received: i64,
}

impl Plugin for NetProbe {
    fn init(&mut self) -> Result<(), String> {
        let ops = match config::get("ops") {
            Ok(Some(Value::StringVal(ops))) => ops,
            _ => String::new(),
        };
        for (index, op) in ops
            .split(';')
            .map(str::trim)
            .filter(|op| !op.is_empty())
            .enumerate()
        {
            let result = match op.split_once(' ') {
                Some(("hold-udp", target)) => hold_udp(target).map(|s| {
                    self.udp.push(s);
                    "held".to_owned()
                }),
                Some(("hold-tcp", target)) => hold_tcp(target).map(|s| {
                    self.tcp.push(s);
                    "held".to_owned()
                }),
                Some(("hold-disc", target)) => hold_disc(target).map(|s| {
                    self.discovery.push(s);
                    "held".to_owned()
                }),
                _ => run(op),
            };
            let result = match result {
                Ok(detail) => format!("ok:{detail}"),
                Err(detail) => format!("err:{detail}"),
            };
            storage::set(&format!("op/{index}"), &Value::StringVal(result))
                .map_err(|e| format!("storing result {index}: {e:?}"))?;
        }
        Ok(())
    }

    fn shutdown(&mut self) {}

    fn tick(&mut self) {
        self.ticks += 1;
        set_int("ticks", self.ticks);
        let mut last = None;
        let mut buf = [0u8; 512];
        for socket in &self.udp {
            for _ in 0..MAX_READS_PER_TICK {
                let Ok((n, _)) = socket.recv_from(&mut buf) else {
                    break;
                };
                last = Some(String::from_utf8_lossy(&buf[..n]).into_owned());
                self.received += 1;
            }
        }
        for socket in &self.discovery {
            for datagram in socket.recv(discovery::MAX_RECV).unwrap_or_default() {
                last = Some(String::from_utf8_lossy(&datagram.data).into_owned());
                self.received += 1;
            }
        }
        // A stream at its end is dropped: the host keeps waking a
        // plugin whose socket stays readable.
        self.tcp.retain_mut(|stream| {
            for _ in 0..MAX_READS_PER_TICK {
                match stream.read(&mut buf) {
                    Ok(0) => return false,
                    Ok(n) => {
                        last = Some(String::from_utf8_lossy(&buf[..n]).trim_end().to_owned());
                        self.received += 1;
                    }
                    Err(e) => return e.kind() == ErrorKind::WouldBlock,
                }
            }
            true
        });
        // `received` last: a test that sees it can read `last`.
        if let Some(last) = last {
            let _ = storage::set("last", &Value::StringVal(last));
            set_int("received", self.received);
        }
    }
}

fn set_int(key: &str, value: i64) {
    let _ = storage::set(key, &Value::IntVal(value));
}

/// Send `ping` to `target` from a non-blocking UDP socket and keep it.
fn hold_udp(target: &str) -> Result<UdpSocket, String> {
    let addr = target
        .to_socket_addrs()
        .map_err(io_err)?
        .next()
        .ok_or("no address")?;
    let socket = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(io_err)?;
    socket.set_nonblocking(true).map_err(io_err)?;
    socket.send_to(b"ping", addr).map_err(io_err)?;
    Ok(socket)
}

/// A discovery socket of `target`'s family on an ephemeral port.
fn disc_socket(target: SocketAddr) -> Result<DiscoverySocket, String> {
    if target.is_ipv4() {
        DiscoverySocket::bind_v4(0)
    } else {
        DiscoverySocket::bind_v6(0)
    }
    .map_err(io_err)
}

fn parse_addr(target: &str) -> Result<SocketAddr, String> {
    target
        .parse()
        .map_err(|_| format!("bad address `{target}`"))
}

/// Send `ping` to `target` from a discovery socket and keep it.
fn hold_disc(target: &str) -> Result<DiscoverySocket, String> {
    let target = parse_addr(target)?;
    let socket = disc_socket(target)?;
    socket.send_to(b"ping", target).map_err(io_err)?;
    Ok(socket)
}

/// Send `ping` to `target` from a discovery socket and wait 2 s for a
/// reply: `<reply>@<from>`.
fn disc(target: &str) -> Result<String, String> {
    let target = parse_addr(target)?;
    let socket = disc_socket(target)?;
    socket.send_to(b"ping", target).map_err(io_err)?;
    let deadline = Instant::now() + UDP_WAIT;
    loop {
        if let Some(d) = socket.recv(1).map_err(io_err)?.pop() {
            return Ok(format!("{}@{}", String::from_utf8_lossy(&d.data), d.from));
        }
        if Instant::now() > deadline {
            return Err("no reply".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Connect to `target`, send `ping\n`, and keep the non-blocking stream.
fn hold_tcp(target: &str) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(target).map_err(io_err)?;
    stream.write_all(b"ping\n").map_err(io_err)?;
    stream.set_nonblocking(true).map_err(io_err)?;
    Ok(stream)
}

impl StreamingPlugin for NetProbe {}

oxidhome_sdk::streaming_plugin!(NetProbe);

fn run(op: &str) -> Result<String, String> {
    let (verb, arg) = op.split_once(' ').ok_or_else(|| format!("bad op `{op}`"))?;
    match verb {
        "tcp" => tcp(arg),
        "udp" => udp(arg),
        "dns" => dns(arg),
        "http" => http(arg),
        "get" => oxidhome_sdk::streaming::http::Request::get(arg)
            .timeout(Duration::from_secs(5))
            .send()
            .map(|r| format!("{}:{}", r.status(), String::from_utf8_lossy(r.body())))
            .map_err(|e| format!("{e:?}")),
        // `post <bytes> <url>`: upload that many bytes.
        "post" => {
            let (len, url) = arg.split_once(' ').ok_or("post <bytes> <url>")?;
            let len: usize = len.parse().map_err(|_| "bad length")?;
            oxidhome_sdk::streaming::http::Request::post(url)
                .body(vec![b'x'; len])
                .timeout(Duration::from_secs(5))
                .send()
                .map(|r| format!("{}:{}", r.status(), String::from_utf8_lossy(r.body())))
                .map_err(|e| format!("{e:?}"))
        }
        "hdr" => header(arg),
        "httppoll" => http_get(arg, false)
            .map(|(status, _, body)| format!("{status}:{}", String::from_utf8_lossy(&body))),
        "bind" => UdpSocket::bind(arg).map(|_| "bound".into()).map_err(io_err),
        "disc" => disc(arg),
        "disc-send" => {
            let target = parse_addr(arg)?;
            let socket = disc_socket(target)?;
            socket
                .send_to(b"ping", target)
                .map(|()| "sent".into())
                .map_err(io_err)
        }
        "disc-bind" => {
            let port: u16 = arg.parse().map_err(|_| format!("bad port `{arg}`"))?;
            DiscoverySocket::bind_v4(port)
                .map(|_| "bound".into())
                .map_err(io_err)
        }
        "disc-join" => {
            let group: std::net::IpAddr = arg.parse().map_err(|_| format!("bad group `{arg}`"))?;
            let socket = if group.is_ipv4() {
                DiscoverySocket::bind_v4(0)
            } else {
                DiscoverySocket::bind_v6(0)
            }
            .map_err(io_err)?;
            socket
                .join_multicast(group)
                .map(|()| "joined".into())
                .map_err(io_err)
        }
        // `nets -`: the local networks, comma-separated.
        "nets" => Ok(discovery::local_networks()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")),
        "listen" => TcpListener::bind(arg)
            .map(|_| "listening".into())
            .map_err(io_err),
        other => Err(format!("unknown op `{other}`")),
    }
}

fn io_err(err: std::io::Error) -> String {
    format!("{:?}", err.kind())
}

fn tcp(target: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(target).map_err(io_err)?;
    stream.write_all(b"ping\n").map_err(io_err)?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(io_err)?;
    Ok(line.trim_end().to_owned())
}

fn udp(target: &str) -> Result<String, String> {
    let addr = target
        .to_socket_addrs()
        .map_err(io_err)?
        .next()
        .ok_or("no address")?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).map_err(io_err)?;
    socket.send_to(b"ping", addr).map_err(io_err)?;
    socket.set_nonblocking(true).map_err(io_err)?;
    let deadline = Instant::now() + UDP_WAIT;
    let mut buf = [0u8; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                return Ok(format!("{}@{from}", String::from_utf8_lossy(&buf[..n])));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(io_err(e)),
        }
    }
}

fn dns(host: &str) -> Result<String, String> {
    let addrs: Vec<String> = (host, 0)
        .to_socket_addrs()
        .map_err(io_err)?
        .map(|a| a.ip().to_string())
        .collect();
    Ok(addrs.join(","))
}

/// Append a header whose name is `len` bytes to a fresh field map.
fn header(len: &str) -> Result<String, String> {
    let len: usize = len.parse().map_err(|_| format!("bad length `{len}`"))?;
    Fields::new()
        .append(&"x".repeat(len), b"v")
        .map(|()| "appended".into())
        .map_err(|e| format!("{e:?}"))
}

/// GET `url`, following redirects; returns `<status>:<body>`.
fn http(url: &str) -> Result<String, String> {
    let mut url = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let (status, location, body) = http_get(&url, true)?;
        match (status, location) {
            (300..=399, Some(location)) => url = location,
            _ => return Ok(format!("{status}:{}", String::from_utf8_lossy(&body))),
        }
    }
    Err("too many redirects".into())
}

/// GET `url` once. With `block`, wait on the response's pollable;
/// without, call `get` until it answers (as a plugin polling from `tick`
/// would).
fn http_get(url: &str, block: bool) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let (scheme, rest) = url.split_once("://").ok_or("no scheme")?;
    // No `/` after the authority: leave the path unset (`none`).
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let scheme = match scheme {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => return Err(format!("scheme {other}")),
    };
    let request = OutgoingRequest::new(Fields::new());
    request.set_method(&Method::Get).map_err(|()| "method")?;
    request.set_scheme(Some(&scheme)).map_err(|()| "scheme")?;
    request
        .set_authority(Some(authority))
        .map_err(|()| "authority")?;
    if !path.is_empty() {
        request
            .set_path_with_query(Some(path))
            .map_err(|()| "path")?;
    }
    let body = request.body().map_err(|()| "body")?;
    OutgoingBody::finish(body, None).map_err(|e| format!("{e:?}"))?;

    // Always with options, so the host's handling of the owned
    // `request-options` handle is exercised on every request.
    let options = RequestOptions::new();
    options
        .set_connect_timeout(Some(10_000_000_000))
        .map_err(|()| "connect timeout")?;
    let pending = outgoing_handler::handle(request, Some(options)).map_err(|e| format!("{e:?}"))?;
    let ready = if block {
        pending.subscribe().block();
        pending.get()
    } else {
        let deadline = Instant::now() + POLL_WAIT;
        loop {
            if let Some(ready) = pending.get() {
                break Some(ready);
            }
            if Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let response = ready
        .ok_or("response not ready")?
        .map_err(|()| "response taken")?
        .map_err(|e| format!("{e:?}"))?;

    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned());
    let incoming = response.consume().map_err(|()| "consume")?;
    let stream = incoming.stream().map_err(|()| "stream")?;
    let mut body = Vec::new();
    loop {
        match stream.blocking_read(4096) {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => return Err(format!("{e:?}")),
        }
    }
    drop(stream);
    let trailers = IncomingBody::finish(incoming);
    if !block {
        // Polled like the response: `get` until it answers.
        let deadline = Instant::now() + POLL_WAIT;
        loop {
            match trailers.get() {
                Some(Ok(Ok(_))) => break,
                Some(other) => return Err(format!("trailers: {other:?}")),
                None if Instant::now() > deadline => return Err("trailers not ready".into()),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
    Ok((status, location, body))
}
