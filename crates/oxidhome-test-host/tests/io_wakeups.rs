//! Phase 8: a streaming instance is ticked early when a socket it holds
//! open becomes readable.
//!
//! `examples/net-probe`'s `hold-udp` / `hold-tcp` operations send `ping`
//! on `init` and keep the socket; each `tick` counts itself (`ticks`)
//! and drains the socket (`received`, `last`). The tests run it under the
//! production supervisor on a virtual clock whose tick cadence is an
//! hour, so any tick before the clock moves is a readiness wakeup.

#[path = "support.rs"]
mod support;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use oxidhome_test_host::wit::types::Value;
use oxidhome_test_host::{InstanceState, LoadOptions, StorageView, SupervisedInstance, TestHost};
use support::{KV_COUNTER, NET_PROBE, NETWORK_DISCOVERY, stage, stage_unchanged, stage_with};

/// The production tick cadence the tests stage: never reached, since
/// the clock doesn't move that far.
const HOUR_MS: i64 = 3_600_000;
/// The host's minimum gap between a tick and an early one.
const GAP: Duration = Duration::from_millis(100);
/// How long (real time) a test waits for something it expects.
const WAIT: Duration = Duration::from_secs(10);
/// How long (real time) a test waits to see that something doesn't
/// happen.
const QUIET: Duration = Duration::from_millis(300);

/// A UDP peer on loopback: answers the first datagram with `pong` and
/// hands the test the socket and the sender's address.
fn udp_peer() -> (SocketAddr, mpsc::Receiver<(UdpSocket, SocketAddr)>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp peer");
    let addr = socket.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((_, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(b"pong", from);
            let _ = tx.send((socket, from));
        }
    });
    (addr, rx)
}

/// A TCP peer on loopback: answers the first line of one connection
/// with a one-byte `!` (so it arrives in one read) and keeps the connection open while the test holds the
/// returned receiver.
fn tcp_peer() -> (SocketAddr, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp peer");
    let addr = listener.local_addr().expect("local addr");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut line = String::new();
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        if reader.read_line(&mut line).is_ok() {
            let _ = stream.write_all(b"!");
            let _ = stream.flush();
        }
        // Open until the test is done.
        let _ = done_rx.recv();
    });
    (addr, done_tx)
}

/// Stage net-probe with `rule`, the given tick cadence, and run `ops`.
fn probe(rule: &str, tick_interval_ms: Option<i64>) -> support::TempDir {
    let rule = rule.to_owned();
    stage_with(NET_PROBE, move |manifest| {
        let caps = manifest
            .get_mut("capabilities")
            .and_then(toml::Value::as_table_mut)
            .expect("[capabilities]");
        caps.insert(
            "network".into(),
            toml::Value::Array(vec![toml::Value::String(rule)]),
        );
        if let Some(ms) = tick_interval_ms {
            manifest
                .get_mut("runtime")
                .and_then(toml::Value::as_table_mut)
                .expect("[runtime]")
                .insert("tick_interval_ms".into(), toml::Value::Integer(ms));
        }
    })
}

async fn start(host: &TestHost, dir: &support::TempDir, op: &str) -> SupervisedInstance {
    let mut overrides = toml::Table::new();
    overrides.insert("ops".into(), toml::Value::String(op.to_owned()));
    let instance = host
        .start_with(
            dir.path(),
            LoadOptions::new().config(toml::Value::Table(overrides)),
        )
        .await
        .expect("start net-probe");
    instance.wait_for_running().await.expect("running");
    assert_eq!(string(&instance.storage(), "op/0"), "ok:held");
    instance
}

fn int(storage: &StorageView, key: &str) -> i64 {
    match storage.get(key).expect("storage") {
        None => 0,
        Some(Value::IntVal(n)) => n,
        other => panic!("{key}: {other:?}"),
    }
}

fn string(storage: &StorageView, key: &str) -> String {
    match storage.get(key).expect("storage") {
        Some(Value::StringVal(s)) => s,
        other => panic!("{key}: {other:?}"),
    }
}

/// Wait (real time, bounded) until `key` reaches `at_least`.
async fn wait_for(storage: &StorageView, key: &str, at_least: i64) {
    let deadline = Instant::now() + WAIT;
    while int(storage, key) < at_least {
        assert!(
            Instant::now() < deadline,
            "{key} stayed at {} (< {at_least})",
            int(storage, key)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait (real time, bounded) until the rate gate after the first tick
/// is registered, i.e. that tick returned at virtual time zero.
async fn wait_for_gate(host: &TestHost) {
    let clock = host.virtual_clock().unwrap();
    let deadline = Instant::now() + WAIT;
    while clock.next_deadline() != Some(GAP) {
        assert!(Instant::now() < deadline, "no rate gate: {clock:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udp_reply_wakes_the_plugin_before_its_tick() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, _socket) = udp_peer();
    let dir = probe(&format!("udp://{peer}"), Some(HOUR_MS));
    let instance = start(&host, &dir, &format!("hold-udp {peer}")).await;
    let storage = instance.storage();

    wait_for(&storage, "received", 1).await;
    assert_eq!(string(&storage, "last"), "pong");
    assert_eq!(int(&storage, "ticks"), 1);
    assert_eq!(host.virtual_clock().unwrap().elapsed(), Duration::ZERO);
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_reply_wakes_the_plugin_before_its_tick() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, done) = tcp_peer();
    let dir = probe(&format!("tcp://{peer}"), Some(HOUR_MS));
    let instance = start(&host, &dir, &format!("hold-tcp {peer}")).await;
    let storage = instance.storage();

    wait_for(&storage, "received", 1).await;
    assert_eq!(string(&storage, "last"), "!");
    assert_eq!(int(&storage, "ticks"), 1);
    wait_for_gate(&host).await;
    // Drained and still open: nothing more to wake it for.
    host.advance(GAP * 5).await.unwrap();
    assert_eq!(int(&storage, "ticks"), 1);
    instance.stop().await.unwrap();
    drop(done);
}

/// Datagrams that arrive while the plugin waits out the gap after a
/// tick wake it once, when the gap ends, and it reads them all then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_is_coalesced_into_one_rate_bounded_wakeup() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, socket) = udp_peer();
    let dir = probe(&format!("udp://{peer}"), Some(HOUR_MS));
    let instance = start(&host, &dir, &format!("hold-udp {peer}")).await;
    let storage = instance.storage();
    wait_for(&storage, "ticks", 1).await;
    wait_for(&storage, "received", 1).await;

    let (socket, plugin) = socket.recv_timeout(WAIT).expect("peer saw the probe");
    for i in 0..20 {
        socket
            .send_to(format!("flood {i}").as_bytes(), plugin)
            .unwrap();
    }
    // The clock stands still, so the gap after the first tick never
    // ends: no wakeup, however long the datagrams wait.
    tokio::time::sleep(QUIET).await;
    assert_eq!(int(&storage, "ticks"), 1);

    wait_for_gate(&host).await;
    // Not a moment before the gap ends.
    host.advance(Duration::from_millis(99)).await.unwrap();
    assert_eq!(int(&storage, "ticks"), 1);
    // The gap ends: one tick reads the whole flood. Usually within the
    // advance; if the host hadn't seen the socket readable yet when the
    // gap ended, as soon as it does.
    host.advance(Duration::from_millis(1)).await.unwrap();
    wait_for(&storage, "received", 21).await;
    assert_eq!(int(&storage, "ticks"), 2);
    assert_eq!(int(&storage, "received"), 21);
    assert_eq!(string(&storage, "last"), "flood 19");

    // Drained: no more wakeups.
    host.advance(GAP * 5).await.unwrap();
    assert_eq!(int(&storage, "ticks"), 2);
    instance.stop().await.unwrap();
}

/// A stop requested while a reply waits out the gap ends the instance
/// without another tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_wakeup_after_stop() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, socket) = udp_peer();
    let dir = probe(&format!("udp://{peer}"), Some(HOUR_MS));
    let instance = start(&host, &dir, &format!("hold-udp {peer}")).await;
    let storage = instance.storage();
    wait_for(&storage, "received", 1).await;

    let (socket, plugin) = socket.recv_timeout(WAIT).expect("peer saw the probe");
    socket.send_to(b"late", plugin).unwrap();
    tokio::time::sleep(QUIET).await;
    assert_eq!(instance.stop().await.unwrap(), InstanceState::Stopped);
    host.advance(GAP * 5).await.unwrap();
    assert_eq!(int(&storage, "ticks"), 1);
    assert_eq!(int(&storage, "received"), 1);
}

/// Without a tick cadence a streaming plugin is never ticked, early or
/// not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_wakeup_without_a_tick_cadence() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, socket) = udp_peer();
    let dir = probe(&format!("udp://{peer}"), None);
    let instance = start(&host, &dir, &format!("hold-udp {peer}")).await;
    let storage = instance.storage();
    socket.recv_timeout(WAIT).expect("peer saw the probe");
    tokio::time::sleep(QUIET).await;
    host.advance(GAP * 5).await.unwrap();
    assert_eq!(int(&storage, "ticks"), 0);
    instance.stop().await.unwrap();
}

/// A `plugin`-world instance keeps its plain tick schedule: no early
/// tick and no rate-gate timer next to its tick interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_world_ticks_only_on_its_cadence() {
    let host = TestHost::with_virtual_clock().unwrap();
    let clock = host.virtual_clock().unwrap().clone();
    let dir = stage_unchanged(KV_COUNTER);
    let instance = host.start(dir.path()).await.unwrap();
    instance.wait_for_running().await.unwrap();
    let storage = instance.storage();
    // kv-counter ticks every second and stores its count under `count`.
    host.advance(Duration::from_millis(999)).await.unwrap();
    assert_eq!(int(&storage, "count"), 0);
    host.advance(Duration::from_millis(1)).await.unwrap();
    assert_eq!(int(&storage, "count"), 1);
    assert_eq!(clock.pending_timers(), 1, "{clock:?}");
    instance.stop().await.unwrap();
}

/// The `network-discovery` example publishes a reply as soon as it
/// arrives, not at its one-minute cadence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_discovery_publishes_a_reply_without_waiting_for_its_tick() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, _socket) = udp_peer();
    let dir = stage(NETWORK_DISCOVERY, |caps| {
        caps.insert(
            "network".into(),
            toml::Value::Array(vec![toml::Value::String(format!("udp://{peer}"))]),
        );
    });
    let mut overrides = toml::Table::new();
    overrides.insert("targets".into(), toml::Value::String(peer.to_string()));
    let instance = host
        .start_with(
            dir.path(),
            LoadOptions::new().config(toml::Value::Table(overrides)),
        )
        .await
        .unwrap();
    instance.wait_for_running().await.unwrap();
    wait_for(&instance.storage(), "replies", 1).await;
    assert_eq!(host.virtual_clock().unwrap().elapsed(), Duration::ZERO);
    instance.stop().await.unwrap();
}

/// A discovery socket wakes the plugin for a datagram the rules allow,
/// and never for one from a sender they refuse: the host discards it
/// while it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_socket_wakes_only_for_allowed_senders() {
    let host = TestHost::with_virtual_clock().unwrap();
    let (peer, socket) = udp_peer();
    let dir = probe(&format!("udp://{peer}"), Some(HOUR_MS));
    let instance = start(&host, &dir, &format!("hold-disc {peer}")).await;
    let storage = instance.storage();
    wait_for(&storage, "received", 1).await;
    assert_eq!(string(&storage, "last"), "pong");
    assert_eq!(int(&storage, "ticks"), 1);
    assert_eq!(host.virtual_clock().unwrap().elapsed(), Duration::ZERO);
    wait_for_gate(&host).await;

    let (socket, plugin) = socket.recv_timeout(WAIT).expect("peer saw the probe");
    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..20 {
        stranger.send_to(b"refused", plugin).unwrap();
    }
    tokio::time::sleep(QUIET).await;
    host.advance(GAP * 5).await.unwrap();
    tokio::time::sleep(QUIET).await;
    assert_eq!(int(&storage, "ticks"), 1);

    socket.send_to(b"allowed", plugin).unwrap();
    wait_for(&storage, "received", 2).await;
    assert_eq!(string(&storage, "last"), "allowed");
    assert_eq!(int(&storage, "ticks"), 2);
    instance.stop().await.unwrap();
}
