//! H4: cursor resume on the live event streams (JSON WebSocket tail
//! and Connect `TailEvents`). The handoff race itself is covered by
//! `state::event_tail` unit tests; these check the wire protocol.

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use futures_util::StreamExt as _;
use http_body_util::BodyExt as _;
use oxidhome_core::Engine;
use oxidhome_core::api::{ApiConfig, bind, build_router, serve};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::{
    CustomEvent, Event, EventPayload,
};
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::{self, Message};
use tower::ServiceExt as _;

fn event(n: u64) -> Event {
    Event {
        device: None,
        timestamp: n,
        origin_plugin_id: "com.example.resume".into(),
        origin_instance_id: "resume-a".into(),
        row_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: "resume.test".into(),
            payload: n.to_string(),
        }),
    }
}

/// Record + fan out under the publish gate, the way `publish_event`
/// does. `received_ms = n` so tests can prune by it.
async fn publish_recorded(engine: &Engine, n: u64) -> u64 {
    let bus = engine.events();
    let gate = bus.publish_sequence();
    let _guard = gate.lock().await;
    let id = engine
        .event_log()
        .record(
            i64::try_from(n).expect("fits"),
            &event(n),
            "resume-a",
            "com.example.resume",
        )
        .expect("record");
    bus.publish_with_id(event(n), Some(id));
    id
}

async fn serve_engine(engine: &Engine) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = bind(ApiConfig {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
    })
    .await
    .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let engine = engine.clone();
    let server = tokio::spawn(async move {
        serve(engine, listener).await.expect("serve");
    });
    (addr, server)
}

async fn ws_connect(
    addr: SocketAddr,
    query: &str,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tungstenite::Error,
> {
    let mut request = format!("ws://{addr}/api/v1/events/tail{query}")
        .into_client_request()
        .expect("ws url");
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header"),
    );
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

async fn ws_connect_with_response(
    addr: SocketAddr,
    query: &str,
    token: &str,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::handshake::client::Response,
    ),
    tungstenite::Error,
> {
    let mut request = format!("ws://{addr}/api/v1/events/tail{query}")
        .into_client_request()
        .expect("ws url");
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header"),
    );
    tokio_tungstenite::connect_async(request).await
}

async fn next_json<S>(ws: &mut S) -> Value
where
    S: futures_util::Stream<Item = Result<Message, tungstenite::Error>> + Unpin,
{
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("frame within 5s")
        .expect("stream open")
        .expect("frame ok");
    serde_json::from_str(&msg.into_text().expect("text")).expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_tail_resumes_from_cursor_then_goes_live() {
    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("resume", br#"["events:tail","events:read"]"#)
        .expect("token");
    for n in 1..=3 {
        publish_recorded(&engine, n).await;
    }
    let (addr, server) = serve_engine(&engine).await;
    let (mut ws, resp) = ws_connect_with_response(addr, "?after_id=1", &token.plaintext)
        .await
        .expect("connect");
    assert_eq!(
        resp.headers()
            .get("oxidhome-resume-after-id")
            .map(|v| v.to_str().expect("ascii")),
        Some("1")
    );
    // The subscription exists before the 101, so this live publish
    // can't fall between the replay and live delivery.
    publish_recorded(&engine, 4).await;
    for want in 2..=4 {
        assert_eq!(next_json(&mut ws).await["id"], want);
    }
    let _ = ws.close(None).await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_tail_reports_cursor_expired_and_closes() {
    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("resume", br#"["events:tail","events:read"]"#)
        .expect("token");
    for n in 1..=5 {
        publish_recorded(&engine, n).await;
    }
    engine.event_log().trim_older_than(4).expect("trim");
    let (addr, server) = serve_engine(&engine).await;
    let mut ws = ws_connect(addr, "?after_id=2", &token.plaintext)
        .await
        .expect("connect");
    let frame = next_json(&mut ws).await;
    assert_eq!(
        frame,
        serde_json::json!({
            "cursor_expired": { "after_id": 2, "oldest_id": 4, "head_id": 5 }
        })
    );
    let close = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("close within 5s");
    assert!(
        matches!(close, Some(Ok(Message::Close(_))) | None),
        "expected close, got {close:?}"
    );
    server.abort();
}

/// A cursor replays history, so it needs `events:read` on top of
/// `events:tail`.
#[tokio::test(flavor = "multi_thread")]
async fn ws_tail_cursor_requires_events_read() {
    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("tail-only", br#"["events:tail"]"#)
        .expect("token");
    let (addr, server) = serve_engine(&engine).await;
    match ws_connect(addr, "?after_id=0", &token.plaintext).await {
        Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 403),
        other => panic!("expected 403, got {:?}", other.map(|_| ())),
    }
    // Without a cursor the same token still tails.
    ws_connect(addr, "", &token.plaintext)
        .await
        .expect("live tail");
    server.abort();
}

/// The replay refusal on both tail transports lands in the audit
/// ledger as a deny naming `events:read`, the scope the cursor needs.
#[tokio::test(flavor = "multi_thread")]
async fn tail_cursor_denials_audit_events_read() {
    let engine = Engine::new().expect("engine");
    let token = engine
        .auth_tokens()
        .create("tail-only", br#"["events:tail"]"#)
        .expect("token");
    let (addr, server) = serve_engine(&engine).await;
    assert!(
        ws_connect(addr, "?after_id=0", &token.plaintext)
            .await
            .is_err()
    );
    server.abort();
    let (_, body) = connect_tail(&engine, br#"["events:tail"]"#, br#"{"afterId":"0"}"#).await;
    let _ = connect_messages(body, 1).await;

    for path in [
        "/api/v1/events/tail",
        "/oxidhome.v1.EventsService/TailEvents",
    ] {
        let mut row = None;
        for _ in 0..50 {
            let rows = engine
                .audit_log()
                .query(&oxidhome_core::state::AuditQuery::default(), 64)
                .expect("audit query");
            row = rows.into_iter().find(|r| r.path == path);
            if row.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let row = row.unwrap_or_else(|| panic!("no audit row for {path}"));
        assert_eq!(row.decision, "deny", "{path}: {row:?}");
        assert_eq!(row.required_scope.as_deref(), Some("events:read"), "{path}");
    }
}

fn connect_envelope(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8];
    frame.extend_from_slice(&u32::try_from(payload.len()).expect("fits").to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Read Connect stream messages until `n` data messages (or the
/// end-of-stream frame) have arrived.
async fn connect_messages(body: Body, n: usize) -> (Vec<Value>, Option<Value>) {
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            while buf.len() >= 5 {
                let flag = buf[0];
                let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                if buf.len() < 5 + len {
                    break;
                }
                let json: Value = serde_json::from_slice(&buf[5..5 + len]).expect("json");
                buf.drain(..5 + len);
                if flag & 0x02 != 0 {
                    return Some(json);
                }
                out.push(json);
                if out.len() == n {
                    return None;
                }
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        buf.extend_from_slice(&data);
                    }
                }
                _ => return None,
            }
        }
    })
    .await
    .map_or_else(|_| panic!("connect messages within 5s"), |end| (out, end))
}

async fn connect_tail(engine: &Engine, scopes: &[u8], request: &[u8]) -> (Option<String>, Body) {
    let token = engine
        .auth_tokens()
        .create("connect", scopes)
        .expect("token");
    let response = build_router(engine.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oxidhome.v1.EventsService/TailEvents")
                .header(header::CONTENT_TYPE, "application/connect+json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .body(Body::from(connect_envelope(request)))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let resume = response
        .headers()
        .get("oxidhome-resume-after-id")
        .map(|v| v.to_str().expect("ascii").to_owned());
    (resume, response.into_body())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_tail_resumes_from_cursor() {
    let engine = Engine::new().expect("engine");
    for n in 1..=3 {
        publish_recorded(&engine, n).await;
    }
    let (resume, body) = connect_tail(
        &engine,
        br#"["events:tail","events:read"]"#,
        br#"{"afterId":"1"}"#,
    )
    .await;
    assert_eq!(resume.as_deref(), Some("1"));
    publish_recorded(&engine, 4).await;
    let (messages, _) = connect_messages(body, 3).await;
    let ids: Vec<&Value> = messages.iter().map(|m| &m["event"]["rowId"]).collect();
    assert_eq!(ids, ["2", "3", "4"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_tail_reports_cursor_expired_then_ends() {
    let engine = Engine::new().expect("engine");
    for n in 1..=5 {
        publish_recorded(&engine, n).await;
    }
    engine.event_log().trim_older_than(4).expect("trim");
    let (resume, body) = connect_tail(
        &engine,
        br#"["events:tail","events:read"]"#,
        br#"{"afterId":"2"}"#,
    )
    .await;
    assert_eq!(resume, None, "expired cursors are not acknowledged");
    let (messages, end) = connect_messages(body, 2).await;
    assert_eq!(
        messages,
        [serde_json::json!({
            "cursorExpired": { "afterId": "2", "oldestId": "4", "headId": "5" }
        })]
    );
    let end = end.expect("end-of-stream frame");
    assert!(end.get("error").is_none(), "clean end, got {end}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_tail_cursor_requires_events_read() {
    let engine = Engine::new().expect("engine");
    let (_, body) = connect_tail(&engine, br#"["events:tail"]"#, br#"{"afterId":"0"}"#).await;
    let (messages, end) = connect_messages(body, 1).await;
    assert_eq!(messages, Vec::<Value>::new());
    assert_eq!(
        end.expect("end-of-stream frame")["error"]["code"],
        "permission_denied"
    );
}

/// History reports a pruned cursor as `410 Gone` instead of
/// silently returning the rows after the gap.
#[tokio::test(flavor = "multi_thread")]
async fn history_query_reports_pruned_cursor_as_gone() {
    let engine = Engine::new().expect("engine");
    for n in 1..=5 {
        publish_recorded(&engine, n).await;
    }
    engine.event_log().trim_older_than(4).expect("trim");
    let token = engine
        .auth_tokens()
        .create("history", br#"["events:read"]"#)
        .expect("token");
    let get = |query: &'static str| {
        Request::builder()
            .uri(format!("/api/v1/events{query}"))
            .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
            .body(Body::empty())
            .expect("request")
    };
    let router = build_router(engine.clone());
    let response = router
        .clone()
        .oneshot(get("?after_id=2"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::GONE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        json,
        serde_json::json!({
            "cursor_expired": { "after_id": 2, "oldest_id": 4, "head_id": 5 }
        })
    );
    for ok in ["?after_id=3", "?after_id=0", "?after_id=5"] {
        let response = router.clone().oneshot(get(ok)).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{ok}");
    }
}

/// M7 + H4: events replayed from history withhold `bytes-val`
/// payloads from a token without `blobs:read`, like live ones.
#[tokio::test(flavor = "multi_thread")]
async fn replayed_events_withhold_bytes_without_blobs_read() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::StateChange;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};

    let engine = Engine::new().expect("engine");
    let event = Event {
        device: Some("dev-1".into()),
        timestamp: 1,
        origin_plugin_id: "com.example.resume".into(),
        origin_instance_id: "resume-a".into(),
        row_id: None,
        payload: EventPayload::StateChanged(StateChange {
            capability: "camera".into(),
            fields: vec![KeyValue {
                key: "frame".into(),
                value: WitValue::BytesVal(vec![1, 2, 3]),
            }],
        }),
    };
    // Recorded and fanned out before the tail opens, so it reaches
    // the client only through the history replay.
    {
        let bus = engine.events();
        let gate = bus.publish_sequence();
        let _guard = gate.lock().await;
        let id = engine
            .event_log()
            .record(1, &event, "resume-a", "com.example.resume")
            .expect("record");
        bus.publish_with_id(event, Some(id));
    }
    let token = engine
        .auth_tokens()
        .create("resume", br#"["events:tail","events:read"]"#)
        .expect("token");
    let (addr, server) = serve_engine(&engine).await;
    let mut ws = ws_connect(addr, "?after_id=0", &token.plaintext)
        .await
        .expect("connect");
    let frame = next_json(&mut ws).await;
    assert_eq!(frame["id"], 1);
    let withheld = serde_json::json!({
        "t": "Json",
        "v": r#"{"withheld":"bytes","size_bytes":3,"required_scope":"blobs:read"}"#,
    });
    assert_eq!(frame["payload"]["fields"][0]["value"], withheld, "{frame}");
    let _ = ws.close(None).await;
    server.abort();

    // Connect replay withholds the same way.
    let (_, body) = connect_tail(
        &engine,
        br#"["events:tail","events:read"]"#,
        br#"{"afterId":"0"}"#,
    )
    .await;
    let (messages, _) = connect_messages(body, 1).await;
    let value = &messages[0]["event"]["stateChanged"]["fields"][0]["value"];
    assert!(value.get("bytesVal").is_none(), "bytes leaked: {value}");
    assert_eq!(
        value["jsonVal"], r#"{"withheld":"bytes","size_bytes":3,"required_scope":"blobs:read"}"#,
        "{value}"
    );

    // With `blobs:read` the bytes come through.
    let (_, body) = connect_tail(
        &engine,
        br#"["events:tail","events:read","blobs:read"]"#,
        br#"{"afterId":"0"}"#,
    )
    .await;
    let (messages, _) = connect_messages(body, 1).await;
    let value = &messages[0]["event"]["stateChanged"]["fields"][0]["value"];
    assert!(value.get("bytesVal").is_some(), "{value}");
}
