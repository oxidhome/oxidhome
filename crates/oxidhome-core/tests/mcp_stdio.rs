//! Phase 14.5 — MCP stdio transport integration tests.
//!
//! Drives [`serve_stdio_over`] against a `tokio::io::duplex()`
//! in-memory pipe to prove the same handshake + tool/resource
//! surface the HTTP mount serves also works over the stdio
//! transport, without needing to spawn a real subprocess or
//! open real stdin/stdout.

#[path = "support.rs"]
mod _support;

use std::time::Duration;

use oxidhome_core::Engine;
use oxidhome_core::api::mcp::serve_stdio_over;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Framing: MCP stdio uses one JSON-RPC message per line
/// (LSP-style newline-delimited JSON via rmcp's default
/// stdio codec). Write helper flushes so the server sees the
/// full frame before its next read poll.
async fn send_line<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &Value) {
    let mut bytes = serde_json::to_vec(payload).expect("serialize");
    bytes.push(b'\n');
    w.write_all(&bytes).await.expect("write");
    w.flush().await.expect("flush");
}

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Value {
    let mut line = String::new();
    let deadline = Duration::from_secs(5);
    let read = tokio::time::timeout(deadline, r.read_line(&mut line))
        .await
        .expect("timed out waiting for a response line")
        .expect("read");
    assert!(read > 0, "server closed the transport before responding");
    serde_json::from_str(line.trim_end()).unwrap_or_else(|e| panic!("bad JSON: {e}: {line}"))
}

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "oxidhome-mcp-stdio-test", "version": env!("CARGO_PKG_VERSION")}
        }
    })
}

/// 14.5: end-to-end handshake over the stdio transport.
/// Initialize round-trips a well-formed `InitializeResult`;
/// notifications/initialized is one-shot; a follow-up
/// `resources/list` returns the same catalogue the HTTP mount
/// serves.
#[tokio::test(flavor = "multi_thread")]
async fn stdio_handshake_and_resources_list() {
    let engine = Engine::new().expect("engine");

    // Client ↔ server duplex. `client_side` is what the "client"
    // reads from and writes to; `server_side` gets fed to
    // `serve_stdio_over` as its `(reader, writer)` pair.
    let (client_to_server, server_reader) = tokio::io::duplex(64 * 1024);
    let (server_writer, server_to_client) = tokio::io::duplex(64 * 1024);

    let server_task =
        tokio::spawn(async move { serve_stdio_over(engine, server_reader, server_writer).await });

    let mut client_writer = client_to_server;
    let mut client_reader = BufReader::new(server_to_client);

    // 1. initialize → response carries InitializeResult with
    //    our advertised capabilities.
    send_line(&mut client_writer, &initialize_body()).await;
    let init_resp = read_line(&mut client_reader).await;
    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    let result = &init_resp["result"];
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "oxidhome");
    let caps = &result["capabilities"];
    assert!(caps["tools"].is_object());
    assert!(caps["resources"].is_object());
    assert!(caps["prompts"].is_object());

    // 2. notifications/initialized — no response expected.
    send_line(
        &mut client_writer,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;

    // 3. resources/list → same catalogue the HTTP mount serves.
    send_line(
        &mut client_writer,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}),
    )
    .await;
    let list_resp = read_line(&mut client_reader).await;
    assert_eq!(list_resp["id"], 2);
    let resources = list_resp["result"]["resources"]
        .as_array()
        .expect("resources array");
    let names: Vec<&str> = resources
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    for expected in ["devices", "plugins", "events", "logs", "status"] {
        assert!(
            names.contains(&expected),
            "resources/list must include `{expected}`; got {names:?}",
        );
    }

    // Close the client side — server should quiesce.
    drop(client_writer);
    drop(client_reader);
    // Round-3 nit on PR #143: assert the server actually
    // returned Ok — a swallowed error would let a broken
    // handshake or a mid-session serve error look like
    // success.
    let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task deadline")
        .expect("server task join");
    joined.expect("serve_stdio_over returned Err");
}

/// 14.5: the stdio ambient actor holds `*` scope, so a
/// `tools/call` on a scope-sensitive tool succeeds (contrast
/// with the HTTP mount, where every call must present a
/// bearer with the matching scope).
#[tokio::test(flavor = "multi_thread")]
async fn stdio_ambient_actor_has_wildcard_scope() {
    let engine = Engine::new().expect("engine");

    let (client_to_server, server_reader) = tokio::io::duplex(64 * 1024);
    let (server_writer, server_to_client) = tokio::io::duplex(64 * 1024);
    let server_task =
        tokio::spawn(async move { serve_stdio_over(engine, server_reader, server_writer).await });

    let mut client_writer = client_to_server;
    let mut client_reader = BufReader::new(server_to_client);

    send_line(&mut client_writer, &initialize_body()).await;
    let _ = read_line(&mut client_reader).await;
    send_line(
        &mut client_writer,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;

    // `plugins.list` requires `plugins:list`. Wildcard actor
    // satisfies it; the tool returns an empty list on a fresh
    // engine.
    send_line(
        &mut client_writer,
        &json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "plugins.list", "arguments": {}}
        }),
    )
    .await;
    let call_resp = read_line(&mut client_reader).await;
    assert!(
        call_resp["error"].is_null(),
        "wildcard actor must satisfy plugins:list; got {call_resp}",
    );
    let plugins = call_resp["result"]["structuredContent"]["plugins"]
        .as_array()
        .expect("plugins array");
    assert!(plugins.is_empty(), "fresh engine has no plugins");

    drop(client_writer);
    drop(client_reader);
    // Round-3 nit on PR #143: assert the server actually
    // returned Ok — a swallowed error would let a broken
    // handshake or a mid-session serve error look like
    // success.
    let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task deadline")
        .expect("server task join");
    joined.expect("serve_stdio_over returned Err");
}
