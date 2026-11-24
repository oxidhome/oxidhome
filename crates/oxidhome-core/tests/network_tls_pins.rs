//! Phase 8.2: the operator surfaces for TLS certificate pins — REST and
//! Connect listing and reset, their gates, and persistence across a
//! restart. The pinning itself is tested end to end in
//! `oxidhome-test-host`'s network tests.

#[path = "support.rs"]
mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use oxidhome_core::Engine;
use oxidhome_core::api::{build_router, ensure_admin_token};
use oxidhome_core::state::{Fingerprint, PinCheck, PinFilter, PinKey};
use serde_json::Value;
use tower::ServiceExt;

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    bearer: &str,
    body: &str,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method(method)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn pin(engine: &Engine, instance: &str, host: &str, port: u16, der: &[u8]) {
    let key = PinKey {
        instance_id: instance.into(),
        host: host.into(),
        port,
    };
    assert_eq!(
        engine
            .tls_pins()
            .check_or_pin(&key, Fingerprint::of_der(der))
            .unwrap(),
        PinCheck::Pinned
    );
}

fn pinned_hosts(body: &Value, field: &str) -> Vec<String> {
    body[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field}: {body}"))
        .iter()
        .map(|p| {
            format!(
                "{}/{}:{}",
                p["instance_id"]
                    .as_str()
                    .or(p["instanceId"].as_str())
                    .unwrap(),
                p["host"].as_str().unwrap(),
                p["port"]
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn operators_list_and_reset_pins() {
    let state = support::tempdir("tls-pins");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let owner = ensure_admin_token(&engine.auth_tokens(), &engine.audit_log(), state.path())
        .expect("bootstrap")
        .expect("first run mints the owner token");
    let wildcard = engine.auth_tokens().create("ha", br#"["*"]"#).unwrap();
    let lister = engine
        .auth_tokens()
        .create("viewer", br#"["instances:list"]"#)
        .unwrap();
    let devices = engine
        .auth_tokens()
        .create("devices", br#"["devices:list"]"#)
        .unwrap();
    pin(&engine, "cam", "192.168.1.20", 443, b"one");
    pin(&engine, "cam", "camera.lan", 8443, b"two");
    pin(&engine, "plug", "10.0.0.7", 443, b"three");
    let router = build_router(engine.clone());

    // Listing needs `instances:list`.
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/network/tls-pins",
        &devices.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(
        &router,
        "GET",
        "/api/v1/network/tls-pins",
        &lister.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        pinned_hosts(&body, "pins"),
        [
            "cam/192.168.1.20:443",
            "cam/camera.lan:8443",
            "plug/10.0.0.7:443"
        ]
    );
    assert_eq!(
        body["pins"][0]["sha256"].as_str().unwrap(),
        Fingerprint::of_der(b"one").to_hex()
    );
    let (_, body) = send(
        &router,
        "GET",
        "/api/v1/network/tls-pins?instance_id=plug",
        &lister.plaintext,
        "",
    )
    .await;
    assert_eq!(pinned_hosts(&body, "pins"), ["plug/10.0.0.7:443"]);
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/network/tls-pins?host=camera.lan",
        &lister.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a host needs an instance");

    // A misspelled filter is refused, not widened to every pin.
    let (status, _) = send(
        &router,
        "DELETE",
        "/api/v1/network/tls-pins?instanceId=cam",
        &owner.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(engine.tls_pins().list(&PinFilter::default()).len(), 3);

    // Resetting is the owner's alone; the wildcard doesn't reach it.
    let reset_one = "/api/v1/network/tls-pins?instance_id=cam&host=Camera.LAN&port=8443";
    let (status, _) = send(&router, "DELETE", reset_one, &wildcard.plaintext, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&router, "DELETE", reset_one, &owner.plaintext, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pinned_hosts(&body, "removed"), ["cam/camera.lan:8443"]);

    // Connect: the same gates, and a reset names its scope.
    let (status, _) = send(
        &router,
        "POST",
        "/oxidhome.v1.NetworkService/ResetTlsPins",
        &wildcard.plaintext,
        r#"{"all":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &router,
        "POST",
        "/oxidhome.v1.NetworkService/ResetTlsPins",
        &owner.plaintext,
        r#"{"instance":"cam"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = send(
        &router,
        "POST",
        "/oxidhome.v1.NetworkService/ListTlsPins",
        &lister.plaintext,
        r#"{"instanceId":"cam"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pinned_hosts(&body, "pins"), ["cam/192.168.1.20:443"]);

    // Pins survive a restart; a reset doesn't come back.
    drop(router);
    drop(engine);
    let engine = Engine::with_state_dir(state.path()).expect("reopen");
    let left: Vec<_> = engine
        .tls_pins()
        .list(&PinFilter::default())
        .into_iter()
        .map(|p| format!("{}/{}:{}", p.key.instance_id, p.key.host, p.key.port))
        .collect();
    assert_eq!(left, ["cam/192.168.1.20:443", "plug/10.0.0.7:443"]);

    // Only an explicit `all` resets everything.
    let router = build_router(engine.clone());
    let (status, _) = send(
        &router,
        "DELETE",
        "/api/v1/network/tls-pins",
        &owner.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = send(
        &router,
        "DELETE",
        "/api/v1/network/tls-pins?all=true",
        &owner.plaintext,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pinned_hosts(&body, "removed").len(), 2);
    assert_eq!(engine.tls_pins().list(&PinFilter::default()), Vec::new());
}
