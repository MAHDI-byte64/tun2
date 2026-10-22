//! The renter's page over the real HTTPS server, outside the secret path: an unknown link
//! is the plain 404, a made one shows the page and its JSON, a restart asked from it is
//! answered with a redirect, and a revoked link is gone.

use std::time::Duration;

use kariz::config::TlsConfig;
use kariz::transport::tls::Client;
use kariz_panel::db::Db;
use kariz_panel::http::{self, AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn request(addr: std::net::SocketAddr, pin: &str, method: &str, path: &str) -> (u16, String) {
    let tls = TlsConfig {
        pin_sha256: Some(pin.to_owned()),
        ..TlsConfig::default()
    };
    let client = Client::new(Some(&tls), "kariz-panel").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut stream = client.connect(tcp).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: panel\r\nAccept-Language: fa\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut text = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut text)).await;
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[tokio::test]
async fn the_renter_s_page_is_served_by_its_link_and_gone_when_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let installed = kariz_panel::init(
        &dir.path().join("panel.toml"),
        &dir.path().join("data"),
        Some(1),
    )
    .unwrap();
    let config = installed.config;
    let db = Db::open(&config.database()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http::router(&config.path, AppState::new(db.clone()));
    let served = config.clone();
    let task = tokio::spawn(async move {
        let _ = http::serve(listener, &served, app).await;
    });
    let pin = &installed.fingerprint;

    // No such link: the plain 404 of an unknown address.
    let (status, text) = request(addr, pin, "GET", "/s/0123456789abcdef0123456789abcdef").await;
    assert_eq!(status, 404, "{text}");
    let (status, _) = request(addr, pin, "GET", "/s/not-a-token").await;
    assert_eq!(status, 404);

    // A limit of 30 days on a tunnel, and its page.
    let end = kariz_panel::auth::now() + 30 * 86_400;
    kariz_panel::quota::write(&db, "rented", 0, 0, end).unwrap();
    let share = kariz_panel::share::make(&db, "rented", "دفتر")
        .unwrap()
        .unwrap();
    let path = format!("/s/{}", share.token);
    let (status, text) = request(addr, pin, "GET", &path).await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.contains("text/html") && text.contains("دفتر") && text.contains("dir=\"rtl\""),
        "{text}"
    );
    assert!(text.contains("30 روز مانده"), "{text}");
    assert!(
        text.contains("default-src 'none'"),
        "its own policy: {text}"
    );
    let (status, text) = request(addr, pin, "GET", &format!("{path}/data")).await;
    assert_eq!(status, 200, "{text}");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let data: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(data["days_left"], 30);
    assert_eq!(data["state"], "stopped", "no server reports it");
    assert_eq!(data["can_restart"], true);

    // A restart asked from the page: taken (as an operation that finds no server), and the
    // page says so; a second one right after is too soon.
    let (status, text) = request(addr, pin, "POST", &format!("{path}/restart")).await;
    assert_eq!(status, 303, "{text}");
    assert!(text.contains(&format!("location: {path}?msg=")), "{text}");
    let (status, text) = request(addr, pin, "GET", &format!("{path}/data")).await;
    assert_eq!(status, 200);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let data: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(data["can_restart"], false);
    assert!(data["restart_wait"].as_i64().unwrap() > 0);

    // Revoked: gone.
    assert!(kariz_panel::share::revoke(&db, "rented").unwrap());
    let (status, _) = request(addr, pin, "GET", &path).await;
    assert_eq!(status, 404);
    task.abort();
}
