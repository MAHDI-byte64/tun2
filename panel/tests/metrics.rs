//! The Prometheus endpoint over the real HTTPS server: off it is a 404, on it wants the
//! token (401 without), and answers with the exposition text.

use std::time::Duration;

use kariz::config::TlsConfig;
use kariz::transport::tls::Client;
use kariz_panel::db::Db;
use kariz_panel::http::{self, AppState};
use kariz_panel::metrics::Settings;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn get(
    addr: std::net::SocketAddr,
    pin: &str,
    path: &str,
    authorization: Option<&str>,
) -> (u16, String) {
    let tls = TlsConfig {
        pin_sha256: Some(pin.to_owned()),
        ..TlsConfig::default()
    };
    let client = Client::new(Some(&tls), "kariz-panel").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut stream = client.connect(tcp).await.unwrap();
    let auth = authorization.map_or(String::new(), |a| format!("Authorization: {a}\r\n"));
    let request = format!("GET {path} HTTP/1.1\r\nHost: panel\r\n{auth}Connection: close\r\n\r\n");
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
async fn the_metrics_endpoint_is_off_by_default_and_wants_the_token_when_on() {
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
    let path = format!("/{}/metrics", config.path);
    let pin = &installed.fingerprint;

    let (status, _) = get(addr, pin, &path, None).await;
    assert_eq!(status, 404, "off: like any unknown address");

    let mut settings = Settings::default();
    settings.enable().unwrap();
    settings.save(&db).unwrap();
    let token = settings.token.clone();
    let (status, text) = get(addr, pin, &path, None).await;
    assert_eq!(status, 401, "{text}");
    let (status, text) = get(addr, pin, &path, Some("Bearer not-it")).await;
    assert_eq!(status, 401, "{text}");
    let (status, text) = get(addr, pin, &path, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("text/plain; version=0.0.4"), "{text}");
    assert!(
        text.contains(&format!(
            "kariz_panel_info{{version=\"{}\"}} 1",
            kariz_panel::version()
        )),
        "{text}"
    );
    assert!(text.contains("kariz_server_online{server=\""), "{text}");

    settings.enabled = false;
    settings.save(&db).unwrap();
    let (status, _) = get(addr, pin, &path, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 404, "off again");
    task.abort();
}
