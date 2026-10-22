//! What one connection may cost the panel: a connection that says nothing is closed, and
//! there is a most number of them. Real TLS on a loopback port, with small limits.

use std::time::{Duration, Instant};

use kariz_panel::config::Config;
use kariz_panel::db::Db;
use kariz_panel::http::{self, AppState, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start(limits: Limits) -> (std::net::SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        path: "k-7f3a9c".into(),
        data_dir: dir.path().to_path_buf(),
        agent_listen: None,
        kariz_dir: dir.path().join("kariz"),
        services: Default::default(),
        terminal: false,
        cert_file: None,
        key_file: None,
        release_api: None,
        release_key: None,
    };
    config.ensure_cert().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http::router(&config.path, AppState::new(Db::in_memory().unwrap()));
    tokio::spawn(async move {
        let _ = http::serve_with(listener, &config, app, limits).await;
    });
    (addr, dir)
}

/// Whether the server closes the connection within `within` (a read returns 0 or fails).
async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(within, stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn a_connection_that_never_finishes_the_handshake_is_closed() {
    let (addr, _dir) = start(Limits {
        handshake: Duration::from_millis(400),
        headers: Duration::from_secs(5),
        connections: 100,
    })
    .await;
    let mut idle = TcpStream::connect(addr).await.unwrap();
    let started = Instant::now();
    assert!(
        closed_within(&mut idle, Duration::from_secs(5)).await,
        "an idle connection was left open"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "it took {:?}",
        started.elapsed()
    );

    // Half a TLS hello and then silence is no different.
    let mut half = TcpStream::connect(addr).await.unwrap();
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01])
        .await
        .unwrap();
    assert!(closed_within(&mut half, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn there_is_a_most_number_of_connections_and_the_rest_are_closed_at_once() {
    let (addr, _dir) = start(Limits {
        handshake: Duration::from_secs(20),
        headers: Duration::from_secs(20),
        connections: 2,
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(TcpStream::connect(addr).await.unwrap());
    }
    // let the server take both
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut third = TcpStream::connect(addr).await.unwrap();
    assert!(
        closed_within(&mut third, Duration::from_secs(3)).await,
        "a third connection was kept"
    );
    // the two that fit are still being served (not closed)
    for c in &mut held {
        assert!(
            !closed_within(c, Duration::from_millis(300)).await,
            "a connection within the limit was closed"
        );
    }
    // when one goes, there is room again
    held.pop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut again = TcpStream::connect(addr).await.unwrap();
    assert!(
        !closed_within(&mut again, Duration::from_millis(500)).await,
        "there was no room after one left"
    );
}
