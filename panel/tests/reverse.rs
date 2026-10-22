//! A server the panel connects to (reverse), with a real agent and a real hub on the
//! loopback: the panel takes no agents at all, the agent listens where its code says, the
//! panel dials it and it joins as the server that was waiting; a code to switch it back to
//! dialing the panel stops the panel dialing; and removing the server stops it too.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kariz_panel::agent::{self, Agent};
use kariz_panel::db::Db;
use kariz_panel::hub::{Hub, ServerView};
use kariz_panel::reverse::Reverse;

/// A port that is free on TCP and UDP, and so is the next one (the agent listens on both).
fn free_pair() -> u16 {
    loop {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        if port < 65000
            && std::net::TcpListener::bind(("127.0.0.1", port + 1)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port + 1)).is_ok()
        {
            return port;
        }
    }
}

fn server(hub: &Hub, id: &str) -> Option<ServerView> {
    hub.snapshot().unwrap().into_iter().find(|s| s.id == id)
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..300 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

fn agent_for(code: &str, dir: &Path) -> Arc<Agent> {
    let path = dir.join("agent.toml");
    let kariz_dir = dir.join("kariz");
    std::fs::create_dir_all(&kariz_dir).unwrap();
    let mut config = agent::enroll_from_code(code, &path).unwrap();
    config.kariz_dir = kariz_dir;
    config.save(&path).unwrap();
    Agent::new(&path, config)
}

#[tokio::test]
async fn the_panel_connects_to_a_server_that_waits_for_it() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("kariz_panel=debug,kariz=warn")
        .with_test_writer()
        .try_init();
    let panel_dir = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // No acceptor: this panel takes no agents.
    let hub = Hub::new(Db::in_memory().unwrap(), panel_dir.path().to_path_buf());
    let port = free_pair();

    // What was typed is checked.
    let why =
        |r: anyhow::Result<kariz_panel::reverse::ReverseJoin>| format!("{:#}", r.unwrap_err());
    assert!(Reverse::new("a b", port, None, false).is_err());
    let target = Reverse::new("127.0.0.1", port, None, false).unwrap();
    assert_eq!(
        why(hub
            .create_reverse_join(Some("bad name!"), target.clone())
            .await),
        "bad_input"
    );

    let made = hub
        .create_reverse_join(Some("behind-nat"), target.clone())
        .await
        .unwrap();
    // Listed and waiting, with where the panel dials it.
    let waiting = server(&hub, &made.id).unwrap();
    assert!(!waiting.online && waiting.last_seen.is_none());
    assert_eq!(waiting.name, "behind-nat");
    assert_eq!(waiting.reverse.as_ref(), Some(&target));
    // The same address cannot be added twice.
    assert_eq!(
        why(hub.create_reverse_join(None, target.clone()).await),
        format!("address_taken:{}", made.id)
    );
    // The code has no panel address: it says where the agent listens.
    let code = kariz_panel::join::decode(&made.code).unwrap();
    assert_eq!(code.p, "");
    assert_eq!(code.l.as_deref(), Some(format!("0.0.0.0:{port}").as_str()));

    // The panel dials nothing that answers yet: the server has a reason, and stays waiting.
    wait_for("a failed try", || {
        server(&hub, &made.id).is_some_and(|s| s.last_error.is_some())
    })
    .await;
    assert!(!server(&hub, &made.id).unwrap().online);

    // ---- the agent joins with the code: it listens, and the panel comes to it ----
    let agent = agent_for(&made.code, dir.path());
    let running = tokio::spawn(agent.run());
    wait_for("the panel to connect to the agent", || {
        server(&hub, &made.id).is_some_and(|s| s.online)
    })
    .await;
    let joined = server(&hub, &made.id).unwrap();
    assert_eq!(
        joined.name, "behind-nat",
        "it came in as the waiting server"
    );
    assert_eq!(joined.link.as_deref(), Some("tcpmux"));
    assert_eq!(hub.snapshot().unwrap().len(), 2, "nothing was added twice");
    // It keeps the identity it was given (a restart of the panel finds it again).
    let saved = std::fs::read_to_string(dir.path().join("agent.toml")).unwrap();
    assert!(
        saved.contains(&made.id) && saved.contains("listen"),
        "{saved}"
    );
    assert!(
        !saved.contains("join ="),
        "the join secret is spent: {saved}"
    );

    // ---- switching it back to dialing the panel: the panel stops dialing it ----
    hub.set_reverse(&made.id, None).unwrap();
    assert_eq!(hub.reverse_of(&made.id), None);
    assert_eq!(server(&hub, &made.id).unwrap().reverse, None);

    // ---- and back again; then removing it stops the panel too ----
    hub.set_reverse(&made.id, Some(&target)).unwrap();
    assert!(hub.remove(&made.id).unwrap());
    assert_eq!(hub.reverse_of(&made.id), None);
    assert!(hub.reverse_all().unwrap().is_empty());
    running.abort();
}

#[tokio::test]
async fn an_agent_that_is_another_server_is_let_go() {
    let panel_dir = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::new(Db::in_memory().unwrap(), panel_dir.path().to_path_buf());
    let (port_a, port_b) = (free_pair(), free_pair());
    let a = hub
        .create_reverse_join(
            Some("a"),
            Reverse::new("127.0.0.1", port_a, Some("tcpmux"), false).unwrap(),
        )
        .await
        .unwrap();
    let b = hub
        .create_reverse_join(
            Some("b"),
            Reverse::new("127.0.0.1", port_b, Some("tcpmux"), false).unwrap(),
        )
        .await
        .unwrap();
    // Server a's agent comes up where the panel dials b.
    let wrong = kariz_panel::join::JoinCode {
        l: Some(format!("0.0.0.0:{port_b}")),
        ..kariz_panel::join::decode(&a.code).unwrap()
    };
    let agent = agent_for(&kariz_panel::join::encode(&wrong), dir.path());
    let running = tokio::spawn(agent.run());
    // The panel reaches it as b, finds a there, and keeps neither online through it.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let b_now = server(&hub, &b.id).unwrap();
    assert!(!b_now.online, "b is not online through a's agent");
    running.abort();
}

/// A server the panel reaches through its SOCKS5 proxy: the link goes through the proxy
/// (counted there), only the TCP transports are tried, turning the proxy off ends the link
/// and says why on the server's card, and turning it on brings the server back.
#[tokio::test]
async fn the_panel_reaches_a_server_through_its_proxy_and_stops_when_the_proxy_is_off() {
    use kariz::transport::proxy::testing::Socks5Server;
    use kariz_panel::proxy::Settings;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("kariz_panel=debug,kariz=warn")
        .with_test_writer()
        .try_init();
    let panel_dir = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::new(Db::in_memory().unwrap(), panel_dir.path().to_path_buf());
    let proxy = Socks5Server::start(Some(("panel".into(), "secret".into()))).await;
    let port = free_pair();

    // Through the proxy, over whichever TCP transport works (auto).
    let target = Reverse::new("127.0.0.1", port, Some("auto"), true).unwrap();
    assert!(target.via_proxy);
    let made = hub
        .create_reverse_join(Some("far"), target.clone())
        .await
        .unwrap();
    assert_eq!(
        server(&hub, &made.id).unwrap().reverse.as_ref(),
        Some(&target)
    );

    // No proxy is set yet: the panel does not dial, and the card says why.
    wait_for("the proxy_off reason", || {
        server(&hub, &made.id)
            .is_some_and(|s| s.last_error.as_ref().is_some_and(|e| e.kind == "proxy_off"))
    })
    .await;
    let agent = agent_for(&made.code, dir.path());
    let running = tokio::spawn(agent.run());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !server(&hub, &made.id).unwrap().online,
        "not dialed while the proxy is off"
    );
    assert_eq!(proxy.relayed(), 0);

    // The proxy is set: the panel comes through it.
    let settings = Settings {
        enabled: true,
        addr: proxy.addr.clone(),
        username: "panel".into(),
        password: "secret".into(),
        panel_internet: false,
    };
    settings.save(hub.db()).unwrap();
    hub.restart_proxied_links();
    wait_for("the panel to connect through the proxy", || {
        server(&hub, &made.id).is_some_and(|s| s.online)
    })
    .await;
    assert!(proxy.relayed() >= 1, "the link went through the proxy");
    assert_eq!(
        server(&hub, &made.id).unwrap().link.as_deref(),
        Some("tcpmux")
    );

    // The proxy is turned off: the link is closed and the server is offline, with the reason.
    Settings {
        enabled: false,
        ..settings.clone()
    }
    .save(hub.db())
    .unwrap();
    hub.restart_proxied_links();
    wait_for("the server to go offline", || {
        server(&hub, &made.id).is_some_and(|s| !s.online)
    })
    .await;
    wait_for("the proxy_off reason again", || {
        server(&hub, &made.id)
            .is_some_and(|s| s.last_error.as_ref().is_some_and(|e| e.kind == "proxy_off"))
    })
    .await;
    let relayed = proxy.relayed();

    // And on again: back through the proxy, with a new connection.
    settings.save(hub.db()).unwrap();
    hub.restart_proxied_links();
    wait_for("the panel to connect through the proxy again", || {
        server(&hub, &made.id).is_some_and(|s| s.online)
    })
    .await;
    assert!(proxy.relayed() > relayed);
    assert!(hub.remove(&made.id).unwrap());
    running.abort();
}
