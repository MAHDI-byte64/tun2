//! Making a tunnel as a pair, through the hub and a real agent, with real `kariz` daemons
//! (run as child processes instead of systemd units): create, traffic, edit, stop, delete,
//! and a create that cannot connect leaving nothing behind. The daemons' status comes over their control sockets, which are Unix only.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kariz_panel::agent::{self, Agent};
use kariz_panel::db::Db;
use kariz_panel::hub::{Hub, LOCAL};
use kariz_panel::manage::Processes;
use kariz_panel::pair::{self, PairRequest};
use kariz_panel::wire::ForwardInfo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The `kariz` program, next to the test programs (built by `cargo build -p kariz`).
fn kariz_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin = exe.parent()?.parent()?.join("kariz");
    bin.exists().then_some(bin)
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn through(port: u16, what: &[u8]) -> bool {
    for _ in 0..40 {
        if let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            if s.write_all(what).await.is_ok() {
                let mut back = vec![0u8; what.len()];
                let read = tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut back));
                if matches!(read.await, Ok(Ok(_))) && back == what {
                    return true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn finished(hub: &Hub, id: &str) -> kariz_panel::pair::Op {
    for _ in 0..600 {
        let op = hub.ops.get(id).expect("the operation is known");
        if op.state != "running" {
            return op;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the operation did not finish");
}

fn files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn a_pair_is_made_edited_stopped_deleted_and_a_failure_leaves_nothing() {
    let Some(binary) = kariz_binary() else {
        eprintln!("skipped: build the kariz program first (cargo build -p kariz)");
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter("kariz_panel=debug,kariz=warn")
        .with_test_writer()
        .try_init();

    // The panel's own server (entry) and an agent (exit), each with its own tunnel directory.
    let root = tempfile::tempdir().unwrap();
    let local_dir = root.path().join("local");
    let agent_dir = root.path().join("agent");
    std::fs::create_dir_all(&local_dir).unwrap();
    std::fs::create_dir_all(&agent_dir).unwrap();

    let hub = Hub::with_options(
        Db::in_memory().unwrap(),
        local_dir.clone(),
        Arc::new(Processes::new(&local_dir, &binary)),
        Duration::from_secs(8),
        None,
        None,
    );
    tokio::spawn(hub.clone().run_local());
    let acceptor = kariz::link::Acceptor::bind("127.0.0.1:0", &hub.link_token().unwrap())
        .await
        .unwrap();
    let addr = acceptor.local_addr().unwrap().to_string();
    tokio::spawn(hub.clone().serve_agents(acceptor));

    let code = hub.create_join(Some("far-away"), &addr).unwrap();
    let agent_file = root.path().join("agent.toml");
    let mut config = agent::enroll_from_code(&code, &agent_file).unwrap();
    config.kariz_dir = agent_dir.clone();
    config.save(&agent_file).unwrap();
    let agent = Agent::with_services(
        &agent_file,
        config,
        Arc::new(Processes::new(&agent_dir, &binary)),
    );
    tokio::spawn(agent.run());
    let exit_id = {
        let mut id = None;
        for _ in 0..100 {
            id = hub
                .snapshot()
                .unwrap()
                .into_iter()
                .find(|s| !s.local && s.online)
                .map(|s| s.id);
            if id.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        id.expect("the agent joined")
    };

    let target = echo_server().await;
    let listen = free_port();
    let front = free_port();
    let request = |front: u16, dial_port: u16| PairRequest {
        name: "pair-1".into(),
        entry: LOCAL.into(),
        exit: exit_id.clone(),
        mode: "reverse".into(),
        transport: "tcpmux".into(),
        profile: None,
        listen: format!("127.0.0.1:{listen}"),
        dial: format!("127.0.0.1:{dial_port}"),
        pool: None,
        ws_path: None,
        ws_host: None,
        tls_sni: None,
        mux: None,
        tls_cert: None,
        tls_key: None,
        tls_host: None,
        encryption: None,
        quic_obfs: false,
        max_conns_per_ip: None,
        udp_max_flows: None,
        proxy_protocol: None,
        forwards: vec![ForwardInfo {
            listen: format!("127.0.0.1:{front}"),
            target: format!("127.0.0.1:{target}"),
            protocol: "tcp".into(),
        }],
        rotate: false,
        network: None,
        ..Default::default()
    };

    // ---- a check names a taken port ----
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().port();
    let mut clash = request(taken, listen);
    clash.name = "clash".into();
    let (entry_check, _) = pair::check(&hub, &clash).await.unwrap();
    if cfg!(target_os = "linux") {
        assert!(!entry_check.ok, "{entry_check:?}");
        assert_eq!(entry_check.conflicts[0].port, taken);
    }
    drop(holder);

    // ---- create ----
    let op = pair::create(&hub, request(front, listen)).unwrap();
    let done = finished(&hub, &op).await;
    assert_eq!(done.state, "done", "{done:?}");
    assert!(done.steps.iter().all(|s| s.state == "ok"), "{done:?}");
    assert!(local_dir.join("pair-1.toml").exists());
    assert!(agent_dir.join("pair-1.toml").exists());
    assert!(through(front, b"hello through the pair").await);
    // the entry's numbers are being remembered for the charts
    let mut points = 0;
    for _ in 0..50 {
        points = hub
            .history
            .series("tun:pair-1:rate", kariz_panel::history::Range::Hour)
            .unwrap()
            .len();
        if points > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(points > 0, "no history was recorded for the tunnel");
    // the same name again is refused while it exists (once the servers have reported it)
    for _ in 0..60 {
        let known = hub
            .snapshot()
            .unwrap()
            .iter()
            .filter(|s| s.tunnels.iter().any(|t| t.info.name == "pair-1"))
            .count();
        if known == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let again = pair::create(&hub, request(front, listen)).unwrap();
    assert_eq!(
        finished(&hub, &again).await.error.as_deref(),
        Some("name_taken")
    );

    // ---- edit: another front port, the token kept ----
    let new_front = free_port();
    let op = pair::edit(&hub, request(new_front, listen)).unwrap();
    let done = finished(&hub, &op).await;
    assert_eq!(done.state, "done", "{done:?}");
    assert!(through(new_front, b"after the edit").await);

    // ---- a new token on both sides ----
    let mut rotate = request(new_front, listen);
    rotate.rotate = true;
    let op = pair::edit(&hub, rotate).unwrap();
    let done = finished(&hub, &op).await;
    assert_eq!(done.state, "done", "{done:?}");
    assert!(through(new_front, b"after the new token").await);

    // ---- stop ----
    let op = pair::control(&hub, "pair-1", "stop").unwrap();
    assert_eq!(finished(&hub, &op).await.state, "done");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", new_front))
        .await
        .is_err());

    // ---- delete ----
    let op = pair::delete(&hub, "pair-1").unwrap();
    assert_eq!(finished(&hub, &op).await.state, "done");
    assert!(files(&local_dir).is_empty(), "{:?}", files(&local_dir));
    assert!(files(&agent_dir).is_empty(), "{:?}", files(&agent_dir));

    // ---- a tunnel that cannot connect is undone on both sides ----
    let dead = free_port();
    let mut broken = request(free_port(), dead);
    broken.name = "broken".into();
    let op = pair::create(&hub, broken).unwrap();
    let done = finished(&hub, &op).await;
    assert_eq!(done.state, "failed", "{done:?}");
    assert_eq!(done.undone, Some(true));
    assert_eq!(done.steps.last().unwrap().id, "connect");
    assert!(files(&local_dir).is_empty(), "{:?}", files(&local_dir));
    assert!(files(&agent_dir).is_empty(), "{:?}", files(&agent_dir));
}
