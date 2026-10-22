//! The agent's tunnel requests through `Agent::handle`, the
//! same path the panel's link uses: check, write, read back, edit, delete, ports.

use kariz_panel::agent::{Agent, AgentConfig};
use kariz_panel::wire::{Ack, CheckReply, ForwardInfo, PortOwner, Request, Spec};

fn dir(tag: &str) -> std::path::PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap();
    let p = std::env::temp_dir().join(format!(
        "kariz-req-{tag}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn agent(kariz_dir: &std::path::Path) -> std::sync::Arc<Agent> {
    let config = AgentConfig {
        panel: "127.0.0.1:1".into(),
        link_token: "t".into(),
        join: None,
        id: Some("id".into()),
        key: Some("00".repeat(32)),
        kariz_dir: kariz_dir.to_path_buf(),
        services: Default::default(),
        release_key: None,
        transport: None,
        listen: None,
        terminal: false,
    };
    Agent::new(&kariz_dir.join("agent.toml"), config)
}

fn spec() -> Spec {
    Spec {
        name: "pair".into(),
        role: "entry".into(),
        mode: "reverse".into(),
        transport: "tcpmux".into(),
        listen: Some("127.0.0.1:0".into()),
        token: Some("c".repeat(48)),
        forwards: vec![ForwardInfo {
            listen: "127.0.0.1:0".into(),
            target: "127.0.0.1:9".into(),
            protocol: "tcp".into(),
        }],
        ..Default::default()
    }
}

async fn ack(agent: &Agent, request: Request) -> Ack {
    serde_json::from_slice(&agent.handle(request).await).unwrap()
}

#[tokio::test]
async fn a_tunnel_is_checked_written_read_back_edited_and_deleted() {
    let d = dir("cycle");
    let agent = agent(&d);

    let check: CheckReply =
        serde_json::from_slice(&agent.handle(Request::TunnelCheck { spec: spec() }).await).unwrap();
    assert!(check.ok, "{check:?}");
    // a check writes nothing
    assert!(!d.join("pair.toml").exists());

    assert!(ack(&agent, Request::TunnelPut { spec: spec() }).await.ok);
    let file = std::fs::read_to_string(d.join("pair.toml")).unwrap();
    assert!(file.contains(&"c".repeat(48)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join("pair.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the token is readable by root only");
    }

    // read back: the spec, and never the token
    let raw = agent
        .handle(Request::TunnelGet {
            name: "pair".into(),
        })
        .await;
    let got: Spec = serde_json::from_slice(&raw).unwrap();
    assert_eq!(got.transport, "tcpmux");
    assert!(got.token.is_none());
    assert!(!String::from_utf8_lossy(&raw).contains(&"c".repeat(48)));

    // an edit without a token keeps it
    let mut edit = got;
    edit.transport = "tcp".into();
    assert!(ack(&agent, Request::TunnelPut { spec: edit }).await.ok);
    let file = std::fs::read_to_string(d.join("pair.toml")).unwrap();
    assert!(file.contains("transport = \"tcp\"") && file.contains(&"c".repeat(48)));

    // bad requests are answered, not crashed on
    let mut bad = spec();
    bad.name = "../../etc/x".into();
    let r = ack(&agent, Request::TunnelPut { spec: bad }).await;
    assert!(!r.ok && r.error.is_some());
    assert!(
        !ack(
            &agent,
            Request::TunnelCtl {
                name: "pair".into(),
                action: "mask".into()
            }
        )
        .await
        .ok
    );

    assert!(
        ack(
            &agent,
            Request::TunnelDelete {
                name: "pair".into()
            }
        )
        .await
        .ok
    );
    assert!(!d.join("pair.toml").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn a_listening_port_is_seen_and_named_as_a_conflict() {
    let d = dir("ports");
    let agent = agent(&d);
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();

    let owners: Vec<PortOwner> =
        serde_json::from_slice(&agent.handle(Request::Ports).await).unwrap();
    if cfg!(target_os = "linux") {
        let mine = owners
            .iter()
            .find(|o| o.proto == "tcp" && o.port == port)
            .expect("the test's own listener is listed");
        assert_eq!(mine.pid, Some(std::process::id()));
        assert!(mine.process.is_some());

        let mut s = spec();
        s.listen = Some(format!("127.0.0.1:{port}"));
        let check: CheckReply =
            serde_json::from_slice(&agent.handle(Request::TunnelCheck { spec: s }).await).unwrap();
        assert!(!check.ok);
        assert_eq!(check.conflicts.len(), 1);
    }
    drop(holder);
    let _ = std::fs::remove_dir_all(&d);
}
