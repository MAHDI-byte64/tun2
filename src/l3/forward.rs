//! Optional port forwarding over the l3 link. Once the tunnel interface is up the peer is
//! an ordinary routable address, so forwarding a port is ordinary userspace forwarding: a
//! local listener whose connections are spliced to `peer`. It needs no tunnel-session code
//! of its own and keeps running across tunnel restarts — while the tunnel is down, dials to
//! the peer simply fail and new connections are refused, as the BackPack behaviour requires.
//!
//! This covers the common `ports = [...]` mappings (TCP, and UDP when `accept_udp` is set).
//! For a target written as a bare port the peer address fills in the host. Highest-
//! throughput setups can skip this and use kernel `iptables` DNAT over the interface
//! instead, exactly as the layer-3 doc notes.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::Forward;
use crate::relay::{relay, Counters};

/// How long a splice buffer is.
const BUFFER: usize = 64 * 1024;
/// A UDP flow with no packet in either direction for this long is dropped.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// The largest UDP datagram carried.
const UDP_BUFFER: usize = 64 * 1024;

/// The running forwarders; dropping it stops them.
pub struct Forwarders {
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Forwarders {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Starts a forwarder for each mapping. A bare-port target is sent to `peer`; an explicit
/// `host:port` target is used as written. `accept_udp` also forwards UDP on the mappings
/// whose protocol allows it. Binding happens up front, so a port already in use is reported
/// now rather than silently.
pub async fn start(
    ports: &[Forward],
    accept_udp: bool,
    peer: Option<&str>,
) -> io::Result<Forwarders> {
    let mut tasks = Vec::new();
    for forward in ports {
        let target = resolve_target(&forward.target, peer)?;
        if forward.protocol.has_tcp() {
            let listener = TcpListener::bind(&forward.listen).await.map_err(|e| {
                io::Error::new(e.kind(), format!("l3 forward {}: {e}", forward.listen))
            })?;
            info!(listen = %forward.listen, %target, "l3 forwards a TCP port over the link");
            tasks.push(tokio::spawn(serve_tcp(listener, target.clone())));
        }
        if accept_udp && forward.protocol.has_udp() {
            let socket = UdpSocket::bind(&forward.listen).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("l3 forward {} (udp): {e}", forward.listen),
                )
            })?;
            info!(listen = %forward.listen, %target, "l3 forwards a UDP port over the link");
            tasks.push(tokio::spawn(serve_udp(socket, target.clone())));
        }
    }
    Ok(Forwarders { tasks })
}

/// A target of just a port means `peer:port`; anything with a host is used as written.
fn resolve_target(target: &str, peer: Option<&str>) -> io::Result<String> {
    if target.contains(':') {
        return Ok(target.to_owned());
    }
    if target.parse::<u16>().is_ok() {
        let peer = peer.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a bare-port l3 forward target needs peer_ip (set it, or write host:port)",
            )
        })?;
        return Ok(format!("{peer}:{target}"));
    }
    Ok(target.to_owned())
}

async fn serve_tcp(listener: TcpListener, target: String) {
    loop {
        let (inbound, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "l3 TCP forward accept failed");
                return;
            }
        };
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = splice_tcp(inbound, &target).await {
                debug!(%target, error = %e, "l3 TCP forward connection ended");
            }
        });
    }
}

async fn splice_tcp(mut inbound: TcpStream, target: &str) -> io::Result<()> {
    // While the tunnel is down the peer is unreachable, so the dial fails and the
    // connection is refused rather than left hanging.
    let mut outbound = TcpStream::connect(target).await?;
    let (read, written) = (AtomicU64::new(0), AtomicU64::new(0));
    let counters = Counters {
        read: &read,
        written: &written,
    };
    relay(&mut inbound, &mut outbound, BUFFER, counters).await?;
    Ok(())
}

/// A minimal UDP forwarder: one connected socket to the target per client address, moving
/// datagrams both ways until the flow is idle.
async fn serve_udp(socket: UdpSocket, target: String) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; UDP_BUFFER];
    use std::collections::HashMap;
    let mut flows: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    loop {
        let (n, client) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(e) => {
                warn!(error = %e, "l3 UDP forward recv failed");
                return;
            }
        };
        let flow = match flows.get(&client) {
            Some(flow) => flow.clone(),
            None => {
                let Ok(flow) = connect_udp(&target).await else {
                    continue;
                };
                let flow = Arc::new(flow);
                flows.insert(client, flow.clone());
                spawn_udp_back(flow.clone(), socket.clone(), client);
                flow
            }
        };
        if flow.send(&buf[..n]).await.is_err() {
            flows.remove(&client);
        }
    }
}

async fn connect_udp(target: &str) -> io::Result<UdpSocket> {
    let addr: SocketAddr = tokio::net::lookup_host(target)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target has no address"))?;
    let local: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// Moves the target's replies back to the client until the flow goes idle.
fn spawn_udp_back(flow: Arc<UdpSocket>, listen: Arc<UdpSocket>, client: SocketAddr) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUFFER];
        loop {
            match tokio::time::timeout(UDP_IDLE, flow.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    let _ = listen.send_to(&buf[..n], client).await;
                }
                _ => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_port_target_uses_peer() {
        assert_eq!(
            resolve_target("443", Some("10.10.0.2")).unwrap(),
            "10.10.0.2:443"
        );
        assert_eq!(
            resolve_target("10.0.0.5:80", Some("10.10.0.2")).unwrap(),
            "10.0.0.5:80"
        );
        assert!(resolve_target("443", None).is_err());
    }
}
