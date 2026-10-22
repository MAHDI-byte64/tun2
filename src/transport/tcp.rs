//! Plain TCP transport.

use std::io;
use std::net::SocketAddr;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::config::Tuning;

pub struct TcpTransportListener {
    inner: TcpListener,
    tuning: Tuning,
}

impl TcpTransportListener {
    pub async fn bind(addr: &str, tuning: &Tuning) -> io::Result<Self> {
        Ok(Self {
            inner: TcpListener::bind(addr).await?,
            tuning: tuning.clone(),
        })
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.inner.accept().await?;
        tune_tunnel_socket(&stream, &self.tuning)?;
        Ok((stream, peer))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

pub struct TcpTransportDialer {
    addr: String,
    tuning: Tuning,
}

impl TcpTransportDialer {
    pub fn new(addr: &str, tuning: &Tuning) -> Self {
        Self {
            addr: addr.to_owned(),
            tuning: tuning.clone(),
        }
    }

    pub async fn dial(&self) -> io::Result<TcpStream> {
        let stream = connect(&self.addr, &self.tuning).await?;
        tune_tunnel_socket(&stream, &self.tuning)?;
        Ok(stream)
    }
}

/// Connects to `addr` (resolved on every call) within the configured dial timeout.
pub async fn connect(addr: &str, tuning: &Tuning) -> io::Result<TcpStream> {
    let stream = timeout(tuning.dial_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect to {addr} timed out"),
            )
        })??;
    stream.set_nodelay(tuning.nodelay)?;
    Ok(stream)
}

/// Socket options for long-lived tunnel connections: nodelay plus TCP keepalive,
/// so NAT mappings stay open and dead peers are noticed, and with mux a small
/// unsent-data limit (see [`Tuning::notsent_lowat`]).
fn tune_tunnel_socket(stream: &TcpStream, tuning: &Tuning) -> io::Result<()> {
    stream.set_nodelay(tuning.nodelay)?;
    let keepalive = TcpKeepalive::new()
        .with_time(tuning.keepalive)
        .with_interval(tuning.keepalive);
    let sock = SockRef::from(stream);
    sock.set_tcp_keepalive(&keepalive)?;
    super::mark_dscp(&sock, tuning.dscp);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(lowat) = tuning.notsent_lowat {
        // Only a latency optimisation: an old kernel without it is no reason to fail.
        if let Err(e) = sock.set_tcp_notsent_lowat(lowat) {
            tracing::debug!(error = %e, "TCP_NOTSENT_LOWAT not available");
        }
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use crate::config::Profile;

    #[tokio::test]
    async fn tunnel_sockets_get_the_unsent_limit() {
        for lowat in [None, Some(16 * 1024)] {
            let tuning = Tuning {
                notsent_lowat: lowat,
                ..Tuning::for_profile(Profile::Balanced)
            };
            let listener = TcpTransportListener::bind("127.0.0.1:0", &tuning)
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let dialer = TcpTransportDialer::new(&addr, &tuning);
            let (dialed, accepted) = tokio::join!(dialer.dial(), listener.accept());
            for stream in [&dialed.unwrap(), &accepted.unwrap().0] {
                let got = SockRef::from(stream).tcp_notsent_lowat().unwrap();
                match lowat {
                    Some(v) => assert_eq!(got, v),
                    // Kernel default: no limit.
                    None => assert!(got == 0 || got == u32::MAX, "{got}"),
                }
            }
        }
    }
}
