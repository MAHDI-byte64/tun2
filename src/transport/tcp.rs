//! Plain TCP transport.

use std::io;
use std::net::SocketAddr;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::config::Tuning;
use crate::transport::proxy::Socks5;

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
    /// A SOCKS5 proxy to dial through instead of connecting to `addr` directly (the panel's
    /// links to the servers it reaches that way); `None` everywhere else. Boxed: a dialer is
    /// carried by value in a few enums, and this is the rare case.
    proxy: Option<Box<Socks5>>,
}

impl TcpTransportDialer {
    pub fn new(addr: &str, tuning: &Tuning) -> Self {
        Self {
            addr: addr.to_owned(),
            tuning: tuning.clone(),
            proxy: None,
        }
    }

    /// The same dialer, through `proxy` (or direct again with `None`).
    pub fn with_proxy(mut self, proxy: Option<Socks5>) -> Self {
        self.proxy = proxy.map(Box::new);
        self
    }

    pub async fn dial(&self) -> io::Result<TcpStream> {
        let stream = match &self.proxy {
            Some(proxy) => proxy.connect(&self.addr, self.tuning.dial_timeout).await?,
            None => connect(&self.addr, &self.tuning).await?,
        };
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
    tune_socket_options(&SockRef::from(&stream), tuning);
    Ok(stream)
}

/// `tuning.tcp_buffer` and `tuning.tcp_congestion`, when set, on any TCP connection:
/// tunnel, user or target. Both are best effort (the kernel caps the buffers at
/// `net.core.rmem_max` / `wmem_max`, and may not have the algorithm).
pub fn tune_socket_options(sock: &SockRef<'_>, tuning: &Tuning) {
    if let Some(size) = tuning.tcp_buffer {
        if let Err(e) = sock
            .set_recv_buffer_size(size)
            .and_then(|_| sock.set_send_buffer_size(size))
        {
            tracing::debug!(error = %e, size, "could not set the TCP socket buffers");
        }
    }
    if let Some(name) = &tuning.tcp_congestion {
        #[cfg(target_os = "linux")]
        if let Err(e) = sock.set_tcp_congestion(name.as_bytes()) {
            tracing::debug!(error = %e, name, "could not set the TCP congestion control");
        }
        #[cfg(not(target_os = "linux"))]
        tracing::debug!(name, "tuning.tcp_congestion is Linux only; ignored");
    }
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
    tune_socket_options(&sock, tuning);
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

    /// A buffer of our own size (the kernel reports twice what was asked, capped by its
    /// sysctl) and a congestion control the kernel has.
    #[tokio::test]
    async fn tunnel_sockets_take_the_buffer_and_congestion_knobs() {
        let tuning = Tuning {
            tcp_buffer: Some(128 * 1024),
            tcp_congestion: Some("cubic".into()),
            ..Tuning::for_profile(Profile::Balanced)
        };
        let listener = TcpTransportListener::bind("127.0.0.1:0", &tuning)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dialer = TcpTransportDialer::new(&addr, &tuning);
        let (dialed, accepted) = tokio::join!(dialer.dial(), listener.accept());
        for stream in [&dialed.unwrap(), &accepted.unwrap().0] {
            let sock = SockRef::from(stream);
            assert!(sock.recv_buffer_size().unwrap() >= 128 * 1024);
            assert!(sock.send_buffer_size().unwrap() >= 128 * 1024);
            // The kernel pads the name to 16 bytes.
            let name = sock.tcp_congestion().unwrap();
            assert_eq!(name.split(|b| *b == 0).next(), Some(&b"cubic"[..]));
        }
    }

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
