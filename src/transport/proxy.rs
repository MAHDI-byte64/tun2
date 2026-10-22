//! A small SOCKS5 client for dialing out through a proxy.
//!
//! Only the panel uses it, for the links it dials to the servers it is set to reach through
//! its proxy: the proxy is handed to that one dialer ([`super::tcp::TcpTransportDialer::with_proxy`],
//! and from there [`crate::link::Dialer::via_proxy`]), so nothing else in the process, and
//! no tunnel, ever dials through it. SOCKS5 carries TCP, so only the stream transports
//! (`tcp`, `tcpmux`, `ws`, `wss`) can go through one.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// A SOCKS5 proxy to dial through, with optional username/password auth (RFC 1929).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5 {
    /// The proxy's own address, `host:port`.
    pub addr: String,
    /// Username and password, when the proxy requires them.
    pub auth: Option<(String, String)>,
}

fn proto(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("socks5: {msg}"))
}

/// A human reason for a SOCKS5 reply code (RFC 1928 §6).
fn reply_reason(code: u8) -> &'static str {
    match code {
        0x01 => "general proxy failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "proxy refused the connection",
    }
}

/// Splits `host:port` (keeping a bracketed IPv6 host) into the host and the port.
fn split_host_port(target: &str) -> io::Result<(&str, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| proto("target is not host:port"))?;
    let port: u16 = port.parse().map_err(|_| proto("target has a bad port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host, port))
}

impl Socks5 {
    /// Connects to the proxy and asks it to CONNECT to `target` (`host:port`), returning the
    /// tunnelled stream. `wait` bounds the whole exchange.
    pub async fn connect(&self, target: &str, wait: Duration) -> io::Result<TcpStream> {
        timeout(wait, self.handshake(target)).await.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "socks5 proxy connect timed out")
        })?
    }

    async fn handshake(&self, target: &str) -> io::Result<TcpStream> {
        let (host, port) = split_host_port(target)?;
        if host.is_empty() || host.len() > 255 {
            return Err(proto("target host is empty or too long"));
        }
        let mut s = TcpStream::connect(&self.addr).await?;
        s.set_nodelay(true).ok();

        // Greeting: offer no-auth, and user/pass when we have credentials.
        if self.auth.is_some() {
            s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            s.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await?;
        if sel[0] != 0x05 {
            return Err(proto("proxy is not SOCKS5"));
        }
        match sel[1] {
            0x00 => {}
            0x02 => {
                let (u, p) = self
                    .auth
                    .as_ref()
                    .ok_or_else(|| proto("proxy asked for auth but none is set"))?;
                if u.len() > 255 || p.len() > 255 {
                    return Err(proto("username or password is too long"));
                }
                let mut req = vec![0x01, u.len() as u8];
                req.extend_from_slice(u.as_bytes());
                req.push(p.len() as u8);
                req.extend_from_slice(p.as_bytes());
                s.write_all(&req).await?;
                let mut ar = [0u8; 2];
                s.read_exact(&mut ar).await?;
                if ar[1] != 0x00 {
                    return Err(proto("proxy rejected the username/password"));
                }
            }
            0xFF => return Err(proto("proxy offered no acceptable auth method")),
            _ => return Err(proto("proxy chose an unknown auth method")),
        }

        // CONNECT to the target as a domain name (the proxy resolves it).
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await?;

        // Reply: version, status, reserved, address type, bound address, bound port.
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("socks5: {}", reply_reason(head[1])),
            ));
        }
        let rest = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                l[0] as usize + 2
            }
            _ => return Err(proto("reply had an unknown address type")),
        };
        let mut bound = vec![0u8; rest];
        s.read_exact(&mut bound).await?;
        Ok(s)
    }
}

/// A SOCKS5 server for tests (the `test-util` feature, for the panel's tests too): it
/// accepts CONNECT, with no auth or with the one username/password it was given, dials the
/// target itself and relays both ways, as many connections as come. It counts the
/// connections it relayed, so a test can check that a link really went through it.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    pub struct Socks5Server {
        /// Where it listens, `127.0.0.1:port`.
        pub addr: String,
        relayed: Arc<AtomicU64>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Socks5Server {
        /// Listens on a free loopback port; with `auth`, only that username/password is let in.
        pub async fn start(auth: Option<(String, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let relayed = Arc::new(AtomicU64::new(0));
            let count = relayed.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let auth = auth.clone();
                    let count = count.clone();
                    tokio::spawn(async move {
                        if let Ok((mut client, mut target)) = serve(stream, auth.as_ref()).await {
                            count.fetch_add(1, Relaxed);
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                        }
                    });
                }
            });
            Self {
                addr,
                relayed,
                task,
            }
        }

        /// The SOCKS5 proxy a client dials this server as.
        pub fn proxy(&self, auth: Option<(String, String)>) -> super::Socks5 {
            super::Socks5 {
                addr: self.addr.clone(),
                auth,
            }
        }

        /// Connections relayed so far.
        pub fn relayed(&self) -> u64 {
            self.relayed.load(Relaxed)
        }
    }

    impl Drop for Socks5Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn bad(msg: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
    }

    /// The greeting, the auth and the CONNECT of one client; the client and the target
    /// streams, ready to relay.
    async fn serve(
        mut client: TcpStream,
        auth: Option<&(String, String)>,
    ) -> io::Result<(TcpStream, TcpStream)> {
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(bad("not SOCKS5"));
        }
        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;
        match auth {
            Some((user, pass)) => {
                if !methods.contains(&0x02) {
                    client.write_all(&[0x05, 0xFF]).await?;
                    return Err(bad("client offers no user/pass"));
                }
                client.write_all(&[0x05, 0x02]).await?;
                let mut v = [0u8; 2];
                client.read_exact(&mut v).await?;
                let mut u = vec![0u8; v[1] as usize];
                client.read_exact(&mut u).await?;
                let mut l = [0u8; 1];
                client.read_exact(&mut l).await?;
                let mut p = vec![0u8; l[0] as usize];
                client.read_exact(&mut p).await?;
                if u != user.as_bytes() || p != pass.as_bytes() {
                    client.write_all(&[0x01, 0x01]).await?;
                    return Err(bad("wrong user/pass"));
                }
                client.write_all(&[0x01, 0x00]).await?;
            }
            None => {
                if !methods.contains(&0x00) {
                    client.write_all(&[0x05, 0xFF]).await?;
                    return Err(bad("client offers no no-auth"));
                }
                client.write_all(&[0x05, 0x00]).await?;
            }
        }
        let mut req = [0u8; 4];
        client.read_exact(&mut req).await?;
        if req[1] != 0x01 {
            client
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(bad("not CONNECT"));
        }
        let host = match req[3] {
            0x01 => {
                let mut a = [0u8; 4];
                client.read_exact(&mut a).await?;
                Ipv4Addr::from(a).to_string()
            }
            0x04 => {
                let mut a = [0u8; 16];
                client.read_exact(&mut a).await?;
                format!("[{}]", Ipv6Addr::from(a))
            }
            0x03 => {
                let mut l = [0u8; 1];
                client.read_exact(&mut l).await?;
                let mut h = vec![0u8; l[0] as usize];
                client.read_exact(&mut h).await?;
                String::from_utf8(h).map_err(|_| bad("bad host"))?
            }
            _ => return Err(bad("bad address type")),
        };
        let mut port = [0u8; 2];
        client.read_exact(&mut port).await?;
        let target = match TcpStream::connect(format!("{host}:{}", u16::from_be_bytes(port))).await
        {
            Ok(t) => t,
            Err(e) => {
                client
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Err(e);
            }
        };
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        Ok((client, target))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Socks5Server;
    use super::*;

    #[test]
    fn host_port_splits_ipv4_and_bracketed_ipv6() {
        assert_eq!(split_host_port("1.2.3.4:443").unwrap(), ("1.2.3.4", 443));
        assert_eq!(split_host_port("[::1]:29001").unwrap(), ("::1", 29001));
        assert!(split_host_port("no-port").is_err());
        assert!(split_host_port("host:bad").is_err());
    }

    /// An echo server to be reached through the proxy.
    async fn echo() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    async fn round_trip(proxy: &Socks5, target: &str) -> io::Result<()> {
        let mut s = proxy.connect(target, Duration::from_secs(5)).await?;
        s.write_all(b"kariz").await?;
        let mut got = [0u8; 5];
        s.read_exact(&mut got).await?;
        assert_eq!(&got, b"kariz");
        Ok(())
    }

    #[tokio::test]
    async fn connects_through_a_socks5_server_without_auth() {
        let target = echo().await;
        let server = Socks5Server::start(None).await;
        round_trip(&server.proxy(None), &target).await.unwrap();
        round_trip(&server.proxy(None), &target).await.unwrap();
        assert_eq!(server.relayed(), 2);
    }

    #[tokio::test]
    async fn the_username_and_password_are_checked() {
        let target = echo().await;
        let auth = Some(("user".to_owned(), "pass".to_owned()));
        let server = Socks5Server::start(auth.clone()).await;
        round_trip(&server.proxy(auth), &target).await.unwrap();
        let wrong = server.proxy(Some(("user".into(), "nope".into())));
        let e = round_trip(&wrong, &target).await.unwrap_err();
        assert!(e.to_string().contains("rejected"), "{e}");
        // No credentials at all: the server offers nothing we accept.
        let e = round_trip(&server.proxy(None), &target).await.unwrap_err();
        assert!(e.to_string().contains("no acceptable auth"), "{e}");
        assert_eq!(server.relayed(), 1);
    }

    #[tokio::test]
    async fn a_target_the_proxy_cannot_reach_is_refused() {
        let server = Socks5Server::start(None).await;
        // A port nobody listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().to_string()
        };
        let e = round_trip(&server.proxy(None), &closed).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(server.relayed(), 0);
    }
}
