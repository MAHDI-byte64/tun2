//! A small SOCKS5 client for routing outbound dials through a proxy, and the process-wide
//! setting the panel uses to send its agent (link) connections through one.
//!
//! Only the panel sets the global proxy, and only for its own process: the tunnel binary
//! never calls [`set_link_proxy`], so a tunnel's own transport dials are never affected. The
//! setting is consulted by [`super::tcp::connect`], the one place a stream transport opens a
//! TCP connection, so a `tcp`/`ws`/`wss` link dial goes through the proxy while everything
//! else is untouched.

use std::io;
use std::sync::RwLock;
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

/// The process-wide proxy the stream transports dial through (set by the panel; `None`
/// everywhere else). A `RwLock` so it can be changed when the panel's settings change.
static LINK_PROXY: RwLock<Option<Socks5>> = RwLock::new(None);

/// Sets (or clears) the process-wide proxy for outbound stream-transport dials.
pub fn set_link_proxy(proxy: Option<Socks5>) {
    if let Ok(mut g) = LINK_PROXY.write() {
        *g = proxy;
    }
}

/// The process-wide proxy, if one is set.
pub fn link_proxy() -> Option<Socks5> {
    LINK_PROXY.read().ok().and_then(|g| g.clone())
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
        if host.len() > 255 {
            return Err(proto("target host is too long"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_splits_ipv4_and_bracketed_ipv6() {
        assert_eq!(split_host_port("1.2.3.4:443").unwrap(), ("1.2.3.4", 443));
        assert_eq!(split_host_port("[::1]:29001").unwrap(), ("::1", 29001));
        assert!(split_host_port("no-port").is_err());
        assert!(split_host_port("host:bad").is_err());
    }

    // The global getter/setter (`set_link_proxy`/`link_proxy`) is exercised by the panel's
    // `proxy::tests::apply_routes_each_scope_to_its_own_place`. It is deliberately not tested
    // here: `connect` reads that same global, and several core tests in this crate dial
    // through `connect`, so setting it to a bogus address in a parallel unit test could make
    // one of those dials fail.

    /// Drives the client against a tiny in-process SOCKS5 server that expects no-auth and a
    /// CONNECT, so the greeting, the request framing and the reply parsing are exercised.
    #[tokio::test]
    async fn connects_through_a_minimal_socks5_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            // Greeting.
            let mut g = [0u8; 3];
            c.read_exact(&mut g).await.unwrap();
            assert_eq!(&g[..2], &[0x05, 0x01]);
            // Offer no-auth.
            c.write_all(&[0x05, 0x00]).await.unwrap();
            // CONNECT request: ver, cmd, rsv, atyp(domain), len, host, port.
            let mut h = [0u8; 5];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(&h[..4], &[0x05, 0x01, 0x00, 0x03]);
            let mut host = vec![0u8; h[4] as usize + 2];
            c.read_exact(&mut host).await.unwrap();
            // Success reply with a zero IPv4 bound address.
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // Echo one byte to prove the tunnel is usable.
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await.unwrap();
            c.write_all(&b).await.unwrap();
        });
        let proxy = Socks5 {
            addr: proxy_addr,
            auth: None,
        };
        let mut s = proxy
            .connect("example.com:443", Duration::from_secs(5))
            .await
            .unwrap();
        s.write_all(b"x").await.unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"x");
        server.await.unwrap();
    }
}
