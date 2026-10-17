//! A minimal SOCKS5 CONNECT client, enough to dial one TCP target through a helper
//! client's local inbound. No authentication (the inbound is on loopback, on a random
//! port the helper supervisor owns), IPv4/IPv6/domain targets, CONNECT only.
//!
//! The helper dialers (`naive` via NaiveProxy's socks listener, `xhttp`/`reality` via
//! Xray's socks inbound) all expose a SOCKS5 inbound, so Kariz reaches the tunnel through
//! this one client. The CONNECT target is the acceptor's internal loopback listener.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const NO_AUTH: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Connects to the SOCKS5 inbound at `socks`, asks it to CONNECT to `target`, and returns
/// the stream positioned for tunnel traffic. The caller writes the tunnel bytes next.
pub async fn connect(socks: SocketAddr, target: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.set_nodelay(true).ok();

    // Greeting: version, one method, no authentication.
    stream.write_all(&[VERSION, 0x01, NO_AUTH]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != VERSION || reply[1] != NO_AUTH {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the helper's SOCKS5 inbound refused no-authentication",
        ));
    }

    // CONNECT request.
    let mut request = vec![VERSION, CMD_CONNECT, 0x00];
    match target.ip() {
        IpAddr::V4(ip) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    // Reply: version, status, reserved, address type, bound address, bound port.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the helper's SOCKS5 reply was not version 5",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "the helper refused the tunnel connection (SOCKS5 status {})",
                head[1]
            ),
        ));
    }
    let bound = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the helper's SOCKS5 reply had an unknown address type {other}"),
            ))
        }
    };
    let mut rest = vec![0u8; bound + 2];
    stream.read_exact(&mut rest).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A tiny SOCKS5 server that accepts a no-auth CONNECT and then echoes the stream.
    async fn socks_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            s.write_all(&[VERSION, NO_AUTH]).await.unwrap();
            // Read CONNECT (ver, cmd, rsv, atyp, 4-byte v4, 2-byte port).
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_CONNECT);
            // Reply success with a 0.0.0.0:0 bound address.
            s.write_all(&[VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn connect_then_relay() {
        let socks = socks_echo().await;
        let target: SocketAddr = "127.0.0.1:41234".parse().unwrap();
        let mut stream = connect(socks, target).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }
}
