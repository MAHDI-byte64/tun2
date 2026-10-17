//! The sealed l3 session: the GRE-framed packets are carried inside the tunnel's own
//! authenticated, encrypted session (reusing `crate::crypto` via [`crate::channel`] for the
//! KCP-family carriers, and the QUIC transport's TLS session for `quic`), then handed to an
//! unreliable carrier. There is never bare IP protocol 47 on the wire.
//!
//! Over the KCP-family carriers (`udp`, `faketcp`, `icmp`) the GRE packets ride the
//! datagram path ([`crate::channel::DatagramPath`]): each is sealed with keys from the
//! handshake and carries its own counter and replay window (see `crate::crypto::datagram`).
//! Over `quic` they ride QUIC's own unreliable DATAGRAM frames, encrypted and
//! replay-protected by the connection's TLS 1.3 session, whose peer identity is the token.
//!
//! Before any packet flows, the two ends exchange a short control message over the
//! authenticated reliable channel and compare the encapsulation (`encap = "gre"`), the GRE
//! key and the layer; a mismatch is refused by name.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::channel::{self, DatagramPath, Link};
use crate::config::Tuning;
use crate::crypto::{Crypto, ReplayFilter};
use crate::mux::Transport;
use crate::transport::{Dialer as TransportDialer, Listener as TransportListener, Settings};

#[cfg(feature = "quic")]
use crate::transport::quic::{QuicDialer, QuicListener, QuicSettings};

/// Both ends compare this in the control exchange and refuse a mismatch by name.
pub const ENCAP: &str = "gre";

/// Magic at the front of the control message, so a stray frame is not mistaken for one.
const CONTROL_MAGIC: [u8; 4] = *b"KZL3";
/// Control message version.
const CONTROL_VERSION: u8 = 1;
/// A sane upper bound on the encap name length in the control message.
const MAX_ENCAP_LEN: usize = 32;

/// Everything shared by every session of one l3 endpoint.
pub struct L3Params {
    pub carrier: crate::config::L3Carrier,
    pub crypto: Crypto,
    pub tuning: Tuning,
    pub settings: Settings,
    #[cfg(feature = "quic")]
    pub quic: Option<QuicSettings>,
    /// The layer (2 or 3) and GRE key both ends must agree on.
    pub layer: u8,
    pub gre_key: u32,
    /// Whether to ask the carrier to protect GRE datagrams with FEC (KCP carriers only).
    pub fec: bool,
}

/// The control message this end sends: magic, version, layer, GRE key and encap name.
fn control_message(layer: u8, gre_key: u32) -> Vec<u8> {
    let encap = ENCAP.as_bytes();
    let mut msg = Vec::with_capacity(11 + encap.len());
    msg.extend_from_slice(&CONTROL_MAGIC);
    msg.push(CONTROL_VERSION);
    msg.push(layer);
    msg.extend_from_slice(&gre_key.to_be_bytes());
    msg.push(encap.len() as u8);
    msg.extend_from_slice(encap);
    msg
}

/// Reads and verifies the peer's control message, refusing a mismatch by name.
async fn verify_control<S>(stream: &mut S, layer: u8, gre_key: u32) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 11];
    stream.read_exact(&mut head).await?;
    if head[..4] != CONTROL_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the peer did not send an l3 tunnel control message",
        ));
    }
    if head[4] != CONTROL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the peer speaks l3 control version {}, not {CONTROL_VERSION}",
                head[4]
            ),
        ));
    }
    let peer_layer = head[5];
    let peer_key = u32::from_be_bytes([head[6], head[7], head[8], head[9]]);
    let encap_len = head[10] as usize;
    if encap_len > MAX_ENCAP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the peer's encapsulation name is too long",
        ));
    }
    let mut encap = vec![0u8; encap_len];
    stream.read_exact(&mut encap).await?;
    let peer_encap = String::from_utf8_lossy(&encap);
    if peer_encap != ENCAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the peer's encapsulation is {peer_encap:?}, not {ENCAP:?}"),
        ));
    }
    if peer_layer != layer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the peer's l3 layer is {peer_layer}, not {layer}"),
        ));
    }
    if peer_key != gre_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the peer's GRE key is {peer_key}, not {gre_key}"),
        ));
    }
    Ok(())
}

/// A sealed l3 session over one carrier connection: the reliable channel is kept open (so
/// the carrier stays alive and the GRE path keeps flowing), and the GRE packets ride the
/// unreliable datagram path.
pub enum L3Session {
    /// A KCP-family carrier (`udp`, `faketcp`, `icmp`): the GRE packets ride the
    /// handshake-sealed datagram path. The link is held to keep the carrier up.
    Kcp {
        _link: Box<Link>,
        datagrams: Box<DatagramPath>,
        fec: bool,
    },
    /// The `quic` carrier: GRE packets ride QUIC DATAGRAM frames. The control streams are
    /// held so the connection is not closed.
    #[cfg(feature = "quic")]
    Quic {
        conn: quinn::Connection,
        _control: Box<(quinn::SendStream, quinn::RecvStream)>,
    },
}

impl L3Session {
    /// Seals and sends one GRE packet; `false` if it was dropped (a congested or closed
    /// carrier, or a packet too large for one datagram).
    pub fn send_gre(&self, gre_packet: &[u8]) -> bool {
        match self {
            Self::Kcp { datagrams, fec, .. } => datagrams.send(gre_packet, *fec),
            #[cfg(feature = "quic")]
            Self::Quic { conn, .. } => {
                let too_big = match conn.max_datagram_size() {
                    Some(max) => gre_packet.len() > max,
                    None => true,
                };
                if too_big {
                    return false;
                }
                conn.send_datagram(Bytes::copy_from_slice(gre_packet))
                    .is_ok()
            }
        }
    }

    /// Receives the next GRE packet; `None` once the carrier is gone.
    pub async fn recv_gre(&self) -> Option<Bytes> {
        match self {
            Self::Kcp { datagrams, .. } => datagrams.recv().await,
            #[cfg(feature = "quic")]
            Self::Quic { conn, .. } => conn.read_datagram().await.ok(),
        }
    }

    /// The largest GRE packet (header included) one datagram can carry.
    pub fn max_packet(&self) -> usize {
        match self {
            Self::Kcp { datagrams, .. } => datagrams.max_frame(),
            #[cfg(feature = "quic")]
            Self::Quic { conn, .. } => conn.max_datagram_size().unwrap_or(0),
        }
    }
}

/// The dialing end: reaches out and establishes a sealed session, retried by the caller.
pub enum L3Dialer {
    Kcp {
        dialer: Box<TransportDialer>,
        crypto: Crypto,
        layer: u8,
        gre_key: u32,
        fec: bool,
    },
    #[cfg(feature = "quic")]
    Quic {
        dialer: Box<QuicDialer>,
        layer: u8,
        gre_key: u32,
    },
}

impl L3Dialer {
    pub fn new(params: &L3Params, addr: &str) -> io::Result<Self> {
        match params.carrier {
            crate::config::L3Carrier::Quic => Self::new_quic(params, addr),
            _ => Ok(Self::Kcp {
                dialer: Box::new(TransportDialer::new(
                    &params.settings,
                    addr,
                    &params.tuning,
                )?),
                crypto: params.crypto.clone(),
                layer: params.layer,
                gre_key: params.gre_key,
                fec: params.fec,
            }),
        }
    }

    #[cfg(feature = "quic")]
    fn new_quic(params: &L3Params, addr: &str) -> io::Result<Self> {
        let quic = params.quic.as_ref().ok_or_else(quic_unconfigured)?;
        Ok(Self::Quic {
            dialer: Box::new(QuicDialer::new(addr, None, quic)?),
            layer: params.layer,
            gre_key: params.gre_key,
        })
    }

    #[cfg(not(feature = "quic"))]
    fn new_quic(_params: &L3Params, _addr: &str) -> io::Result<Self> {
        Err(quic_unsupported())
    }

    /// Dials and establishes one sealed session (handshake + control exchange).
    pub async fn dial(&self) -> io::Result<L3Session> {
        match self {
            Self::Kcp {
                dialer,
                crypto,
                layer,
                gre_key,
                fec,
            } => {
                let mut link = channel::connect(dialer, crypto, &[]).await?;
                link.write_all(&control_message(*layer, *gre_key)).await?;
                link.flush().await?;
                verify_control(&mut link, *layer, *gre_key).await?;
                let datagrams = link.take_datagram_path().ok_or_else(no_datagrams)?;
                Ok(L3Session::Kcp {
                    _link: Box::new(link),
                    datagrams: Box::new(datagrams),
                    fec: *fec,
                })
            }
            #[cfg(feature = "quic")]
            Self::Quic {
                dialer,
                layer,
                gre_key,
            } => {
                let conn = dialer.connect().await?;
                let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
                send.write_all(&control_message(*layer, *gre_key)).await?;
                send.flush().await?;
                verify_control(&mut recv, *layer, *gre_key).await?;
                Ok(L3Session::Quic {
                    conn,
                    _control: Box::new((send, recv)),
                })
            }
        }
    }
}

/// The listening end: waits for the inbound connection and establishes a sealed session.
pub enum L3Listener {
    Kcp {
        listener: Box<TransportListener>,
        crypto: Crypto,
        replay: Arc<ReplayFilter>,
        handshake_timeout: Duration,
        layer: u8,
        gre_key: u32,
        fec: bool,
    },
    #[cfg(feature = "quic")]
    Quic {
        listener: Box<QuicListener>,
        handshake_timeout: Duration,
        layer: u8,
        gre_key: u32,
    },
}

impl L3Listener {
    pub async fn bind(params: &L3Params, addr: &str) -> io::Result<Self> {
        match params.carrier {
            crate::config::L3Carrier::Quic => Self::bind_quic(params, addr).await,
            _ => Ok(Self::Kcp {
                listener: Box::new(
                    TransportListener::bind(&params.settings, addr, &params.tuning).await?,
                ),
                crypto: params.crypto.clone(),
                replay: Arc::new(ReplayFilter::default()),
                handshake_timeout: params.tuning.handshake_timeout,
                layer: params.layer,
                gre_key: params.gre_key,
                fec: params.fec,
            }),
        }
    }

    #[cfg(feature = "quic")]
    async fn bind_quic(params: &L3Params, addr: &str) -> io::Result<Self> {
        let quic = params.quic.as_ref().ok_or_else(quic_unconfigured)?;
        Ok(Self::Quic {
            listener: Box::new(QuicListener::bind(addr, quic).await?),
            handshake_timeout: params.tuning.handshake_timeout,
            layer: params.layer,
            gre_key: params.gre_key,
        })
    }

    #[cfg(not(feature = "quic"))]
    async fn bind_quic(_params: &L3Params, _addr: &str) -> io::Result<Self> {
        Err(quic_unsupported())
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Kcp { listener, .. } => listener.local_addr(),
            #[cfg(feature = "quic")]
            Self::Quic { listener, .. } => listener.local_addr(),
        }
    }

    /// Waits for the next peer and establishes a sealed session. A peer that fails the
    /// handshake or the control exchange is dropped (silently, as the rest of Kariz does);
    /// the caller loops.
    pub async fn accept(&self) -> io::Result<L3Session> {
        match self {
            Self::Kcp {
                listener,
                crypto,
                replay,
                handshake_timeout,
                layer,
                gre_key,
                fec,
            } => {
                let (incoming, _peer) = listener.accept().await?;
                let mut link =
                    channel::accept(incoming, crypto, replay, *handshake_timeout).await?;
                link.write_all(&control_message(*layer, *gre_key)).await?;
                link.flush().await?;
                verify_control(&mut link, *layer, *gre_key).await?;
                let datagrams = link.take_datagram_path().ok_or_else(no_datagrams)?;
                Ok(L3Session::Kcp {
                    _link: Box::new(link),
                    datagrams: Box::new(datagrams),
                    fec: *fec,
                })
            }
            #[cfg(feature = "quic")]
            Self::Quic {
                listener,
                handshake_timeout,
                layer,
                gre_key,
            } => {
                let accepting = listener.accept().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "the QUIC endpoint is closed")
                })?;
                let conn = tokio::time::timeout(*handshake_timeout, accepting.establish())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out")
                    })??;
                let (mut send, mut recv) = conn.accept_bi().await.map_err(io::Error::other)?;
                send.write_all(&control_message(*layer, *gre_key)).await?;
                send.flush().await?;
                verify_control(&mut recv, *layer, *gre_key).await?;
                Ok(L3Session::Quic {
                    conn,
                    _control: Box::new((send, recv)),
                })
            }
        }
    }
}

fn no_datagrams() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the l3 carrier did not provide a datagram path (needs [tunnel.kcp] datagrams)",
    )
}

#[cfg(feature = "quic")]
fn quic_unconfigured() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the quic carrier needs its endpoint settings",
    )
}

#[cfg(not(feature = "quic"))]
fn quic_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "carrier = \"quic\" needs the `quic` cargo feature, which this build lacks",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_message_roundtrips() {
        let msg = control_message(3, 0x1234_5678);
        assert_eq!(&msg[..4], &CONTROL_MAGIC);
        assert_eq!(msg[5], 3);
        assert_eq!(&msg[6..10], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&msg[11..], ENCAP.as_bytes());
    }

    async fn verify(bytes: &[u8], layer: u8, gre_key: u32) -> io::Result<()> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        verify_control(&mut cursor, layer, gre_key).await
    }

    #[tokio::test]
    async fn matching_control_is_accepted() {
        let msg = control_message(2, 7);
        verify(&msg, 2, 7).await.unwrap();
    }

    #[tokio::test]
    async fn mismatched_layer_key_and_magic_are_refused() {
        let msg = control_message(3, 1);
        assert!(verify(&msg, 2, 1)
            .await
            .unwrap_err()
            .to_string()
            .contains("layer"));
        assert!(verify(&msg, 3, 2)
            .await
            .unwrap_err()
            .to_string()
            .contains("GRE key"));
        assert!(verify(b"nope", 3, 1).await.is_err());
    }

    #[tokio::test]
    async fn a_foreign_encap_is_refused_by_name() {
        // Hand-built control message that names "ipip".
        let mut msg = Vec::new();
        msg.extend_from_slice(&CONTROL_MAGIC);
        msg.push(CONTROL_VERSION);
        msg.push(3);
        msg.extend_from_slice(&0u32.to_be_bytes());
        msg.push(4);
        msg.extend_from_slice(b"ipip");
        let err = verify(&msg, 3, 0).await.unwrap_err().to_string();
        assert!(err.contains("\"ipip\"") && err.contains("\"gre\""), "{err}");
    }
}
