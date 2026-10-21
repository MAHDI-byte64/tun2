//! Tunnel transports.
//!
//! Each transport provides a [`Listener`] and a [`Dialer`] that produce [`TunnelStream`]s.
//! Dispatch is done with enums instead of trait objects so the hot path stays
//! statically dispatched. New transports (udp) are added as new
//! variants. `tcpmux` is the `tcp` transport with mux on top, so it has no variant;
//! `ws` and `wss` share the WebSocket code and differ only in the TLS layer.

pub mod helper;
#[cfg(feature = "kcp")]
pub mod kcp;
#[cfg(not(feature = "kcp"))]
#[path = "kcp_disabled.rs"]
pub mod kcp;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
mod quic_obfs;
pub mod proxy;
pub mod split;
pub mod tcp;
pub mod tls;
pub mod ws;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::{TlsConfig, TransportKind, Tuning, TunnelConfig, WsConfig};

/// A TLS connection over TCP, either side.
pub type TlsTcp = tokio_rustls::TlsStream<TcpStream>;

/// The record-padding and timing-jitter parameters of the `stealth` transport.
///
/// It rides in [`Settings::stealth`] for stealth links only, so no other transport's wire
/// is touched. The record layer reads it as a [`crate::crypto::Shaping`] (see
/// [`StealthParams::shaping`]), set the same on both ends of the link.
#[derive(Debug, Clone)]
pub struct StealthParams {
    /// Add random padding inside each AEAD record.
    pub padding: bool,
    /// Largest padding per record, in bytes.
    pub pad_max: u16,
    /// Random delay before flushing a record.
    pub jitter: Duration,
}

impl StealthParams {
    /// The record-layer shaping these settings ask for: padding bounded by `pad_max` when
    /// it is on (`pad_max == 0` turns it off), and the timing jitter.
    pub fn shaping(&self) -> crate::crypto::Shaping {
        crate::crypto::Shaping {
            pad_max: if self.padding { self.pad_max } else { 0 },
            jitter: self.jitter,
        }
    }
}

/// The transport part of `[tunnel]`: everything listeners and dialers need besides the
/// address.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub kind: TransportKind,
    pub ws: Option<WsConfig>,
    pub tls: Option<TlsConfig>,
    pub kcp: kcp::KcpParams,
    /// Set for `transport = "stealth"`.
    pub stealth: Option<StealthParams>,
    /// Set for the managed-helper transports (`naive`, `xhttp`, `reality`).
    #[cfg(feature = "helpers")]
    pub helper: Option<helper::HelperParams>,
}

impl Settings {
    /// `kcp`: `[tunnel.kcp]` with the profile's defaults (`Config::kcp`).
    pub fn new(tunnel: &TunnelConfig, kcp: crate::config::KcpConfig) -> Self {
        let stealth = (tunnel.transport == TransportKind::Stealth).then(|| {
            let s = tunnel.stealth.clone().unwrap_or_default();
            StealthParams {
                padding: s.padding,
                pad_max: s.pad_max,
                jitter: Duration::from_millis(u64::from(s.jitter_ms)),
            }
        });
        #[cfg(feature = "helpers")]
        let helper = tunnel.transport.is_helper().then(|| helper::HelperParams {
            config: tunnel.helper.clone().unwrap_or_default(),
            token: tunnel.token.clone(),
        });
        Self {
            kind: tunnel.transport,
            ws: tunnel.ws.clone(),
            tls: tunnel.tls.clone(),
            kcp: kcp::KcpParams::new(tunnel, kcp),
            stealth,
            #[cfg(feature = "helpers")]
            helper,
        }
    }

    /// The same settings for a different transport, keeping the shared options (ws path, TLS,
    /// kcp). Used to build the receive link of an asymmetric tunnel from the send link's.
    pub fn with_kind(&self, kind: TransportKind) -> Self {
        Self {
            kind,
            ..self.clone()
        }
    }
}

pub enum Listener {
    Tcp(tcp::TcpTransportListener),
    /// `ws`, or `wss` with the acceptor.
    Ws(
        tcp::TcpTransportListener,
        Arc<ws::ServerConfig>,
        Option<TlsAcceptor>,
    ),
    Kcp(kcp::KcpListener),
    /// A managed-helper transport (`naive`, `xhttp`, `reality`): a supervised helper
    /// server process plus the Kariz-owned internal loopback listener it forwards to.
    #[cfg(all(feature = "helpers", unix))]
    Helper(helper::HelperListener),
    /// Asymmetric transport: the send-link and receive-link listeners, whose connections are
    /// paired in the background; `accept` yields already-combined streams.
    Split(Box<split::SplitListener>),
}

impl Listener {
    pub async fn bind(settings: &Settings, addr: &str, tuning: &Tuning) -> io::Result<Self> {
        // Certificate problems are reported before the port is taken.
        let tls = match settings.kind {
            TransportKind::Wss | TransportKind::Wssmux => {
                let tls = settings.tls.as_ref();
                let (Some(cert), Some(key)) = (
                    tls.and_then(|t| t.cert.as_deref()),
                    tls.and_then(|t| t.key.as_deref()),
                ) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wss needs tunnel.tls.cert and tunnel.tls.key",
                    ));
                };
                Some(tls::acceptor(cert, key)?)
            }
            _ => None,
        };
        match settings.kind {
            TransportKind::Quic | TransportKind::Auto => return Err(not_a_stream_transport()),
            // The KCP stack over its chosen carrier (UDP, or a raw-packet carrier).
            TransportKind::Kcp
            | TransportKind::Udp
            | TransportKind::Faketcp
            | TransportKind::Icmp
            | TransportKind::Proto47
            | TransportKind::Spoof => {
                let listener = kcp::KcpListener::bind(addr, &settings.kcp, tuning).await?;
                return Ok(Self::Kcp(listener));
            }
            TransportKind::Naive | TransportKind::Xhttp | TransportKind::Reality => {
                #[cfg(all(feature = "helpers", unix))]
                {
                    let listener = helper::HelperListener::bind(settings, addr, tuning).await?;
                    return Ok(Self::Helper(listener));
                }
                #[cfg(not(all(feature = "helpers", unix)))]
                {
                    return Err(helper::unsupported(settings.kind));
                }
            }
            _ => {}
        }
        let tcp = tcp::TcpTransportListener::bind(addr, tuning).await?;
        match settings.kind {
            TransportKind::Quic
            | TransportKind::Kcp
            | TransportKind::Auto
            | TransportKind::Udp
            | TransportKind::Faketcp
            | TransportKind::Icmp
            | TransportKind::Proto47
            | TransportKind::Spoof
            | TransportKind::Naive
            | TransportKind::Xhttp
            | TransportKind::Reality => {
                unreachable!("handled above")
            }
            // Stealth is a plain TCP stream here; its record-padding layer sits above the
            // transport (see `StealthParams`), so it needs no special listener.
            TransportKind::Tcp | TransportKind::Tcpmux | TransportKind::Stealth => {
                Ok(Self::Tcp(tcp))
            }
            TransportKind::Ws
            | TransportKind::Wss
            | TransportKind::Wsmux
            | TransportKind::Wssmux => Ok(Self::Ws(
                tcp,
                Arc::new(ws::ServerConfig::new(settings.ws.as_ref())),
                tls,
            )),
        }
    }

    /// Accepts a connection. Transports with their own handshake (TLS, the WebSocket
    /// upgrade) finish it in [`Incoming::establish`], so a slow client never holds up
    /// the accept loop.
    pub async fn accept(&self) -> io::Result<(Incoming, SocketAddr)> {
        match self {
            Self::Tcp(l) => {
                let (s, peer) = l.accept().await?;
                Ok((Incoming::Tcp(s), peer))
            }
            Self::Ws(l, config, tls) => {
                let (stream, peer) = l.accept().await?;
                let incoming = Incoming::Ws {
                    stream,
                    config: config.clone(),
                    tls: tls.clone(),
                    peer,
                };
                Ok((incoming, peer))
            }
            Self::Kcp(l) => {
                let (s, peer) = l.accept().await?;
                Ok((Incoming::Kcp(s), peer))
            }
            // A helper connection arrives as a plain TCP stream on the internal listener.
            #[cfg(all(feature = "helpers", unix))]
            Self::Helper(l) => {
                let (s, peer) = l.accept().await?;
                Ok((Incoming::Tcp(s), peer))
            }
            Self::Split(l) => l.accept().await,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(l) | Self::Ws(l, ..) => l.local_addr(),
            Self::Kcp(l) => l.local_addr(),
            #[cfg(all(feature = "helpers", unix))]
            Self::Helper(l) => l.local_addr(),
            Self::Split(l) => l.local_addr(),
        }
    }
}

/// An accepted connection whose transport handshake may still be pending.
pub enum Incoming {
    Tcp(TcpStream),
    /// An asymmetric tunnel's two links, already paired into one combined stream (the
    /// correlation id has been read off the send link, so the handshake comes next).
    Combined(TunnelStream),
    Ws {
        stream: TcpStream,
        config: Arc<ws::ServerConfig>,
        tls: Option<TlsAcceptor>,
        peer: SocketAddr,
    },
    Kcp(kcp::KcpStream),
}

impl Incoming {
    /// Finishes the transport handshake. A rejected WebSocket upgrade has already been
    /// answered (`404`) and closed when this returns an error. Callers bound the time.
    ///
    /// With WebSocket early data the `101` is held back until the first write, so the
    /// caller can still [`TunnelStream::reject_upgrade`] after checking what it read.
    pub async fn establish(self) -> io::Result<TunnelStream> {
        match self {
            Self::Tcp(s) => Ok(TunnelStream::Tcp(s)),
            Self::Kcp(s) => Ok(TunnelStream::Kcp(s)),
            // Already established and paired by the split listener.
            Self::Combined(stream) => Ok(stream),
            Self::Ws {
                mut stream,
                config,
                tls: None,
                peer,
            } => {
                let accepted = ws::upgrade::accept(&mut stream, &config, peer).await?;
                let (r, w) = stream.into_split();
                let mut stream = TunnelStream::Ws(ws::WsStream::accepted(r, w, accepted)?);
                stream.answer_upgrade().await?;
                Ok(stream)
            }
            Self::Ws {
                stream,
                config,
                tls: Some(acceptor),
                peer,
            } => {
                let mut stream = TlsTcp::Server(acceptor.accept(stream).await?);
                let accepted = ws::upgrade::accept(&mut stream, &config, peer).await?;
                let (r, w) = tokio::io::split(stream);
                let ws = ws::WsStream::accepted(r, w, accepted)?;
                let mut stream = TunnelStream::Wss(Box::new(ws));
                stream.answer_upgrade().await?;
                Ok(stream)
            }
        }
    }
}

pub enum Dialer {
    Tcp(tcp::TcpTransportDialer),
    Ws(tcp::TcpTransportDialer, Box<WsDialer>),
    Kcp(kcp::KcpDialer),
    /// A managed-helper transport: a supervised helper client process whose local SOCKS5
    /// inbound Kariz dials through.
    #[cfg(all(feature = "helpers", unix))]
    Helper(helper::HelperDialer),
    /// Asymmetric transport: two dialers (send link and receive link) joined into one
    /// combined stream. [`crate::channel::connect`] drives it like any other dialer.
    Split(Box<split::SplitDialer>),
}

/// WebSocket part of a [`Dialer`].
pub struct WsDialer {
    config: ws::ClientConfig,
    /// Set for `wss`.
    tls: Option<tls::Client>,
    /// Bound on the TLS handshake plus the upgrade round trip.
    timeout: Duration,
}

impl Dialer {
    pub fn new(settings: &Settings, addr: &str, tuning: &Tuning) -> io::Result<Self> {
        if settings.kind.is_kcp_based() {
            return Ok(Self::Kcp(kcp::KcpDialer::new(addr, &settings.kcp, tuning)));
        }
        let tcp = tcp::TcpTransportDialer::new(addr, tuning);
        let ws = settings.ws.as_ref();
        let (config, tls) = match settings.kind {
            // Stealth dials like TCP; its record-padding layer sits above the transport.
            TransportKind::Tcp | TransportKind::Tcpmux | TransportKind::Stealth => {
                return Ok(Self::Tcp(tcp))
            }
            TransportKind::Quic | TransportKind::Auto => return Err(not_a_stream_transport()),
            TransportKind::Kcp
            | TransportKind::Udp
            | TransportKind::Faketcp
            | TransportKind::Icmp
            | TransportKind::Proto47
            | TransportKind::Spoof => unreachable!("handled above"),
            TransportKind::Naive | TransportKind::Xhttp | TransportKind::Reality => {
                #[cfg(all(feature = "helpers", unix))]
                {
                    return Ok(Self::Helper(helper::HelperDialer::new(
                        settings, addr, tuning,
                    )?));
                }
                #[cfg(not(all(feature = "helpers", unix)))]
                {
                    return Err(helper::unsupported(settings.kind));
                }
            }
            TransportKind::Ws | TransportKind::Wsmux => {
                (ws::ClientConfig::new(ws, addr, "http", 80), None)
            }
            TransportKind::Wss | TransportKind::Wssmux => {
                // SNI: tls.sni, else the Host we send, else the host we dial.
                let host = ws.and_then(|w| w.host.as_deref()).unwrap_or(addr);
                let name = ws::upgrade::split_port(host).0;
                let name = name.trim_start_matches('[').trim_end_matches(']');
                let tls = tls::Client::new(settings.tls.as_ref(), name)?;
                (ws::ClientConfig::new(ws, addr, "https", 443), Some(tls))
            }
        };
        let dialer = WsDialer {
            config,
            tls,
            timeout: tuning.handshake_timeout,
        };
        Ok(Self::Ws(tcp, Box::new(dialer)))
    }

    pub async fn dial(&self) -> io::Result<TunnelStream> {
        self.dial_with(&[]).await
    }

    /// Dials and sends `first` (possibly empty) as the first bytes of the connection:
    /// in the upgrade request itself when WebSocket early data is on and it fits,
    /// otherwise as the first write.
    pub async fn dial_with(&self, first: &[u8]) -> io::Result<TunnelStream> {
        match self {
            Self::Tcp(d) => {
                let mut stream = d.dial().await?;
                if !first.is_empty() {
                    stream.write_all(first).await?;
                    stream.flush().await?;
                }
                Ok(TunnelStream::Tcp(stream))
            }
            Self::Kcp(d) => {
                let mut stream = d.dial().await?;
                if !first.is_empty() {
                    stream.write_all(first).await?;
                }
                Ok(TunnelStream::Kcp(stream))
            }
            #[cfg(all(feature = "helpers", unix))]
            Self::Helper(d) => d.dial_with(first).await,
            // Boxed to break the type-level async recursion (a split dialer's inner dialers
            // are themselves never split).
            Self::Split(d) => Box::pin(d.dial_with(first)).await,
            Self::Ws(d, ws) => {
                let stream = d.dial().await?;
                timeout(ws.timeout, ws.establish(stream, first))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TLS or websocket handshake timed out",
                        )
                    })?
            }
        }
    }
}

impl WsDialer {
    async fn establish(&self, mut stream: TcpStream, first: &[u8]) -> io::Result<TunnelStream> {
        let early = self.config.early_data() && first.len() <= ws::upgrade::MAX_EARLY_DATA;
        let (early, late) = if early {
            (first, &[][..])
        } else {
            (&[][..], first)
        };
        let mut stream = match &self.tls {
            None => {
                let read_ahead = ws::upgrade::connect(&mut stream, &self.config, early).await?;
                let (r, w) = stream.into_split();
                TunnelStream::Ws(ws::WsStream::new(r, w, ws::Role::Client, &read_ahead)?)
            }
            Some(tls) => {
                let mut stream = TlsTcp::Client(tls.connect(stream).await?);
                let read_ahead = ws::upgrade::connect(&mut stream, &self.config, early).await?;
                let (r, w) = tokio::io::split(stream);
                let ws = ws::WsStream::new(r, w, ws::Role::Client, &read_ahead)?;
                TunnelStream::Wss(Box::new(ws))
            }
        };
        if !late.is_empty() {
            stream.write_all(late).await?;
            stream.flush().await?;
        }
        Ok(stream)
    }
}

/// Marks a socket's packets with the DSCP codepoint `dscp`:
/// `IP_TOS` for IPv4, and on Unix `IPV6_TCLASS` for IPv6 (plus `IP_TOS` for the IPv4
/// traffic of a dual-stack socket). The ECN bits stay 0. Failing only costs the mark,
/// so it is logged rather than returned. Not for QUIC sockets: quinn sets the TOS byte of
/// every packet itself.
pub fn mark_dscp(sock: &socket2::SockRef<'_>, dscp: Option<u8>) {
    let Some(dscp) = dscp else {
        return;
    };
    let tos = u32::from(dscp) << 2;
    let ipv6 = sock
        .local_addr()
        .is_ok_and(|a| a.as_socket().is_some_and(|a| a.is_ipv6()));
    let result = if ipv6 {
        set_tclass(sock, tos)
    } else {
        sock.set_tos_v4(tos)
    };
    if let Err(e) = result {
        tracing::debug!(error = %e, dscp, "could not set the DSCP mark");
    }
}

#[cfg(unix)]
fn set_tclass(sock: &socket2::SockRef<'_>, tos: u32) -> io::Result<()> {
    let result = sock.set_tclass_v6(tos);
    // IPv4 peers of a dual-stack socket; a v6-only socket refuses it, which is fine.
    let _ = sock.set_tos_v4(tos);
    result
}

#[cfg(not(unix))]
fn set_tclass(_: &socket2::SockRef<'_>, _: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPV6_TCLASS is not available on this system",
    ))
}

/// QUIC is not a byte stream: it has its own endpoints ([`quic`]) and sessions.
fn not_a_stream_transport() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "quic is not a stream transport; use transport::quic",
    )
}

/// A single tunnel connection, whatever transport carries it.
pub enum TunnelStream {
    Tcp(TcpStream),
    Ws(ws::WsStream<OwnedReadHalf, OwnedWriteHalf>),
    /// Boxed: the TLS state is large, and it is one allocation per connection.
    /// TLS state is shared by both directions, so its halves share a lock.
    Wss(Box<ws::WsStream<ReadHalf<TlsTcp>, WriteHalf<TlsTcp>>>),
    Kcp(kcp::KcpStream),
    /// Asymmetric transport: writes go to one physical connection and reads come from a
    /// second, so the two tunnel directions can ride different transports. Built by
    /// [`crate::channel::connect_split`] / [`crate::channel::accept_split`] from two already
    /// established links; the handshake and everything above it run over it unchanged. The
    /// two *unused* halves (this connection's read side on the send link, its write side on
    /// the receive link) are dropped — safe for the stream transports (`tcp`, `ws`, `wss`),
    /// which only close the idle direction; KCP-based links are not allowed here (they would
    /// half-close prematurely).
    Combined {
        reader: TunnelReader,
        writer: TunnelWriter,
    },
}

impl TunnelStream {
    /// The datagram side of a KCP connection; other transports have none.
    pub fn datagrams(&self) -> Option<kcp::KcpDatagrams> {
        match self {
            Self::Kcp(s) => s.datagrams(),
            Self::Tcp(_) | Self::Ws(_) | Self::Wss(_) | Self::Combined { .. } => None,
        }
    }

    /// Sends a held-back `101` now unless early data came with the request, in which
    /// case the caller checks that first (see [`Self::reject_upgrade`]).
    async fn answer_upgrade(&mut self) -> io::Result<()> {
        let early = match self {
            // The combined stream is built after each link's upgrade is already finished.
            Self::Tcp(_) | Self::Kcp(_) | Self::Combined { .. } => return Ok(()),
            Self::Ws(s) => s.reader().has_early(),
            Self::Wss(s) => s.reader().has_early(),
        };
        if !early {
            self.flush().await?;
        }
        Ok(())
    }

    /// Listening side of a WebSocket with early data: if the `101` has not gone out
    /// yet, replace it with a `404` (sent on shutdown) and return true. For anything
    /// else, false: the connection has to be dealt with some other way.
    pub fn reject_upgrade(&mut self) -> bool {
        match self {
            Self::Tcp(_) | Self::Kcp(_) | Self::Combined { .. } => false,
            Self::Ws(s) => s.reject_upgrade(),
            Self::Wss(s) => s.reject_upgrade(),
        }
    }

    /// Cheap, non-blocking check that an idle connection has not been closed by the peer.
    /// Only meaningful while the peer is not expected to send anything: whatever
    /// arrives counts as "not idle", and may be consumed by the check.
    pub fn is_alive(&mut self) -> bool {
        let mut probe = [0u8; 1];
        let would_block =
            |r: io::Result<usize>| matches!(r, Err(e) if e.kind() == io::ErrorKind::WouldBlock);
        match self {
            Self::Tcp(s) => would_block(s.try_read(&mut probe)),
            Self::Kcp(s) => s.is_alive(),
            // Anything from the peer (even a ping) means the connection is not idle.
            Self::Ws(s) => {
                !s.reader().has_buffered() && would_block(s.reader().get_ref().try_read(&mut probe))
            }
            // TLS may carry records that are not data (tickets, key updates), so read
            // through it; pending means idle and open.
            Self::Wss(s) => {
                let waker = Waker::from(Arc::new(NoopWaker));
                let mut buf = ReadBuf::new(&mut probe);
                Pin::new(&mut **s)
                    .poll_read(&mut Context::from_waker(&waker), &mut buf)
                    .is_pending()
            }
            // Probe the receive link the same way (pending means idle and open).
            Self::Combined { reader, .. } => {
                let waker = Waker::from(Arc::new(NoopWaker));
                let mut buf = ReadBuf::new(&mut probe);
                Pin::new(reader)
                    .poll_read(&mut Context::from_waker(&waker), &mut buf)
                    .is_pending()
            }
        }
    }
}

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_read(cx, buf),
            Self::Wss(s) => Pin::new(&mut **s).poll_read(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Combined { reader, .. } => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_write(cx, buf),
            Self::Wss(s) => Pin::new(&mut **s).poll_write(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Combined { writer, .. } => Pin::new(writer).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Ws(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Wss(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
            Self::Kcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Combined { writer, .. } => Pin::new(writer).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Ws(s) => s.is_write_vectored(),
            Self::Wss(s) => s.is_write_vectored(),
            Self::Kcp(_) => false,
            Self::Combined { writer, .. } => writer.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Ws(s) => Pin::new(s).poll_flush(cx),
            Self::Wss(s) => Pin::new(&mut **s).poll_flush(cx),
            Self::Kcp(s) => Pin::new(s).poll_flush(cx),
            Self::Combined { writer, .. } => Pin::new(writer).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Ws(s) => Pin::new(s).poll_shutdown(cx),
            Self::Wss(s) => Pin::new(&mut **s).poll_shutdown(cx),
            Self::Kcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Combined { writer, .. } => Pin::new(writer).poll_shutdown(cx),
        }
    }
}

impl TunnelStream {
    /// Splits into independently usable halves (no lock between them).
    // Without the `kcp` feature its stream type has no values, so its arm cannot run.
    #[cfg_attr(not(feature = "kcp"), allow(unreachable_code))]
    pub fn into_split(self) -> (TunnelReader, TunnelWriter) {
        match self {
            Self::Tcp(s) => {
                let (r, w) = s.into_split();
                (TunnelReader::Tcp(r), TunnelWriter::Tcp(w))
            }
            Self::Ws(s) => {
                let (r, w) = s.into_split();
                (TunnelReader::Ws(r), TunnelWriter::Ws(w))
            }
            Self::Wss(s) => {
                let (r, w) = s.into_split();
                (
                    TunnelReader::Wss(Box::new(r)),
                    TunnelWriter::Wss(Box::new(w)),
                )
            }
            Self::Kcp(s) => {
                let (r, w) = s.into_split();
                (TunnelReader::Kcp(r), TunnelWriter::Kcp(w))
            }
            // Already a reader from one link and a writer from the other.
            Self::Combined { reader, writer } => (reader, writer),
        }
    }
}

/// Receiving half of a [`TunnelStream`].
pub enum TunnelReader {
    Tcp(OwnedReadHalf),
    Ws(ws::WsReader<OwnedReadHalf>),
    Wss(Box<ws::WsReader<ReadHalf<TlsTcp>>>),
    Kcp(kcp::KcpReader),
}

/// Sending half of a [`TunnelStream`].
pub enum TunnelWriter {
    Tcp(OwnedWriteHalf),
    Ws(ws::WsWriter<OwnedWriteHalf>),
    Wss(Box<ws::WsWriter<WriteHalf<TlsTcp>>>),
    Kcp(kcp::KcpWriter),
}

impl AsyncRead for TunnelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_read(cx, buf),
            Self::Wss(s) => Pin::new(&mut **s).poll_read(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_write(cx, buf),
            Self::Wss(s) => Pin::new(&mut **s).poll_write(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Ws(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Wss(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
            Self::Kcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Ws(s) => s.is_write_vectored(),
            Self::Wss(s) => s.is_write_vectored(),
            Self::Kcp(_) => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Ws(s) => Pin::new(s).poll_flush(cx),
            Self::Wss(s) => Pin::new(&mut **s).poll_flush(cx),
            Self::Kcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Ws(s) => Pin::new(s).poll_shutdown(cx),
            Self::Wss(s) => Pin::new(&mut **s).poll_shutdown(cx),
            Self::Kcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use socket2::SockRef;

    use super::*;
    use crate::config::Profile;

    /// The TOS byte (IPv4) or traffic class (IPv6) a socket reports back.
    pub(crate) fn mark_of(sock: SockRef<'_>) -> u32 {
        let local = sock.local_addr().unwrap().as_socket().unwrap();
        if local.is_ipv4() {
            return sock.tos_v4().unwrap();
        }
        #[cfg(unix)]
        return sock.tclass_v6().unwrap();
        #[cfg(not(unix))]
        unreachable!("IPv6 marks are only set on Unix");
    }

    /// Addresses to test marks on: IPv4, and IPv6 where it can be read back and the
    /// machine has it.
    pub(crate) fn local_addrs() -> Vec<&'static str> {
        let mut addrs = vec!["127.0.0.1:0"];
        if cfg!(unix) && std::net::UdpSocket::bind("[::1]:0").is_ok() {
            addrs.push("[::1]:0");
        }
        addrs
    }

    pub(crate) fn tos(dscp: Option<u8>) -> u32 {
        dscp.map_or(0, |d| u32::from(d) << 2)
    }

    #[test]
    fn udp_sockets_are_marked() {
        for addr in local_addrs() {
            for dscp in [None, Some(46), Some(34)] {
                let socket = std::net::UdpSocket::bind(addr).unwrap();
                mark_dscp(&SockRef::from(&socket), dscp);
                assert_eq!(
                    mark_of(SockRef::from(&socket)),
                    tos(dscp),
                    "{addr} {dscp:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn tcp_tunnel_sockets_are_marked_both_ways() {
        for addr in local_addrs() {
            for dscp in [None, Some(46)] {
                let tuning = Tuning {
                    dscp,
                    ..Tuning::for_profile(Profile::Balanced)
                };
                let settings = Settings::default();
                let l = Listener::bind(&settings, addr, &tuning).await.unwrap();
                let remote = l.local_addr().unwrap().to_string();
                let d = Dialer::new(&settings, &remote, &tuning).unwrap();
                let (dialed, accepted) = tokio::join!(d.dial(), l.accept());
                let TunnelStream::Tcp(dialed) = dialed.unwrap() else {
                    panic!("not tcp")
                };
                let Incoming::Tcp(accepted) = accepted.unwrap().0 else {
                    panic!("not tcp")
                };
                for s in [&dialed, &accepted] {
                    assert_eq!(mark_of(SockRef::from(s)), tos(dscp), "{addr} {dscp:?}");
                }
            }
        }
    }
}
