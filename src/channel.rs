//! Channels: authenticated paths through the tunnel, one per user connection.
//!
//! Entry and exit only deal with [`Channel`]s and never touch the handshake or the
//! transport directly. The handshake turns a transport connection into a [`Link`] (an
//! authenticated, normally encrypted connection). A channel is then either a whole link
//! or one stream of a mux session running over a link.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{timeout_at, Instant};

use crate::crypto::datagram::{self, DatagramOpener, DatagramSealer};
use crate::crypto::handshake::{self, SessionKeys};
use crate::crypto::record::{
    Opener, Sealer, SecureReader, SecureStream, SecureWriter, MAX_PAYLOAD,
};
use crate::crypto::{random_below, Cipher, Crypto, ReplayFilter, Shaping};
use crate::mux::Transport;
use crate::session::SessionStream;
use crate::transport::kcp::KcpDatagrams;
use crate::transport::{Dialer, Incoming, TunnelReader, TunnelStream, TunnelWriter};

/// A failed handshake is drained for a random time in this range (seconds).
const DRAIN_SECS: (u64, u64) = (5, 30);
/// Stop reading (but keep the connection open) after this many drained bytes.
const DRAIN_MAX_BYTES: usize = 1 << 20;

/// An authenticated tunnel connection, the result of a handshake.
pub struct Link {
    io: LinkIo,
    /// Beside a KCP connection that carries mux: the datagram path, which the mux session
    /// takes. Boxed for the same reason as `LinkIo::Secure`.
    datagrams: Option<Box<DatagramPath>>,
}

enum LinkIo {
    /// `encryption = "none"`: authenticated, but the bytes are sent as they are.
    Plain(TunnelStream),
    /// Boxed: the cipher key schedules make it large, and it is one allocation per
    /// tunnel connection, not per packet.
    Secure(Box<SecureStream<TunnelStream>>),
}

impl Link {
    /// `mux`: the link will carry a mux session, which may then use a datagram path.
    /// `shaping`: the record-layer padding and jitter of a stealth link (`None` otherwise).
    fn new(
        stream: TunnelStream,
        keys: SessionKeys,
        dialer: bool,
        early: Option<&handshake::Key>,
        mux: bool,
        shaping: Option<Shaping>,
    ) -> io::Result<Self> {
        let datagrams = match stream.datagrams() {
            Some(kcp) if mux => Some(Box::new(DatagramPath::new(kcp, &keys, dialer)?)),
            _ => None,
        };
        if keys.cipher == Cipher::None {
            return Ok(Self {
                io: LinkIo::Plain(stream),
                datagrams,
            });
        }
        let (send, recv) = if dialer {
            (&keys.c2s, &keys.s2c)
        } else {
            (&keys.s2c, &keys.c2s)
        };
        let early = early.map(|k| Opener::new(keys.cipher, k)).transpose()?;
        // On a stealth link the sealer pads and the opener strips; the padding field is in
        // the record only when the peer pads (`pad_max > 0`), so the opener matches it.
        let (sealer, opener) = match shaping {
            Some(s) => (
                Sealer::stealth(keys.cipher, send, s)?,
                if s.pad_max > 0 {
                    Opener::stealth(keys.cipher, recv)?
                } else {
                    Opener::new(keys.cipher, recv)?
                },
            ),
            None => (
                Sealer::new(keys.cipher, send)?,
                Opener::new(keys.cipher, recv)?,
            ),
        };
        let secure = SecureStream::new(stream, sealer, opener, early);
        Ok(Self {
            io: LinkIo::Secure(Box::new(secure)),
            datagrams,
        })
    }

    /// Cheap, non-blocking check that an idle link has not been closed by the peer.
    /// Only meaningful while the peer is not expected to send anything.
    pub fn is_alive(&mut self) -> bool {
        match &mut self.io {
            LinkIo::Plain(s) => s.is_alive(),
            LinkIo::Secure(s) => s.get_mut().is_alive(),
        }
    }
}

/// The datagram path beside a KCP link: mux frames
/// sealed with keys from the handshake and sent as KCP datagrams, unreliably.
pub struct DatagramPath {
    kcp: KcpDatagrams,
    sealer: std::sync::Mutex<DatagramSealer>,
    opener: std::sync::Mutex<DatagramOpener>,
    max_frame: usize,
}

impl DatagramPath {
    fn new(kcp: KcpDatagrams, keys: &SessionKeys, dialer: bool) -> io::Result<Self> {
        // The record keys of each direction, from which the datagram keys derive.
        let (send, recv) = if dialer {
            (&keys.c2s, &keys.s2c)
        } else {
            (&keys.s2c, &keys.c2s)
        };
        let max_frame = kcp
            .max_len()
            .saturating_sub(datagram::overhead(keys.cipher));
        Ok(Self {
            kcp,
            sealer: std::sync::Mutex::new(DatagramSealer::new(keys.cipher, send)?),
            opener: std::sync::Mutex::new(DatagramOpener::new(keys.cipher, recv)?),
            max_frame,
        })
    }

    /// Largest frame (mux header and payload) that fits in one datagram.
    pub fn max_frame(&self) -> usize {
        self.max_frame
    }

    /// Seals and sends `frame` at once; false if it was dropped. `fec`: see
    /// [`KcpDatagrams::send`].
    pub fn send(&self, frame: &[u8], fec: bool) -> bool {
        let mut sealed = Vec::with_capacity(frame.len() + datagram::overhead(Cipher::Aes256Gcm));
        let sealer = &mut *self.sealer.lock().unwrap_or_else(|e| e.into_inner());
        if sealer.seal(frame, &mut sealed).is_err() {
            return false;
        }
        self.kcp.send(&sealed, fec)
    }

    /// The next frame that opens (others are dropped); `None` once the link is over.
    pub async fn recv(&self) -> Option<Bytes> {
        loop {
            let mut datagram = self.kcp.recv().await?.to_vec();
            let opener = &mut *self.opener.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(frame) = opener.open(&mut datagram) {
                return Some(Bytes::copy_from_slice(frame));
            }
        }
    }
}

/// Receiving half of a [`Link`].
pub enum LinkReader {
    Plain(TunnelReader),
    Secure(Box<SecureReader<TunnelReader>>),
}

/// Sending half of a [`Link`].
pub enum LinkWriter {
    Plain(TunnelWriter),
    Secure(Box<SecureWriter<TunnelWriter>>),
}

impl Transport for Link {
    type Reader = LinkReader;
    type Writer = LinkWriter;

    fn take_datagram_path(&mut self) -> Option<DatagramPath> {
        self.datagrams.take().map(|path| *path)
    }

    fn into_halves(self) -> (LinkReader, LinkWriter) {
        match self.io {
            LinkIo::Plain(s) => {
                let (r, w) = s.into_split();
                (LinkReader::Plain(r), LinkWriter::Plain(w))
            }
            LinkIo::Secure(s) => {
                let (r, w) = s.split(TunnelStream::into_split);
                (
                    LinkReader::Secure(Box::new(r)),
                    LinkWriter::Secure(Box::new(w)),
                )
            }
        }
    }
}

/// One user connection's path through the tunnel.
pub enum Channel {
    /// A whole link used for this connection alone.
    Link(Link),
    /// One stream of a session (kmux).
    Stream(SessionStream),
}

impl From<Link> for Channel {
    fn from(link: Link) -> Self {
        Self::Link(link)
    }
}

/// Dialing side: opens a tunnel connection with `dialer` and runs the handshake on it.
/// `early` (possibly empty) goes out in the same write as the hello (0-RTT), so the
/// other side can act on it before the handshake round trip completes. With WebSocket
/// early data, both even ride in the upgrade request.
///
/// Callers bound the time: dial plus handshake.
pub async fn connect(dialer: &Dialer, crypto: &Crypto, early: &[u8]) -> io::Result<Link> {
    let cipher = crypto.cipher();
    let sealed_early = cipher != Cipher::None && !early.is_empty() && early.len() <= MAX_PAYLOAD;
    let (mut msg, state) =
        handshake::client_hello(crypto.psk(), cipher, sealed_early, crypto.mux())?;
    let mut late: &[u8] = &[];
    match state.early_key() {
        Some(key) => Sealer::new(cipher, key)?.seal(early, &mut msg)?,
        // Without encryption the early data simply follows the hello.
        None if cipher == Cipher::None => msg.extend_from_slice(early),
        // Too long for one record: send it after the handshake instead.
        None => late = early,
    }
    let mut stream = dialer.dial_with(&msg).await?;
    let keys = state.read_reply(&mut stream).await?;
    let mut link = Link::new(stream, keys, true, None, crypto.mux(), crypto.shaping())?;
    if !late.is_empty() {
        link.write_all(late).await?;
        link.flush().await?;
    }
    Ok(link)
}

/// Listening side: finishes the transport handshake (the WebSocket upgrade) and runs
/// the tunnel handshake on a connection the other side opened, both within
/// `handshake_timeout`.
///
/// A connection that fails the tunnel handshake (or does not finish it in time) is not
/// closed right away: it is read and discarded for a random time first, so probing does
/// not reveal a Kariz server by how fast it hangs up. A failed WebSocket upgrade has
/// been answered like a web server would and is closed; so is an upgrade whose early
/// data does not hold a valid hello (`404` instead of `101`).
pub async fn accept(
    incoming: Incoming,
    crypto: &Crypto,
    replay: &ReplayFilter,
    handshake_timeout: Duration,
) -> io::Result<Link> {
    let deadline = Instant::now() + handshake_timeout;
    let mut stream = timeout_at(deadline, incoming.establish())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "transport handshake timed out"))??;
    let result = timeout_at(
        deadline,
        handshake::accept(
            &mut stream,
            crypto.psk(),
            replay,
            |c| crypto.allows(c),
            crypto.mux(),
        ),
    )
    .await
    .unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "handshake timed out",
        ))
    });
    match result {
        Ok(accepted) => Link::new(
            stream,
            accepted.keys,
            false,
            accepted.early_key.as_ref(),
            crypto.mux(),
            crypto.shaping(),
        ),
        // The peer proved it knows the token; it is misconfigured, not probing.
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            let _ = timeout_at(deadline, stream.shutdown()).await;
            Err(e)
        }
        Err(e) => {
            if stream.reject_upgrade() {
                let _ = timeout_at(deadline + Duration::from_secs(1), stream.shutdown()).await;
            } else {
                drain(stream).await;
            }
            Err(e)
        }
    }
}

async fn drain(mut stream: TunnelStream) {
    let (min, max) = DRAIN_SECS;
    let secs = min + random_below((max - min + 1) as u32).map_or(0, u64::from);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let _ = timeout_at(deadline, async {
        let mut buf = [0u8; 4096];
        let mut total = 0;
        while total < DRAIN_MAX_BYTES {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => total += n,
            }
        }
        std::future::pending::<()>().await
    })
    .await;
}

impl AsyncRead for Link {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            LinkIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            LinkIo::Secure(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Link {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().io {
            LinkIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
            LinkIo::Secure(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().io {
            LinkIo::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            LinkIo::Secure(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.io {
            LinkIo::Plain(s) => s.is_write_vectored(),
            LinkIo::Secure(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            LinkIo::Plain(s) => Pin::new(s).poll_flush(cx),
            LinkIo::Secure(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            LinkIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            LinkIo::Secure(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for LinkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Secure(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LinkWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Secure(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Secure(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Secure(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Secure(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Secure(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Encryption, Tuning};
    use crate::transport::{Dialer, Listener, Settings};

    async fn listener() -> (Listener, Dialer) {
        let tuning = Tuning::for_profile(Default::default());
        let settings = Settings::default();
        let l = Listener::bind(&settings, "127.0.0.1:0", &tuning)
            .await
            .unwrap();
        let addr = l.local_addr().unwrap().to_string();
        (l, Dialer::new(&settings, &addr, &tuning).unwrap())
    }

    const TOKEN: &str = "channel-test-token-0123";

    #[tokio::test]
    async fn early_data_arrives_first_then_both_directions_work() {
        for (enc, early_len) in [
            (Encryption::Auto, 20),
            (Encryption::Chacha20Poly1305, MAX_PAYLOAD + 10),
            (Encryption::None, 20),
            (Encryption::Auto, 0),
        ] {
            let (l, d) = listener().await;
            let crypto = Crypto::new(TOKEN, enc);
            let c2 = crypto.clone();
            let early = vec![7u8; early_len];
            let e2 = early.clone();
            let server = tokio::spawn(async move {
                let (s, _) = l.accept().await.unwrap();
                let mut ch = accept(s, &c2, &ReplayFilter::default(), Duration::from_secs(5))
                    .await
                    .unwrap();
                let mut got = vec![0u8; e2.len() + 5];
                ch.read_exact(&mut got).await.unwrap();
                ch.write_all(b"pong").await.unwrap();
                ch.flush().await.unwrap();
                got
            });
            let mut ch = connect(&d, &crypto, &early).await.unwrap();
            assert_eq!(matches!(ch.io, LinkIo::Plain(_)), enc == Encryption::None);
            ch.write_all(b"hello").await.unwrap();
            ch.flush().await.unwrap();
            let mut pong = [0u8; 4];
            ch.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            assert_eq!(server.await.unwrap(), [early, b"hello".to_vec()].concat());
        }
    }

    #[tokio::test]
    async fn failed_handshake_is_not_closed_right_away() {
        let (l, d) = listener().await;
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let crypto = Crypto::new(TOKEN, Encryption::Auto);
            let _ = accept(s, &crypto, &ReplayFilter::default(), Duration::from_secs(5)).await;
        });
        let mut probe = d.dial().await.unwrap();
        probe.write_all(&[0x16; 600]).await.unwrap();
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), probe.read(&mut buf)).await;
        assert!(read.is_err(), "probe got an answer or a close: {read:?}");
    }

    #[tokio::test]
    async fn cipher_mismatch_fails_fast() {
        let (l, d) = listener().await;
        let server = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let crypto = Crypto::new(TOKEN, Encryption::Chacha20Poly1305);
            accept(s, &crypto, &ReplayFilter::default(), Duration::from_secs(5))
                .await
                .err()
                .unwrap()
        });
        let crypto = Crypto::new(TOKEN, Encryption::Aes256Gcm);
        let started = std::time::Instant::now();
        assert!(connect(&d, &crypto, &[]).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(server.await.unwrap().kind(), io::ErrorKind::Unsupported);
    }

    /// Forwards one connection to `to` and returns everything that crossed it.
    async fn spy(to: std::net::SocketAddr) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut a, _) = l.accept().await.unwrap();
            let mut b = tokio::net::TcpStream::connect(to).await.unwrap();
            let (mut ar, mut aw) = a.split();
            let (mut br, mut bw) = b.split();
            let mut seen = Vec::new();
            let (mut up, mut down) = (vec![0u8; 4096], vec![0u8; 4096]);
            let (mut up_open, mut down_open) = (true, true);
            while up_open || down_open {
                tokio::select! {
                    n = ar.read(&mut up), if up_open => match n.unwrap_or(0) {
                        0 => { up_open = false; let _ = bw.shutdown().await; }
                        n => { seen.extend_from_slice(&up[..n]); bw.write_all(&up[..n]).await.unwrap(); }
                    },
                    n = br.read(&mut down), if down_open => match n.unwrap_or(0) {
                        0 => { down_open = false; let _ = aw.shutdown().await; }
                        n => { seen.extend_from_slice(&down[..n]); aw.write_all(&down[..n]).await.unwrap(); }
                    },
                }
            }
            seen
        });
        (port, task)
    }

    #[tokio::test]
    async fn nothing_readable_on_the_wire() {
        const MARKER: &[u8] = b"KARIZ-PLAINTEXT-MARKER";
        for enc in [Encryption::Auto, Encryption::None] {
            let (l, _) = listener().await;
            let (port, captured) = spy(l.local_addr().unwrap()).await;
            let tuning = Tuning::for_profile(Default::default());
            let dialer =
                Dialer::new(&Settings::default(), &format!("127.0.0.1:{port}"), &tuning).unwrap();
            let crypto = Crypto::new(TOKEN, enc);
            let c2 = crypto.clone();
            let server = tokio::spawn(async move {
                let (s, _) = l.accept().await.unwrap();
                let mut ch = accept(s, &c2, &ReplayFilter::default(), Duration::from_secs(5))
                    .await
                    .unwrap();
                let mut got = vec![0u8; MARKER.len() * 2];
                ch.read_exact(&mut got).await.unwrap();
                ch.write_all(MARKER).await.unwrap();
                ch.shutdown().await.unwrap();
            });
            let mut ch = connect(&dialer, &crypto, MARKER).await.unwrap();
            ch.write_all(MARKER).await.unwrap();
            ch.flush().await.unwrap();
            let mut back = Vec::new();
            ch.read_to_end(&mut back).await.unwrap();
            assert_eq!(back, MARKER);
            server.await.unwrap();
            drop(ch);
            let wire = captured.await.unwrap();
            let visible = wire.windows(MARKER.len()).filter(|w| *w == MARKER).count();
            match enc {
                Encryption::None => assert_eq!(visible, 3, "control: plain mode shows the marker"),
                _ => assert_eq!(visible, 0, "marker visible on the wire with {enc:?}"),
            }
        }
    }

    /// A `ws` listener, and a dialer with early data on or off.
    async fn ws_pair(early_data: bool) -> (Listener, Dialer) {
        let tuning = Tuning::for_profile(Default::default());
        let server = Settings {
            kind: crate::config::TransportKind::Ws,
            ..Default::default()
        };
        let l = Listener::bind(&server, "127.0.0.1:0", &tuning)
            .await
            .unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let client = Settings {
            ws: Some(toml::from_str(&format!("early_data = {early_data}")).unwrap()),
            ..server
        };
        (l, Dialer::new(&client, &addr, &tuning).unwrap())
    }

    #[tokio::test]
    async fn ws_early_data_carries_hello_and_open() {
        for (early_data, enc) in [
            (true, Encryption::Auto),
            (true, Encryption::None),
            (false, Encryption::Auto),
        ] {
            let (l, d) = ws_pair(early_data).await;
            let crypto = Crypto::new(TOKEN, enc);
            let c2 = crypto.clone();
            let server = tokio::spawn(async move {
                let (s, _) = l.accept().await.unwrap();
                let mut ch = accept(s, &c2, &ReplayFilter::default(), Duration::from_secs(5))
                    .await
                    .unwrap();
                let mut got = [0u8; 9];
                ch.read_exact(&mut got).await.unwrap();
                ch.write_all(b"pong").await.unwrap();
                ch.flush().await.unwrap();
                got
            });
            let mut ch = connect(&d, &crypto, b"open").await.unwrap();
            ch.write_all(b"-more").await.unwrap();
            ch.flush().await.unwrap();
            let mut pong = [0u8; 4];
            ch.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            assert_eq!(&server.await.unwrap(), b"open-more");
        }
    }

    #[tokio::test]
    async fn ws_early_data_with_a_bad_hello_gets_a_404() {
        // Wrong token: the listener never sends 101.
        let (l, d) = ws_pair(true).await;
        tokio::spawn(async move {
            let crypto = Crypto::new("another-token-0123456789", Encryption::Auto);
            let (s, _) = l.accept().await.unwrap();
            let _ = accept(s, &crypto, &ReplayFilter::default(), Duration::from_secs(5)).await;
        });
        let started = std::time::Instant::now();
        let err = connect(&d, &Crypto::new(TOKEN, Encryption::Auto), &[])
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("404"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn ws_early_data_replay_gets_a_404() {
        let (l, d) = ws_pair(true).await;
        let (port, captured) = spy(l.local_addr().unwrap()).await;
        let addr = format!("127.0.0.1:{port}");
        let tuning = Tuning::for_profile(Default::default());
        let client = Settings {
            kind: crate::config::TransportKind::Ws,
            ws: Some(toml::from_str("early_data = true").unwrap()),
            ..Default::default()
        };
        let spied = Dialer::new(&client, &addr, &tuning).unwrap();
        drop(d);
        let crypto = Crypto::new(TOKEN, Encryption::Auto);
        let c2 = crypto.clone();
        let real = l.local_addr().unwrap();
        tokio::spawn(async move {
            // One filter for both connections, as in a running server.
            let replay = std::sync::Arc::new(ReplayFilter::default());
            loop {
                let (s, _) = l.accept().await.unwrap();
                let (c2, replay) = (c2.clone(), replay.clone());
                tokio::spawn(async move {
                    if let Ok(mut ch) = accept(s, &c2, &replay, Duration::from_secs(5)).await {
                        let _ = ch.shutdown().await;
                    }
                });
            }
        });
        let mut ch = connect(&spied, &crypto, &[]).await.unwrap();
        let mut rest = Vec::new();
        let _ = ch.read_to_end(&mut rest).await;
        drop(ch);
        let wire = captured.await.unwrap();
        let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let request = &wire[..end];
        assert!(String::from_utf8_lossy(request).contains("Sec-WebSocket-Protocol: "));

        // The same upgrade request again: the hello inside is a replay.
        let mut probe = tokio::net::TcpStream::connect(real).await.unwrap();
        probe.write_all(request).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), probe.read_to_end(&mut answer))
            .await
            .expect("a replay must be answered at once")
            .unwrap();
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"), "{answer}");
    }

    /// Mux sessions over a KCP link and its datagram path.
    #[cfg(feature = "kcp")]
    mod datagram_path {
        use super::*;
        use crate::config::TransportKind;
        use crate::mux::{MuxSession, MuxStream, SessionConfig, Side};
        use crate::transport::kcp::KcpParams;

        fn config() -> SessionConfig {
            SessionConfig {
                stream_window: 256 * 1024,
                max_streams: 64,
                keepalive: Duration::from_secs(2),
                coalesce: true,
                datagram_buffer: 256 * 1024,
                datagram_queue: 1024,
            }
        }

        /// A client and a server session over one KCP link. `client_path`: whether the
        /// client uses the datagram path; without it, it ignores the path as v0.4 does.
        /// The listener is returned too, since dropping it ends the link.
        async fn sessions(client_path: bool, fec: bool) -> (MuxSession, MuxSession, Listener) {
            let tuning = Tuning::for_profile(Default::default());
            let mut kcp = KcpParams::default();
            if fec {
                kcp.config.fec_data = Some(4);
                kcp.config.fec_parity = Some(2);
            }
            let settings = Settings {
                kind: TransportKind::Kcp,
                kcp,
                ..Default::default()
            };
            let l = Listener::bind(&settings, "127.0.0.1:0", &tuning)
                .await
                .unwrap();
            let d = Dialer::new(&settings, &l.local_addr().unwrap().to_string(), &tuning).unwrap();
            let crypto = Crypto::new(TOKEN, Encryption::Auto).with_mux(true);
            let (link, accepted) = tokio::join!(connect(&d, &crypto, &[]), async {
                let (s, _) = l.accept().await.unwrap();
                accept(s, &crypto, &ReplayFilter::default(), Duration::from_secs(5)).await
            });
            let (link, accepted) = (link.unwrap(), accepted.unwrap());
            assert!(link.datagrams.is_some() && accepted.datagrams.is_some());
            let client = if client_path {
                MuxSession::over(link, Side::Client, config())
            } else {
                let (r, w) = link.into_halves();
                MuxSession::from_halves(r, w, Side::Client, config())
            };
            let server = MuxSession::over(accepted, Side::Server, config());
            (client, server, l)
        }

        async fn eventually(mut f: impl FnMut() -> bool) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !f() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("in time");
        }

        /// Sends `count` datagrams of `len` bytes and returns how many of them arrived,
        /// intact, on `to`.
        async fn exchange(from: &MuxStream, to: &MuxStream, count: u8, len: usize) -> usize {
            for i in 0..count {
                assert!(from.send_datagram(Bytes::from(vec![i; len])));
            }
            let mut got = 0;
            while let Ok(Ok(Some(d))) =
                tokio::time::timeout(Duration::from_millis(300), to.recv_datagram()).await
            {
                assert_eq!(d.len(), len);
                got += 1;
            }
            got
        }

        #[tokio::test]
        async fn datagrams_take_the_path_once_the_peer_is_heard() {
            for fec in [false, true] {
                let (client, server, _l) = sessions(true, fec).await;
                let a = client.open(Bytes::from_static(b"flow")).unwrap();
                let (b, _) = server.accept().await.unwrap();
                // Both probes answered: each side has heard the other on the path.
                eventually(|| {
                    client.datagram_stats().path_received > 0
                        && server.datagram_stats().path_received > 0
                })
                .await;
                // The server knows the stream (the client opened it): the path at once.
                assert_eq!(exchange(&b, &a, 50, 100).await, 50, "fec {fec}");
                assert_eq!(server.datagram_stats().path_sent, 50);
                // The client has now heard from the server on the stream: the path too.
                assert_eq!(exchange(&a, &b, 50, 100).await, 50, "fec {fec}");
                assert_eq!(client.datagram_stats().path_sent, 50);
                // Too large for one packet: in the connection, and it still arrives.
                assert_eq!(exchange(&b, &a, 1, 3000).await, 1);
                assert_eq!(server.datagram_stats().path_sent, 50);
                // The streams themselves still work beside the path.
                a.send(Bytes::from_static(b"data")).await.unwrap();
                assert_eq!(&b.recv().await.unwrap().unwrap()[..], b"data");
            }
        }

        /// A datagram never overtakes its stream's `SYN`: until the peer shows it knows
        /// the stream, the opener sends in the connection.
        #[tokio::test]
        async fn the_opener_waits_until_the_peer_knows_the_stream() {
            let (client, server, _l) = sessions(true, false).await;
            eventually(|| client.datagram_stats().path_received > 0).await;
            let a = client.open(Bytes::from_static(b"flow")).unwrap();
            assert!(a.send_datagram(Bytes::from_static(b"first")));
            let (b, _) = server.accept().await.unwrap();
            assert_eq!(&b.recv_datagram().await.unwrap().unwrap()[..], b"first");
            assert_eq!(client.datagram_stats().path_sent, 0);
        }

        /// A peer that ignores the path (as v0.4 does) gets everything in the connection.
        #[tokio::test]
        async fn a_peer_without_the_path_gets_everything_in_the_stream() {
            let (client, server, _l) = sessions(false, false).await;
            let a = client.open(Bytes::from_static(b"flow")).unwrap();
            let (b, _) = server.accept().await.unwrap();
            // Long enough for the server's probes to go out and be ignored.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(exchange(&b, &a, 20, 100).await, 20);
            assert_eq!(exchange(&a, &b, 20, 100).await, 20);
            let (c, s) = (client.datagram_stats(), server.datagram_stats());
            assert_eq!((c.path_sent, c.path_received), (0, 0));
            assert_eq!((s.path_sent, s.path_received), (0, 0));
        }
    }
}
