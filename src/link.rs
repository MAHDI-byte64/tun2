//! A management link: one authenticated, encrypted mux session between two Kariz programs,
//! made the way a tunnel's connections are (the token handshake, the encrypted records,
//! the mux), so it resists DPI like a tunnel does. The web panel uses it to talk to its
//! agents; nothing in the tunnel core uses it.
//!
//! The transport is `tcpmux`, `kcp`, `wss` or `quic` ([`LINK_TRANSPORTS`]): a panel listens
//! on all of them (TCP and UDP of its agents port, and TLS and QUIC on the next port,
//! [`wss_addr`]), and an agent uses the one that gets through. Which side dials and which
//! opens streams are independent: an agent dials the panel, but the panel is the one that
//! opens streams (requests).
//!
//! Over `wss` the dialing side does not check the certificate: TLS is only there to look
//! like a web site. Who is on the other end is proven by the token handshake inside, as on
//! the other transports.
//!
//! `quic` is always obfuscated (`[tunnel.quic] obfs`, see `transport/quic_obfs.rs`): every
//! UDP packet is sealed with a key from the token, so the link does not look like QUIC to a
//! network that filters it, and the port answers nothing that was not made with the token.
//! There is no setting for it: a link that is meant to get through is never plain QUIC.
//! Its TLS 1.3 handshake proves the token, so it has no handshake of its own.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::channel;
use crate::config::{Config, TransportKind, Tuning};
use crate::crypto::{Crypto, ReplayFilter};
use crate::mux::{MuxSession, SessionConfig, Side};
#[cfg(feature = "quic")]
use crate::session::quic::QuicSession;
use crate::session::Session;
use crate::transport::proxy::Socks5;
#[cfg(feature = "quic")]
use crate::transport::quic::{Accepting, QuicDialer, QuicListener, QuicSettings};
use crate::transport::{Dialer as TransportDialer, Incoming, Listener, Settings};

/// The transports a management link can use, in the order an agent tries them. Some
/// networks let a TCP connection open and then stall it; KCP (over UDP) often gets
/// through those, WebSocket over TLS looks like an ordinary web site, and QUIC (sealed, so
/// it is not recognised as QUIC) is another way over UDP. QUIC is last: an agent before it
/// existed does not try it, and one that does tries it after the others.
///
/// The fork's new tunnel transports are deliberately kept off this list: the panel ↔ agent
/// link must stay on the transports an agent is sure to be able to bring up anywhere, with
/// no extra privilege or state. `stealth`, `wsmux` and `wssmux` would only duplicate
/// `tcpmux` and `wss` here (the link already muxes and already seals every byte); `udp` is
/// datagram-only, so it cannot carry the link's request streams; and `faketcp` / `icmp`
/// need root, raw sockets and host firewall rules, which a management link must never
/// require. The managed-helper transports need external, credentialed binaries on both
/// ends. A tunnel can use any of them; the link stays on the proven four.
#[cfg(feature = "quic")]
pub const LINK_TRANSPORTS: [TransportKind; 4] = [
    TransportKind::Tcpmux,
    TransportKind::Kcp,
    TransportKind::Wss,
    TransportKind::Quic,
];
#[cfg(not(feature = "quic"))]
pub const LINK_TRANSPORTS: [TransportKind; 3] = [
    TransportKind::Tcpmux,
    TransportKind::Kcp,
    TransportKind::Wss,
];

/// The address of a panel's `wss` and `quic` links, whose agents port is in `addr`: the
/// next port (`wss` on TCP, `quic` on UDP), as the other transports use the agents port
/// itself (TCP and UDP).
pub fn wss_addr(addr: &str) -> io::Result<String> {
    next_port(addr)
}

/// The address a link over `kind` uses, given the panel's agents port address `addr`: the
/// next port for `wss` and `quic`, the agents port itself for the others.
pub fn address_for(addr: &str, kind: TransportKind) -> io::Result<String> {
    match kind {
        TransportKind::Wss | TransportKind::Quic => next_port(addr),
        _ => Ok(addr.to_owned()),
    }
}

/// `addr` with its port one higher.
pub fn next_port(addr: &str) -> io::Result<String> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not an address with a port: {addr}"),
        )
    };
    let (host, port) = addr.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    let next = port.checked_add(1).ok_or_else(bad)?;
    Ok(format!("{host}:{next}"))
}

/// The WebSocket path of the link: made from the token, so both ends know it and a
/// scanner does not.
fn ws_path(token: &str) -> String {
    let hash = blake3::hash(format!("kariz link ws {token}").as_bytes());
    format!("/{}", &hash.to_hex()[..16])
}

/// What a link is made of beyond its transport: a management link is always the defaults;
/// a benchmark's test link ([`crate::bench`]) can be any transport it measures, with the
/// profile the tunnel will have.
#[derive(Clone, Copy)]
pub(crate) struct Shape<'a> {
    pub kind: TransportKind,
    pub profile: Option<&'a str>,
    /// Allow the transports a management link does not use (`ws`).
    pub any: bool,
    /// The server name a dialing `wss` end sends (none: none is sent, as for an IP address).
    pub sni: Option<&'a str>,
}

impl Shape<'_> {
    fn link(kind: TransportKind) -> Self {
        Shape {
            kind,
            profile: None,
            any: false,
            sni: None,
        }
    }
}

/// The synthetic config of one end. `tls`: the listening side's certificate and key for
/// `wss`.
fn toml(
    shape: Shape,
    listening: bool,
    addr: &str,
    token: &str,
    tls: Option<(&Path, &Path)>,
) -> io::Result<String> {
    let kind = shape.kind;
    if shape.any {
        crate::bench::check(kind)?;
    } else {
        check(kind)?;
    }
    let (mode, key) = if listening {
        ("direct", "listen")
    } else {
        ("reverse", "remote")
    };
    let profile = shape
        .profile
        .map(|p| {
            format!(
                "profile = {p:?}
"
            )
        })
        .unwrap_or_default();
    let mut toml = format!(
        "role = \"exit\"
mode = \"{mode}\"
{profile}[tunnel]
transport = \"{}\"
{key} = {addr:?}
token = {token:?}
",
        kind.name()
    );
    if kind == TransportKind::Quic {
        toml.push_str("[tunnel.quic]\nobfs = true\n");
    }
    if matches!(kind, TransportKind::Ws | TransportKind::Wsmux) {
        toml.push_str(&format!(
            "[tunnel.ws]
path = {:?}
",
            ws_path(token)
        ));
    }
    if matches!(kind, TransportKind::Wss | TransportKind::Wssmux) {
        toml.push_str(&format!(
            "[tunnel.ws]
path = {:?}
[tunnel.tls]
",
            ws_path(token)
        ));
        if listening {
            let (cert, key) = tls.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a wss link needs a certificate and its key",
                )
            })?;
            toml.push_str(&format!(
                "cert = {:?}
key = {:?}
",
                cert.display().to_string(),
                key.display().to_string()
            ));
        } else {
            toml.push_str(
                "insecure = true
",
            );
            if let Some(sni) = shape.sni {
                toml.push_str(&format!(
                    "sni = {sni:?}
"
                ));
            }
        }
    }
    Ok(toml)
}

fn check(kind: TransportKind) -> io::Result<()> {
    if LINK_TRANSPORTS.contains(&kind) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a management link cannot use {}", kind.name()),
        ))
    }
}

/// What both ends share, worked out once from a small synthetic config so the link
/// follows the same defaults as a `tcpmux` tunnel.
struct Common {
    crypto: Crypto,
    tuning: Tuning,
    settings: Settings,
    sessions: SessionConfig,
    /// A `quic` link's endpoint settings (the token's identity, and the seal on every packet).
    #[cfg(feature = "quic")]
    quic: Option<QuicSettings>,
}

fn common(toml: String) -> io::Result<Common> {
    let config = Config::parse(&toml)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:#}")))?;
    let mux = config.mux();
    let settings = Settings::new(&config.tunnel, config.kcp());
    let crypto = Crypto::new(&config.tunnel.token, config.tunnel.encryption)
        .with_mux(true)
        .with_stealth(settings.stealth.as_ref().map(|s| s.shaping()));
    let tuning = config.tuning();
    #[cfg(feature = "quic")]
    let quic = if config.tunnel.transport == TransportKind::Quic {
        let quic = config.tunnel.quic.clone().unwrap_or_default();
        Some(QuicSettings::new(crypto.psk(), &quic, &mux, &tuning)?)
    } else {
        None
    };
    Ok(Common {
        crypto,
        tuning,
        settings,
        sessions: SessionConfig::new(&mux),
        #[cfg(feature = "quic")]
        quic,
    })
}

/// What an [`Acceptor`] listens with: a stream transport's listener, or a QUIC endpoint.
enum Listening {
    Stream(Listener),
    #[cfg(feature = "quic")]
    Quic(QuicListener),
}

/// The listening end.
pub struct Acceptor {
    kind: TransportKind,
    listening: Listening,
    replay: Arc<ReplayFilter>,
    common: Arc<Common>,
}

impl Acceptor {
    /// Listens on `addr`; only a peer that knows `token` gets a session.
    pub async fn bind(addr: &str, token: &str) -> io::Result<Self> {
        Self::bind_via(addr, token, TransportKind::Tcpmux).await
    }

    /// Like [`Acceptor::bind`], over `tcpmux`, `kcp` or `quic` (always sealed).
    pub async fn bind_via(addr: &str, token: &str, kind: TransportKind) -> io::Result<Self> {
        Self::bind_with(addr, token, kind, None).await
    }

    /// Like [`Acceptor::bind`], over `wss` with this certificate (reloaded when its files
    /// change).
    pub async fn bind_wss(addr: &str, token: &str, cert: &Path, key: &Path) -> io::Result<Self> {
        Self::bind_with(addr, token, TransportKind::Wss, Some((cert, key))).await
    }

    async fn bind_with(
        addr: &str,
        token: &str,
        kind: TransportKind,
        tls: Option<(&Path, &Path)>,
    ) -> io::Result<Self> {
        Self::bind_shape(addr, token, Shape::link(kind), tls).await
    }

    pub(crate) async fn bind_shape(
        addr: &str,
        token: &str,
        shape: Shape<'_>,
        tls: Option<(&Path, &Path)>,
    ) -> io::Result<Self> {
        let kind = shape.kind;
        let toml = toml(shape, true, addr, token, tls)?;
        let common = common(toml)?;
        #[cfg(feature = "quic")]
        let listening = match &common.quic {
            Some(settings) => Listening::Quic(QuicListener::bind(addr, settings).await?),
            None => {
                Listening::Stream(Listener::bind(&common.settings, addr, &common.tuning).await?)
            }
        };
        #[cfg(not(feature = "quic"))]
        let listening =
            Listening::Stream(Listener::bind(&common.settings, addr, &common.tuning).await?);
        Ok(Self {
            kind,
            listening,
            replay: Arc::new(ReplayFilter::default()),
            common: Arc::new(common),
        })
    }

    /// The transport it takes links over.
    pub fn kind(&self) -> TransportKind {
        self.kind
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.listening {
            Listening::Stream(l) => l.local_addr(),
            #[cfg(feature = "quic")]
            Listening::Quic(l) => l.local_addr(),
        }
    }

    /// The next connection. It is not authenticated yet: hand it to a task and call
    /// [`Pending::establish`], so a slow or hostile peer never holds up this loop.
    pub async fn accept(&self) -> io::Result<Pending> {
        let (waiting, peer) = match &self.listening {
            Listening::Stream(l) => {
                let (incoming, peer) = l.accept().await?;
                (Waiting::Stream(incoming), peer)
            }
            #[cfg(feature = "quic")]
            Listening::Quic(l) => {
                let accepting = l.accept().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "the QUIC endpoint is closed")
                })?;
                let peer = accepting.remote_address();
                (Waiting::Quic(Box::new(accepting)), peer)
            }
        };
        Ok(Pending {
            waiting,
            peer,
            replay: self.replay.clone(),
            common: self.common.clone(),
        })
    }
}

/// A connection whose handshake is still to be run.
enum Waiting {
    Stream(Incoming),
    #[cfg(feature = "quic")]
    Quic(Box<Accepting>),
}

/// A connection that has not finished its handshake.
pub struct Pending {
    waiting: Waiting,
    peer: SocketAddr,
    replay: Arc<ReplayFilter>,
    common: Arc<Common>,
}

impl Pending {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Runs the handshake and starts the session, with `side` as this end's mux role (a
    /// QUIC link has no such roles: either end can open streams). A peer with a wrong
    /// token is kept waiting for a random 5-30 s before it is let go, like a tunnel does;
    /// over QUIC (sealed) it gets no answer at all.
    pub async fn establish(self, side: Side) -> io::Result<Session> {
        let c = &self.common;
        match self.waiting {
            Waiting::Stream(incoming) => {
                let link = channel::accept(
                    incoming,
                    &c.crypto,
                    &self.replay,
                    c.tuning.handshake_timeout,
                )
                .await?;
                Ok(Session::Kmux(MuxSession::over(
                    link,
                    side,
                    c.sessions.clone(),
                )))
            }
            #[cfg(feature = "quic")]
            Waiting::Quic(accepting) => {
                let conn = accepting.establish().await?;
                Ok(Session::Quic(QuicSession::new(
                    conn,
                    &c.sessions,
                    c.tuning.handshake_timeout,
                )))
            }
        }
    }
}

/// How a [`Dialer`] connects.
enum Dialing {
    Stream(TransportDialer),
    #[cfg(feature = "quic")]
    Quic(Box<QuicDialer>),
}

/// The dialing end.
pub struct Dialer {
    dialing: Dialing,
    common: Common,
}

impl Dialer {
    /// Dials `addr` with `token`.
    pub fn new(addr: &str, token: &str) -> io::Result<Self> {
        Self::via(addr, token, TransportKind::Tcpmux)
    }

    /// Like [`Dialer::new`], over `kind` (one of [`LINK_TRANSPORTS`]; for `wss` and `quic`,
    /// `addr` is the panel's [`wss_addr`], see [`address_for`]).
    pub fn via(addr: &str, token: &str, kind: TransportKind) -> io::Result<Self> {
        Self::via_proxy(addr, token, kind, None)
    }

    /// Like [`Dialer::via`], dialing through a SOCKS5 proxy when one is given (the panel's
    /// links to the servers it reaches that way). A proxy carries TCP, so only `tcpmux` and
    /// `wss` can go through one: `kcp` and `quic` are refused with a proxy.
    pub fn via_proxy(
        addr: &str,
        token: &str,
        kind: TransportKind,
        proxy: Option<Socks5>,
    ) -> io::Result<Self> {
        let mut dialer = Self::shaped(addr, token, Shape::link(kind))?;
        if let Some(proxy) = proxy {
            dialer.dialing =
                match dialer.dialing {
                    Dialing::Stream(d) => Dialing::Stream(d.with_proxy(Some(proxy))?),
                    #[cfg(feature = "quic")]
                    Dialing::Quic(_) => return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "a SOCKS5 proxy carries only the TCP transports (tcpmux, wss), not quic",
                    )),
                };
        }
        Ok(dialer)
    }

    pub(crate) fn shaped(addr: &str, token: &str, shape: Shape<'_>) -> io::Result<Self> {
        let toml = toml(shape, false, addr, token, None)?;
        let common = common(toml)?;
        #[cfg(feature = "quic")]
        let dialing = match &common.quic {
            Some(settings) => Dialing::Quic(Box::new(QuicDialer::new(addr, None, settings)?)),
            None => Dialing::Stream(TransportDialer::new(
                &common.settings,
                addr,
                &common.tuning,
            )?),
        };
        #[cfg(not(feature = "quic"))]
        let dialing = Dialing::Stream(TransportDialer::new(
            &common.settings,
            addr,
            &common.tuning,
        )?);
        Ok(Self { dialing, common })
    }

    /// Connects, authenticates and starts a session, with `side` as this end's mux role
    /// (not used by QUIC).
    pub async fn connect(&self, side: Side) -> io::Result<Session> {
        let c = &self.common;
        let wait: Duration = c.tuning.dial_timeout + c.tuning.handshake_timeout;
        match &self.dialing {
            Dialing::Stream(dialer) => {
                let link = timeout(wait, channel::connect(dialer, &c.crypto, &[]))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "handshake timed out")
                    })??;
                Ok(Session::Kmux(MuxSession::over(
                    link,
                    side,
                    c.sessions.clone(),
                )))
            }
            #[cfg(feature = "quic")]
            Dialing::Quic(dialer) => {
                let conn = timeout(wait, dialer.connect()).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "handshake timed out")
                })??;
                Ok(Session::Quic(QuicSession::new(
                    conn,
                    &c.sessions,
                    c.tuning.handshake_timeout,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn a_dialer_and_an_acceptor_share_streams_in_either_direction() {
        let acceptor = Acceptor::bind("127.0.0.1:0", TOKEN).await.unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        // The dialing end is the mux server: the accepting end opens the streams.
        let dialer = Dialer::new(&addr, TOKEN).unwrap();
        let (dialed, accepted) = tokio::join!(dialer.connect(Side::Server), async {
            let pending = acceptor.accept().await.unwrap();
            pending.establish(Side::Client).await
        });
        let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());

        let opened = accepted.open(Bytes::from_static(b"ping")).unwrap();
        let (stream, syn) = dialed.accept().await.unwrap();
        assert_eq!(&syn[..], b"ping");
        stream.send(Bytes::from_static(b"pong")).await.unwrap();
        stream.finish().unwrap();
        assert_eq!(
            opened.recv().await.unwrap().unwrap(),
            Bytes::from_static(b"pong")
        );
    }

    /// Three requests from the accepting end, answered by the dialing end.
    async fn round_trips(acceptor: Acceptor, dialer: Dialer) {
        let (dialed, accepted) = tokio::join!(dialer.connect(Side::Server), async {
            let pending = acceptor.accept().await.unwrap();
            pending.establish(Side::Client).await
        });
        let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
        for round in 0..3u8 {
            let opened = accepted.open(Bytes::from(vec![round; 3])).unwrap();
            opened.finish().unwrap();
            let (stream, syn) = dialed.accept().await.unwrap();
            assert_eq!(&syn[..], &[round; 3]);
            stream.send(Bytes::from_static(b"pong")).await.unwrap();
            stream.finish().unwrap();
            assert_eq!(
                opened.recv().await.unwrap().unwrap(),
                Bytes::from_static(b"pong")
            );
        }
    }

    #[cfg(feature = "kcp")]
    #[tokio::test]
    async fn a_link_works_over_kcp_too() {
        let acceptor = Acceptor::bind_via("127.0.0.1:0", TOKEN, TransportKind::Kcp)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer = Dialer::via(&addr, TOKEN, TransportKind::Kcp).unwrap();
        round_trips(acceptor, dialer).await;
        assert!(Dialer::via(&addr, TOKEN, TransportKind::Ws).is_err());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn a_link_works_over_quic_and_is_always_sealed() {
        let acceptor = Acceptor::bind_via("127.0.0.1:0", TOKEN, TransportKind::Quic)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();

        // Plain QUIC (no seal) with the very same token gets no answer: the port takes only
        // what was sealed with the token, so a link is never plain QUIC.
        let plain =
            crate::transport::quic::tests::settings(TOKEN, &crate::config::QuicConfig::default());
        let plain = crate::transport::quic::QuicDialer::new(&addr, None, &plain).unwrap();
        assert!(plain.connect().await.is_err(), "plain QUIC got a link");

        let dialer = Dialer::via(&addr, TOKEN, TransportKind::Quic).unwrap();
        round_trips(acceptor, dialer).await;
        assert!(Dialer::via(&addr, TOKEN, TransportKind::Ws).is_err());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn a_quic_link_with_another_token_never_connects() {
        let acceptor = Acceptor::bind_via("127.0.0.1:0", TOKEN, TransportKind::Quic)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer =
            Dialer::via(&addr, "another-token-0123456789abcdef", TransportKind::Quic).unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(15), dialer.connect(Side::Server)).await;
        assert!(
            !matches!(result, Ok(Ok(_))),
            "a wrong token must not connect"
        );
    }

    #[test]
    fn quic_and_wss_links_use_the_next_port() {
        assert_eq!(
            address_for("203.0.113.5:29001", TransportKind::Quic).unwrap(),
            "203.0.113.5:29002"
        );
        assert_eq!(
            address_for("203.0.113.5:29001", TransportKind::Wss).unwrap(),
            "203.0.113.5:29002"
        );
        for kind in [TransportKind::Tcpmux, TransportKind::Kcp] {
            assert_eq!(
                address_for("203.0.113.5:29001", kind).unwrap(),
                "203.0.113.5:29001"
            );
        }
    }

    #[tokio::test]
    async fn a_link_works_over_wss_with_any_certificate() {
        // A self-signed certificate for another name: the dialing end does not check it.
        let c = rcgen::generate_simple_self_signed(vec!["panel.example".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("kariz-link-wss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.signing_key.serialize_pem()).unwrap();
        let acceptor = Acceptor::bind_wss("127.0.0.1:0", TOKEN, &cert, &key)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer = Dialer::via(&addr, TOKEN, TransportKind::Wss).unwrap();
        round_trips(acceptor, dialer).await;
        // Without a certificate there is no wss listener.
        assert!(Acceptor::bind_via("127.0.0.1:0", TOKEN, TransportKind::Wss)
            .await
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A link dialed through a SOCKS5 proxy works like a direct one, and really goes through
    /// the proxy; the UDP transports cannot.
    #[tokio::test]
    async fn a_link_goes_through_a_socks5_proxy_over_the_tcp_transports() {
        use crate::transport::proxy::testing::Socks5Server;
        let proxy = Socks5Server::start(Some(("panel".into(), "secret".into()))).await;
        let auth = Some(("panel".to_owned(), "secret".to_owned()));

        let acceptor = Acceptor::bind("127.0.0.1:0", TOKEN).await.unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer = Dialer::via_proxy(
            &addr,
            TOKEN,
            TransportKind::Tcpmux,
            Some(proxy.proxy(auth.clone())),
        )
        .unwrap();
        round_trips(acceptor, dialer).await;
        assert_eq!(proxy.relayed(), 1, "the tcpmux link went through the proxy");

        let c = rcgen::generate_simple_self_signed(vec!["panel.example".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("kariz-link-proxy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.signing_key.serialize_pem()).unwrap();
        let acceptor = Acceptor::bind_wss("127.0.0.1:0", TOKEN, &cert, &key)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer = Dialer::via_proxy(
            &addr,
            TOKEN,
            TransportKind::Wss,
            Some(proxy.proxy(auth.clone())),
        )
        .unwrap();
        round_trips(acceptor, dialer).await;
        assert_eq!(proxy.relayed(), 2, "the wss link went through the proxy");
        let _ = std::fs::remove_dir_all(&dir);

        // The wrong password never gets a link.
        let acceptor = Acceptor::bind("127.0.0.1:0", TOKEN).await.unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let wrong = Some(("panel".to_owned(), "nope".to_owned()));
        let dialer = Dialer::via_proxy(
            &addr,
            TOKEN,
            TransportKind::Tcpmux,
            Some(proxy.proxy(wrong)),
        )
        .unwrap();
        assert!(dialer.connect(Side::Server).await.is_err());

        // A proxy carries TCP only.
        #[cfg(feature = "kcp")]
        assert!(Dialer::via_proxy(
            &addr,
            TOKEN,
            TransportKind::Kcp,
            Some(proxy.proxy(auth.clone()))
        )
        .is_err());
        #[cfg(feature = "quic")]
        assert!(
            Dialer::via_proxy(&addr, TOKEN, TransportKind::Quic, Some(proxy.proxy(auth))).is_err()
        );
    }

    #[test]
    fn the_wss_port_is_the_next_one() {
        assert_eq!(wss_addr("203.0.113.5:29001").unwrap(), "203.0.113.5:29002");
        assert_eq!(
            wss_addr("[2001:db8::1]:29001").unwrap(),
            "[2001:db8::1]:29002"
        );
        assert!(wss_addr("host").is_err());
        assert!(wss_addr("host:65535").is_err());
    }

    #[tokio::test]
    async fn a_wrong_token_never_gets_a_session() {
        let acceptor = Acceptor::bind("127.0.0.1:0", TOKEN).await.unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let dialer = Dialer::new(&addr, "another-token-0123456789abcdef").unwrap();
        tokio::spawn(async move {
            if let Ok(pending) = acceptor.accept().await {
                let _ = pending.establish(Side::Client).await;
            }
        });
        let result =
            tokio::time::timeout(Duration::from_secs(15), dialer.connect(Side::Server)).await;
        assert!(
            !matches!(result, Ok(Ok(_))),
            "a wrong token must not connect"
        );
    }
}
