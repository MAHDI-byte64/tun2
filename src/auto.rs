//! `transport = "auto"`: one tunnel that keeps working when a network stalls one way of
//! getting through.
//!
//! The accepting side listens on all of [`KINDS`] at once: `tcpmux` on TCP port P, `kcp` on
//! UDP port P and `ws` on TCP port P+1. The dialing side tries them in turn: the one that
//! worked last first, the next after a failed or stalled connect, round and round, and
//! remembers the one that got through. Auto always multiplexes, and pings faster than the
//! other transports, so a link that goes quiet is noticed in a few seconds and the sessions
//! are made again over whichever transport gets through.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::channel::{self, Link};
use crate::config::{TransportKind, Tuning, WsConfig};
use crate::crypto::Crypto;
use crate::transport::{Dialer, Listener, Settings};

/// The transports `auto` uses, in the order a dialing side tries them.
pub const KINDS: [TransportKind; 3] =
    [TransportKind::Tcpmux, TransportKind::Kcp, TransportKind::Ws];

/// Seconds between mux pings of an `auto` tunnel (a silent peer is dead after twice that).
pub const PING_SECS: u64 = 2;

/// The longest one transport is given to connect before the next is tried.
const ATTEMPT: Duration = Duration::from_secs(4);

/// The WebSocket path: made from the token, so both ends know it and a scanner does not.
fn ws_path(token: &str) -> String {
    let hash = blake3::hash(format!("kariz auto ws {token}").as_bytes());
    format!("/{}", &hash.to_hex()[..16])
}

/// `base` (the tunnel's settings) as the transport `kind` uses them.
fn settings_for(base: &Settings, kind: TransportKind, token: &str) -> Settings {
    let mut settings = base.clone();
    settings.kind = kind;
    settings.tls = None;
    settings.ws = (kind == TransportKind::Ws).then(|| WsConfig {
        path: ws_path(token),
        host: None,
        user_agent: None,
        headers: Default::default(),
        early_data: false,
    });
    settings
}

/// The address `kind` uses when the tunnel's is `addr`: `ws` is on the next port, the
/// others on the port itself (TCP and UDP).
pub fn addr_for(kind: TransportKind, addr: &str) -> io::Result<String> {
    if kind == TransportKind::Ws {
        crate::link::next_port(addr)
    } else {
        Ok(addr.to_owned())
    }
}

/// Listens for each of [`KINDS`]. Only `tcpmux` has to work: a port that is taken for the
/// others is said and left out.
pub async fn bind_all(
    base: &Settings,
    token: &str,
    addr: &str,
    tuning: &Tuning,
) -> Result<Vec<(&'static str, Listener)>> {
    let mut listeners = Vec::new();
    for kind in KINDS {
        let at = addr_for(kind, addr)?;
        let settings = settings_for(base, kind, token);
        match Listener::bind(&settings, &at, tuning).await {
            Ok(listener) => {
                info!(transport = kind.name(), addr = %at, "auto: listening");
                listeners.push((kind.name(), listener));
            }
            Err(e) if kind == KINDS[0] => {
                return Err(e)
                    .with_context(|| format!("failed to listen for tunnel connections on {at}"))
            }
            Err(e) => {
                warn!(transport = kind.name(), addr = %at, error = %e, "auto: cannot listen, this transport is left out")
            }
        }
    }
    Ok(listeners)
}

/// The dialing side of a tunnel: one transport, or all of [`KINDS`] in turn.
pub enum Dial {
    One(Dialer),
    Auto {
        dialers: Vec<(TransportKind, Dialer)>,
        /// The one that connected last: where the next try starts.
        preferred: AtomicUsize,
    },
}

impl Dial {
    pub fn one(settings: &Settings, addr: &str, tuning: &Tuning) -> io::Result<Self> {
        Ok(Self::One(Dialer::new(settings, addr, tuning)?))
    }

    pub fn auto(base: &Settings, token: &str, addr: &str, tuning: &Tuning) -> io::Result<Self> {
        let mut dialers = Vec::new();
        for kind in KINDS {
            let at = addr_for(kind, addr)?;
            dialers.push((
                kind,
                Dialer::new(&settings_for(base, kind, token), &at, tuning)?,
            ));
        }
        Ok(Self::Auto {
            dialers,
            preferred: AtomicUsize::new(0),
        })
    }

    /// Connects and authenticates, within `wait`. Auto gives each transport a few seconds
    /// and goes on to the next; the last error comes back if none gets through.
    /// The transport that connected comes back too, for an `auto` tunnel.
    pub async fn connect(
        &self,
        crypto: &Crypto,
        wait: Duration,
    ) -> io::Result<(Link, Option<&'static str>)> {
        match self {
            Self::One(dialer) => timeout(wait, channel::connect(dialer, crypto, &[]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
                .map(|link| (link, None)),
            Self::Auto { dialers, preferred } => {
                let start = preferred.load(Ordering::Relaxed);
                let mut last = None;
                for step in 0..dialers.len() {
                    let at = (start + step) % dialers.len();
                    let (kind, dialer) = &dialers[at];
                    match timeout(wait.min(ATTEMPT), channel::connect(dialer, crypto, &[])).await {
                        Ok(Ok(link)) => {
                            if preferred.swap(at, Ordering::Relaxed) != at {
                                info!(transport = kind.name(), "auto: now using this transport");
                            }
                            return Ok((link, Some(kind.name())));
                        }
                        Ok(Err(e)) => {
                            debug!(transport = kind.name(), error = %e, "auto: could not connect");
                            last = Some(e);
                        }
                        Err(_) => {
                            debug!(transport = kind.name(), "auto: connecting timed out");
                            last = Some(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("{} handshake timed out", kind.name()),
                            ));
                        }
                    }
                }
                Err(last.unwrap_or_else(|| io::Error::other("no transport to try")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Encryption, Profile};
    use crate::crypto::ReplayFilter;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    const TOKEN: &str = "auto-test-token-0123456789";

    /// A port that is free for TCP and UDP, with the next one free for TCP.
    async fn ports() -> (TcpListener, u16) {
        loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            if port < u16::MAX
                && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
                && std::net::TcpListener::bind(("127.0.0.1", port + 1)).is_ok()
            {
                return (tcp, port);
            }
        }
    }

    #[test]
    fn each_transport_has_its_own_address_and_settings() {
        assert_eq!(
            addr_for(TransportKind::Tcpmux, "1.2.3.4:3080").unwrap(),
            "1.2.3.4:3080"
        );
        assert_eq!(
            addr_for(TransportKind::Kcp, "1.2.3.4:3080").unwrap(),
            "1.2.3.4:3080"
        );
        assert_eq!(
            addr_for(TransportKind::Ws, "[::1]:3080").unwrap(),
            "[::1]:3081"
        );
        assert!(addr_for(TransportKind::Ws, "no-port").is_err());
        let base = Settings::default();
        let ws = settings_for(&base, TransportKind::Ws, TOKEN);
        assert_eq!(ws.kind, TransportKind::Ws);
        assert!(ws.ws.is_some_and(|w| w.path.len() == 17));
        assert!(settings_for(&base, TransportKind::Kcp, TOKEN).ws.is_none());
    }

    /// TCP connects and then says nothing (a path that stalls it): the dialer gives up on
    /// it after a few seconds and gets through over UDP, and starts there next time.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dialer_moves_on_when_tcp_stalls() {
        let (stalled, port) = ports().await;
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = stalled.accept().await {
                held.push(s);
            }
        });
        let tuning = Tuning::for_profile(Profile::Balanced);
        let base = Settings::default();
        let crypto = Crypto::new(TOKEN, Encryption::Auto).with_mux(true);
        let addr = format!("127.0.0.1:{port}");
        // The other ends: KCP on the port itself, WebSocket on the next.
        let replay = Arc::new(ReplayFilter::default());
        for kind in [TransportKind::Kcp, TransportKind::Ws] {
            let at = addr_for(kind, &addr).unwrap();
            let listener = Listener::bind(&settings_for(&base, kind, TOKEN), &at, &tuning)
                .await
                .unwrap();
            let (crypto, replay, hs) = (crypto.clone(), replay.clone(), tuning.handshake_timeout);
            tokio::spawn(async move {
                let mut links = Vec::new();
                while let Ok((incoming, _)) = listener.accept().await {
                    let (crypto, replay) = (crypto.clone(), replay.clone());
                    links.push(tokio::spawn(async move {
                        channel::accept(incoming, &crypto, &replay, hs)
                            .await
                            .map(|_| ())
                    }));
                }
            });
        }
        let dial = Dial::auto(&base, TOKEN, &addr, &tuning).unwrap();
        let started = std::time::Instant::now();
        let link = dial.connect(&crypto, Duration::from_secs(20)).await;
        assert!(link.is_ok(), "{:?}", link.err());
        assert!(
            started.elapsed() >= Duration::from_secs(3),
            "TCP was tried first"
        );
        let Dial::Auto { preferred, .. } = &dial else {
            unreachable!()
        };
        assert_eq!(
            preferred.load(Ordering::Relaxed),
            1,
            "UDP is the one that worked"
        );
        // The next connect starts with it: no wait for the stalled TCP.
        let started = std::time::Instant::now();
        assert!(dial.connect(&crypto, Duration::from_secs(20)).await.is_ok());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
