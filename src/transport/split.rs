//! Asymmetric ("split") transport: a tunnel whose two directions ride different transports
//! over two paired connections. The dialer writes on one link (the *send* link, the tunnel's
//! `transport`) and reads from the other (the *receive* link, `recv_transport`); the acceptor
//! mirrors it. A 16-byte random correlation id, sent first on each link, lets the acceptor
//! pair the two; a link's role is fixed by which listener accepted it, so nothing more is on
//! the wire. Everything above the transport — the handshake, the record crypto and the mux —
//! runs over the resulting [`TunnelStream::Combined`] unchanged.
//!
//! Only the stream transports (`tcp`, `ws`, `wss`) are used as the two halves: each is driven
//! in one direction only, and dropping a half's unused side closes just that idle direction.
//! KCP-based links would half-close the whole conversation prematurely, so config validation
//! keeps them out.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::{Dialer, Incoming, Listener, Settings, TunnelReader, TunnelStream, TunnelWriter};

/// How often a split tunnel's idle ws writer is flushed to push out any queued pong.
const PONG_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Services the idle read half of a split tunnel's ws/wss leg so incoming WebSocket control
/// frames are handled: a background read drives the ws read path, which answers a ping (queues
/// a pong, flushed by the data writer on this leg) and notices a close. A `tcp` leg carries no
/// control frames, so its idle half is just dropped. The task ends when the leg closes.
fn service_idle_reader(reader: TunnelReader) {
    if !matches!(reader, TunnelReader::Ws(_) | TunnelReader::Wss(_)) {
        return;
    }
    tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = [0u8; 256];
        // No tunnel data ever flows this (idle) direction; a single read stays pending and
        // services control frames internally, returning only on data (none) or close.
        while reader.read(&mut buf).await.is_ok_and(|n| n > 0) {}
    });
}

/// Services the idle write half of a split tunnel's ws/wss leg: periodically flushes it so a
/// pong queued by this leg's reader (the one the combined stream reads) is actually sent, which
/// a CDN or reverse proxy on that leg needs to see. A `tcp` leg is just dropped. The task ends
/// when the leg closes.
fn service_idle_writer(writer: TunnelWriter) {
    if !matches!(writer, TunnelWriter::Ws(_) | TunnelWriter::Wss(_)) {
        return;
    }
    tokio::spawn(async move {
        let mut writer = writer;
        loop {
            tokio::time::sleep(PONG_FLUSH_INTERVAL).await;
            if writer.flush().await.is_err() {
                break;
            }
        }
    });
}
use crate::config::{TransportKind, Tuning};

/// Builds a dialer for a tunnel: a normal one, or an asymmetric (split) one when `recv` names
/// the receive link's transport and address. `base` is the send link's settings; the receive
/// link reuses its shared options.
pub fn dialer(
    base: &Settings,
    send_addr: &str,
    recv: Option<(TransportKind, &str)>,
    tuning: &Tuning,
) -> io::Result<Dialer> {
    match recv {
        Some((kind, recv_addr)) => {
            // ws/wss legs of a split tunnel cannot use early_data (it deadlocks the one-way
            // handshake), so clear it on both legs.
            let base = base.without_early_data();
            Ok(Dialer::Split(Box::new(SplitDialer::new(
                &base,
                send_addr,
                &base.with_kind(kind),
                recv_addr,
                tuning,
            )?)))
        }
        None => Dialer::new(base, send_addr, tuning),
    }
}

/// Builds a listener for a tunnel: a normal one, or an asymmetric (split) one when `recv`
/// names the receive link's transport and address.
pub async fn listener(
    base: &Settings,
    send_addr: &str,
    recv: Option<(TransportKind, &str)>,
    tuning: &Tuning,
) -> io::Result<Listener> {
    match recv {
        Some((kind, recv_addr)) => {
            // Match the dialer: no early_data on a split tunnel's ws/wss legs.
            let base = base.without_early_data();
            Ok(Listener::Split(Box::new(
                SplitListener::bind(&base, send_addr, &base.with_kind(kind), recv_addr, tuning)
                    .await?,
            )))
        }
        None => Listener::bind(base, send_addr, tuning).await,
    }
}

/// The correlation id a dialer sends first on each of a split tunnel's two links.
const PAIR_ID_LEN: usize = 16;

/// How many completed pairs the accept channel buffers before back-pressuring the loops.
const ACCEPT_BACKLOG: usize = 64;

/// Dialing side of an asymmetric tunnel: the send link (`transport`) and the receive link
/// (`recv_transport`).
pub struct SplitDialer {
    send: Dialer,
    recv: Dialer,
}

impl SplitDialer {
    pub fn new(
        send: &Settings,
        send_addr: &str,
        recv: &Settings,
        recv_addr: &str,
        tuning: &Tuning,
    ) -> io::Result<Self> {
        Ok(Self {
            send: Dialer::new(send, send_addr, tuning)?,
            recv: Dialer::new(recv, recv_addr, tuning)?,
        })
    }

    /// Dials both links, sends the correlation id first on each, then writes `first` (the
    /// tunnel hello) on the send link and returns the combined stream. [`crate::channel::
    /// connect`] then reads the reply from it, which arrives on the receive link.
    pub async fn dial_with(&self, first: &[u8]) -> io::Result<TunnelStream> {
        let id = crate::crypto::random_bytes::<PAIR_ID_LEN>()?;
        let send = self.send.dial_with(&id).await?;
        let recv = self.recv.dial_with(&id).await?;
        // Keep the send link's writer and the receive link's reader. The other two halves are
        // the idle directions: on a ws/wss leg they are serviced in the background so control
        // frames (ping/close) are still handled; on a tcp leg they are dropped.
        let (send_reader, send_writer) = send.into_split();
        let (recv_reader, recv_writer) = recv.into_split();
        service_idle_reader(send_reader);
        service_idle_writer(recv_writer);
        let mut stream = TunnelStream::Combined {
            reader: recv_reader,
            writer: send_writer,
        };
        if !first.is_empty() {
            stream.write_all(first).await?;
            stream.flush().await?;
        }
        Ok(stream)
    }
}

/// Accepting side of an asymmetric tunnel: two listeners (the send-link and receive-link
/// ports) whose connections are paired by correlation id in the background. [`accept`] hands
/// back each already-combined stream, so the caller's accept loop is unchanged.
pub struct SplitListener {
    incoming: AsyncMutex<mpsc::Receiver<(TunnelStream, SocketAddr)>>,
    local: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for SplitListener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl SplitListener {
    /// Binds both links' listeners and starts pairing their connections in the background.
    pub async fn bind(
        send: &Settings,
        send_addr: &str,
        recv: &Settings,
        recv_addr: &str,
        tuning: &Tuning,
    ) -> io::Result<Self> {
        let send_listener = Listener::bind(send, send_addr, tuning).await?;
        let recv_listener = Listener::bind(recv, recv_addr, tuning).await?;
        let local = send_listener.local_addr()?;
        let pairing = Arc::new(Pairing::default());
        let (tx, rx) = mpsc::channel(ACCEPT_BACKLOG);
        // A connection has this long to establish, send its id and find its partner.
        let wait = tuning.dial_timeout + tuning.handshake_timeout;
        let tasks = vec![
            accept_loop(send_listener, true, pairing.clone(), tx.clone(), wait),
            accept_loop(recv_listener, false, pairing, tx, wait),
        ];
        Ok(Self {
            incoming: AsyncMutex::new(rx),
            local,
            tasks,
        })
    }

    /// The next paired, combined connection.
    pub async fn accept(&self) -> io::Result<(Incoming, SocketAddr)> {
        match self.incoming.lock().await.recv().await {
            Some((stream, peer)) => Ok((Incoming::Combined(stream), peer)),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "split listener's accept loops stopped",
            )),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// Spawns one listener's accept loop. Each accepted connection is handled in its own task so a
/// slow or silent client cannot hold up pairing of the others.
fn accept_loop(
    listener: Listener,
    is_send: bool,
    pairing: Arc<Pairing>,
    tx: mpsc::Sender<(TunnelStream, SocketAddr)>,
    wait: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (incoming, peer) = match listener.accept().await {
                Ok(v) => v,
                // A transient accept error should not spin the loop hot.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            if tx.is_closed() {
                return;
            }
            let (pairing, tx) = (pairing.clone(), tx.clone());
            tokio::spawn(async move {
                if let Some(combined) = pair_one(incoming, is_send, &pairing, wait).await {
                    let _ = tx.send((combined, peer)).await;
                }
            });
        }
    })
}

/// Establishes one link, reads its correlation id, and joins it with its partner. Returns the
/// combined stream only to the second link of a pair (which then drives the session).
async fn pair_one(
    incoming: Incoming,
    is_send: bool,
    pairing: &Arc<Pairing>,
    wait: Duration,
) -> Option<TunnelStream> {
    let mut stream = timeout(wait, incoming.establish()).await.ok()?.ok()?;
    let mut id = [0u8; PAIR_ID_LEN];
    timeout(wait, stream.read_exact(&mut id)).await.ok()?.ok()?;
    pairing.join(id, is_send, stream, wait).await
}

/// Pairs the two physical connections of each asymmetric tunnel by their correlation id,
/// across the send-link and receive-link accept loops.
#[derive(Default)]
struct Pairing {
    waiting: Mutex<HashMap<[u8; PAIR_ID_LEN], Parked>>,
}

/// The first link of a pair, waiting for its partner.
struct Parked {
    stream: TunnelStream,
    is_send: bool,
    /// Resolves when the partner takes this link, so the first loop stops waiting.
    taken: oneshot::Sender<()>,
}

impl Pairing {
    /// Registers a just-read link. The *second* arrival of a pair gets the combined stream
    /// (`reader` from the send link, `writer` to the receive link) and drives the session;
    /// the first arrival returns `None` once its partner takes it, or after `wait` elapses
    /// with no partner (its connection is then dropped).
    async fn join(
        self: &Arc<Self>,
        id: [u8; PAIR_ID_LEN],
        is_send: bool,
        stream: TunnelStream,
        wait: Duration,
    ) -> Option<TunnelStream> {
        let rx = {
            let mut waiting = self.waiting.lock().unwrap();
            if let Some(other) = waiting.remove(&id) {
                // Both links claiming the same role is a stray or an attack: drop both.
                if other.is_send == is_send {
                    return None;
                }
                let _ = other.taken.send(());
                let (send, recv) = if is_send {
                    (stream, other.stream)
                } else {
                    (other.stream, stream)
                };
                // The acceptor reads the send link and writes the receive link; the idle halves
                // are serviced (ws/wss) or dropped (tcp) just as on the dialing side.
                let (send_reader, send_writer) = send.into_split();
                let (recv_reader, recv_writer) = recv.into_split();
                service_idle_writer(send_writer);
                service_idle_reader(recv_reader);
                return Some(TunnelStream::Combined {
                    reader: send_reader,
                    writer: recv_writer,
                });
            }
            let (taken, rx) = oneshot::channel();
            waiting.insert(
                id,
                Parked {
                    stream,
                    is_send,
                    taken,
                },
            );
            rx
        };
        // First arrival: wait for the partner. On timeout, take our own entry back out (if the
        // partner has not already claimed it) so its connection is dropped rather than leaked.
        if timeout(wait, rx).await.is_err() {
            self.waiting.lock().unwrap().remove(&id);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    /// An asymmetric tunnel with two *different* transports (tcp out, ws back) pairs its two
    /// connections and carries data each way over the combined stream.
    #[tokio::test]
    async fn split_pairs_two_transports_and_carries_both_ways() {
        let tuning = Tuning::for_profile(crate::config::Profile::default());
        let send = Settings {
            kind: TransportKind::Tcp,
            ..Default::default()
        };
        let recv = Settings {
            kind: TransportKind::Ws,
            ..Default::default()
        };
        let send_addr = format!("127.0.0.1:{}", free_port().await);
        let recv_addr = format!("127.0.0.1:{}", free_port().await);

        let listener = SplitListener::bind(&send, &send_addr, &recv, &recv_addr, &tuning)
            .await
            .unwrap();
        let dialer = SplitDialer::new(&send, &send_addr, &recv, &recv_addr, &tuning).unwrap();

        let dial = tokio::spawn(async move {
            // The hello-sized first bytes ride the send link; the reply comes back on the
            // receive link.
            let mut s = dialer.dial_with(b"ping-from-dialer").await.unwrap();
            let mut buf = [0u8; 16];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong-to-dialer!!");
        });

        let (incoming, _peer) = listener.accept().await.unwrap();
        let mut acc = incoming.establish().await.unwrap();
        let mut buf = [0u8; 16];
        acc.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-from-dialer");
        acc.write_all(b"pong-to-dialer!!").await.unwrap();
        acc.flush().await.unwrap();

        dial.await.unwrap();
    }

    /// A ws leg with `early_data` on used to deadlock a split tunnel's handshake (the acceptor
    /// never writes the send link, so the held-back HTTP 101 was never flushed). The split
    /// builder now turns `early_data` off, so the tunnel comes up. Goes through the free
    /// `dialer`/`listener`, which is where that happens.
    #[tokio::test]
    async fn split_ws_leg_with_early_data_still_establishes() {
        let tuning = Tuning::for_profile(crate::config::Profile::default());
        let base = Settings {
            kind: TransportKind::Ws,
            ws: Some(crate::config::WsConfig {
                path: "/stream".into(),
                host: None,
                user_agent: None,
                headers: Default::default(),
                early_data: true,
            }),
            ..Default::default()
        };
        let send_addr = format!("127.0.0.1:{}", free_port().await);
        let recv_addr = format!("127.0.0.1:{}", free_port().await);
        let recv = Some((TransportKind::Tcp, recv_addr.as_str()));

        let listener = super::listener(&base, &send_addr, recv, &tuning)
            .await
            .unwrap();
        let dialer = super::dialer(&base, &send_addr, recv, &tuning).unwrap();

        let dial = tokio::spawn(async move {
            // Without the fix this never returns and the timeout fires.
            let mut s = timeout(
                Duration::from_secs(5),
                dialer.dial_with(b"ping-from-dialer"),
            )
            .await
            .expect("dial timed out: early_data deadlock")
            .unwrap();
            let mut buf = [0u8; 16];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong-to-dialer!!");
        });

        let (incoming, _peer) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timed out")
            .unwrap();
        let mut acc = incoming.establish().await.unwrap();
        let mut buf = [0u8; 16];
        acc.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-from-dialer");
        acc.write_all(b"pong-to-dialer!!").await.unwrap();
        acc.flush().await.unwrap();

        dial.await.unwrap();
    }
}
