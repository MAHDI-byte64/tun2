use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::Profile;

fn params(key: u8) -> KcpParams {
    KcpParams {
        config: KcpConfig::default(),
        key: [key; 32],
        carrier: Carrier::Udp,
    }
}

fn tuning() -> Tuning {
    let mut t = Tuning::for_profile(Profile::Balanced);
    t.keepalive = Duration::from_secs(3);
    t
}

async fn listener(key: u8) -> (KcpListener, String) {
    let l = KcpListener::bind("127.0.0.1:0", &params(key), &tuning())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (l, addr)
}

async fn accept(l: &KcpListener) -> KcpStream {
    tokio::time::timeout(Duration::from_secs(5), l.accept())
        .await
        .expect("accepted in time")
        .unwrap()
        .0
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// Echoes one accepted connection until the peer's FIN, then closes.
fn echo(stream: KcpStream) {
    tokio::spawn(async move {
        let (mut r, mut w) = stream.into_split();
        tokio::io::copy(&mut r, &mut w).await.unwrap();
        w.shutdown().await.unwrap();
    });
}

/// Writes `payload`, shuts down, and reads until the end of the stream.
async fn round_trip(stream: KcpStream, payload: &[u8]) -> io::Result<Vec<u8>> {
    let (mut r, mut w) = stream.into_split();
    let write = async {
        w.write_all(payload).await?;
        w.shutdown().await
    };
    let mut out = Vec::new();
    let (a, b) = tokio::join!(write, r.read_to_end(&mut out));
    a?;
    b?;
    Ok(out)
}

#[tokio::test]
async fn echo_with_half_close() {
    let (l, addr) = listener(1).await;
    let dialer = KcpDialer::new(&addr, &params(1), &tuning());
    let client = dialer.dial().await.unwrap();
    echo(accept(&l).await);
    let got = round_trip(client, b"hello over kcp").await.unwrap();
    assert_eq!(got, b"hello over kcp");
}

#[tokio::test]
async fn large_transfer_arrives_intact() {
    let (l, addr) = listener(1).await;
    let dialer = KcpDialer::new(&addr, &params(1), &tuning());
    let client = dialer.dial().await.unwrap();
    echo(accept(&l).await);
    let payload = pattern(8 << 20);
    let got = tokio::time::timeout(Duration::from_secs(60), round_trip(client, &payload))
        .await
        .expect("transfer in time")
        .unwrap();
    assert!(got == payload, "payload corrupted");
}

#[tokio::test]
async fn many_connections_on_one_listener() {
    // A slow machine (the ARM tests run under QEMU) drops some of the 20 dialers' first
    // packets when their bursts fill the listener's socket buffer. Until KCP's resend
    // gets through, a keep-alive ping for a conversation the listener does not know
    // ends it (that is how a restarted listener closes old conversations), so this
    // test's pings must be rarer than its slowest start.
    let mut slow = tuning();
    slow.keepalive = Duration::from_secs(60);
    let l = KcpListener::bind("127.0.0.1:0", &params(1), &slow)
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let l = Arc::new(l);
    let acceptor = {
        let l = l.clone();
        tokio::spawn(async move {
            loop {
                echo(accept(&l).await);
            }
        })
    };
    let dialer = Arc::new(KcpDialer::new(&addr, &params(1), &slow));
    let clients = (0..20).map(|i| {
        let dialer = dialer.clone();
        tokio::spawn(async move {
            let payload = pattern(1000 + i * 7919);
            let got = round_trip(dialer.dial().await.unwrap(), &payload)
                .await
                .unwrap();
            assert!(got == payload, "connection {i} corrupted");
        })
    });
    for c in clients.collect::<Vec<_>>() {
        c.await.unwrap();
    }
    acceptor.abort();
}

/// Anything not sealed with the token gets no answer and opens nothing, whether random
/// bytes or a well-formed KCP packet in the clear.
#[tokio::test]
async fn probes_get_no_answer() {
    let (l, addr) = listener(1).await;
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.connect(&addr).await.unwrap();
    let mut kcp_open = vec![PACKET_DATA];
    kcp_open.extend_from_slice(&7u32.to_le_bytes());
    kcp_open.extend_from_slice(&[KCP_CMD_PUSH, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
    kcp_open.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, MSG_OPEN]);
    let mut probes: Vec<Vec<u8>> = vec![Vec::new(), vec![0], kcp_open, pattern(1200)];
    for len in [28, 29, 64, 1400] {
        probes.push((0..len).map(|i| (i * 7 + len) as u8).collect());
    }
    for p in &probes {
        probe.send(p).await.unwrap();
    }
    let mut buf = [0u8; 2048];
    let answer = tokio::time::timeout(Duration::from_millis(500), probe.recv(&mut buf)).await;
    assert!(answer.is_err(), "the listener answered a probe");
    let accepted = tokio::time::timeout(Duration::from_millis(100), l.accept()).await;
    assert!(accepted.is_err(), "a probe opened a connection");
}

/// A dialer with another token is ignored the same way.
#[tokio::test]
async fn wrong_key_is_ignored() {
    let (l, addr) = listener(1).await;
    let dialer = KcpDialer::new(&addr, &params(2), &tuning());
    let mut client = dialer.dial().await.unwrap();
    client.write_all(b"let me in").await.unwrap();
    let accepted = tokio::time::timeout(Duration::from_millis(500), l.accept()).await;
    assert!(accepted.is_err(), "a wrong key opened a connection");
}

/// A UDP proxy in front of `to`. Towards the listener it corrupts one byte in a share
/// `corrupt` (percent) of the packets; in both directions it drops a share `drop` and
/// delays the rest by `delay`. Large buffers, so it loses nothing else. Returns its
/// address and the task, to abort.
async fn proxy(
    to: &str,
    corrupt: u64,
    drop: u64,
    delay: Duration,
) -> (String, tokio::task::JoinHandle<()>) {
    let front = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap(), 4 << 20, None).unwrap());
    let front_addr = front.local_addr().unwrap().to_string();
    let upstream = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap(), 4 << 20, None).unwrap());
    upstream.connect(to).await.unwrap();
    // Sends after the delay, in order: (due, packet, destination or the connected peer).
    type Delayed = (Instant, Vec<u8>, Option<SocketAddr>);
    let delayed = |socket: Arc<UdpSocket>| {
        let (tx, mut rx) = mpsc::unbounded_channel::<Delayed>();
        let task = tokio::spawn(async move {
            while let Some((due, packet, to)) = rx.recv().await {
                sleep_until(due).await;
                let _ = match to {
                    Some(to) => socket.send_to(&packet, to).await,
                    None => socket.send(&packet).await,
                };
            }
        });
        (tx, task)
    };
    let (to_listener, forward) = delayed(upstream.clone());
    let (to_dialer, back_task) = delayed(front.clone());
    let task = tokio::spawn(async move {
        let _tasks = (AbortOnDrop(forward), AbortOnDrop(back_task));
        let (mut buf, mut back) = (vec![0u8; 65_536], vec![0u8; 65_536]);
        let mut client = None;
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        // A percentage and a spare random number, per packet.
        let mut draw = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng % 100, rng >> 8)
        };
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut buf) => {
                    client = Some(from);
                    let (p, r) = draw();
                    if p < drop {
                        continue;
                    }
                    if p < drop + corrupt {
                        buf[r as usize % n] ^= 0x40;
                    }
                    let _ = to_listener.send((Instant::now() + delay, buf[..n].to_vec(), None));
                }
                Ok(n) = upstream.recv(&mut back) => {
                    if draw().0 < drop {
                        continue;
                    }
                    if client.is_some() {
                        let _ = to_dialer.send((Instant::now() + delay, back[..n].to_vec(), client));
                    }
                }
            }
        }
    });
    (front_addr, task)
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A proxy that corrupts one byte in a fifth of the packets towards the listener: the
/// protection drops those, KCP resends them, and the data arrives intact.
#[tokio::test]
async fn tampered_packets_are_dropped() {
    let (l, addr) = listener(1).await;
    let (proxy_addr, forward) = proxy(&addr, 20, 0, Duration::ZERO).await;
    let dialer = KcpDialer::new(&proxy_addr, &params(1), &tuning());
    let client = dialer.dial().await.unwrap();
    echo(accept(&l).await);
    let payload = pattern(1 << 20);
    let got = tokio::time::timeout(Duration::from_secs(60), round_trip(client, &payload))
        .await
        .expect("transfer in time")
        .unwrap();
    assert!(got == payload, "payload corrupted");
    forward.abort();
}

fn params_fec(key: u8, data: usize, parity: usize) -> KcpParams {
    let mut p = params(key);
    p.config.fec_data = Some(data);
    p.config.fec_parity = Some(parity);
    p
}

/// 2 MiB sent one way through a proxy that drops 5 % of the packets each way, with a
/// 20 ms round trip, and FEC on both sides or off. Returns the sender's packet counts
/// and the receiver's.
async fn transfer_with_loss(fec: Option<(usize, usize)>) -> (KcpStats, KcpStats) {
    let mut params = match fec {
        Some((data, parity)) => params_fec(1, data, parity),
        None => params(1),
    };
    // A window near the path's capacity, as it would be configured for it, and the
    // gentle preset: with a 30 ms minimum timeout (the fast ones) KCP also resends many
    // segments that only had their acks delayed, which would drown what FEC saves.
    params.config.send_window = 256;
    params.config.recv_window = 256;
    params.config.mode = crate::config::KcpMode::Normal;
    let l = KcpListener::bind("127.0.0.1:0", &params, &tuning())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (proxy_addr, forward) = proxy(&addr, 0, 5, Duration::from_millis(10)).await;
    let mut client = KcpDialer::new(&proxy_addr, &params, &tuning())
        .dial()
        .await
        .unwrap();
    let mut server = accept(&l).await;
    let payload = pattern(2 << 20);
    let send = async {
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
    };
    let mut got = Vec::new();
    let receive = tokio::time::timeout(Duration::from_secs(60), server.read_to_end(&mut got));
    let ((), received) = tokio::join!(send, receive);
    received.expect("transfer in time").unwrap();
    assert!(got == payload, "payload corrupted");
    forward.abort();
    (client.stats(), server.stats())
}

/// With FEC the receiver rebuilds lost packets itself, so fewer resends are needed:
/// fewer gaps in the received data are filled by a resent segment. (The sender's own
/// resend count is no measure: it also counts resends of segments whose acks were only
/// late, which depend on how busy the machine is.)
#[tokio::test(flavor = "multi_thread")]
async fn fec_saves_retransmissions() {
    let (plain, plain_receiver) = transfer_with_loss(None).await;
    let (fec, receiver) = transfer_with_loss(Some((10, 3))).await;
    assert_eq!((plain.parity_packets, plain_receiver.recovered), (0, 0));
    assert!(plain_receiver.gaps_filled > 10, "{plain_receiver:?}");
    assert!(fec.parity_packets > 0, "{fec:?}");
    assert!(receiver.recovered > 0, "{receiver:?}");
    assert!(
        receiver.gaps_filled * 2 < plain_receiver.gaps_filled,
        "with FEC {receiver:?}, without {plain_receiver:?}"
    );
}

/// Only the sender's settings decide whether it uses FEC: each side reads what comes.
#[tokio::test]
async fn fec_on_one_side_only() {
    for (listening, dialing) in [
        (params_fec(1, 4, 2), params(1)),
        (params(1), params_fec(1, 4, 2)),
    ] {
        let l = KcpListener::bind("127.0.0.1:0", &listening, &tuning())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let client = KcpDialer::new(&addr, &dialing, &tuning())
            .dial()
            .await
            .unwrap();
        echo(accept(&l).await);
        let payload = pattern(300_000);
        let got = round_trip(client, &payload).await.unwrap();
        assert!(got == payload);
    }
}

/// A lone small write with FEC: its group is closed after the KCP interval, so parity
/// follows without waiting for more traffic.
#[tokio::test]
async fn fec_closes_a_lone_packet_group() {
    let params = params_fec(1, 10, 3);
    let l = KcpListener::bind("127.0.0.1:0", &params, &tuning())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let mut client = KcpDialer::new(&addr, &params, &tuning())
        .dial()
        .await
        .unwrap();
    let mut server = accept(&l).await;
    client.write_all(b"one").await.unwrap();
    let mut buf = [0u8; 3];
    server.read_exact(&mut buf).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(client.stats().parity_packets > 0, "{:?}", client.stats());
}

/// A listener restarted on the same port answers the old conversation with a close, so
/// the dialer's connection fails at once instead of after the keep-alive timeout.
#[tokio::test]
async fn restarted_listener_closes_old_conversations() {
    let (l, addr) = listener(1).await;
    let dialer = KcpDialer::new(&addr, &params(1), &tuning());
    let mut client = dialer.dial().await.unwrap();
    let mut server = accept(&l).await;
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    // The dialer has heard from this listener (as after any handshake).
    server.write_all(b"pong").await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    drop((server, l));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _l = KcpListener::bind(&addr, &params(1), &tuning())
        .await
        .unwrap();
    let started = Instant::now();
    let failed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client.write_all(b"more").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(failed.is_ok(), "old conversation still open");
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Both halves dropped on one side: the other side reads to the end and is done.
#[tokio::test]
async fn dropping_a_stream_ends_it_cleanly() {
    let (l, addr) = listener(1).await;
    let dialer = KcpDialer::new(&addr, &params(1), &tuning());
    let mut client = dialer.dial().await.unwrap();
    let mut server = accept(&l).await;
    client.write_all(b"last words").await.unwrap();
    drop(client);
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut got))
        .await
        .expect("end of stream in time")
        .unwrap();
    assert_eq!(got, b"last words");
}

/// A peer that disappears without a word (its process gone) is noticed by its silence
/// after twice the keep-alive.
#[tokio::test(flavor = "multi_thread")]
async fn silent_peer_times_out() {
    let (l, addr) = listener(1).await;
    let dialing = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dialer = KcpDialer::new(&addr, &params(1), &tuning());
            let mut client = dialer.dial().await.unwrap();
            client.write_all(b"x").await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        // Dropping the runtime stops the driver without a close, like a killed process.
    });
    let mut server = accept(&l).await;
    let mut buf = [0u8; 1];
    server.read_exact(&mut buf).await.unwrap();
    tokio::task::spawn_blocking(move || dialing.join().unwrap())
        .await
        .unwrap();
    let started = Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(10), server.read(&mut buf)).await;
    let err = read
        .expect("noticed in time")
        .expect_err("silence is an error");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(!server.is_alive());
}

/// A dialed connection and the listener's side of it, with the listener kept alive.
async fn pair(p: &KcpParams) -> Pair {
    let l = KcpListener::bind("127.0.0.1:0", p, &tuning())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let mut client = KcpDialer::new(&addr, p, &tuning()).dial().await.unwrap();
    // The listener hears of the conversation with the first data.
    client.write_all(b"hi").await.unwrap();
    let mut server = accept(&l).await;
    let mut buf = [0u8; 2];
    server.read_exact(&mut buf).await.unwrap();
    Pair {
        client,
        server,
        _listener: l,
    }
}

struct Pair {
    client: KcpStream,
    server: KcpStream,
    _listener: KcpListener,
}

/// Receives datagrams until `quiet` passes without one.
async fn drain_datagrams(d: &KcpDatagrams, quiet: Duration) -> Vec<Bytes> {
    let mut got = Vec::new();
    while let Ok(Some(datagram)) = tokio::time::timeout(quiet, d.recv()).await {
        got.push(datagram);
    }
    got
}

#[tokio::test]
async fn datagrams_both_ways_beside_the_stream() {
    for fec in [false, true] {
        let p = if fec { params_fec(1, 4, 2) } else { params(1) };
        let Pair {
            mut client,
            mut server,
            _listener,
        } = pair(&p).await;
        let (c, s) = (client.datagrams().unwrap(), server.datagrams().unwrap());
        let max = c.max_len();
        assert_eq!(max, KcpConfig::default().mtu - DATAGRAM_HEADER);
        for len in [0, 1, 100, max] {
            assert!(c.send(&pattern(len), fec));
            assert_eq!(s.recv().await.unwrap(), pattern(len), "fec {fec}, {len}");
            assert!(s.send(&pattern(len), fec));
            assert_eq!(c.recv().await.unwrap(), pattern(len), "fec {fec}, {len}");
        }
        assert!(!c.send(&pattern(max + 1), fec), "too large");
        // The stream is unaffected.
        client.write_all(b"stream").await.unwrap();
        let mut buf = [0u8; 6];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"stream");
        assert_eq!(client.stats().datagrams_sent, 4);
        assert_eq!(server.stats().datagrams_received, 4);
    }
}

/// Datagrams are never resent: through a link that drops a fifth of the packets, about
/// a fifth of them are missing, while the stream beside them still arrives whole.
#[tokio::test]
async fn lost_datagrams_are_not_resent() {
    let (l, addr) = listener(1).await;
    let (proxy_addr, forward) = proxy(&addr, 0, 20, Duration::from_millis(5)).await;
    let mut client = KcpDialer::new(&proxy_addr, &params(1), &tuning())
        .dial()
        .await
        .unwrap();
    client.write_all(b"hi").await.unwrap();
    let mut server = accept(&l).await;
    let (c, s) = (client.datagrams().unwrap(), server.datagrams().unwrap());
    let payload = pattern(256 << 10);
    let stream = async {
        let mut got = vec![0u8; 2 + payload.len()];
        server.read_exact(&mut got).await.unwrap();
        got
    };
    let datagrams = async {
        for i in 0..200u32 {
            c.send(&i.to_le_bytes(), false);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    let ((), (), got) = tokio::join!(
        async { client.write_all(&payload).await.unwrap() },
        datagrams,
        stream
    );
    assert!(got[2..] == payload[..], "stream corrupted");
    let received = drain_datagrams(&s, Duration::from_millis(300)).await;
    // 20 % loss of 200: well inside 100-190 for any seed.
    assert!(
        (100..190).contains(&received.len()),
        "{} of 200 datagrams arrived",
        received.len()
    );
    forward.abort();
}

/// With FEC, lost datagrams are rebuilt from parity: through a link that drops a tenth
/// of the packets, nearly all arrive, some of them rebuilt.
#[tokio::test]
async fn fec_rebuilds_lost_datagrams() {
    let p = params_fec(1, 4, 2);
    let l = KcpListener::bind("127.0.0.1:0", &p, &tuning())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (proxy_addr, forward) = proxy(&addr, 0, 10, Duration::ZERO).await;
    let mut client = KcpDialer::new(&proxy_addr, &p, &tuning())
        .dial()
        .await
        .unwrap();
    client.write_all(b"hi").await.unwrap();
    let server = accept(&l).await;
    let (c, s) = (client.datagrams().unwrap(), server.datagrams().unwrap());
    // Received while sent: the receive queue holds 256.
    let send = async {
        for i in 0..400u32 {
            c.send(&i.to_le_bytes(), true);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let ((), received) = tokio::join!(send, drain_datagrams(&s, Duration::from_millis(300)));
    let mut unique: Vec<&[u8]> = received.iter().map(|d| &d[..]).collect();
    unique.sort();
    unique.dedup();
    // Without FEC about 360 would arrive; with 4 + 2 a group loses packets only when
    // three of its six are lost.
    assert!(
        unique.len() >= 385,
        "{} of 400 datagrams arrived",
        unique.len()
    );
    assert!(server.stats().recovered > 0, "{:?}", server.stats());
    forward.abort();
}

#[test]
fn only_a_first_data_segment_opens_a_conversation() {
    let mut first = vec![PACKET_DATA];
    first.extend_from_slice(&[9, 0, 0, 0, KCP_CMD_PUSH, 0, 0, 4]);
    first.extend_from_slice(&[0; 16]);
    assert!(opens_conversation(&first));
    let mut later = first.clone();
    later[1 + 12] = 1;
    assert!(!opens_conversation(&later));
    let mut ack = first.clone();
    ack[1 + 4] = 82;
    assert!(!opens_conversation(&ack));
    let mut ping = first.clone();
    ping[0] = PACKET_PING;
    assert!(!opens_conversation(&ping));
    assert!(!opens_conversation(&first[..10]));
}

/// `tuning.dscp` reaches the sockets of dialers and listeners.
#[tokio::test]
async fn kcp_sockets_are_marked() {
    use crate::transport::tests::{local_addrs, mark_of, tos};
    for dscp in [None, Some(46)] {
        let mut t = tuning();
        t.dscp = dscp;
        let settings = ConnSettings::new(&params(1), &t);
        for addr in local_addrs() {
            let socket = udp_socket(addr.parse().unwrap(), 1 << 20, settings.dscp).unwrap();
            let mark = mark_of(socket2::SockRef::from(&socket));
            assert_eq!(mark, tos(dscp), "{addr} {dscp:?}");
        }
    }
}

/// `[tunnel.kcp] datagrams = false`: streams offer no datagram side, so UDP flows stay
/// in the reliable stream as in v0.4.
#[tokio::test]
async fn datagrams_can_be_turned_off() {
    let mut p = params(1);
    p.config.datagrams = false;
    let Pair {
        client,
        server,
        _listener,
    } = pair(&p).await;
    assert!(client.datagrams().is_none() && server.datagrams().is_none());
}
