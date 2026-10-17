//! `transport = "kcp"`: KCP, an ARQ protocol over UDP that trades bandwidth for latency,
//! as a byte stream under the tunnel's handshake, records and mux.
//!
//! ```text
//!  handshake / records / kmux      unchanged, over a KcpStream
//!  KcpStream                       reader and writer halves, fed by a driver task
//!  KCP (message mode)              one driver per connection: `kcp` crate, our timers
//!  packet protection               every UDP packet sealed with a key from the token
//!  UDP socket                      the dialer's own, or the listener's shared one
//! ```
//!
//! Each UDP packet carries one of these (the first plaintext byte): KCP segments, a ping,
//! a close, a datagram, or with FEC on (`fec.rs`) KCP segments or a datagram as a data
//! shard, or a parity shard. Datagrams travel beside KCP,
//! not through it: they are never resent and never wait for a lost segment.
//! KCP runs in message mode so a message can say what it is: data, the
//! end of the stream in that direction (FIN), or the dialer's opening message, which makes
//! sure every conversation starts with a data segment numbered 0. The listener starts a
//! conversation only for such a packet; any other packet for a conversation it does not
//! know (after a restart, say) is answered with a close, so the dialer finds out at once.
//! Packets that were not sealed with the token get no answer at all.

pub mod carrier;
mod fec;
pub mod protect;
#[cfg(feature = "rawlink")]
pub mod rawlink;

pub use carrier::Carrier;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kcp::Kcp;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};
use tracing::debug;

use crate::config::{KcpConfig, KcpTiming, Tuning, TunnelConfig};
use crate::crypto::handshake::Key;
use crate::crypto::Psk;
use fec::{FecDecoder, FecEncoder, Shard};
use protect::{Nonces, Protection};

const KEY_CONTEXT: &str = "kariz 2026-10 kcp packets v1";

/// Packet types, the first byte of a packet's plaintext.
const PACKET_DATA: u8 = 0;
/// Keep-alive: `conv (4)`.
const PACKET_PING: u8 = 1;
/// The conversation is over: `conv (4)`.
const PACKET_CLOSE: u8 = 2;
/// KCP segments as an FEC data shard: `conv (4) | group (4) | index (1) | len (2) |
/// segments`.
const PACKET_FEC_DATA: u8 = 3;
/// `conv (4) | group (4) | index (1) | data count (1) | parity count (1) | shard`.
const PACKET_FEC_PARITY: u8 = 4;
/// Bytes before the shard in FEC packets.
const FEC_DATA_HEADER: usize = 1 + 4 + 4 + 1;
const FEC_PARITY_HEADER: usize = FEC_DATA_HEADER + 2;
/// A datagram beside KCP: `conv (4) | datagram`. Older versions ignore the type. In an
/// FEC data shard, a datagram is `!conv (4) | datagram`, which no KCP packet of the
/// conversation starts with (they start with `conv`).
const PACKET_DATAGRAM: u8 = 5;

/// Message tags, the first byte of every KCP message.
const MSG_DATA: u8 = 0;
const MSG_FIN: u8 = 1;
const MSG_OPEN: u8 = 2;

/// KCP segment header: conv (4) cmd (1) frg (1) wnd (2) ts (4) sn (4) una (4) len (4).
const KCP_HEADER: usize = 24;
const KCP_CMD_PUSH: u8 = 81;
const KCP_CMD_ACK: u8 = 82;
/// How far ahead the send time of a rebuilt ack is put, so KCP takes no round trip
/// sample from it (it only samples send times in the past).
const REBUILT_ACK_AHEAD_MS: u32 = 1000;

/// Largest KCP message: a tag and up to this much data less one byte.
const MAX_MESSAGE: usize = 16 * 1024;
/// Data a writer may queue for the driver before it has to wait.
const WRITE_QUEUE: usize = 64 * 1024;
/// Data the driver takes out of KCP ahead of the reader. Beyond it KCP's receive window
/// fills up, which slows the peer down.
const READ_QUEUE: usize = 256 * 1024;
/// Packets waiting for a listener-side connection's driver; more are dropped, like
/// packets on a congested link.
const CONN_QUEUE: usize = 1024;
/// New conversations waiting to be accepted; more are dropped (the dialer retries).
const ACCEPT_QUEUE: usize = 128;
const MAX_CONVERSATIONS: usize = 4096;
/// Datagrams received and not yet taken; the oldest are dropped.
const DATAGRAM_QUEUE: usize = 256;
/// Bytes before a datagram in a packet, beyond what a KCP packet has: the conversation
/// id (`PACKET_DATAGRAM`) or its marker (FEC).
const DATAGRAM_HEADER: usize = 4;

/// What listeners and dialers need from `[tunnel]`: `[tunnel.kcp]`, the packet key, and
/// which datagram carrier the KCP stack rides.
#[derive(Clone, Default)]
pub struct KcpParams {
    pub config: KcpConfig,
    key: Key,
    /// The carrier chosen from `[tunnel] transport` (udp, faketcp or icmp).
    pub carrier: Carrier,
}

impl fmt::Debug for KcpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpParams")
            .field("config", &self.config)
            .field("carrier", &self.carrier)
            .finish_non_exhaustive()
    }
}

impl KcpParams {
    /// `config`: `[tunnel.kcp]` with the profile's defaults (`Config::kcp`).
    pub fn new(tunnel: &TunnelConfig, config: KcpConfig) -> Self {
        Self {
            config,
            key: Psk::new(&tunnel.token).subkey(KEY_CONTEXT),
            carrier: Carrier::from_transport(tunnel.transport),
        }
    }
}

/// Per-connection settings.
#[derive(Clone)]
struct ConnSettings {
    timing: KcpTiming,
    send_window: u16,
    recv_window: u16,
    mtu: usize,
    /// A ping goes out every third of it; a peer silent for twice as long is dead.
    keepalive: Duration,
    socket_buffer: usize,
    dscp: Option<u8>,
    /// Whether streams offer their datagram side (`[tunnel.kcp] datagrams`).
    datagrams: bool,
    protection: Arc<Protection>,
    /// Data and parity shards per FEC group; `None`: FEC off.
    fec: Option<(usize, usize)>,
    /// The datagram carrier the packets ride.
    carrier: Carrier,
}

/// The UDP-carrier socket helper, kept for the kcp unit tests that build sockets directly.
#[cfg(test)]
fn udp_socket(addr: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<UdpSocket> {
    carrier::open(Carrier::Udp, addr, buffer, dscp)
}

impl ConnSettings {
    fn new(params: &KcpParams, tuning: &Tuning) -> Self {
        Self {
            timing: params.config.timing(),
            send_window: params.config.send_window,
            recv_window: params.config.recv_window,
            mtu: params.config.mtu,
            keepalive: tuning.keepalive,
            socket_buffer: tuning.udp.socket_buffer,
            dscp: tuning.dscp,
            datagrams: params.config.datagrams,
            protection: Arc::new(Protection::new(&params.key)),
            fec: params.config.fec(),
            carrier: params.carrier,
        }
    }
}

/// Seals packets and sends them without waiting: a full socket buffer drops the packet,
/// as a congested link would, and KCP sends it again.
struct Sender {
    socket: Arc<UdpSocket>,
    /// `None`: the socket is connected.
    peer: Option<SocketAddr>,
    conv: u32,
    protection: Arc<Protection>,
    nonces: Nonces,
    fec: Option<FecEncoder>,
    stats: Arc<ConnStats>,
    /// The next data segment number never sent: lower ones are resent.
    next_new_sn: u32,
    plain: Vec<u8>,
    sealed: Vec<u8>,
}

impl Sender {
    fn new(
        socket: Arc<UdpSocket>,
        peer: Option<SocketAddr>,
        conv: u32,
        settings: &ConnSettings,
        stats: Arc<ConnStats>,
    ) -> io::Result<Self> {
        let interval = Duration::from_millis(settings.timing.interval_ms.into());
        Ok(Self {
            socket,
            peer,
            conv,
            protection: settings.protection.clone(),
            nonces: Nonces::new()?,
            fec: settings
                .fec
                .map(|(data, parity)| FecEncoder::new(data, parity, interval)),
            stats,
            next_new_sn: 0,
            plain: Vec::with_capacity(1500),
            sealed: Vec::with_capacity(1500),
        })
    }

    /// Seals and sends `plain`.
    fn send_plain(&mut self) {
        self.protection
            .seal(&mut self.nonces, &self.plain, &mut self.sealed);
        let _ = match self.peer {
            Some(peer) => self.socket.try_send_to(&self.sealed, peer),
            None => self.socket.try_send(&self.sealed),
        };
    }

    fn send(&mut self, kind: u8, body: &[u8]) {
        self.plain.clear();
        self.plain.push(kind);
        self.plain.extend_from_slice(body);
        self.send_plain();
    }

    fn control(&mut self, kind: u8, conv: u32) {
        self.send(kind, &conv.to_le_bytes());
    }

    /// Sends a datagram beside KCP. With `fec` and FEC on, it goes into the open group
    /// (true: the driver has a group to close on time).
    fn datagram(&mut self, datagram: &[u8], fec: bool, now: Instant) -> bool {
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        match self.fec.take() {
            Some(mut encoder) if fec => {
                let mut content = Vec::with_capacity(DATAGRAM_HEADER + datagram.len());
                content.extend_from_slice(&(!self.conv).to_le_bytes());
                content.extend_from_slice(datagram);
                encoder.push(&content, now, &mut |shard| self.send_shard(shard));
                self.fec = Some(encoder);
                true
            }
            encoder => {
                self.fec = encoder;
                self.plain.clear();
                self.plain.push(PACKET_DATAGRAM);
                self.plain.extend_from_slice(&self.conv.to_le_bytes());
                self.plain.extend_from_slice(datagram);
                self.send_plain();
                false
            }
        }
    }

    /// A packet of KCP segments, as is or as an FEC data shard (then the group's parity
    /// follows when the group is full).
    fn kcp_packet(&mut self, packet: &[u8], now: Instant) {
        self.stats.kcp_packets.fetch_add(1, Ordering::Relaxed);
        for segment in segments(packet) {
            if segment[4] != KCP_CMD_PUSH {
                continue;
            }
            let sn = segment_sn(segment);
            if sn.wrapping_sub(self.next_new_sn) < 1 << 31 {
                self.next_new_sn = sn.wrapping_add(1);
            } else {
                self.stats.resent.fetch_add(1, Ordering::Relaxed);
            }
        }
        let segments = packet;
        let Some(mut fec) = self.fec.take() else {
            return self.send(PACKET_DATA, segments);
        };
        fec.push(segments, now, &mut |shard| self.send_shard(shard));
        self.fec = Some(fec);
    }

    /// Closes the FEC group if it has waited long enough.
    fn close_fec_group(&mut self, now: Instant) {
        if let Some(mut fec) = self.fec.take() {
            fec.close_if_due(now, &mut |shard| self.send_shard(shard));
            self.fec = Some(fec);
        }
    }

    fn fec_deadline(&self) -> Option<Instant> {
        self.fec.as_ref().and_then(FecEncoder::deadline)
    }

    fn send_shard(&mut self, shard: Shard<'_>) {
        self.plain.clear();
        let (group, index, shard) = match shard {
            Shard::Data {
                group,
                index,
                shard,
            } => {
                self.plain.push(PACKET_FEC_DATA);
                (group, index, shard)
            }
            Shard::Parity {
                group,
                index,
                data_count,
                parity_count,
                shard,
            } => {
                self.stats.parity_packets.fetch_add(1, Ordering::Relaxed);
                self.plain.push(PACKET_FEC_PARITY);
                self.plain.extend_from_slice(&self.conv.to_le_bytes());
                self.plain.extend_from_slice(&group.to_le_bytes());
                self.plain
                    .extend_from_slice(&[index, data_count, parity_count]);
                self.plain.extend_from_slice(shard);
                return self.send_plain();
            }
        };
        self.plain.extend_from_slice(&self.conv.to_le_bytes());
        self.plain.extend_from_slice(&group.to_le_bytes());
        self.plain.push(index);
        self.plain.extend_from_slice(shard);
        self.send_plain();
    }
}

/// KCP's side of the [`Sender`], which the driver shares for pings, closes and FEC.
struct Output(Arc<Mutex<Sender>>);

impl Write for Output {
    fn write(&mut self, segments: &[u8]) -> io::Result<usize> {
        lock(&self.0).kcp_packet(segments, Instant::now());
        Ok(segments.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Packet counts of a connection.
#[derive(Default, Debug)]
struct ConnStats {
    /// Packets of KCP segments sent (as FEC data shards or not).
    kcp_packets: AtomicU64,
    parity_packets: AtomicU64,
    /// Data segments sent again (KCP's retransmissions).
    resent: AtomicU64,
    /// KCP packets rebuilt from parity.
    recovered: AtomicU64,
    /// Data segments received that filled a gap: the resends a loss really needed
    /// (resends of segments that had arrived, or had been rebuilt, are not counted).
    gaps_filled: AtomicU64,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
}

/// A snapshot of a connection's packet counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KcpStats {
    pub kcp_packets: u64,
    pub parity_packets: u64,
    pub resent: u64,
    pub recovered: u64,
    pub gaps_filled: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
}

/// The conversation a packet's plaintext belongs to (every type starts with it).
fn conv_of(plain: &[u8]) -> Option<u32> {
    plain
        .get(1..5)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
}

/// The KCP segments in a packet's plaintext, if it carries them as they are (FEC or not).
fn segments_of(plain: &[u8]) -> Option<&[u8]> {
    match *plain.first()? {
        PACKET_DATA => Some(&plain[1..]),
        PACKET_FEC_DATA => {
            let shard = plain.get(FEC_DATA_HEADER..)?;
            let len = u16::from_le_bytes(shard.get(..2)?.try_into().ok()?) as usize;
            shard.get(2..2 + len)
        }
        _ => None,
    }
}

/// Whether a packet for a conversation the listener does not know comes from one it had
/// before (it was restarted, or ended the conversation): such a dialer gets a close. A
/// dialer that has received nothing yet (`una` 0 in its segments) may only have lost its
/// opening packet, which KCP will resend, so it gets no answer.
fn from_earlier_conversation(plain: &[u8]) -> bool {
    if plain[0] == PACKET_PING {
        return true;
    }
    segments_of(plain)
        .and_then(|segments| segments.get(16..20))
        .is_some_and(|una| una != [0; 4])
}

/// A packet that may start a conversation: KCP data whose first segment is the first
/// data segment (the dialer's opening message).
fn opens_conversation(plain: &[u8]) -> bool {
    let Some(segment) = segments_of(plain).and_then(|s| s.get(..KCP_HEADER)) else {
        return false;
    };
    segment[4] == KCP_CMD_PUSH && segment[12..16] == [0; 4]
}

/// State shared by a connection's halves and its driver.
#[derive(Default)]
struct State {
    /// Messages written and not yet handed to KCP.
    outgoing: VecDeque<Bytes>,
    outgoing_bytes: usize,
    write_waker: Option<Waker>,
    /// The writer was shut down or dropped: a FIN follows the queued data.
    shutdown: bool,
    reader_gone: bool,
    incoming: VecDeque<Bytes>,
    incoming_bytes: usize,
    read_waker: Option<Waker>,
    /// The peer's FIN came: reads return end of stream once `incoming` is empty.
    eof: bool,
    /// Datagrams received, oldest first.
    datagrams: VecDeque<Bytes>,
    datagram_waker: Option<Waker>,
    /// The driver has stopped; with `error`, the connection failed.
    ended: bool,
    error: Option<io::ErrorKind>,
}

struct Link {
    state: Mutex<State>,
    wake_driver: Notify,
    stats: Arc<ConnStats>,
}

impl Link {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A KCP connection as a byte stream.
pub struct KcpStream {
    reader: KcpReader,
    writer: KcpWriter,
    /// `None` with `[tunnel.kcp] datagrams = false`.
    datagrams: Option<KcpDatagrams>,
}

/// The datagram side of a KCP connection: packets sent beside KCP, unreliably, in the
/// same conversation (same socket, protection and FEC).
#[derive(Clone)]
pub struct KcpDatagrams {
    sender: Arc<Mutex<Sender>>,
    link: Arc<Link>,
    max_len: usize,
}

impl KcpDatagrams {
    /// Largest datagram that fits in one packet.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Sends `datagram` at once, or drops it (too large, connection over, socket buffer
    /// full). `fec`: protect it with FEC when FEC is on. Off for datagrams an older peer
    /// must be able to ignore: it would take one in an FEC shard for KCP data.
    pub fn send(&self, datagram: &[u8], fec: bool) -> bool {
        if datagram.len() > self.max_len || self.link.lock().ended {
            return false;
        }
        if lock(&self.sender).datagram(datagram, fec, Instant::now()) {
            // An FEC group may have opened: the driver closes it on time.
            self.link.wake_driver.notify_one();
        }
        true
    }

    /// The next datagram received; `None` once the connection is over.
    pub async fn recv(&self) -> Option<Bytes> {
        std::future::poll_fn(|cx| {
            let mut st = self.link.lock();
            if let Some(datagram) = st.datagrams.pop_front() {
                return Poll::Ready(Some(datagram));
            }
            if st.ended {
                return Poll::Ready(None);
            }
            st.datagram_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

pub struct KcpReader {
    link: Arc<Link>,
}

pub struct KcpWriter {
    link: Arc<Link>,
}

impl KcpStream {
    pub fn into_split(self) -> (KcpReader, KcpWriter) {
        (self.reader, self.writer)
    }

    /// The datagram side, unless `[tunnel.kcp] datagrams = false`.
    pub fn datagrams(&self) -> Option<KcpDatagrams> {
        self.datagrams.clone()
    }

    pub fn stats(&self) -> KcpStats {
        Self::stats_of(&self.reader.link.stats)
    }

    fn stats_of(stats: &ConnStats) -> KcpStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        KcpStats {
            kcp_packets: get(&stats.kcp_packets),
            parity_packets: get(&stats.parity_packets),
            resent: get(&stats.resent),
            recovered: get(&stats.recovered),
            gaps_filled: get(&stats.gaps_filled),
            datagrams_sent: get(&stats.datagrams_sent),
            datagrams_received: get(&stats.datagrams_received),
        }
    }

    /// True while the connection is open and nothing has arrived (see
    /// `TunnelStream::is_alive`).
    pub fn is_alive(&self) -> bool {
        let st = self.reader.link.lock();
        !st.ended && st.incoming.is_empty() && !st.eof
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl AsyncRead for KcpReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut st = self.link.lock();
        if st.incoming.is_empty() {
            if st.eof || (st.ended && st.error.is_none()) {
                return Poll::Ready(Ok(()));
            }
            if let Some(kind) = st.error {
                return Poll::Ready(Err(kind.into()));
            }
            st.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let was_full = st.incoming_bytes >= READ_QUEUE;
        while buf.remaining() > 0 {
            let Some(front) = st.incoming.front_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                st.incoming.pop_front();
            }
            st.incoming_bytes -= n;
        }
        let resume = was_full && st.incoming_bytes < READ_QUEUE;
        drop(st);
        if resume {
            self.link.wake_driver.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for KcpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.link.lock();
        if let Some(kind) = st.error {
            return Poll::Ready(Err(kind.into()));
        }
        if st.ended || st.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if st.outgoing_bytes >= WRITE_QUEUE {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(MAX_MESSAGE - 1);
        let mut message = BytesMut::with_capacity(n + 1);
        message.put_u8(MSG_DATA);
        message.put_slice(&buf[..n]);
        st.outgoing_bytes += message.len();
        st.outgoing.push_back(message.freeze());
        drop(st);
        self.link.wake_driver.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.link.lock().error {
            Some(kind) => Poll::Ready(Err(kind.into())),
            None => Poll::Ready(Ok(())),
        }
    }

    /// Queues the FIN behind the data written so far, like TCP.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.link.lock().shutdown = true;
        self.link.wake_driver.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// Dropping the writer ends the stream in that direction, as dropping a TCP write half
/// does.
impl Drop for KcpWriter {
    fn drop(&mut self) {
        self.link.lock().shutdown = true;
        self.link.wake_driver.notify_one();
    }
}

impl Drop for KcpReader {
    fn drop(&mut self) {
        let mut st = self.link.lock();
        st.reader_gone = true;
        st.incoming.clear();
        st.incoming_bytes = 0;
        drop(st);
        self.link.wake_driver.notify_one();
    }
}

/// Where a driver's packets come from.
enum Inbound {
    /// The listener's demultiplexer, already opened.
    Listener(mpsc::Receiver<Bytes>),
    /// The dialer's own socket.
    Dialer {
        socket: Arc<UdpSocket>,
        protection: Arc<Protection>,
        buf: Vec<u8>,
    },
}

impl Inbound {
    /// The next packet's plaintext for conversation `conv`.
    async fn next(&mut self, conv: u32) -> io::Result<Bytes> {
        match self {
            Self::Listener(rx) => rx
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "listener closed")),
            Self::Dialer {
                socket,
                protection,
                buf,
            } => loop {
                let n = match socket.recv(buf).await {
                    Ok(n) => n,
                    Err(e) if is_icmp_error(&e) => continue,
                    Err(e) => return Err(e),
                };
                let Some(plain) = protection.open(&mut buf[..n]) else {
                    continue;
                };
                if conv_of(plain) == Some(conv) {
                    return Ok(Bytes::copy_from_slice(plain));
                }
            },
        }
    }
}

/// An ICMP error (port unreachable) for an earlier send, which the OS reports on a later
/// receive. Ignored: it may come from a peer that is restarting, or from anyone at all
/// (ICMP is easy to forge); a peer that is really gone falls silent.
fn is_icmp_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    )
}

/// The KCP segments in a packet, whole (header and data); a truncated one ends the list.
fn segments(packet: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = packet;
    std::iter::from_fn(move || {
        let len = u32::from_le_bytes(rest.get(20..24)?.try_into().ok()?) as usize;
        let segment = rest.get(..KCP_HEADER.checked_add(len)?)?;
        rest = &rest[segment.len()..];
        Some(segment)
    })
}

fn segment_sn(segment: &[u8]) -> u32 {
    u32::from_le_bytes(segment[12..16].try_into().expect("4 bytes"))
}

/// Sequence numbers of data segments received lately, the oldest forgotten first.
#[derive(Default)]
struct SeenSegments {
    set: std::collections::HashSet<u32>,
    order: VecDeque<u32>,
    /// One past the highest sequence number seen.
    next: u32,
}

impl SeenSegments {
    /// Well above any receive window, so a rebuilt segment is never mistaken for new.
    const KEEP: usize = 1 << 16;

    /// Records the data segments of a packet that came as it was sent, and returns how
    /// many were new and below the highest seen: they filled a gap left by a loss.
    fn record(&mut self, packet: &[u8]) -> u64 {
        let mut filled = 0;
        for segment in segments(packet) {
            if segment[4] != KCP_CMD_PUSH {
                continue;
            }
            let sn = segment_sn(segment);
            let below = self.next.wrapping_sub(sn).wrapping_sub(1) < 1 << 31;
            if self.insert(sn) && below {
                filled += 1;
            }
        }
        filled
    }

    /// Returns true if `sn` was not seen before.
    fn insert(&mut self, sn: u32) -> bool {
        if !self.set.insert(sn) {
            return false;
        }
        if sn.wrapping_sub(self.next) < 1 << 31 {
            self.next = sn.wrapping_add(1);
        }
        self.order.push_back(sn);
        if self.order.len() > Self::KEEP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// Group and index of an FEC packet (long enough: checked by the caller).
fn fec_header(plain: &[u8]) -> (u32, u8) {
    let group = u32::from_le_bytes(plain[5..9].try_into().expect("4 bytes"));
    (group, plain[9])
}

fn kcp_error(e: kcp::Error) -> io::Error {
    io::Error::other(e)
}

/// Runs one connection: moves data between the stream halves and KCP, feeds KCP the
/// packets and the clock, sends pings and ends the connection.
struct Driver {
    kcp: Kcp<Output>,
    conv: u32,
    link: Arc<Link>,
    /// Shared with KCP's output: pings, closes, and closing FEC groups on time.
    sender: Arc<Mutex<Sender>>,
    fec: FecDecoder,
    /// Data segments received, for telling rebuilt ones that already came apart.
    received: SeenSegments,
    inbound: Inbound,
    keepalive: Duration,
    start: Instant,
    last_heard: Instant,
    last_ping: Instant,
    fin_sent: bool,
    /// Segments KCP may hold (queued and in flight) before writers wait.
    max_queued: usize,
    /// Listener side: tell the demultiplexer when the conversation is over.
    on_exit: Option<(mpsc::UnboundedSender<ConnKey>, ConnKey)>,
}

type ConnKey = (SocketAddr, u32);

impl Driver {
    fn start(
        conv: u32,
        socket: Arc<UdpSocket>,
        peer: Option<SocketAddr>,
        inbound: Inbound,
        settings: &ConnSettings,
        on_exit: Option<(mpsc::UnboundedSender<ConnKey>, ConnKey)>,
    ) -> io::Result<(KcpStream, Self)> {
        let stats = Arc::new(ConnStats::default());
        let sender = Sender::new(socket, peer, conv, settings, stats.clone())?;
        let sender = Arc::new(Mutex::new(sender));
        let mut kcp = Kcp::new(conv, Output(sender.clone()));
        let t = settings.timing;
        kcp.set_nodelay(
            t.nodelay,
            t.interval_ms as i32,
            t.resend as i32,
            t.no_congestion,
        );
        kcp.set_wndsize(settings.send_window, settings.recv_window);
        kcp.set_mtu(settings.mtu).map_err(kcp_error)?;
        let link = Arc::new(Link {
            state: Mutex::new(State::default()),
            wake_driver: Notify::new(),
            stats,
        });
        let stream = KcpStream {
            reader: KcpReader { link: link.clone() },
            writer: KcpWriter { link: link.clone() },
            datagrams: settings.datagrams.then(|| KcpDatagrams {
                sender: sender.clone(),
                link: link.clone(),
                max_len: settings.mtu - DATAGRAM_HEADER,
            }),
        };
        let now = Instant::now();
        let driver = Self {
            kcp,
            conv,
            link,
            sender,
            fec: FecDecoder::default(),
            received: SeenSegments::default(),
            inbound,
            keepalive: settings.keepalive,
            start: now,
            last_heard: now,
            last_ping: now,
            fin_sent: false,
            max_queued: settings.send_window as usize * 2,
            on_exit,
        };
        Ok((stream, driver))
    }

    fn ms(&self, at: Instant) -> u32 {
        (at - self.start).as_millis() as u32
    }

    async fn run(mut self, dialer: bool) {
        let result = self.drive(dialer).await;
        let stats = &self.link.stats;
        let error = result.as_ref().err().map(ToString::to_string);
        debug!(
            conv = self.conv,
            error,
            packets = stats.kcp_packets.load(Ordering::Relaxed),
            parity = stats.parity_packets.load(Ordering::Relaxed),
            resent = stats.resent.load(Ordering::Relaxed),
            recovered = stats.recovered.load(Ordering::Relaxed),
            gaps_filled = stats.gaps_filled.load(Ordering::Relaxed),
            "kcp connection ended"
        );
        let mut st = self.link.lock();
        st.ended = true;
        if let Err(e) = result {
            st.error = Some(e.kind());
        }
        let wakers = [
            st.read_waker.take(),
            st.write_waker.take(),
            st.datagram_waker.take(),
        ];
        drop(st);
        wakers.into_iter().flatten().for_each(Waker::wake);
        if let Some((tx, key)) = self.on_exit.take() {
            let _ = tx.send(key);
        }
    }

    async fn drive(&mut self, dialer: bool) -> io::Result<()> {
        let ping_every = self.keepalive / 3;
        let silent_limit = self.keepalive * 2;
        self.kcp
            .update(self.ms(Instant::now()))
            .map_err(kcp_error)?;
        if dialer {
            // Numbered 0, so the listener knows the conversation is new.
            self.kcp.send(&[MSG_OPEN]).map_err(kcp_error)?;
            self.kcp.flush().map_err(kcp_error)?;
        }
        loop {
            let now = Instant::now();
            self.kcp.update(self.ms(now)).map_err(kcp_error)?;
            self.pump_send()?;
            self.pump_recv(false)?;
            if now - self.last_heard >= silent_limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kcp peer went silent",
                ));
            }
            if self.kcp.is_dead_link() {
                self.control(PACKET_CLOSE);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kcp peer stopped acking",
                ));
            }
            lock(&self.sender).close_fec_group(now);
            if now - self.last_ping >= ping_every {
                self.control(PACKET_PING);
                self.last_ping = now;
            }
            if self.finished() {
                // Ack what came last, then let the peer go.
                self.kcp.flush_ack().map_err(kcp_error)?;
                self.control(PACKET_CLOSE);
                return Ok(());
            }
            let update = now + Duration::from_millis(self.kcp.check(self.ms(now)).into());
            let mut wake = update
                .min(self.last_ping + ping_every)
                .min(self.last_heard + silent_limit);
            if let Some(deadline) = lock(&self.sender).fec_deadline() {
                wake = wake.min(deadline);
            }
            tokio::select! {
                packet = self.inbound.next(self.conv) => {
                    if self.on_packet(&packet?)? {
                        return Ok(());
                    }
                }
                _ = self.link.wake_driver.notified() => {}
                _ = sleep_until(wake) => {}
            }
        }
    }

    fn control(&mut self, kind: u8) {
        lock(&self.sender).control(kind, self.conv);
    }

    /// Returns true when the peer closed the conversation cleanly.
    fn on_packet(&mut self, plain: &[u8]) -> io::Result<bool> {
        self.last_heard = Instant::now();
        // A malformed packet from a token holder is its problem: KCP and the FEC decoder
        // skip what they cannot use.
        match plain[0] {
            PACKET_DATA => {
                let filled = self.received.record(&plain[1..]);
                self.link
                    .stats
                    .gaps_filled
                    .fetch_add(filled, Ordering::Relaxed);
                let _ = self.kcp.input(&plain[1..]);
            }
            PACKET_DATAGRAM => self.deliver_datagram(&plain[5..]),
            PACKET_FEC_DATA => {
                if let Some(content) = segments_of(plain) {
                    if let Some(datagram) = self.datagram_in(content) {
                        self.deliver_datagram(datagram);
                    } else {
                        let filled = self.received.record(content);
                        self.link
                            .stats
                            .gaps_filled
                            .fetch_add(filled, Ordering::Relaxed);
                        let _ = self.kcp.input(content);
                    }
                    let (group, index) = fec_header(plain);
                    let rebuilt = self.fec.data(group, index, &plain[FEC_DATA_HEADER..]);
                    self.input_rebuilt(rebuilt);
                }
            }
            PACKET_FEC_PARITY => {
                if let Some(shard) = plain.get(FEC_PARITY_HEADER..) {
                    let (group, index) = fec_header(plain);
                    let (k, m) = (plain[FEC_DATA_HEADER], plain[FEC_DATA_HEADER + 1]);
                    let rebuilt = self.fec.parity(group, index, k, m, shard);
                    self.input_rebuilt(rebuilt);
                }
            }
            PACKET_CLOSE => {
                // No more packets: deliver what KCP holds, whatever the reader's pace.
                self.pump_recv(true)?;
                if self.link.lock().eof {
                    return Ok(true);
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "kcp peer closed the connection",
                ));
            }
            _ => {}
        }
        Ok(false)
    }

    /// Hands KCP the packets FEC rebuilt, which arrive late: their data segments that
    /// came meanwhile (resent) are left out, since KCP would ack them again with their
    /// old send time and the peer would take that for its round trip time. Their acks
    /// get a send time in the future, which KCP takes as no round trip sample at all
    /// (kcp-go skips the sample for FEC packets the same way).
    fn input_rebuilt(&mut self, packets: Vec<Vec<u8>>) {
        let future = self.ms(Instant::now()).wrapping_add(REBUILT_ACK_AHEAD_MS);
        let mut fresh = Vec::new();
        for packet in &packets {
            if let Some(datagram) = self.datagram_in(packet) {
                self.deliver_datagram(datagram);
                continue;
            }
            fresh.clear();
            for segment in segments(packet) {
                match segment[4] {
                    KCP_CMD_PUSH if !self.received.insert(segment_sn(segment)) => continue,
                    KCP_CMD_ACK => {
                        let start = fresh.len();
                        fresh.extend_from_slice(segment);
                        fresh[start + 8..start + 12].copy_from_slice(&future.to_le_bytes());
                        continue;
                    }
                    _ => {}
                }
                fresh.extend_from_slice(segment);
            }
            if !fresh.is_empty() {
                let _ = self.kcp.input(&fresh);
            }
        }
        let n = packets.len() as u64;
        self.link.stats.recovered.fetch_add(n, Ordering::Relaxed);
    }

    /// The datagram in the content of an FEC data shard, if it holds one.
    fn datagram_in<'a>(&self, content: &'a [u8]) -> Option<&'a [u8]> {
        content.strip_prefix(&(!self.conv).to_le_bytes()[..])
    }

    fn deliver_datagram(&self, datagram: &[u8]) {
        self.link
            .stats
            .datagrams_received
            .fetch_add(1, Ordering::Relaxed);
        let mut st = self.link.lock();
        if st.datagrams.len() >= DATAGRAM_QUEUE {
            st.datagrams.pop_front();
        }
        st.datagrams.push_back(Bytes::copy_from_slice(datagram));
        let waker = st.datagram_waker.take();
        drop(st);
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Moves written messages into KCP while it has room, then the FIN.
    fn pump_send(&mut self) -> io::Result<()> {
        let mut sent = false;
        let mut st = self.link.lock();
        while self.kcp.wait_snd() < self.max_queued {
            let Some(message) = st.outgoing.pop_front() else {
                break;
            };
            st.outgoing_bytes -= message.len();
            self.kcp.send(&message).map_err(kcp_error)?;
            sent = true;
        }
        if st.outgoing.is_empty()
            && st.shutdown
            && !self.fin_sent
            && self.kcp.wait_snd() < self.max_queued
        {
            self.kcp.send(&[MSG_FIN]).map_err(kcp_error)?;
            self.fin_sent = true;
            sent = true;
        }
        let waker = (st.outgoing_bytes < WRITE_QUEUE)
            .then(|| st.write_waker.take())
            .flatten();
        drop(st);
        if let Some(w) = waker {
            w.wake();
        }
        if sent {
            // Send now rather than at the next interval.
            self.kcp.flush().map_err(kcp_error)?;
        }
        Ok(())
    }

    /// Moves complete messages out of KCP while the reader keeps up (or all of them).
    fn pump_recv(&mut self, all: bool) -> io::Result<()> {
        let mut st = self.link.lock();
        let mut wake = false;
        loop {
            if !all && !st.reader_gone && st.incoming_bytes >= READ_QUEUE {
                break;
            }
            let Ok(size) = self.kcp.peeksize() else {
                break;
            };
            let mut message = BytesMut::zeroed(size);
            self.kcp.recv(&mut message).map_err(kcp_error)?;
            match message.first() {
                Some(&MSG_DATA) if size > 1 && !st.reader_gone => {
                    let data = message.freeze().slice(1..);
                    st.incoming_bytes += data.len();
                    st.incoming.push_back(data);
                    wake = true;
                }
                Some(&MSG_DATA | &MSG_OPEN) => {}
                Some(&MSG_FIN) => {
                    st.eof = true;
                    wake = true;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown kcp message",
                    ))
                }
            }
        }
        let waker = wake.then(|| st.read_waker.take()).flatten();
        drop(st);
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }

    /// Both directions are done: our FIN is acked, and the peer's came (or nobody reads).
    fn finished(&self) -> bool {
        if !self.fin_sent || self.kcp.wait_snd() > 0 {
            return false;
        }
        let st = self.link.lock();
        st.eof || st.reader_gone
    }
}

/// Dials a new KCP connection each time, from a fresh socket (a random source port).
pub struct KcpDialer {
    remote: String,
    settings: ConnSettings,
}

impl KcpDialer {
    pub fn new(remote: &str, params: &KcpParams, tuning: &Tuning) -> Self {
        Self {
            remote: remote.to_string(),
            settings: ConnSettings::new(params, tuning),
        }
    }

    pub async fn dial(&self) -> io::Result<KcpStream> {
        let peer = tokio::net::lookup_host(&self.remote)
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "remote did not resolve"))?;
        let local = match peer {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = carrier::open(
            self.settings.carrier,
            local,
            self.settings.socket_buffer,
            self.settings.dscp,
        )?;
        socket.connect(peer).await?;
        let socket = Arc::new(socket);
        let conv = Nonces::new()?.next_u32();
        let inbound = Inbound::Dialer {
            socket: socket.clone(),
            protection: self.settings.protection.clone(),
            buf: vec![0u8; 65_536],
        };
        let (stream, driver) = Driver::start(conv, socket, None, inbound, &self.settings, None)?;
        tokio::spawn(driver.run(true));
        Ok(stream)
    }
}

/// One UDP socket for every dialer: packets are sorted into conversations by peer
/// address and conversation id.
pub struct KcpListener {
    local: SocketAddr,
    accepted: tokio::sync::Mutex<mpsc::Receiver<(KcpStream, SocketAddr)>>,
    task: JoinHandle<()>,
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl KcpListener {
    pub async fn bind(addr: &str, params: &KcpParams, tuning: &Tuning) -> io::Result<Self> {
        let addr = tokio::net::lookup_host(addr).await?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "listen address did not resolve")
        })?;
        let settings = ConnSettings::new(params, tuning);
        let socket = Arc::new(carrier::open(
            settings.carrier,
            addr,
            settings.socket_buffer,
            settings.dscp,
        )?);
        let local = socket.local_addr()?;
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        let task = tokio::spawn(demultiplex(socket, settings, tx));
        Ok(Self {
            local,
            accepted: tokio::sync::Mutex::new(rx),
            task,
        })
    }

    pub async fn accept(&self) -> io::Result<(KcpStream, SocketAddr)> {
        self.accepted
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::other("kcp listener stopped"))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

async fn demultiplex(
    socket: Arc<UdpSocket>,
    settings: ConnSettings,
    accepted: mpsc::Sender<(KcpStream, SocketAddr)>,
) {
    let mut conns: HashMap<ConnKey, mpsc::Sender<Bytes>> = HashMap::new();
    let (ended_tx, mut ended) = mpsc::unbounded_channel::<ConnKey>();
    let stats = Arc::new(ConnStats::default());
    let Ok(mut replies) = Sender::new(socket.clone(), None, 0, &settings, stats) else {
        return;
    };
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer) = tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok(r) => r,
                Err(e) if is_icmp_error(&e) => continue,
                Err(e) => {
                    debug!(error = %e, "kcp listener socket failed");
                    return;
                }
            },
            Some(key) = ended.recv() => {
                conns.remove(&key);
                continue;
            }
        };
        let Some(plain) = settings.protection.open(&mut buf[..n]) else {
            // Not made with the token: no answer, as from a closed port.
            continue;
        };
        let Some(conv) = conv_of(plain) else {
            continue;
        };
        let key = (peer, conv);
        if let Some(tx) = conns.get(&key) {
            match tx.try_send(Bytes::copy_from_slice(plain)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    conns.remove(&key);
                }
            }
        }
        if !opens_conversation(plain) {
            if from_earlier_conversation(plain) {
                replies.peer = Some(peer);
                replies.control(PACKET_CLOSE, conv);
            }
            continue;
        }
        if conns.len() >= MAX_CONVERSATIONS {
            continue;
        }
        let Ok(permit) = accepted.try_reserve() else {
            continue;
        };
        let (tx, rx) = mpsc::channel(CONN_QUEUE);
        let started = Driver::start(
            conv,
            socket.clone(),
            Some(peer),
            Inbound::Listener(rx),
            &settings,
            Some((ended_tx.clone(), key)),
        );
        let Ok((stream, driver)) = started else {
            continue;
        };
        let _ = tx.try_send(Bytes::copy_from_slice(plain));
        conns.insert(key, tx);
        tokio::spawn(driver.run(false));
        permit.send((stream, peer));
    }
}

#[cfg(test)]
mod tests;
