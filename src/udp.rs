//! UDP forwarding (phase 3).
//!
//! A **flow** is one client address talking to one UDP forward rule. The entry keeps a
//! flow table per rule and opens a tunnel path per flow; the exit gives each flow its own
//! UDP socket connected to the target. On a mux session a flow is a stream carrying
//! `DGRAM` frames; without mux it is a whole channel carrying length-prefixed packets.
//! Either way [`relay`] moves packets both ways until the flow has been idle for the
//! configured timeout or one side ends it.
//!
//! **Duplication**: a flow opened with it numbers every
//! packet, `seq (4, BE) | packet`, in both directions. A packet that goes where it may be
//! lost (KCP's datagram path, a QUIC datagram) is sent again `gap` later, once or twice;
//! the receiver drops the numbers it has seen. Packets that go reliably are numbered but
//! not copied.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::{sleep, sleep_until, timeout, Instant};
use tracing::{debug, warn};

use crate::channel::Channel;
use crate::config::{Tuning, UdpTuning};
use crate::crypto::datagram::ReplayWindow;
use crate::limit::{PerIp, Slot};
use crate::mux::Transport;
use crate::proto::{self, Duplicate, MAX_DATAGRAM};
use crate::relay::Counters;
use crate::session::{ResetReason, SessionStream};
use crate::stats::{ForwardStats, Tally};

/// Receive buffer for one packet: the largest UDP payload fits.
const PACKET_BUFFER: usize = 64 * 1024;
/// Packets gathered into one write on a channel without mux.
const WRITE_BATCH: usize = 64 * 1024;
/// A client whose flow could not be opened is ignored this long.
const FAILED_BACKOFF: Duration = Duration::from_secs(5);
/// At most one "too many flows" warning per rule in this interval.
const FULL_WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Where a flow's packets come from outside the tunnel.
pub trait PacketSource: Send {
    /// The next packet; `None` when the source is gone.
    fn recv(&mut self) -> impl Future<Output = io::Result<Option<Bytes>>> + Send;

    /// A packet that is already waiting, if any (to gather several into one write).
    fn try_recv(&mut self) -> Option<Bytes> {
        None
    }
}

/// Where a flow's packets go outside the tunnel.
pub trait PacketSink: Send + Sync {
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// Bytes in front of every packet of a flow with duplication.
const SEQUENCE_LEN: usize = 4;

/// Numbers the packets of a flow with duplication.
#[derive(Default)]
struct Numbering(u32);

impl Numbering {
    fn number(&mut self, packet: &[u8]) -> Bytes {
        let mut out = BytesMut::with_capacity(SEQUENCE_LEN + packet.len());
        out.put_u32(self.0);
        out.put_slice(packet);
        self.0 = self.0.wrapping_add(1);
        out.freeze()
    }
}

/// Drops the copies of packets already received, and strips the numbers.
#[derive(Default)]
struct Dedup(ReplayWindow);

impl Dedup {
    fn accept(&mut self, packet: Bytes) -> Option<Bytes> {
        let seq = u32::from_be_bytes(packet.get(..SEQUENCE_LEN)?.try_into().ok()?);
        let n = unwrap_sequence(self.0.end(), seq);
        if !self.0.is_new(n) {
            return None;
        }
        self.0.insert(n);
        Some(packet.slice(SEQUENCE_LEN..))
    }
}

/// The 64-bit number whose low 32 bits are `seq`, nearest to `expected` (the way QUIC
/// decodes packet numbers), so numbering goes on past 2^32 packets.
fn unwrap_sequence(expected: u64, seq: u32) -> u64 {
    const SPAN: u64 = 1 << 32;
    let candidate = (expected & !(SPAN - 1)) | u64::from(seq);
    if candidate + SPAN / 2 <= expected {
        candidate + SPAN
    } else if candidate > expected + SPAN / 2 && candidate >= SPAN {
        candidate - SPAN
    } else {
        candidate
    }
}

/// Copies waiting for their time: one queue for second copies and one for third ones.
/// Each is in sending order, so the earliest due copy is at a front.
#[derive(Default)]
struct Copies {
    rounds: [VecDeque<(Instant, Bytes)>; 2],
}

impl Copies {
    /// Sends the copies of `packet` now (no gap) or queues them.
    fn add(&mut self, packet: &Bytes, duplicate: Duplicate, stream: &SessionStream) {
        let gap = Duration::from_millis(duplicate.gap_ms.into());
        let now = Instant::now();
        for round in 1..duplicate.copies as u32 {
            if gap.is_zero() {
                stream.send_datagram(packet.clone());
            } else {
                self.rounds[round as usize - 1].push_back((now + gap * round, packet.clone()));
            }
        }
    }

    fn next_due(&self) -> Option<Instant> {
        self.rounds
            .iter()
            .filter_map(|r| r.front())
            .map(|c| c.0)
            .min()
    }

    fn send_due(&mut self, stream: &SessionStream) {
        let now = Instant::now();
        for round in &mut self.rounds {
            while round.front().is_some_and(|c| c.0 <= now) {
                let (_, packet) = round.pop_front().expect("not empty");
                stream.send_datagram(packet);
            }
        }
    }
}

/// Moves packets between `channel` and the local side until the flow has seen no packet
/// in either direction for `idle`, or either side ends it. Ends the tunnel side cleanly
/// (`FIN` or shutdown) so the peer ends its side too. `duplicate`: the flow's packet
/// duplication, as both sides know it from the open request. `counters.read` counts the
/// bytes of packets from the local side, `counters.written` those delivered to it.
/// `datagram_only`: for the `udp` transport, a mux packet that cannot ride the unreliable
/// datagram path is dropped rather than queued on the reliable stream, so forwarding never
/// retransmits (bare UDP semantics). Only the `Channel::Stream` (mux) path honours it.
pub async fn relay<Src, Snk>(
    channel: Channel,
    mut source: Src,
    sink: Snk,
    idle: Duration,
    duplicate: Option<Duplicate>,
    datagram_only: bool,
    counters: Counters<'_>,
) -> io::Result<()>
where
    Src: PacketSource,
    Snk: PacketSink,
{
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let touch = || last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    let watchdog = async {
        loop {
            let quiet = start.elapsed() - Duration::from_millis(last.load(Ordering::Relaxed));
            if quiet >= idle {
                return io::Result::Ok(());
            }
            sleep(idle - quiet).await;
        }
    };
    let deliver = |packet: Bytes, tally: &mut Tally<'_>| {
        tally.add(packet.len());
        let sink = &sink;
        async move {
            if let Err(e) = sink.send(&packet).await {
                debug!(error = %e, "UDP packet not delivered");
            }
        }
    };

    match channel {
        Channel::Stream(stream) => {
            let up = async {
                let mut tally = Tally::new(counters.read);
                let (mut numbering, mut copies) = (Numbering::default(), Copies::default());
                loop {
                    let due = copies.next_due();
                    let packet = tokio::select! {
                        packet = source.recv() => packet?,
                        () = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                            copies.send_due(&stream);
                            continue;
                        }
                    };
                    let Some(packet) = packet else {
                        return Ok(());
                    };
                    touch();
                    tally.add(packet.len());
                    let Some(duplicate) = duplicate else {
                        // A full session queue drops the packet (counted by the session).
                        // With `datagram_only`, a packet that would fall back to the
                        // reliable stream is dropped instead, as a bare UDP datagram is.
                        if !datagram_only || stream.sends_unreliably(packet.len()) {
                            stream.send_datagram(packet);
                        }
                        continue;
                    };
                    let packet = numbering.number(&packet);
                    // Copies only where the packet may be lost.
                    let unreliable = stream.sends_unreliably(packet.len());
                    if unreliable || !datagram_only {
                        stream.send_datagram(packet.clone());
                    }
                    if unreliable {
                        copies.add(&packet, duplicate, &stream);
                    }
                }
            };
            let down = async {
                let mut tally = Tally::new(counters.written);
                let mut dedup = duplicate.map(|_| Dedup::default());
                loop {
                    match stream.recv_datagram().await {
                        Ok(Some(packet)) => {
                            touch();
                            let packet = match &mut dedup {
                                Some(dedup) => match dedup.accept(packet) {
                                    Some(packet) => packet,
                                    None => continue,
                                },
                                None => packet,
                            };
                            deliver(packet, &mut tally).await;
                        }
                        Ok(None) => return Ok(()),
                        // v0.2 peers reset UDP opens as a protocol error.
                        Err(_) if stream.reset_reason() == Some(ResetReason::Protocol) => {
                            return Err(ResetReason::Unsupported.to_error())
                        }
                        Err(e) => return Err(e),
                    }
                }
            };
            let result = tokio::select! {
                r = up => r,
                r = down => r,
                r = watchdog => r,
            };
            let _ = stream.finish();
            result
        }
        Channel::Link(link) => {
            let (mut reader, mut writer) = link.into_halves();
            let up = async {
                let mut tally = Tally::new(counters.read);
                let mut batch = Vec::with_capacity(WRITE_BATCH);
                // Numbered like any flow with duplication, but a channel loses nothing,
                // so nothing is copied.
                let mut numbering = duplicate.map(|_| Numbering::default());
                while let Some(packet) = source.recv().await? {
                    touch();
                    batch.clear();
                    let mut next = Some(packet);
                    while let Some(mut packet) = next {
                        tally.add(packet.len());
                        if let Some(numbering) = &mut numbering {
                            packet = numbering.number(&packet);
                        }
                        // Larger than UDP over IPv4 allows (IPv6 jumbo); cannot be framed.
                        if packet.len() <= MAX_DATAGRAM {
                            proto::put_datagram(&packet, &mut batch)?;
                        }
                        next = if batch.len() < WRITE_BATCH {
                            source.try_recv()
                        } else {
                            None
                        };
                    }
                    writer.write_all(&batch).await?;
                    writer.flush().await?;
                }
                Ok(())
            };
            let down = async {
                let mut tally = Tally::new(counters.written);
                let mut dedup = duplicate.map(|_| Dedup::default());
                while let Some(packet) = proto::read_datagram(&mut reader).await? {
                    touch();
                    let packet = match &mut dedup {
                        Some(dedup) => match dedup.accept(packet) {
                            Some(packet) => packet,
                            None => continue,
                        },
                        None => packet,
                    };
                    deliver(packet, &mut tally).await;
                }
                Ok(())
            };
            let result = tokio::select! {
                r = up => r,
                r = down => r,
                r = watchdog => r,
            };
            let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
            result
        }
    }
}

/// Sets the socket buffer sizes; the kernel may cap them (`net.core.rmem_max`).
fn tune(socket: &UdpSocket, udp: &UdpTuning) {
    let sock = SockRef::from(socket);
    if let Err(e) = sock
        .set_recv_buffer_size(udp.socket_buffer)
        .and_then(|_| sock.set_send_buffer_size(udp.socket_buffer))
    {
        debug!(error = %e, "could not set UDP socket buffers");
    }
}

// ---- Exit side ----

/// Exit side: a UDP socket connected to `target` (resolved now), for one flow.
pub async fn connect(target: &str, tuning: &Tuning) -> io::Result<UdpSocket> {
    let addr = timeout(tuning.dial_timeout, tokio::net::lookup_host(target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolving the target timed out"))??
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target has no address"))?;
    let local: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    tune(&socket, &tuning.udp);
    crate::transport::mark_dscp(&SockRef::from(&socket), tuning.dscp);
    socket.connect(addr).await?;
    Ok(socket)
}

thread_local! {
    /// Receive buffer for the exit's flow sockets, one per worker thread instead of one
    /// per flow: a packet is read only once the socket is readable, and copied out at its
    /// real size right away.
    static RECV_BUFFER: std::cell::RefCell<Box<[u8]>> =
        std::cell::RefCell::new(vec![0u8; PACKET_BUFFER].into_boxed_slice());
}

/// A connected socket as both ends of the local side.
pub struct Connected {
    socket: Arc<UdpSocket>,
}

impl Connected {
    pub fn new(socket: UdpSocket) -> (Self, ConnectedSink) {
        let socket = Arc::new(socket);
        (
            Self {
                socket: socket.clone(),
            },
            ConnectedSink(socket),
        )
    }

    fn read_now(&self) -> io::Result<Bytes> {
        RECV_BUFFER.with_borrow_mut(|buf| {
            let n = self.socket.try_recv(buf)?;
            Ok(Bytes::copy_from_slice(&buf[..n]))
        })
    }
}

impl PacketSource for Connected {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            self.socket.readable().await?;
            match self.read_now() {
                Ok(packet) => return Ok(Some(packet)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // An ICMP "port unreachable" from an earlier packet: the target may come
                // back, so keep the flow.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn try_recv(&mut self) -> Option<Bytes> {
        self.read_now().ok()
    }
}

pub struct ConnectedSink(Arc<UdpSocket>);

impl PacketSink for ConnectedSink {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        match self.0.send(packet).await {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            r => r.map(|_| ()),
        }
    }
}

// ---- Entry side ----

/// Packets from one client waiting for its flow. Bounded, and it allocates only as
/// packets arrive (a tokio channel reserves room for 32 packets up front, which adds up
/// with thousands of mostly idle flows).
struct FlowQueue {
    state: Mutex<QueueState>,
    ready: Notify,
    capacity: usize,
}

#[derive(Default)]
struct QueueState {
    packets: VecDeque<Bytes>,
    /// The flow has ended; no more packets are taken.
    closed: bool,
}

enum PushError {
    Full,
    Closed(Bytes),
}

impl FlowQueue {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState::default()),
            ready: Notify::new(),
            capacity,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, packet: Bytes) -> Result<(), PushError> {
        let mut st = self.lock();
        if st.closed {
            return Err(PushError::Closed(packet));
        }
        if st.packets.len() >= self.capacity {
            return Err(PushError::Full);
        }
        st.packets.push_back(packet);
        drop(st);
        // One consumer: a stored permit covers a push that races with its wait.
        self.ready.notify_one();
        Ok(())
    }
}

/// The flow's end of a [`FlowQueue`]; dropping it closes the queue.
struct FlowReceiver(Arc<FlowQueue>);

impl Drop for FlowReceiver {
    fn drop(&mut self) {
        let mut st = self.0.lock();
        st.closed = true;
        st.packets.clear();
    }
}

impl PacketSource for FlowReceiver {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.0.lock().packets.pop_front() {
                return Ok(Some(packet));
            }
            self.0.ready.notified().await;
        }
    }

    fn try_recv(&mut self) -> Option<Bytes> {
        self.0.lock().packets.pop_front()
    }
}

/// Replies to one client through the rule's shared socket.
struct ReplyTo {
    socket: Arc<UdpSocket>,
    client: SocketAddr,
}

impl PacketSink for ReplyTo {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.socket.send_to(packet, self.client).await.map(|_| ())
    }
}

/// Binds the UDP socket of a forward rule.
pub async fn bind(listen: &str, udp: &UdpTuning) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(listen).await?;
    tune(&socket, udp);
    Ok(socket)
}

enum FlowState {
    Active {
        queue: Arc<FlowQueue>,
        id: u64,
    },
    /// Opening failed; packets from this client are dropped until then.
    Failed {
        until: Instant,
    },
}

#[derive(Default)]
struct Flows {
    map: HashMap<SocketAddr, FlowState>,
    active: usize,
    next_id: u64,
    last_full_warning: Option<Instant>,
}

impl Flows {
    /// Removes flow `id` of `client` (not a newer one for the same client), marking the
    /// client as failed for a while if the flow could not be opened.
    fn finish(&mut self, client: SocketAddr, id: u64, open_failed: bool) {
        if !matches!(self.map.get(&client), Some(FlowState::Active { id: i, .. }) if *i == id) {
            return;
        }
        self.active -= 1;
        if open_failed {
            let until = Instant::now() + FAILED_BACKOFF;
            self.map.insert(client, FlowState::Failed { until });
        } else {
            self.map.remove(&client);
        }
    }
}

/// Entry side: serves one UDP forward rule on `socket`. `open` opens a tunnel path for a
/// new flow (the open request is the caller's, and carries `duplicate`). A flow holds a
/// slot of `per_ip` while it lives. `datagram_only`: the `udp` transport forwards without
/// a reliable fallback (see [`relay`]). Runs until the socket fails.
#[allow(clippy::too_many_arguments)]
pub async fn serve<O, F>(
    socket: UdpSocket,
    udp: UdpTuning,
    target: String,
    duplicate: Option<Duplicate>,
    datagram_only: bool,
    stats: Arc<ForwardStats>,
    per_ip: Option<Arc<PerIp>>,
    open: O,
) -> io::Result<()>
where
    O: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<Channel>> + Send + 'static,
{
    let socket = Arc::new(socket);
    let flows = Arc::new(Mutex::new(Flows::default()));
    let open = Arc::new(open);
    let mut buf = vec![0u8; PACKET_BUFFER];
    loop {
        let (n, client) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Linux reports ICMP errors for earlier replies here; not fatal.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(e) => return Err(e),
        };
        let packet = Bytes::copy_from_slice(&buf[..n]);
        let mut guard = flows.lock().unwrap_or_else(|e| e.into_inner());
        let table = &mut *guard;
        let now = Instant::now();
        match table.map.get(&client) {
            Some(FlowState::Active { queue, .. }) => match queue.push(packet) {
                Ok(()) => continue,
                // The flow is behind: drop, as the network would.
                Err(PushError::Full) => continue,
                // The flow just ended; start a new one.
                Err(PushError::Closed(p)) => {
                    if let Some(slot) = slot_for(table, client, per_ip.as_ref(), &stats) {
                        let rule = (&udp, target.as_str(), duplicate, datagram_only, &stats);
                        start_flow(table, client, p, slot, &socket, rule, &flows, &open);
                    }
                    continue;
                }
            },
            Some(FlowState::Failed { until }) if now < *until => continue,
            _ => {}
        }
        if table.active >= udp.max_flows {
            let due = table
                .last_full_warning
                .map_or(true, |t| now.duration_since(t) >= FULL_WARN_INTERVAL);
            if due {
                table.last_full_warning = Some(now);
                warn!(%target, max = udp.max_flows, "too many UDP flows (tuning.udp_max_flows), dropping packets from new clients; the ones open go on");
            }
            continue;
        }
        let Some(slot) = slot_for(table, client, per_ip.as_ref(), &stats) else {
            continue;
        };
        let rule = (&udp, target.as_str(), duplicate, datagram_only, &stats);
        start_flow(table, client, packet, slot, &socket, rule, &flows, &open);
    }
}

/// The per-address slot for a new flow of `client` (`Some(None)` without a limit), or
/// `None` when its address has its fill: the client is then ignored for a while, like
/// one whose flow could not be opened, so its packets are not counted one by one.
fn slot_for(
    table: &mut Flows,
    client: SocketAddr,
    per_ip: Option<&Arc<PerIp>>,
    stats: &ForwardStats,
) -> Option<Option<Slot>> {
    let Some(limit) = per_ip else {
        return Some(None);
    };
    if let Some(slot) = limit.acquire(client.ip()) {
        return Some(Some(slot));
    }
    stats.refused_per_ip();
    if matches!(table.map.get(&client), Some(FlowState::Active { .. })) {
        table.active -= 1;
    }
    let until = Instant::now() + FAILED_BACKOFF;
    table.map.insert(client, FlowState::Failed { until });
    None
}

/// Starts a flow for `client` with `packet` as its first packet. `rule`: the rule's
/// tuning, target, duplication, `datagram_only` (see [`relay`]) and counters.
#[allow(clippy::too_many_arguments)]
fn start_flow<O, F>(
    table: &mut Flows,
    client: SocketAddr,
    packet: Bytes,
    slot: Option<Slot>,
    socket: &Arc<UdpSocket>,
    rule: (
        &UdpTuning,
        &str,
        Option<Duplicate>,
        bool,
        &Arc<ForwardStats>,
    ),
    flows: &Arc<Mutex<Flows>>,
    open: &Arc<O>,
) where
    O: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<Channel>> + Send + 'static,
{
    let (udp, target, duplicate, datagram_only, stats) = rule;
    if matches!(table.map.get(&client), Some(FlowState::Active { .. })) {
        table.active -= 1;
    }
    let queue = FlowQueue::new(udp.flow_queue);
    let _ = queue.push(packet);
    let rx = FlowReceiver(queue.clone());
    table.next_id += 1;
    let id = table.next_id;
    table.map.insert(client, FlowState::Active { queue, id });
    table.active += 1;

    let (socket, flows, open) = (socket.clone(), flows.clone(), open.clone());
    let (idle, target, stats) = (udp.timeout, target.to_owned(), stats.clone());
    tokio::spawn(async move {
        debug!(%client, %target, "UDP flow opened");
        let _open = stats.udp_flow();
        let _slot = slot;
        let mut opened = false;
        let result = async {
            // Boxed: opening (dial, handshake, waiting for a session) needs far more state
            // than relaying, and an unboxed future would reserve that for the flow's life.
            let channel = Box::pin(open()).await?;
            opened = true;
            let counters = Counters {
                read: &stats.traffic.up,
                written: &stats.traffic.down,
            };
            let sink = ReplyTo { socket, client };
            relay(channel, rx, sink, idle, duplicate, datagram_only, counters).await
        }
        .await;
        let open_failed = match &result {
            Err(e) if !opened => {
                warn!(%client, %target, error = %e, "could not open a UDP flow");
                true
            }
            // Rejected by the exit side right after an optimistic (mux) open.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::Unsupported
                ) =>
            {
                warn!(%client, %target, error = %e, "UDP flow rejected by the exit side");
                true
            }
            Err(e) => {
                debug!(%client, %target, error = %e, "UDP flow ended with error");
                false
            }
            Ok(()) => {
                debug!(%client, %target, "UDP flow closed");
                false
            }
        };
        if open_failed {
            stats.open_failed();
        }
        flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish(client, id, open_failed);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn tuning(max_flows: usize) -> UdpTuning {
        UdpTuning {
            timeout: Duration::from_secs(60),
            max_flows,
            socket_buffer: 1 << 20,
            flow_queue: 16,
            session_buffer: 64 * 1024,
        }
    }

    /// Serves a rule whose opener only counts calls and fails (or never finishes).
    async fn serve_counting(max_flows: usize, fail: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let (addr, calls, _) = serve_limited(max_flows, fail, None).await;
        (addr, calls)
    }

    /// Also with a per-address limit; the rule's counters come back too.
    async fn serve_limited(
        max_flows: usize,
        fail: bool,
        per_ip: Option<Arc<PerIp>>,
    ) -> (SocketAddr, Arc<AtomicUsize>, Arc<ForwardStats>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let opener = move || {
            c.fetch_add(1, Ordering::SeqCst);
            async move {
                if fail {
                    Err(io::Error::other("exit side unreachable"))
                } else {
                    std::future::pending::<io::Result<Channel>>().await
                }
            }
        };
        let stats = ForwardStats::new("127.0.0.1:0", "target", "udp");
        tokio::spawn(serve(
            socket,
            tuning(max_flows),
            "target".into(),
            None,
            false,
            stats.clone(),
            per_ip,
            opener,
        ));
        (addr, calls, stats)
    }

    async fn client(to: SocketAddr) -> UdpSocket {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.connect(to).await.unwrap();
        s
    }

    #[tokio::test]
    async fn packets_of_one_client_share_a_flow() {
        let (addr, calls) = serve_counting(10, false).await;
        let c = client(addr).await;
        for _ in 0..20 {
            c.send(b"x").await.unwrap();
        }
        sleep(Duration::from_millis(200)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_opens_back_off() {
        let (addr, calls) = serve_counting(10, true).await;
        let c = client(addr).await;
        for _ in 0..20 {
            c.send(b"x").await.unwrap();
            sleep(Duration::from_millis(20)).await;
        }
        // One attempt, then the client is ignored for FAILED_BACKOFF.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_address_gets_only_its_share_of_flows() {
        let limit = PerIp::new(2);
        let (addr, calls, stats) = serve_limited(10, false, Some(limit)).await;
        // Five clients from one address (127.0.0.1): two flows, the rest refused.
        let mut clients = Vec::new();
        for _ in 0..5 {
            let c = client(addr).await;
            c.send(b"x").await.unwrap();
            c.send(b"y").await.unwrap();
            clients.push(c);
        }
        sleep(Duration::from_millis(200)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let refused = stats_of(&stats).refused_per_ip;
        assert_eq!(refused, 3, "counted once per client, not per packet");
    }

    fn stats_of(stats: &Arc<ForwardStats>) -> crate::stats::ForwardStatus {
        let config = crate::config::Config::parse(
            "role = \"entry\"\nmode = \"reverse\"\n[tunnel]\nlisten = \"0.0.0.0:3080\"\n\
             token = \"0123456789abcdef0123\"\n[[forward]]\nlisten = \"127.0.0.1:0\"\n\
             target = \"127.0.0.1:53\"\nprotocol = \"udp\"\n",
        )
        .unwrap();
        let mut all = crate::stats::Stats::new(&config);
        Arc::get_mut(&mut all).unwrap().forwards = vec![stats.clone()];
        all.snapshot().forwards.remove(0)
    }

    #[tokio::test]
    async fn clients_beyond_max_flows_are_dropped() {
        let (addr, calls) = serve_counting(2, false).await;
        let mut clients = Vec::new();
        for _ in 0..5 {
            let c = client(addr).await;
            c.send(b"x").await.unwrap();
            clients.push(c);
        }
        sleep(Duration::from_millis(200)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// `tuning.dscp` marks the exit's sockets to UDP targets.
    #[tokio::test]
    async fn target_sockets_are_marked() {
        use crate::transport::tests::{local_addrs, mark_of, tos};
        for addr in local_addrs() {
            let target = UdpSocket::bind(addr).await.unwrap();
            let target = target.local_addr().unwrap().to_string();
            for dscp in [None, Some(46)] {
                let tuning = Tuning {
                    dscp,
                    ..Tuning::for_profile(crate::config::Profile::Gaming)
                };
                let socket = connect(&target, &tuning).await.unwrap();
                assert_eq!(
                    mark_of(SockRef::from(&socket)),
                    tos(dscp),
                    "{addr} {dscp:?}"
                );
            }
        }
    }

    #[test]
    fn copies_are_dropped_and_numbers_stripped() {
        let (mut numbering, mut dedup) = (Numbering::default(), Dedup::default());
        let packets: Vec<Bytes> = (0..5u8).map(|i| numbering.number(&[i; 3])).collect();
        assert_eq!(&packets[1][..SEQUENCE_LEN], 1u32.to_be_bytes());
        // Out of order, each twice: every packet once, in the order it first came.
        let mut got = Vec::new();
        for i in [0, 2, 1, 2, 0, 4, 3, 4, 1, 3] {
            if let Some(p) = dedup.accept(packets[i].clone()) {
                got.push(p[0]);
            }
        }
        assert_eq!(got, [0, 2, 1, 4, 3]);
        assert_eq!(dedup.accept(Bytes::from_static(b"abc")), None, "too short");
        assert_eq!(
            dedup.accept(numbering.number(b"")).as_deref(),
            Some(&b""[..]),
            "an empty packet"
        );
    }

    #[test]
    fn sequence_numbers_go_on_past_32_bits() {
        const SPAN: u64 = 1 << 32;
        assert_eq!(unwrap_sequence(0, 0), 0);
        assert_eq!(unwrap_sequence(10, 7), 7);
        // Across the wrap, forwards and a late one from before it.
        assert_eq!(unwrap_sequence(SPAN - 1, 0), SPAN);
        assert_eq!(unwrap_sequence(SPAN + 5, u32::MAX - 1), SPAN - 2);
        assert_eq!(unwrap_sequence(3 * SPAN + 2, 1), 3 * SPAN + 1);
        // A flow numbered from 0 through the wrap, each packet sent twice.
        let (mut numbering, mut dedup) = (Numbering(u32::MAX - 2), Dedup::default());
        dedup.0.insert(u64::from(u32::MAX - 3));
        let mut delivered = 0;
        for _ in 0..6 {
            let packet = numbering.number(b"x");
            for _ in 0..2 {
                delivered += usize::from(dedup.accept(packet.clone()).is_some());
            }
        }
        assert_eq!(delivered, 6);
        assert_eq!(dedup.0.end(), SPAN + 3);
    }
}
