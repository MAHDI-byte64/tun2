//! A mux session: many streams over one tunnel connection.
//!
//! One driver task per session runs three loops over the connection:
//!
//! * **reader**: decodes frames and hands data to the streams;
//! * **writer**: sends queued control frames first (`WINDOW`, `RST`, `PING`, ...), then
//!   takes turns between streams that have data, coalescing several frames per write;
//! * **keepalive**: sends `PING`s and closes the session when the peer goes silent.
//!
//! Streams never touch the connection. They move bytes in and out of their buffers in
//! the shared state and wake the writer; the per-stream credit window bounds every
//! buffer, so a stream whose reader is slow only ever stalls itself.
//!
//! **Datagrams** (UDP flows, phase 3) ride on a stream as `DGRAM` frames, one packet per
//! frame. They are not flow controlled: the session keeps one bounded send queue for all
//! of them, which the writer serves before stream data, and each stream a bounded
//! receive queue. When a queue is full a packet is dropped, never waited for: new ones on
//! the send side, the oldest on the receive side.
//!
//! **The datagram path** (a KCP link): `DGRAM` frames that fit
//! are sent beside the connection instead, unreliably, straight from `send_datagram`.
//! Both ends probe for it when the session starts (a `DGRAM` frame for stream 0, which
//! older versions ignore) and use it once anything came over it from the peer, and for a
//! stream only once the peer knows the stream (it opened it, or sent a frame on it), so
//! a datagram never arrives before its stream's `SYN`.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{interval, Instant, MissedTickBehavior};

use super::frame::{self, FrameType, Header, HEADER_LEN};
use super::{ResetReason, SessionConfig, Side};
use crate::channel::DatagramPath;

/// Credit every stream starts with in both directions, before any `WINDOW` frame.
pub const INITIAL_WINDOW: u64 = 64 * 1024;
/// Largest `DATA` payload the writer produces.
pub const MAX_DATA_FRAME: usize = 16 * 1024;
/// Bytes a stream may have accepted from its writer but not yet framed.
const SEND_BUFFER: usize = 64 * 1024;
/// Bytes the writer gathers into one write when coalescing.
const BATCH: usize = 64 * 1024;
/// Most buffers passed to one vectored write.
const MAX_IOV: usize = 64;
/// Read buffer growth step.
const READ_CHUNK: usize = 64 * 1024;
/// Payloads smaller than this are copied out of the read buffer, so a small frame
/// waiting in a stream's queue does not keep a whole read buffer alive; larger ones are
/// shared without copying.
const COPY_BELOW: usize = 4 * 1024;
/// Stop answering pings when this much control data is already queued.
const MAX_CONTROL_BACKLOG: usize = 64 * 1024;
/// Upper bound on a stream's send credit; more means the peer is broken.
const MAX_SEND_CREDIT: u64 = 1 << 32;
/// Payloads of the probe frames (`DGRAM` for stream 0) on the datagram path: a probe is
/// answered, an answer is not.
const PROBE: u8 = 0;
const PROBE_ANSWER: u8 = 1;

struct Stream {
    // Receive side.
    recv: VecDeque<Bytes>,
    recv_buffered: usize,
    /// Credit granted to the peer and not used yet.
    recv_credit: u64,
    recv_fin: bool,
    read_waker: Option<Waker>,

    // Send side.
    /// `SYN` payload, until the writer sends it.
    syn: Option<Bytes>,
    /// `WINDOW` increment to send right after our `SYN` (the peer cannot take credit for
    /// a stream it does not know yet).
    syn_window: Option<u32>,
    /// Data accepted from the stream's writer, not yet framed; `send_queued` bytes.
    send_queue: VecDeque<Bytes>,
    send_queued: usize,
    send_credit: u64,
    fin_queued: bool,
    fin_sent: bool,
    write_waker: Option<Waker>,
    /// In the writer's ready queue.
    queued: bool,

    /// Datagrams received and not yet taken, oldest first.
    datagrams: VecDeque<Bytes>,
    /// The peer knows the stream (it opened it, or sent a frame on it), so datagrams for
    /// it may take the datagram path.
    peer_knows: bool,

    /// Set once the stream is reset by either side.
    reset: Option<ResetReason>,
    /// The `MuxStream` handle is gone; remove the stream once nothing is pending.
    detached: bool,
}

impl Stream {
    fn new() -> Self {
        Self {
            recv: VecDeque::new(),
            recv_buffered: 0,
            recv_credit: INITIAL_WINDOW,
            recv_fin: false,
            read_waker: None,
            syn: None,
            syn_window: None,
            send_queue: VecDeque::new(),
            send_queued: 0,
            send_credit: INITIAL_WINDOW,
            fin_queued: false,
            fin_sent: false,
            write_waker: None,
            queued: false,
            datagrams: VecDeque::new(),
            peer_knows: false,
            reset: None,
            detached: false,
        }
    }

    /// Credit to hand back to the peer so it can have `window` bytes outstanding again.
    /// Only sent once at least half a window is available, to keep `WINDOW` frames rare.
    fn window_update(&mut self, window: u64) -> Option<u32> {
        if self.recv_fin || self.reset.is_some() {
            return None;
        }
        let outstanding = self.recv_credit + self.recv_buffered as u64;
        let inc = window.checked_sub(outstanding)?;
        if inc == 0 || inc < window / 2 {
            return None;
        }
        let inc = inc.min(u32::MAX as u64) as u32;
        self.recv_credit += inc as u64;
        Some(inc)
    }

    fn wake(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

struct State {
    streams: HashMap<u32, Stream>,
    /// Streams with something for the writer, in turn order.
    ready: VecDeque<u32>,
    /// Encoded control frames, sent before any stream data.
    control: Vec<u8>,
    /// Streams whose `SYN` is not sent yet, in id order. They go out right after the
    /// control frames: the peer requires increasing ids, and a stream's `SYN` must
    /// precede its first `DATA` or `DGRAM`.
    syns: VecDeque<u32>,
    next_id: u32,
    last_peer_id: u32,
    goaway: bool,
    /// Why the session closed, once it has.
    closed: Option<String>,
    incoming: Option<mpsc::UnboundedSender<(MuxStream, Bytes)>>,
    last_recv: Instant,
    ping_seq: u64,
    /// The latest ping not answered yet, and when it went out.
    ping_sent: Option<(u64, Instant)>,
    /// Smoothed round-trip time from ping to pong (7/8 old, 1/8 new, as TCP's SRTT).
    srtt: Option<Duration>,
    /// Datagrams to send, all streams, oldest first; `dgram_bytes` counts them with
    /// their frame headers.
    dgrams: VecDeque<(u32, Bytes)>,
    dgram_bytes: usize,
    /// Without coalescing, whether the last write carried a datagram (so streams get
    /// the next turn).
    dgram_turn: bool,
    /// Something came over the datagram path: the peer has one too.
    peer_path: bool,
    stats: DatagramStats,
}

/// Datagrams a session dropped because a queue was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramStats {
    /// Not sent: the session's send queue was full.
    pub dropped_send: u64,
    /// Received but discarded: the stream's receive queue was full (oldest dropped).
    pub dropped_recv: u64,
    /// Sent over the datagram path (the rest went in the connection).
    pub path_sent: u64,
    /// Received over the datagram path, probes included.
    pub path_received: u64,
}

struct Shared {
    state: Mutex<State>,
    /// Wakes the writer; `notify_one` keeps a permit, so no wake-up is lost.
    writer: Notify,
    closed: watch::Sender<bool>,
    config: SessionConfig,
    side: Side,
    path: Option<DatagramPath>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn close(&self, reason: String) {
        let incoming = {
            let mut st = self.lock();
            if st.closed.is_some() {
                return;
            }
            st.closed = Some(reason);
            for s in st.streams.values_mut() {
                s.wake();
            }
            st.incoming.take()
        };
        drop(incoming);
        self.closed.send_replace(true);
        self.writer.notify_one();
    }

    fn peer_parity(&self) -> u32 {
        match self.side {
            Side::Client => 0,
            Side::Server => 1,
        }
    }

    /// Applies one frame from the peer. An error is a protocol violation and ends the
    /// session.
    fn handle_frame(self: &Arc<Self>, h: Header, payload: Bytes) -> io::Result<()> {
        let window = self.config.stream_window as u64;
        let mut rejected = None;
        let mut notify = false;
        let mut dropped_recv = 0;
        {
            let mut st = self.lock();
            st.last_recv = Instant::now();
            let State {
                streams,
                control,
                incoming,
                last_peer_id,
                goaway,
                ping_sent,
                srtt,
                ..
            } = &mut *st;
            match h.kind {
                FrameType::Syn => {
                    if h.stream % 2 != self.peer_parity() || h.stream <= *last_peer_id {
                        return Err(protocol_error("peer opened a stream with an invalid id"));
                    }
                    *last_peer_id = h.stream;
                    let full = streams.len() >= self.config.max_streams;
                    if *goaway || full || incoming.is_none() {
                        frame::put(
                            control,
                            FrameType::Rst,
                            h.stream,
                            &[ResetReason::Refused.id()],
                        );
                        notify = true;
                    } else {
                        let mut stream = Stream::new();
                        stream.peer_knows = true;
                        if let Some(inc) = stream.window_update(window) {
                            frame::put(control, FrameType::Window, h.stream, &inc.to_be_bytes());
                            notify = true;
                        }
                        streams.insert(h.stream, stream);
                        let handle = MuxStream {
                            shared: self.clone(),
                            id: h.stream,
                        };
                        let sent = incoming.as_ref().map(|tx| tx.send((handle, payload)));
                        if let Some(Err(e)) = sent {
                            // Dropping the handle locks the state; do it after unlocking.
                            rejected = Some(e.0 .0);
                        }
                    }
                }
                FrameType::Data => {
                    if let Some(s) = streams.get_mut(&h.stream) {
                        s.peer_knows = true;
                        if s.reset.is_none() {
                            if s.recv_fin {
                                return Err(protocol_error("peer sent data after FIN"));
                            }
                            let len = payload.len() as u64;
                            if len > s.recv_credit {
                                return Err(protocol_error("peer exceeded the stream window"));
                            }
                            s.recv_credit -= len;
                            if !s.detached && !payload.is_empty() {
                                s.recv_buffered += payload.len();
                                s.recv.push_back(payload);
                                if let Some(w) = s.read_waker.take() {
                                    w.wake();
                                }
                            }
                        }
                    }
                }
                FrameType::Fin => {
                    if let Some(s) = streams.get_mut(&h.stream) {
                        s.peer_knows = true;
                        s.recv_fin = true;
                        if let Some(w) = s.read_waker.take() {
                            w.wake();
                        }
                        if s.detached && s.fin_sent {
                            streams.remove(&h.stream);
                        }
                    }
                }
                FrameType::Rst => {
                    if let Some(s) = streams.get_mut(&h.stream) {
                        s.reset.get_or_insert(ResetReason::from_id(payload[0]));
                        s.send_queue.clear();
                        s.send_queued = 0;
                        s.wake();
                        if s.detached {
                            streams.remove(&h.stream);
                        }
                    }
                }
                FrameType::Window => {
                    if let Some(s) = streams.get_mut(&h.stream) {
                        s.peer_knows = true;
                        let inc = u32::from_be_bytes(payload[..4].try_into().unwrap()) as u64;
                        s.send_credit += inc;
                        if s.send_credit > MAX_SEND_CREDIT {
                            return Err(protocol_error("peer granted too much credit"));
                        }
                        if let Some(w) = s.write_waker.take() {
                            w.wake();
                        }
                    }
                }
                FrameType::Ping => {
                    if control.len() < MAX_CONTROL_BACKLOG {
                        frame::put(control, FrameType::Pong, 0, &payload);
                        notify = true;
                    }
                }
                FrameType::Dgram => {
                    // Unknown, closed or abandoned streams: dropped, it may race a close.
                    if let Some(s) = streams.get_mut(&h.stream) {
                        s.peer_knows = true;
                        if s.reset.is_none() && !s.detached && !s.recv_fin {
                            if s.datagrams.len() >= self.config.datagram_queue {
                                s.datagrams.pop_front();
                                dropped_recv += 1;
                            }
                            s.datagrams.push_back(payload);
                            if let Some(w) = s.read_waker.take() {
                                w.wake();
                            }
                        }
                    }
                }
                FrameType::Pong => {
                    // Every peer echoes the ping's 8 bytes (our sequence number), so this
                    // measures the round trip against old peers too.
                    let seq = u64::from_be_bytes(payload[..8].try_into().unwrap());
                    if let Some((sent_seq, at)) = *ping_sent {
                        if sent_seq == seq {
                            let sample = at.elapsed();
                            *srtt = Some(srtt.map_or(sample, |old| (old * 7 + sample) / 8));
                            *ping_sent = None;
                        }
                    }
                }
                FrameType::GoAway => {
                    *goaway = true;
                    // No more streams will arrive.
                    drop(incoming.take());
                }
            }
            st.stats.dropped_recv += dropped_recv;
        }
        drop(rejected);
        if notify {
            self.writer.notify_one();
        }
        Ok(())
    }

    /// Moves queued frames into `out`. Fails once the session is closed.
    fn next_batch(&self, out: &mut Batch) -> io::Result<()> {
        let mut st = self.lock();
        if let Some(reason) = &st.closed {
            return Err(closed_error(reason));
        }
        out.put_inline(&st.control);
        st.control.clear();
        let coalesce = self.config.coalesce;
        let room = |out: &Batch| {
            if coalesce {
                out.len < BATCH
            } else {
                out.len == 0
            }
        };
        let State {
            streams,
            ready,
            syns,
            dgrams,
            dgram_bytes,
            dgram_turn,
            ..
        } = &mut *st;

        for id in syns.drain(..) {
            let Some(s) = streams.get_mut(&id) else {
                continue;
            };
            if s.reset.is_some() {
                continue;
            }
            if let Some(syn) = s.syn.take() {
                out.put_frame(FrameType::Syn, id, &syn);
                if let Some(inc) = s.syn_window.take() {
                    out.put_frame(FrameType::Window, id, &inc.to_be_bytes());
                }
            }
        }

        // Datagrams first, so real-time packets do not wait behind bulk stream data. They
        // get at most half of a batch while streams have data too, and without
        // coalescing they alternate with streams, so a flood cannot starve TCP.
        let budget = if ready.is_empty() { BATCH } else { BATCH / 2 };
        let datagrams_turn = coalesce || !*dgram_turn || ready.is_empty();
        let mut used = 0;
        while datagrams_turn && room(out) && used < budget {
            let Some((id, packet)) = dgrams.pop_front() else {
                break;
            };
            *dgram_bytes -= HEADER_LEN + packet.len();
            let Some(s) = streams.get_mut(&id) else {
                continue;
            };
            if s.reset.is_some() {
                continue;
            }
            used += HEADER_LEN + packet.len();
            out.put_payload(FrameType::Dgram, id, packet);
        }
        *dgram_turn = used > 0;

        loop {
            if !room(out) {
                break;
            }
            let Some(id) = ready.pop_front() else {
                break;
            };
            let Some(s) = streams.get_mut(&id) else {
                continue;
            };
            s.queued = false;
            if s.reset.is_some() {
                continue;
            }
            if let Some(front) = s.send_queue.front_mut() {
                let data = if front.len() <= MAX_DATA_FRAME {
                    s.send_queue.pop_front().unwrap()
                } else {
                    front.split_to(MAX_DATA_FRAME)
                };
                s.send_queued -= data.len();
                out.put_data(id, data);
                if let Some(w) = s.write_waker.take() {
                    w.wake();
                }
            }
            if s.send_queued > 0 {
                s.queued = true;
                ready.push_back(id);
            } else if s.fin_queued && !s.fin_sent {
                out.put_frame(FrameType::Fin, id, &[]);
                s.fin_sent = true;
                if s.detached && s.recv_fin {
                    streams.remove(&id);
                }
            }
        }
        Ok(())
    }
}

/// Frames gathered for one write. Headers and small payloads are stored inline;
/// stream data stays in its `Bytes` and goes out with a vectored write, uncopied.
#[derive(Default)]
struct Batch {
    inline: Vec<u8>,
    segments: Vec<Segment>,
    len: usize,
}

enum Segment {
    Inline(Range<usize>),
    Data(Bytes),
}

impl Batch {
    fn clear(&mut self) {
        self.inline.clear();
        self.segments.clear();
        self.len = 0;
    }

    fn put_inline(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let start = self.inline.len();
        self.inline.extend_from_slice(bytes);
        let end = self.inline.len();
        match self.segments.last_mut() {
            Some(Segment::Inline(r)) if r.end == start => r.end = end,
            _ => self.segments.push(Segment::Inline(start..end)),
        }
        self.len += bytes.len();
    }

    fn put_frame(&mut self, kind: FrameType, stream: u32, payload: &[u8]) {
        self.put_inline(&frame::header(kind, stream, payload.len()));
        self.put_inline(payload);
    }

    fn put_data(&mut self, stream: u32, data: Bytes) {
        self.put_payload(FrameType::Data, stream, data);
    }

    /// A frame whose payload goes out from its own `Bytes`, uncopied.
    fn put_payload(&mut self, kind: FrameType, stream: u32, payload: Bytes) {
        self.put_inline(&frame::header(kind, stream, payload.len()));
        // An empty segment could end up alone in a vectored write, which then writes
        // nothing and looks like a dead connection.
        if !payload.is_empty() {
            self.len += payload.len();
            self.segments.push(Segment::Data(payload));
        }
    }

    fn segment(&self, i: usize) -> &[u8] {
        match &self.segments[i] {
            Segment::Inline(r) => &self.inline[r.clone()],
            Segment::Data(b) => b,
        }
    }

    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let (mut i, mut offset) = (0, 0);
        let mut slices = [io::IoSlice::new(&[]); MAX_IOV];
        while i < self.segments.len() {
            let count = self.segments.len().min(i + MAX_IOV) - i;
            for (k, slot) in slices.iter_mut().enumerate().take(count) {
                let s = self.segment(i + k);
                *slot = io::IoSlice::new(if k == 0 { &s[offset..] } else { s });
            }
            let mut n = writer.write_vectored(&slices[..count]).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            while n > 0 {
                let rest = self.segment(i).len() - offset;
                if n >= rest {
                    n -= rest;
                    i += 1;
                    offset = 0;
                } else {
                    offset += n;
                    n = 0;
                }
            }
        }
        Ok(())
    }
}

/// Handle to a mux session. Dropping it closes the session and all its streams.
pub struct MuxSession {
    shared: Arc<Shared>,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<(MuxStream, Bytes)>>,
    /// The transport it runs over, when something wants to tell (`auto` does).
    transport: std::sync::OnceLock<&'static str>,
}

impl MuxSession {
    /// Starts a session over `io`. Both ends must use opposite `side`s.
    ///
    /// Reading and writing share `io` through a lock; prefer [`MuxSession::from_halves`]
    /// when the connection can be split into independent halves.
    pub fn new<T>(io: T, side: Side, config: SessionConfig) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(io);
        Self::from_halves(reader, writer, side, config)
    }

    /// Starts a session over `transport`, reading and writing in parallel, with the
    /// transport's datagram path if it has one.
    pub fn over<T: super::Transport>(mut transport: T, side: Side, config: SessionConfig) -> Self {
        let path = transport.take_datagram_path();
        let (reader, writer) = transport.into_halves();
        Self::start(reader, writer, path, side, config)
    }

    /// Starts a session over a connection split into a read and a write half. Reading
    /// (and decrypting) and writing (and encrypting) then run in separate tasks, in
    /// parallel.
    pub fn from_halves<R, W>(reader: R, writer: W, side: Side, config: SessionConfig) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::start(reader, writer, None, side, config)
    }

    fn start<R, W>(
        reader: R,
        writer: W,
        path: Option<DatagramPath>,
        side: Side,
        config: SessionConfig,
    ) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                streams: HashMap::new(),
                ready: VecDeque::new(),
                control: Vec::new(),
                syns: VecDeque::new(),
                next_id: match side {
                    Side::Client => 1,
                    Side::Server => 2,
                },
                last_peer_id: 0,
                goaway: false,
                closed: None,
                incoming: Some(tx),
                last_recv: Instant::now(),
                ping_seq: 0,
                ping_sent: None,
                srtt: None,
                dgrams: VecDeque::new(),
                dgram_bytes: 0,
                dgram_turn: false,
                peer_path: false,
                stats: DatagramStats::default(),
            }),
            writer: Notify::new(),
            closed: watch::channel(false).0,
            config,
            side,
            path,
        });
        shared.probe(PROBE);

        // Whichever task ends first closes the session, which stops the other one.
        let s = shared.clone();
        tokio::spawn(async move {
            let mut closed = s.closed.subscribe();
            let result = tokio::select! {
                r = read_loop(&s, reader) => r,
                r = datagram_loop(&s) => r,
                _ = closed.wait_for(|c| *c) => Ok(()),
            };
            s.close(end_reason(result));
        });
        let s = shared.clone();
        tokio::spawn(async move {
            let mut closed = s.closed.subscribe();
            let result = tokio::select! {
                r = write_loop(&s, writer) => r,
                r = keepalive_loop(&s) => r,
                _ = closed.wait_for(|c| *c) => Ok(()),
            };
            s.close(end_reason(result));
        });

        Self {
            shared,
            incoming: tokio::sync::Mutex::new(rx),
            transport: std::sync::OnceLock::new(),
        }
    }

    /// Notes which transport this session runs over (once; later calls change nothing).
    pub fn set_transport(&self, name: &'static str) {
        let _ = self.transport.set(name);
    }

    /// The transport noted by [`MuxSession::set_transport`], if any.
    pub fn transport(&self) -> Option<&'static str> {
        self.transport.get().copied()
    }

    /// Opens a stream. `syn` (the open request) and any data written right away are sent
    /// without waiting for the peer: the peer answers a failed open with a reset.
    pub fn open(&self, syn: Bytes) -> io::Result<MuxStream> {
        if syn.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "open request too long",
            ));
        }
        let window = self.shared.config.stream_window as u64;
        let id = {
            let mut st = self.shared.lock();
            if let Some(reason) = &st.closed {
                return Err(closed_error(reason));
            }
            if st.goaway {
                return Err(io::Error::other("mux session is going away"));
            }
            if st.streams.len() >= self.shared.config.max_streams {
                return Err(io::Error::other("mux session has too many streams"));
            }
            let id = st.next_id;
            st.next_id = match id.checked_add(2) {
                Some(next) => next,
                None => {
                    st.goaway = true;
                    return Err(io::Error::other("mux stream ids exhausted"));
                }
            };
            let mut stream = Stream::new();
            stream.syn = Some(syn);
            stream.syn_window = stream.window_update(window);
            st.streams.insert(id, stream);
            st.syns.push_back(id);
            id
        };
        self.shared.writer.notify_one();
        Ok(MuxStream {
            shared: self.shared.clone(),
            id,
        })
    }

    /// Waits for a stream the peer opened, with its `SYN` payload. `None` once the
    /// session is closed or going away.
    pub async fn accept(&self) -> Option<(MuxStream, Bytes)> {
        self.incoming.lock().await.recv().await
    }

    /// Stops new streams in both directions; existing streams continue.
    pub fn goaway(&self) {
        let incoming = {
            let mut st = self.shared.lock();
            if st.goaway || st.closed.is_some() {
                return;
            }
            st.goaway = true;
            frame::put(&mut st.control, FrameType::GoAway, 0, &[]);
            st.incoming.take()
        };
        drop(incoming);
        self.shared.writer.notify_one();
    }

    pub fn is_closed(&self) -> bool {
        self.shared.lock().closed.is_some()
    }

    /// Why the session closed, once it has.
    pub fn close_reason(&self) -> Option<String> {
        self.shared.lock().closed.clone()
    }

    /// Going away (either side sent `GOAWAY`) or closed: no new streams.
    pub fn is_draining(&self) -> bool {
        let st = self.shared.lock();
        st.goaway || st.closed.is_some()
    }

    /// Datagrams dropped so far because a queue was full.
    pub fn datagram_stats(&self) -> DatagramStats {
        self.shared.lock().stats
    }

    pub fn stream_count(&self) -> usize {
        self.shared.lock().streams.len()
    }

    /// Smoothed round-trip time from pings; `None` until the first pong.
    pub fn rtt(&self) -> Option<Duration> {
        self.shared.lock().srtt
    }

    /// Resolves once the session is closed, for whatever reason.
    pub async fn closed(&self) {
        let mut rx = self.shared.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub fn close(&self) {
        self.shared.close("closed locally".into());
    }

    /// Stops new streams, waits for the existing ones to finish, then closes the session.
    pub async fn drain(&self) {
        self.goaway();
        let mut tick = interval(Duration::from_millis(250));
        while !self.is_closed() && self.stream_count() > 0 {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.closed() => {}
            }
        }
        self.close();
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.close();
    }
}

impl Shared {
    /// Sends a probe frame over the datagram path, without FEC: an older peer ignores
    /// the packet type, but would take an FEC shard for KCP data.
    fn probe(&self, kind: u8) {
        if let Some(path) = &self.path {
            let mut probe = frame::header(FrameType::Dgram, 0, 1).to_vec();
            probe.push(kind);
            path.send(&probe, false);
        }
    }
}

/// Receives frames over the datagram path (`DGRAM` only; anything else is dropped). Never
/// ends on its own: when the link goes, the read loop ends the session.
async fn datagram_loop(shared: &Arc<Shared>) -> io::Result<()> {
    let Some(path) = &shared.path else {
        return std::future::pending().await;
    };
    while let Some(mut frame) = path.recv().await {
        let Some(header) = frame.get(..HEADER_LEN) else {
            continue;
        };
        let Ok(h) = Header::decode(header.try_into().unwrap()) else {
            continue;
        };
        if h.kind != FrameType::Dgram || h.len as usize != frame.len() - HEADER_LEN {
            continue;
        }
        frame.advance(HEADER_LEN);
        {
            let mut st = shared.lock();
            st.peer_path = true;
            st.stats.path_received += 1;
        }
        if h.stream == 0 {
            if frame.first() == Some(&PROBE) {
                shared.probe(PROBE_ANSWER);
            }
            continue;
        }
        shared.handle_frame(h, frame)?;
    }
    std::future::pending().await
}

/// Reads straight into one buffer and cuts frames out of it.
async fn read_loop<R: AsyncRead + Unpin>(shared: &Arc<Shared>, mut reader: R) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    loop {
        while buf.len() >= HEADER_LEN {
            let h = Header::decode(buf[..HEADER_LEN].try_into().unwrap())?;
            let len = h.len as usize;
            if buf.len() < HEADER_LEN + len {
                break;
            }
            buf.advance(HEADER_LEN);
            let payload = if len < COPY_BELOW {
                let p = Bytes::copy_from_slice(&buf[..len]);
                buf.advance(len);
                p
            } else {
                buf.split_to(len).freeze()
            };
            shared.handle_frame(h, payload)?;
        }
        if buf.capacity() - buf.len() < READ_CHUNK / 2 {
            buf.reserve(READ_CHUNK);
        }
        if reader.read_buf(&mut buf).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "peer closed the mux session",
            ));
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(shared: &Shared, mut writer: W) -> io::Result<()> {
    let mut batch = Batch::default();
    loop {
        batch.clear();
        shared.next_batch(&mut batch)?;
        if batch.len == 0 {
            shared.writer.notified().await;
            continue;
        }
        batch.write_to(&mut writer).await?;
        writer.flush().await?;
    }
}

async fn keepalive_loop(shared: &Shared) -> io::Result<()> {
    let period = shared.config.keepalive;
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let peer_path = {
            let mut st = shared.lock();
            if st.last_recv.elapsed() > period * 2 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mux peer stopped answering pings",
                ));
            }
            st.ping_seq += 1;
            st.ping_sent = Some((st.ping_seq, Instant::now()));
            let seq = st.ping_seq.to_be_bytes();
            frame::put(&mut st.control, FrameType::Ping, 0, &seq);
            st.peer_path
        };
        shared.writer.notify_one();
        // Until the peer is heard on the datagram path: our probe may have been lost.
        if !peer_path {
            shared.probe(PROBE);
        }
    }
}

/// One stream of a [`MuxSession`]. Dropping it before both directions have finished
/// resets the stream.
pub struct MuxStream {
    shared: Arc<Shared>,
    id: u32,
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream").field("id", &self.id).finish()
    }
}

impl MuxStream {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Why the stream was reset, once it has been (by either side).
    pub fn reset_reason(&self) -> Option<ResetReason> {
        self.shared
            .lock()
            .streams
            .get(&self.id)
            .and_then(|s| s.reset)
    }

    /// Aborts the stream and tells the peer why.
    pub fn reset(self, reason: ResetReason) {
        {
            let mut st = self.shared.lock();
            let State {
                streams, control, ..
            } = &mut *st;
            if let Some(s) = streams.get_mut(&self.id) {
                if s.reset.is_none() {
                    s.reset = Some(reason);
                    frame::put(control, FrameType::Rst, self.id, &[reason.id()]);
                }
            }
        }
        self.shared.writer.notify_one();
        // Drop removes the stream.
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let mut notify = false;
        {
            let mut st = self.shared.lock();
            let State {
                streams, control, ..
            } = &mut *st;
            let Some(s) = streams.get_mut(&self.id) else {
                return;
            };
            s.detached = true;
            s.recv.clear();
            s.recv_buffered = 0;
            s.datagrams.clear();
            if s.reset.is_some() || (s.fin_sent && s.recv_fin) {
                streams.remove(&self.id);
            } else if s.fin_queued && s.recv_fin {
                // The writer removes it after sending the queued data and FIN.
            } else {
                frame::put(
                    control,
                    FrameType::Rst,
                    self.id,
                    &[ResetReason::Cancel.id()],
                );
                streams.remove(&self.id);
                notify = true;
            }
        }
        if notify {
            self.shared.writer.notify_one();
        }
    }
}

impl MuxStream {
    /// Hands the peer credit back after the reader consumed data, if due.
    fn consumed(&self, st: MutexGuard<'_, State>) {
        let mut st = st;
        let window = self.shared.config.stream_window as u64;
        let State {
            streams, control, ..
        } = &mut *st;
        let Some(s) = streams.get_mut(&self.id) else {
            return;
        };
        if let Some(inc) = s.window_update(window) {
            frame::put(control, FrameType::Window, self.id, &inc.to_be_bytes());
            drop(st);
            self.shared.writer.notify_one();
        }
    }

    /// Waits for received data, then lets `take` consume some of it. `Ok(None)` at the
    /// end of the stream.
    fn poll_recv_with<T>(
        &self,
        cx: &mut Context<'_>,
        take: impl FnOnce(&mut Stream) -> T,
    ) -> Poll<io::Result<Option<T>>> {
        let mut st = self.shared.lock();
        let State {
            streams, closed, ..
        } = &mut *st;
        let Some(s) = streams.get_mut(&self.id) else {
            return Poll::Ready(Err(stream_gone()));
        };
        if s.recv_buffered > 0 {
            let out = take(s);
            self.consumed(st);
            return Poll::Ready(Ok(Some(out)));
        }
        if let Some(reason) = s.reset {
            return Poll::Ready(Err(reason.to_error()));
        }
        if s.recv_fin {
            return Poll::Ready(Ok(None));
        }
        if let Some(reason) = closed {
            return Poll::Ready(Err(closed_error(reason)));
        }
        s.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Receives the next chunk of data exactly as it arrived, without copying it.
    /// `None` at the end of the stream.
    pub async fn recv(&self) -> io::Result<Option<Bytes>> {
        std::future::poll_fn(|cx| {
            self.poll_recv_with(cx, |s| {
                let chunk = s.recv.pop_front().expect("data is buffered");
                s.recv_buffered -= chunk.len();
                chunk
            })
        })
        .await
    }

    /// Queues up to `len` bytes for sending, as far as credit and buffer room allow:
    /// `take(n)` provides the first `n` bytes. Returns how many were queued.
    fn poll_send_with(
        &self,
        cx: &mut Context<'_>,
        len: usize,
        take: impl FnOnce(usize) -> Bytes,
    ) -> Poll<io::Result<usize>> {
        let mut st = self.shared.lock();
        let State {
            streams,
            ready,
            closed,
            ..
        } = &mut *st;
        if let Some(reason) = closed {
            return Poll::Ready(Err(closed_error(reason)));
        }
        let Some(s) = streams.get_mut(&self.id) else {
            return Poll::Ready(Err(stream_gone()));
        };
        if let Some(reason) = s.reset {
            return Poll::Ready(Err(reason.to_error()));
        }
        if s.fin_queued {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        let room = (SEND_BUFFER - s.send_queued) as u64;
        let n = s.send_credit.min(room).min(len as u64) as usize;
        if n == 0 {
            s.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        s.send_queue.push_back(take(n));
        s.send_queued += n;
        s.send_credit -= n as u64;
        if !s.queued {
            s.queued = true;
            ready.push_back(self.id);
        }
        drop(st);
        self.shared.writer.notify_one();
        Poll::Ready(Ok(n))
    }

    /// Sends `data` without copying it, waiting for flow-control credit as needed.
    pub async fn send(&self, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            std::future::poll_fn(|cx| {
                let len = data.len();
                self.poll_send_with(cx, len, |n| data.split_to(n))
            })
            .await?;
        }
        Ok(())
    }

    /// Queues one datagram (at most 65,535 bytes) for sending. Never waits: returns false
    /// if it was dropped because the session's datagram queue is full, or cannot be sent
    /// at all (stream finished or reset, session closed).
    pub fn send_datagram(&self, packet: Bytes) -> bool {
        if packet.len() > u16::MAX as usize {
            return false;
        }
        let path = self
            .shared
            .path
            .as_ref()
            .filter(|p| HEADER_LEN + packet.len() <= p.max_frame());
        {
            let mut st = self.shared.lock();
            if st.closed.is_some() {
                return false;
            }
            let peer_knows = match st.streams.get(&self.id) {
                Some(s) if s.reset.is_none() && !s.fin_queued => s.peer_knows,
                _ => return false,
            };
            if let Some(path) = path.filter(|_| peer_knows && st.peer_path) {
                drop(st);
                return self.send_on_path(path, &packet);
            }
            let size = HEADER_LEN + packet.len();
            if st.dgram_bytes + size > self.shared.config.datagram_buffer {
                st.stats.dropped_send += 1;
                return false;
            }
            st.dgram_bytes += size;
            st.dgrams.push_back((self.id, packet));
        }
        self.shared.writer.notify_one();
        true
    }

    /// Whether a datagram of `len` bytes would take the datagram path now, where it may
    /// be lost, rather than the connection.
    pub fn sends_unreliably(&self, len: usize) -> bool {
        let Some(path) = &self.shared.path else {
            return false;
        };
        if HEADER_LEN + len > path.max_frame() {
            return false;
        }
        let st = self.shared.lock();
        st.peer_path && st.streams.get(&self.id).is_some_and(|s| s.peer_knows)
    }

    fn send_on_path(&self, path: &DatagramPath, packet: &[u8]) -> bool {
        let mut frame = Vec::with_capacity(HEADER_LEN + packet.len());
        frame.extend_from_slice(&frame::header(FrameType::Dgram, self.id, packet.len()));
        frame.extend_from_slice(packet);
        let sent = path.send(&frame, true);
        let mut st = self.shared.lock();
        if sent {
            st.stats.path_sent += 1;
        } else {
            st.stats.dropped_send += 1;
        }
        sent
    }

    fn poll_recv_datagram(&self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        let mut st = self.shared.lock();
        let State {
            streams, closed, ..
        } = &mut *st;
        let Some(s) = streams.get_mut(&self.id) else {
            return Poll::Ready(Err(stream_gone()));
        };
        if let Some(packet) = s.datagrams.pop_front() {
            return Poll::Ready(Ok(Some(packet)));
        }
        if let Some(reason) = s.reset {
            return Poll::Ready(Err(reason.to_error()));
        }
        if s.recv_fin {
            return Poll::Ready(Ok(None));
        }
        if let Some(reason) = closed {
            return Poll::Ready(Err(closed_error(reason)));
        }
        s.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Receives the next datagram, whole. `None` once the peer finished the stream.
    pub async fn recv_datagram(&self) -> io::Result<Option<Bytes>> {
        std::future::poll_fn(|cx| self.poll_recv_datagram(cx)).await
    }

    /// A datagram already received, if any (to gather several into one send).
    pub fn try_recv_datagram(&self) -> Option<Bytes> {
        let mut st = self.shared.lock();
        st.streams
            .get_mut(&self.id)
            .and_then(|s| s.datagrams.pop_front())
    }

    /// Half close: no more data from this side. Queued data is still sent first.
    pub fn finish(&self) -> io::Result<()> {
        {
            let mut st = self.shared.lock();
            let State {
                streams,
                ready,
                closed,
                ..
            } = &mut *st;
            if let Some(reason) = closed {
                return Err(closed_error(reason));
            }
            let Some(s) = streams.get_mut(&self.id) else {
                return Err(stream_gone());
            };
            if let Some(reason) = s.reset {
                return Err(reason.to_error());
            }
            if s.fin_queued {
                return Ok(());
            }
            s.fin_queued = true;
            if !s.queued {
                s.queued = true;
                ready.push_back(self.id);
            }
        }
        self.shared.writer.notify_one();
        Ok(())
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let copied = self.poll_recv_with(cx, |s| {
            let mut n = 0;
            while buf.remaining() > 0 {
                let Some(front) = s.recv.front_mut() else {
                    break;
                };
                let k = front.len().min(buf.remaining());
                buf.put_slice(&front[..k]);
                front.advance(k);
                if front.is_empty() {
                    s.recv.pop_front();
                }
                n += k;
            }
            s.recv_buffered -= n;
        });
        copied.map_ok(|_| ())
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_send_with(cx, buf.len(), |n| Bytes::copy_from_slice(&buf[..n]))
    }

    /// Queued data is sent by the session on its own; nothing to wait for.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.finish())
    }
}

fn end_reason(result: io::Result<()>) -> String {
    match result {
        Ok(()) => "closed".into(),
        Err(e) => e.to_string(),
    }
}

fn closed_error(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("mux session closed: {reason}"),
    )
}

fn stream_gone() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "mux stream is gone")
}

fn protocol_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
