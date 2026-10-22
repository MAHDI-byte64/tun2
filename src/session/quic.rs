//! QUIC sessions: one QUIC connection carries the tunnel's streams and datagrams natively,
//! without kmux or the record layer (TLS 1.3 inside QUIC already encrypts).
//!
//! * A stream opened by us starts with the open request, `len (2, BE) | request`, and
//!   carries raw data after it (TCP) or length-prefixed packets (UDP flows, only for
//!   packets too large for a datagram).
//! * UDP flow packets travel as QUIC datagrams prefixed with the stream id (QUIC
//!   varint). A datagram that arrives before its stream is known (they can overtake the
//!   stream's first bytes) is held for a moment instead of dropped.
//! * Reset reasons travel as QUIC error codes (the same numbers as kmux's `RST`).
//! * `GOAWAY` is a unidirectional stream carrying `GOAWAY`: QUIC has no such frame.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use quinn::{Connection, ReadError, ReadExactError, RecvStream, SendStream, VarInt, WriteError};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use super::ResetReason;
use crate::mux::SessionConfig;

const GOAWAY: &[u8] = b"GOAWAY";
/// Datagrams for not-yet-known streams: at most this many, for at most this long.
const MAX_EARLY_DATAGRAMS: usize = 256;
const EARLY_DATAGRAM_TTL: Duration = Duration::from_secs(2);
/// Oversized packets queued for writing on their stream (bytes, per stream).
const MAX_STREAM_FALLBACK: usize = 256 * 1024;

/// One QUIC connection as a tunnel session.
pub struct QuicSession {
    shared: Arc<Shared>,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<(QuicStream, Bytes)>>,
}

struct Shared {
    conn: Connection,
    flows: Mutex<Flows>,
    draining: AtomicBool,
    /// Wakes the accept loop when draining starts.
    drain_started: Notify,
    streams: AtomicUsize,
    stream_ended: Notify,
    datagram_queue: usize,
    open_timeout: Duration,
}

#[derive(Default)]
struct Flows {
    inboxes: HashMap<u64, Arc<Inbox>>,
    /// Datagrams for stream ids we have not seen yet, oldest first.
    early: VecDeque<(u64, Bytes, Instant)>,
}

impl Shared {
    fn flows(&self) -> MutexGuard<'_, Flows> {
        self.flows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a new stream's datagram inbox, with any datagrams that arrived early.
    fn register(&self, id: u64) -> Arc<Inbox> {
        let inbox = Arc::new(Inbox::new(self.datagram_queue));
        let mut flows = self.flows();
        let early = std::mem::take(&mut flows.early);
        for (sid, packet, at) in early {
            if sid == id {
                inbox.push(packet);
            } else {
                flows.early.push_back((sid, packet, at));
            }
        }
        flows.inboxes.insert(id, inbox.clone());
        drop(flows);
        self.streams.fetch_add(1, Ordering::SeqCst);
        inbox
    }

    fn unregister(&self, id: u64) {
        self.flows().inboxes.remove(&id);
        self.streams.fetch_sub(1, Ordering::SeqCst);
        self.stream_ended.notify_waiters();
    }

    fn deliver(&self, datagram: Bytes) {
        let Some((id, len)) = get_varint(&datagram) else {
            return;
        };
        let packet = datagram.slice(len..);
        let mut flows = self.flows();
        if let Some(inbox) = flows.inboxes.get(&id) {
            inbox.push(packet);
            return;
        }
        let now = Instant::now();
        while flows
            .early
            .front()
            .is_some_and(|(_, _, at)| now.duration_since(*at) > EARLY_DATAGRAM_TTL)
        {
            flows.early.pop_front();
        }
        if flows.early.len() >= MAX_EARLY_DATAGRAMS {
            flows.early.pop_front();
        }
        flows.early.push_back((id, packet, now));
    }

    fn set_draining(&self) -> bool {
        let first = !self.draining.swap(true, Ordering::SeqCst);
        if first {
            self.drain_started.notify_waiters();
        }
        first
    }
}

impl QuicSession {
    /// Starts a session over an established connection (either side).
    pub fn new(conn: Connection, config: &SessionConfig, open_timeout: Duration) -> Self {
        let shared = Arc::new(Shared {
            conn,
            flows: Mutex::default(),
            draining: AtomicBool::new(false),
            drain_started: Notify::new(),
            streams: AtomicUsize::new(0),
            stream_ended: Notify::new(),
            datagram_queue: config.datagram_queue,
            open_timeout,
        });
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(accept_streams(shared.clone(), tx));
        tokio::spawn(accept_notices(shared.clone()));
        tokio::spawn(receive_datagrams(shared.clone()));
        Self {
            shared,
            incoming: tokio::sync::Mutex::new(rx),
        }
    }

    /// Opens a stream starting with `syn`; data may follow at once. Fails (so another
    /// session can be tried) when the peer's stream limit is reached.
    pub fn open(&self, syn: Bytes) -> io::Result<QuicStream> {
        if self.is_draining() {
            return Err(io::Error::other("QUIC session is going away"));
        }
        if syn.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "open request too long",
            ));
        }
        let (send, recv) = match poll_once(self.shared.conn.open_bi()) {
            Some(Ok(pair)) => pair,
            Some(Err(e)) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
            None => return Err(io::Error::other("QUIC session has too many streams")),
        };
        let stream = QuicStream::new(self.shared.clone(), send, recv);
        // The peer only learns about the stream from its first bytes: send the open
        // request now. The lock is taken here, so later writes queue behind it.
        let guard = stream
            .send
            .clone()
            .try_lock_owned()
            .expect("a new stream is not locked");
        tokio::spawn(async move {
            let mut send = guard;
            let mut head = BytesMut::with_capacity(2 + syn.len());
            head.put_u16(syn.len() as u16);
            head.put_slice(&syn);
            let _ = send.write_chunk(head.freeze()).await;
        });
        Ok(stream)
    }

    pub async fn accept(&self) -> Option<(QuicStream, Bytes)> {
        self.incoming.lock().await.recv().await
    }

    /// No new streams from either side: the peer is told on a unidirectional stream.
    pub fn goaway(&self) {
        if !self.shared.set_draining() {
            return;
        }
        let conn = self.shared.conn.clone();
        tokio::spawn(async move {
            if let Ok(mut notice) = conn.open_uni().await {
                let _ = notice.write_all(GOAWAY).await;
                let _ = notice.finish();
            }
        });
    }

    pub fn is_closed(&self) -> bool {
        self.shared.conn.close_reason().is_some()
    }

    pub fn is_draining(&self) -> bool {
        self.shared.draining.load(Ordering::SeqCst) || self.is_closed()
    }

    pub fn stream_count(&self) -> usize {
        self.shared.streams.load(Ordering::SeqCst)
    }

    pub fn rtt(&self) -> Option<Duration> {
        Some(self.shared.conn.rtt())
    }

    pub fn close_reason(&self) -> Option<String> {
        self.shared.conn.close_reason().map(|e| e.to_string())
    }

    pub async fn closed(&self) {
        self.shared.conn.closed().await;
    }

    pub fn close(&self) {
        self.shared.conn.close(VarInt::from_u32(0), b"");
    }

    pub async fn drain(&self) {
        self.goaway();
        loop {
            let ended = self.shared.stream_ended.notified();
            if self.stream_count() == 0 || self.is_closed() {
                break;
            }
            tokio::select! {
                _ = ended => {}
                _ = self.closed() => {}
                // Belt and braces against a missed wake-up.
                _ = sleep(Duration::from_millis(500)) => {}
            }
        }
        self.close();
    }
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Streams the peer opens: read their open request (in their own task, so a slow peer
/// never blocks the others), then hand them to `accept`.
async fn accept_streams(shared: Arc<Shared>, tx: mpsc::UnboundedSender<(QuicStream, Bytes)>) {
    loop {
        let draining = shared.drain_started.notified();
        if shared.draining.load(Ordering::SeqCst) {
            break;
        }
        let (send, recv) = tokio::select! {
            r = shared.conn.accept_bi() => match r {
                Ok(pair) => pair,
                Err(_) => break,
            },
            _ = draining => break,
        };
        let stream = QuicStream::new(shared.clone(), send, recv);
        let (tx, open_timeout) = (tx.clone(), shared.open_timeout);
        tokio::spawn(async move {
            match timeout(open_timeout, stream.read_open()).await {
                Ok(Ok(syn)) => {
                    let _ = tx.send((stream, syn));
                }
                _ => stream.reset(ResetReason::Protocol),
            }
        });
    }
    // Refuse whatever the peer still opens while we go away.
    while let Ok((send, recv)) = shared.conn.accept_bi().await {
        QuicStream::new(shared.clone(), send, recv).reset(ResetReason::Refused);
    }
}

/// Unidirectional streams carry notices; `GOAWAY` is the only one.
async fn accept_notices(shared: Arc<Shared>) {
    while let Ok(mut notice) = shared.conn.accept_uni().await {
        if let Ok(msg) = notice.read_to_end(GOAWAY.len()).await {
            if msg == GOAWAY {
                shared.set_draining();
            }
        }
    }
}

async fn receive_datagrams(shared: Arc<Shared>) {
    while let Ok(datagram) = shared.conn.read_datagram().await {
        shared.deliver(datagram);
    }
}

/// Received datagrams of one stream (a UDP flow), oldest first; the oldest is dropped
/// when full, as for kmux.
struct Inbox {
    state: Mutex<InboxState>,
    ready: Notify,
    capacity: usize,
}

#[derive(Default)]
struct InboxState {
    packets: VecDeque<Bytes>,
    /// How the flow's stream ended, once it has.
    end: Option<End>,
}

enum End {
    Finished,
    Reset(ResetReason),
    Failed(io::ErrorKind, String),
}

impl Inbox {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::default(),
            ready: Notify::new(),
            capacity,
        }
    }

    fn lock(&self) -> MutexGuard<'_, InboxState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, packet: Bytes) {
        let mut st = self.lock();
        if st.packets.len() >= self.capacity {
            st.packets.pop_front();
        }
        st.packets.push_back(packet);
        drop(st);
        self.ready.notify_one();
    }

    fn end(&self, end: End) {
        self.lock().end.get_or_insert(end);
        self.ready.notify_one();
    }
}

#[derive(Default)]
struct StreamState {
    reset: Option<ResetReason>,
    finished: bool,
    /// Reads packets sent on the stream (too large for a datagram) into the inbox.
    reader: Option<JoinHandle<()>>,
}

/// One stream of a [`QuicSession`].
pub struct QuicStream {
    shared: Arc<Shared>,
    id: u64,
    send: Arc<tokio::sync::Mutex<SendStream>>,
    recv: Arc<tokio::sync::Mutex<RecvStream>>,
    inbox: Arc<Inbox>,
    state: Arc<Mutex<StreamState>>,
    fallback: Arc<AtomicUsize>,
}

impl std::fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicStream").field("id", &self.id).finish()
    }
}

fn code(reason: ResetReason) -> VarInt {
    VarInt::from_u32(reason.id() as u32)
}

fn reason(code: VarInt) -> ResetReason {
    u8::try_from(code.into_inner()).map_or(ResetReason::Cancel, ResetReason::from_id)
}

impl QuicStream {
    fn new(shared: Arc<Shared>, send: SendStream, recv: RecvStream) -> Self {
        let id = u64::from(send.id());
        Self {
            inbox: shared.register(id),
            shared,
            id,
            send: Arc::new(tokio::sync::Mutex::new(send)),
            recv: Arc::new(tokio::sync::Mutex::new(recv)),
            state: Arc::default(),
            fallback: Arc::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, StreamState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The open request at the start of a stream the peer opened.
    async fn read_open(&self) -> io::Result<Bytes> {
        let mut recv = self.recv.lock().await;
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.map_err(io::Error::other)?;
        let mut syn = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut syn).await.map_err(io::Error::other)?;
        Ok(syn.into())
    }

    fn write_error(&self, e: WriteError) -> io::Error {
        match e {
            WriteError::Stopped(c) => {
                let r = reason(c);
                self.state().reset.get_or_insert(r);
                r.to_error()
            }
            WriteError::ConnectionLost(e) => io::Error::new(io::ErrorKind::ConnectionAborted, e),
            e => io::Error::new(io::ErrorKind::BrokenPipe, e),
        }
    }

    fn read_error(state: &Mutex<StreamState>, e: ReadError) -> io::Error {
        match e {
            ReadError::Reset(c) => {
                let r = reason(c);
                state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .reset
                    .get_or_insert(r);
                r.to_error()
            }
            ReadError::ConnectionLost(e) => io::Error::new(io::ErrorKind::ConnectionAborted, e),
            e => io::Error::new(io::ErrorKind::ConnectionReset, e),
        }
    }

    pub async fn send(&self, data: Bytes) -> io::Result<()> {
        let mut send = self.send.lock().await;
        send.write_chunk(data)
            .await
            .map_err(|e| self.write_error(e))
    }

    pub async fn recv(&self) -> io::Result<Option<Bytes>> {
        let mut recv = self.recv.lock().await;
        match recv.read_chunk(usize::MAX, true).await {
            Ok(chunk) => Ok(chunk.map(|c| c.bytes)),
            Err(e) => Err(Self::read_error(&self.state, e)),
        }
    }

    pub fn finish(&self) -> io::Result<()> {
        {
            let mut st = self.state();
            if let Some(r) = st.reset {
                return Err(r.to_error());
            }
            if std::mem::replace(&mut st.finished, true) {
                return Ok(());
            }
        }
        match self.send.clone().try_lock_owned() {
            Ok(mut send) => {
                let _ = send.finish();
            }
            // A write is in progress: finish right after it.
            Err(_) => {
                let send = self.send.clone();
                tokio::spawn(async move {
                    let _ = send.lock().await.finish();
                });
            }
        }
        Ok(())
    }

    pub fn reset(self, reason: ResetReason) {
        self.abort(reason);
    }

    fn abort(&self, reason: ResetReason) {
        {
            let mut st = self.state();
            if st.reset.is_some() {
                return;
            }
            st.reset = Some(reason);
        }
        let (send, recv) = (self.send.clone(), self.recv.clone());
        match (send.clone().try_lock_owned(), recv.clone().try_lock_owned()) {
            (Ok(mut s), Ok(mut r)) => {
                let _ = s.reset(code(reason));
                let _ = r.stop(code(reason));
            }
            _ => {
                tokio::spawn(async move {
                    let _ = send.lock().await.reset(code(reason));
                    let _ = recv.lock().await.stop(code(reason));
                });
            }
        }
    }

    pub fn reset_reason(&self) -> Option<ResetReason> {
        self.state().reset
    }

    /// Whether a packet of `len` bytes would go as a datagram, where it may be lost,
    /// rather than on the stream.
    pub fn sends_unreliably(&self, len: usize) -> bool {
        let mut id = BytesMut::with_capacity(8);
        put_varint(self.id, &mut id);
        self.shared
            .conn
            .max_datagram_size()
            .is_some_and(|max| id.len() + len <= max)
    }

    /// Sends one packet as a datagram, or on the stream if it is too large for one.
    /// Never waits; false if dropped.
    pub fn send_datagram(&self, packet: Bytes) -> bool {
        {
            let st = self.state();
            if st.reset.is_some() || st.finished {
                return false;
            }
        }
        let mut datagram = BytesMut::with_capacity(8 + packet.len());
        put_varint(self.id, &mut datagram);
        let fits = self
            .shared
            .conn
            .max_datagram_size()
            .is_some_and(|max| datagram.len() + packet.len() <= max);
        if fits {
            datagram.put_slice(&packet);
            return self.shared.conn.send_datagram(datagram.freeze()).is_ok();
        }
        // Too large for a datagram: reliably on the stream, length-prefixed.
        if packet.len() > u16::MAX as usize {
            return false;
        }
        let size = packet.len() + 2;
        if self.fallback.fetch_add(size, Ordering::SeqCst) + size > MAX_STREAM_FALLBACK {
            self.fallback.fetch_sub(size, Ordering::SeqCst);
            return false;
        }
        let (send, fallback) = (self.send.clone(), self.fallback.clone());
        tokio::spawn(async move {
            let mut frame = BytesMut::with_capacity(size);
            frame.put_u16(packet.len() as u16);
            frame.put_slice(&packet);
            let _ = send.lock().await.write_chunk(frame.freeze()).await;
            fallback.fetch_sub(size, Ordering::SeqCst);
        });
        true
    }

    /// Starts the task that reads packets sent on the stream, and notices its end.
    fn start_reader(&self) {
        let mut st = self.state();
        if st.reader.is_some() {
            return;
        }
        let (recv, inbox, state) = (self.recv.clone(), self.inbox.clone(), self.state.clone());
        st.reader = Some(tokio::spawn(async move {
            let mut recv = recv.lock().await;
            loop {
                let mut len = [0u8; 2];
                match recv.read_exact(&mut len).await {
                    Ok(()) => {}
                    Err(ReadExactError::FinishedEarly(0)) => return inbox.end(End::Finished),
                    Err(ReadExactError::ReadError(e)) => {
                        let e = Self::read_error(&state, e);
                        return inbox.end(match state.lock().map(|s| s.reset).ok().flatten() {
                            Some(r) => End::Reset(r),
                            None => End::Failed(e.kind(), e.to_string()),
                        });
                    }
                    Err(e) => {
                        return inbox.end(End::Failed(io::ErrorKind::InvalidData, e.to_string()))
                    }
                }
                let mut packet = vec![0u8; u16::from_be_bytes(len) as usize];
                if let Err(e) = recv.read_exact(&mut packet).await {
                    return inbox.end(End::Failed(io::ErrorKind::InvalidData, e.to_string()));
                }
                inbox.push(packet.into());
            }
        }));
    }

    pub async fn recv_datagram(&self) -> io::Result<Option<Bytes>> {
        self.start_reader();
        loop {
            let ready = self.inbox.ready.notified();
            {
                let mut st = self.inbox.lock();
                if let Some(packet) = st.packets.pop_front() {
                    return Ok(Some(packet));
                }
                match &st.end {
                    Some(End::Finished) => return Ok(None),
                    Some(End::Reset(r)) => return Err(r.to_error()),
                    Some(End::Failed(kind, msg)) => return Err(io::Error::new(*kind, msg.clone())),
                    None => {}
                }
            }
            ready.await;
        }
    }

    /// A datagram already received, if any (to gather several into one send).
    pub fn try_recv_datagram(&self) -> Option<Bytes> {
        self.inbox.lock().packets.pop_front()
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        let unfinished = {
            let mut st = self.state();
            if let Some(reader) = st.reader.take() {
                reader.abort();
            }
            !st.finished && st.reset.is_none()
        };
        // Dropped before finishing: abort, as kmux does (quinn would finish it).
        if unfinished {
            self.abort(ResetReason::Cancel);
        }
        self.shared.unregister(self.id);
    }
}

/// Listening side: completes each incoming handshake in its own task and hands the new
/// sessions to `on_session`, with the peer's address. Runs until the endpoint closes.
pub async fn accept_sessions(
    listener: crate::transport::quic::QuicListener,
    config: SessionConfig,
    open_timeout: Duration,
    link: Arc<crate::stats::Peer>,
    on_session: impl Fn(QuicSession, std::net::SocketAddr) + Send + Sync + 'static,
) {
    let on_session = Arc::new(on_session);
    while let Some(accepting) = listener.accept().await {
        let peer = accepting.remote_address();
        let (config, on_session, link) = (config.clone(), on_session.clone(), link.clone());
        tokio::spawn(async move {
            match accepting.establish().await {
                Ok(conn) => on_session(QuicSession::new(conn, &config, open_timeout), peer),
                Err(e) => {
                    link.failed(&e);
                    tracing::warn!(%peer, error = %e, "QUIC handshake failed")
                }
            }
        });
    }
}

/// Polls a future once without a real waker: `Some` if it completed right away.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Noop));
    let fut = pin!(fut);
    match fut.poll(&mut Context::from_waker(&waker)) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// QUIC variable-length integer (RFC 9000, section 16).
fn put_varint(v: u64, out: &mut BytesMut) {
    if v < 1 << 6 {
        out.put_u8(v as u8);
    } else if v < 1 << 14 {
        out.put_u16(0x4000 | v as u16);
    } else if v < 1 << 30 {
        out.put_u32(0x8000_0000 | v as u32);
    } else {
        out.put_u64(0xc000_0000_0000_0000 | v);
    }
}

fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QuicConfig;

    const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

    /// Two ends of one QUIC connection: (dialer, listener).
    async fn pair() -> (QuicSession, QuicSession) {
        let (a, b) = crate::transport::quic::tests::pair(&QuicConfig::default()).await;
        let config = crate::mux::tests::config();
        (
            QuicSession::new(a, &config, OPEN_TIMEOUT),
            QuicSession::new(b, &config, OPEN_TIMEOUT),
        )
    }

    async fn within<F: Future>(f: F) -> F::Output {
        timeout(Duration::from_secs(5), f).await.expect("timed out")
    }

    async fn read_all(stream: &QuicStream) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = within(stream.recv()).await.unwrap() {
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[tokio::test]
    async fn streams_carry_the_open_request_and_data_both_ways() {
        let (a, b) = pair().await;
        let s = a.open(Bytes::from_static(b"syn-1")).unwrap();
        s.send(Bytes::from_static(b"hello")).await.unwrap();
        s.finish().unwrap();
        let (t, syn) = within(b.accept()).await.unwrap();
        assert_eq!(syn, "syn-1");
        assert_eq!(read_all(&t).await, b"hello");
        // More than the stream window: sending waits for the reader.
        let big = Bytes::from(vec![7u8; 3 << 20]);
        let send = async {
            within(t.send(big.clone())).await.unwrap();
            t.finish().unwrap();
        };
        let ((), got) = tokio::join!(send, read_all(&s));
        assert_eq!(got, big);
        assert_eq!((a.stream_count(), b.stream_count()), (1, 1));
        drop((s, t));
        assert_eq!((a.stream_count(), b.stream_count()), (0, 0));

        // The other side opens too; an empty open request is fine.
        let t = b.open(Bytes::new()).unwrap();
        t.finish().unwrap();
        let (s, syn) = within(a.accept()).await.unwrap();
        assert!(syn.is_empty());
        assert!(read_all(&s).await.is_empty());
    }

    #[tokio::test]
    async fn reset_reasons_reach_the_peer() {
        let (a, b) = pair().await;
        for reason in [
            ResetReason::Refused,
            ResetReason::DialFailed,
            ResetReason::Unsupported,
        ] {
            let s = a.open(Bytes::from_static(b"x")).unwrap();
            let (t, _) = within(b.accept()).await.unwrap();
            t.reset(reason);
            let err = within(s.recv()).await.unwrap_err();
            assert_eq!(err.kind(), reason.to_error().kind(), "{reason:?}");
            assert_eq!(s.reset_reason(), Some(reason));
        }
        // Dropping an unfinished stream cancels it.
        let s = a.open(Bytes::from_static(b"x")).unwrap();
        let (t, _) = within(b.accept()).await.unwrap();
        drop(s);
        assert!(within(t.recv()).await.is_err());
        assert_eq!(t.reset_reason(), Some(ResetReason::Cancel));
    }

    #[tokio::test]
    async fn datagrams_fall_back_to_the_stream_when_too_large() {
        let (a, b) = pair().await;
        let s = a.open(Bytes::from_static(b"udp")).unwrap();
        let (t, _) = within(b.accept()).await.unwrap();
        let max = a.shared.conn.max_datagram_size().unwrap();
        let sizes = [0, 1, 500, max - 8, max, 20_000, 65_535];
        for &n in &sizes {
            assert!(s.send_datagram(Bytes::from(vec![n as u8; n])), "{n}");
            // One at a time: datagrams and the stream do not keep each other's order.
            let got = within(t.recv_datagram()).await.unwrap().unwrap();
            assert_eq!((got.len(), got.first()), (n, (n > 0).then_some(&(n as u8))));
        }
        assert!(!s.send_datagram(Bytes::from(vec![0; 65_536])));
        // Replies go the other way.
        assert!(t.send_datagram(Bytes::from_static(b"pong")));
        assert_eq!(within(s.recv_datagram()).await.unwrap().unwrap(), "pong");
        // A finished flow ends; nothing is sent after that.
        s.finish().unwrap();
        assert_eq!(within(t.recv_datagram()).await.unwrap(), None);
        assert!(!s.send_datagram(Bytes::from_static(b"late")));
    }

    #[tokio::test]
    async fn datagrams_before_their_stream_are_kept() {
        let (a, _b) = pair().await;
        let shared = &a.shared;
        let mut early = BytesMut::new();
        put_varint(1_000, &mut early);
        early.put_slice(b"early");
        shared.deliver(early.freeze());
        shared.deliver(Bytes::new()); // no stream id: ignored
        let inbox = shared.register(1_000);
        assert_eq!(inbox.lock().packets.pop_front().unwrap(), "early");
        shared.unregister(1_000);

        // Bounded: only the newest `MAX_EARLY_DATAGRAMS` wait.
        for i in 0..MAX_EARLY_DATAGRAMS + 10 {
            let mut d = BytesMut::new();
            put_varint(2_000, &mut d);
            d.put_u32(i as u32);
            shared.deliver(d.freeze());
        }
        let inbox = shared.register(2_000);
        let packets = &inbox.lock().packets;
        assert_eq!(packets.len(), MAX_EARLY_DATAGRAMS.min(inbox.capacity));
        assert_eq!(
            packets.back().unwrap()[..],
            ((MAX_EARLY_DATAGRAMS + 9) as u32).to_be_bytes()
        );
        shared.unregister(2_000);
    }

    #[tokio::test]
    async fn goaway_stops_new_streams_and_drain_waits_for_old_ones() {
        let (a, b) = pair().await;
        let s = a.open(Bytes::from_static(b"old")).unwrap();
        let (t, _) = within(b.accept()).await.unwrap();
        b.goaway();
        assert!(b.is_draining());
        assert!(b.open(Bytes::new()).is_err());
        // The notice reaches the other side, which stops opening too.
        within(async {
            while !a.is_draining() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(a.open(Bytes::new()).is_err());
        assert!(!a.is_closed());

        // Old streams still work; draining ends once they are done.
        let drained = tokio::spawn(async move {
            b.drain().await;
            b
        });
        s.send(Bytes::from_static(b"still here")).await.unwrap();
        s.finish().unwrap();
        assert_eq!(read_all(&t).await, b"still here");
        t.finish().unwrap();
        assert!(read_all(&s).await.is_empty());
        drop((s, t));
        let b = within(drained).await.unwrap();
        assert!(b.is_closed());
        within(a.closed()).await;
    }

    #[test]
    fn varints_roundtrip() {
        for v in [
            0u64,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut b = BytesMut::new();
            put_varint(v, &mut b);
            assert_eq!(get_varint(&b), Some((v, b.len())), "{v}");
        }
        // RFC 9000, appendix A.1.
        assert_eq!(
            get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494_878_333, 4))
        );
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(get_varint(&[0x7b]), None);
    }
}
