//! The session layer: many streams (user TCP connections) and datagrams (UDP flows) over
//! one tunnel connection.
//!
//! Entry, exit and the UDP code work with [`Session`] and [`SessionStream`] only. Today
//! the one implementation is kmux (`src/mux/`), running over an authenticated link;
//! QUIC, which brings its own streams and datagrams, becomes a second variant. Enums rather than trait objects keep dispatch static.

mod manager;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(not(feature = "quic"))]
#[path = "quic_disabled.rs"]
pub mod quic;

use std::io;

use bytes::Bytes;

use crate::mux::{MuxSession, MuxStream};
use quic::{QuicSession, QuicStream};

pub use crate::mux::ResetReason;
pub use manager::{is_full, maintain, SessionPool};

/// One tunnel connection carrying streams and datagrams.
pub enum Session {
    Kmux(MuxSession),
    Quic(QuicSession),
}

impl Session {
    /// Short name for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Kmux(_) => "mux",
            Self::Quic(_) => "quic",
        }
    }

    /// The transport an `auto` tunnel's session runs over; `None` for the others.
    pub fn transport(&self) -> Option<&'static str> {
        match self {
            Self::Kmux(s) => s.transport(),
            Self::Quic(_) => None,
        }
    }

    /// Opens a stream whose first bytes are `syn` (the open request). Data can be sent
    /// right away; the peer answers a failed open with a reset.
    pub fn open(&self, syn: Bytes) -> io::Result<SessionStream> {
        match self {
            Self::Kmux(s) => s.open(syn).map(SessionStream::Kmux),
            Self::Quic(s) => s.open(syn).map(SessionStream::Quic),
        }
    }

    /// Waits for a stream the peer opened, with its open request. `None` once the
    /// session is closed or going away.
    pub async fn accept(&self) -> Option<(SessionStream, Bytes)> {
        match self {
            Self::Kmux(s) => s
                .accept()
                .await
                .map(|(stream, syn)| (SessionStream::Kmux(stream), syn)),
            Self::Quic(s) => s
                .accept()
                .await
                .map(|(stream, syn)| (SessionStream::Quic(stream), syn)),
        }
    }

    /// No new streams in either direction; existing ones continue.
    pub fn goaway(&self) {
        match self {
            Self::Kmux(s) => s.goaway(),
            Self::Quic(s) => s.goaway(),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Self::Kmux(s) => s.is_closed(),
            Self::Quic(s) => s.is_closed(),
        }
    }

    /// Going away or closed: takes no new streams.
    pub fn is_draining(&self) -> bool {
        match self {
            Self::Kmux(s) => s.is_draining(),
            Self::Quic(s) => s.is_draining(),
        }
    }

    pub fn stream_count(&self) -> usize {
        match self {
            Self::Kmux(s) => s.stream_count(),
            Self::Quic(s) => s.stream_count(),
        }
    }

    /// Round-trip time to the peer: from pings (kmux) or QUIC's own estimate.
    pub fn rtt(&self) -> Option<std::time::Duration> {
        match self {
            Self::Kmux(s) => s.rtt(),
            Self::Quic(s) => s.rtt(),
        }
    }

    /// Why the session closed, once it has.
    pub fn close_reason(&self) -> Option<String> {
        match self {
            Self::Kmux(s) => s.close_reason(),
            Self::Quic(s) => s.close_reason(),
        }
    }

    /// Resolves once the session is closed.
    pub async fn closed(&self) {
        match self {
            Self::Kmux(s) => s.closed().await,
            Self::Quic(s) => s.closed().await,
        }
    }

    pub fn close(&self) {
        match self {
            Self::Kmux(s) => s.close(),
            Self::Quic(s) => s.close(),
        }
    }

    /// Stops new streams, waits for the existing ones to finish, then closes.
    pub async fn drain(&self) {
        match self {
            Self::Kmux(s) => s.drain().await,
            Self::Quic(s) => s.drain().await,
        }
    }
}

/// One stream of a [`Session`]: a user TCP connection, or a UDP flow (whose packets
/// travel as datagrams).
#[derive(Debug)]
pub enum SessionStream {
    Kmux(MuxStream),
    Quic(QuicStream),
}

impl SessionStream {
    /// Sends `data`, waiting for flow-control credit as needed.
    pub async fn send(&self, data: Bytes) -> io::Result<()> {
        match self {
            Self::Kmux(s) => s.send(data).await,
            Self::Quic(s) => s.send(data).await,
        }
    }

    /// Receives the next chunk of data; `None` at the end of the stream.
    pub async fn recv(&self) -> io::Result<Option<Bytes>> {
        match self {
            Self::Kmux(s) => s.recv().await,
            Self::Quic(s) => s.recv().await,
        }
    }

    /// Half close: no more data from this side.
    pub fn finish(&self) -> io::Result<()> {
        match self {
            Self::Kmux(s) => s.finish(),
            Self::Quic(s) => s.finish(),
        }
    }

    /// Aborts the stream and tells the peer why.
    pub fn reset(self, reason: ResetReason) {
        match self {
            Self::Kmux(s) => s.reset(reason),
            Self::Quic(s) => s.reset(reason),
        }
    }

    /// Why the stream was reset, once it has been (by either side).
    pub fn reset_reason(&self) -> Option<ResetReason> {
        match self {
            Self::Kmux(s) => s.reset_reason(),
            Self::Quic(s) => s.reset_reason(),
        }
    }

    /// Queues one datagram; never waits. False if it was dropped or cannot be sent.
    pub fn send_datagram(&self, packet: Bytes) -> bool {
        match self {
            Self::Kmux(s) => s.send_datagram(packet),
            Self::Quic(s) => s.send_datagram(packet),
        }
    }

    /// Whether a datagram of `len` bytes would be sent where it may be lost (KCP's
    /// datagram path, a QUIC datagram), rather than reliably in the connection.
    pub fn sends_unreliably(&self, len: usize) -> bool {
        match self {
            Self::Kmux(s) => s.sends_unreliably(len),
            Self::Quic(s) => s.sends_unreliably(len),
        }
    }

    /// Receives the next datagram, whole; `None` once the peer finished the stream.
    pub async fn recv_datagram(&self) -> io::Result<Option<Bytes>> {
        match self {
            Self::Kmux(s) => s.recv_datagram().await,
            Self::Quic(s) => s.recv_datagram().await,
        }
    }

    /// A datagram already received, if any (to gather several into one send).
    pub fn try_recv_datagram(&self) -> Option<Bytes> {
        match self {
            Self::Kmux(s) => s.try_recv_datagram(),
            Self::Quic(s) => s.try_recv_datagram(),
        }
    }
}
