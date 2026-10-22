//! Stands in for `quic.rs` in builds without the `quic` feature. The types have no
//! values, so every path that would use one is unreachable, and the compiler knows it.
//! Config validation rejects `transport = "quic"` in such a build.

use std::io;

use bytes::Bytes;

use crate::mux::ResetReason;

pub enum QuicSession {}

#[derive(Debug)]
pub enum QuicStream {}

impl QuicSession {
    pub fn open(&self, _: Bytes) -> io::Result<QuicStream> {
        match *self {}
    }

    pub async fn accept(&self) -> Option<(QuicStream, Bytes)> {
        match *self {}
    }

    pub fn goaway(&self) {
        match *self {}
    }

    pub fn is_closed(&self) -> bool {
        match *self {}
    }

    pub fn is_draining(&self) -> bool {
        match *self {}
    }

    pub fn stream_count(&self) -> usize {
        match *self {}
    }

    pub fn rtt(&self) -> Option<std::time::Duration> {
        match *self {}
    }

    pub fn close_reason(&self) -> Option<String> {
        match *self {}
    }

    pub async fn closed(&self) {
        match *self {}
    }

    pub fn close(&self) {
        match *self {}
    }

    pub async fn drain(&self) {
        match *self {}
    }
}

impl QuicStream {
    pub async fn send(&self, _: Bytes) -> io::Result<()> {
        match *self {}
    }

    pub async fn recv(&self) -> io::Result<Option<Bytes>> {
        match *self {}
    }

    pub fn finish(&self) -> io::Result<()> {
        match *self {}
    }

    pub fn reset(self, _: ResetReason) {
        match self {}
    }

    pub fn reset_reason(&self) -> Option<ResetReason> {
        match *self {}
    }

    pub fn send_datagram(&self, _: Bytes) -> bool {
        match *self {}
    }

    pub fn sends_unreliably(&self, _: usize) -> bool {
        match *self {}
    }

    pub async fn recv_datagram(&self) -> io::Result<Option<Bytes>> {
        match *self {}
    }

    pub fn try_recv_datagram(&self) -> Option<Bytes> {
        match *self {}
    }
}
