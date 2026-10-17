//! The sealed l3 session: the GRE-framed IP packets are carried inside the tunnel's own
//! handshake + record keys (reusing `crate::crypto`), with a per-packet explicit counter, a
//! sliding replay window, a periodic rekey, and an `encap = "gre"` value both ends compare
//! in the handshake and refuse a mismatch by name.
//!
//! Scaffold: the seal/open methods return [`io::ErrorKind::Unsupported`]. The l3 unit wires
//! the handshake and the record layer (pattern: `crate::crypto::datagram`, replay window
//! widened to 2048) in here.

use std::io;

/// Both ends compare this in the handshake and refuse a mismatch by name.
pub const ENCAP: &str = "gre";

/// A sealed l3 session over a carrier.
pub enum L3Session {}

impl L3Session {
    /// Seals a GRE-framed packet for the wire.
    pub fn seal(&self, _gre_packet: &[u8], _out: &mut Vec<u8>) -> io::Result<()> {
        match *self {}
    }

    /// Opens a sealed packet, rejecting replays and counter rollbacks.
    pub fn open<'a>(&self, _packet: &'a mut [u8]) -> io::Result<&'a [u8]> {
        match *self {}
    }
}
