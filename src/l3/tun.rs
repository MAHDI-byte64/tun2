//! The TUN device of an l3 tunnel (`kz0`, `kz1`, ...): created on start with its addresses
//! and routes set, torn down on stop (RAII). Linux only, `/dev/net/tun` + `CAP_NET_ADMIN`.
//!
//! Scaffold: [`TunDevice::create`] returns [`io::ErrorKind::Unsupported`]. The l3 unit adds
//! the pinned pure-Rust TUN + netlink crates (none are added by the scaffold) and fills
//! this in.

use std::io;

/// A created TUN interface. The real type owns the device fd and removes the interface on
/// drop; the scaffold is uninhabited so its callers stay statically unreachable.
pub enum TunDevice {}

impl TunDevice {
    /// Creates `name` (or the next free `kzN`), sets `local_ip`/`peer_ip` and the MTU.
    pub fn create(_name: &str, _local_ip: &str, _peer_ip: &str, _mtu: u16) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the l3 TUN device is not built yet",
        ))
    }

    /// Reads one whole IP packet from the interface.
    pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        match *self {}
    }

    /// Writes one whole IP packet to the interface.
    pub async fn send(&self, _packet: &[u8]) -> io::Result<()> {
        match *self {}
    }
}
