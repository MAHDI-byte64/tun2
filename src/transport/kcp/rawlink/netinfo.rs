//! Egress-path lookup for the fake-TCP carrier: the local source address and the egress
//! interface for a given peer, overridable from `[tunnel.faketcp]`.
//!
//! The source address is what the kernel would route to the peer (found with a connected
//! but unsent UDP socket, so nothing is forged — the real address is used). The interface
//! is the one that owns that address (matched through `getifaddrs`), unless the config
//! names one. The next-hop MAC is only needed for an L2 send path, which this carrier does
//! not use (it sends whole IP packets through a raw `IP_HDRINCL` socket); the override is
//! accepted and logged for completeness.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// The local IPv4 source address the kernel would use to reach `peer`.
pub(crate) fn local_addr_for(peer: Ipv4Addr) -> io::Result<Ipv4Addr> {
    // A connected UDP socket sends nothing but resolves the route, so its local address is
    // the source address the kernel picked for this peer.
    let socket = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddrV4::new(peer, 9))?;
    match socket.local_addr()? {
        SocketAddr::V4(a) => Ok(*a.ip()),
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "faketcp supports IPv4 only",
        )),
    }
}

/// The egress interface name and index for `local`. `override_name`, when non-empty, is
/// used directly (for virtualised networks whose address does not match an interface the
/// usual way); otherwise the interface that owns `local` is found.
pub(crate) fn egress_interface(local: Ipv4Addr, override_name: &str) -> io::Result<(String, u32)> {
    if !override_name.is_empty() {
        let index = index_of(override_name)?;
        return Ok((override_name.to_owned(), index));
    }
    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| io::Error::other(format!("getifaddrs failed: {e}")))?;
    for ifa in addrs {
        let owns = ifa
            .address
            .and_then(|a| a.as_sockaddr_in().map(|v4| v4.ip()))
            .is_some_and(|ip| ip == local);
        if owns {
            let index = index_of(&ifa.interface_name)?;
            return Ok((ifa.interface_name, index));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no interface owns the local address {local}; \
             set tunnel.faketcp.interface to the egress interface"
        ),
    ))
}

/// The kernel index of an interface by name.
fn index_of(name: &str) -> io::Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name:?} not found: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves_to_lo() {
        // The route to a loopback peer is loopback, owned by "lo".
        let local = local_addr_for(Ipv4Addr::LOCALHOST).unwrap();
        assert!(
            local.is_loopback(),
            "local for 127.0.0.1 should be loopback"
        );
        let (name, index) = egress_interface(local, "").unwrap();
        assert_eq!(name, "lo");
        assert!(index > 0);
        // An explicit override is honoured.
        let (name, _) = egress_interface(local, "lo").unwrap();
        assert_eq!(name, "lo");
    }
}
