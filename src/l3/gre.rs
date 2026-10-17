//! GRE framing for the l3 tunnel: an RFC 2784 header with the RFC 2890 key, wrapping a
//! whole inner IP packet. This header is always sealed inside the tunnel session before it
//! reaches the carrier, so it never appears as bare IP protocol 47 on the wire.
//!
//! Only the Key bit is set (RFC 2890); Checksum and Sequence are not used (the session's
//! own per-packet counter and AEAD cover integrity and replay). The header is therefore a
//! fixed 8 bytes: flags/version (2), protocol type (2), key (4).

/// GRE flag: Key Present (RFC 2890), bit 2 of the 16-bit flags/version field.
const FLAG_KEY: u16 = 0x2000;
/// EtherType of an inner IPv4 packet.
const PROTO_IPV4: u16 = 0x0800;
/// EtherType of an inner IPv6 packet.
const PROTO_IPV6: u16 = 0x86DD;
/// flags/version (2) + protocol (2) + key (4).
pub const HEADER_LEN: usize = 8;

/// The EtherType for an inner IP packet, read from its version nibble; `None` for anything
/// that is not IPv4 or IPv6.
fn proto_of(inner: &[u8]) -> Option<u16> {
    match inner.first()? >> 4 {
        4 => Some(PROTO_IPV4),
        6 => Some(PROTO_IPV6),
        _ => None,
    }
}

/// Writes the GRE header for `inner` (keyed with `key`) and the packet into `out`.
/// Returns whether `inner` was a recognised IP packet (IPv4 or IPv6); a non-IP packet is
/// not written.
pub fn encode(key: u32, inner: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(proto) = proto_of(inner) else {
        return false;
    };
    out.reserve(HEADER_LEN + inner.len());
    out.extend_from_slice(&FLAG_KEY.to_be_bytes());
    out.extend_from_slice(&proto.to_be_bytes());
    out.extend_from_slice(&key.to_be_bytes());
    out.extend_from_slice(inner);
    true
}

/// Parses a GRE packet, returning `(key, inner)`. Rejects anything but a version-0, Key-only
/// header whose protocol type matches the inner packet's version nibble.
pub fn decode(packet: &[u8]) -> Option<(u32, &[u8])> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([packet[0], packet[1]]);
    // Version must be 0 and only the Key bit may be set (no checksum/sequence/routing).
    if flags != FLAG_KEY {
        return None;
    }
    let proto = u16::from_be_bytes([packet[2], packet[3]]);
    let key = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let inner = &packet[HEADER_LEN..];
    if proto_of(inner)? != proto {
        return None;
    }
    Some((key, inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(payload_byte: u8) -> Vec<u8> {
        // A minimal IPv4-looking packet: version nibble 4, then filler.
        let mut p = vec![0x45, 0, 0, 20];
        p.extend_from_slice(&[payload_byte; 16]);
        p
    }

    fn ipv6() -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&[0u8; 36]);
        p
    }

    #[test]
    fn roundtrip_ipv4() {
        let inner = ipv4(0xAB);
        let mut out = Vec::new();
        assert!(encode(0x1234_5678, &inner, &mut out));
        assert_eq!(out.len(), HEADER_LEN + inner.len());
        let (key, back) = decode(&out).expect("decodes");
        assert_eq!(key, 0x1234_5678);
        assert_eq!(back, &inner[..]);
    }

    #[test]
    fn roundtrip_ipv6() {
        let inner = ipv6();
        let mut out = Vec::new();
        assert!(encode(7, &inner, &mut out));
        let (key, back) = decode(&out).unwrap();
        assert_eq!(key, 7);
        assert_eq!(back, &inner[..]);
    }

    #[test]
    fn rejects_non_ip() {
        let mut out = Vec::new();
        assert!(!encode(1, &[0x00, 0x00], &mut out));
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_short_and_mismatched() {
        assert!(decode(&[0; 4]).is_none());
        // Protocol says IPv4 but the inner packet is IPv6: reject.
        let mut out = Vec::new();
        out.extend_from_slice(&FLAG_KEY.to_be_bytes());
        out.extend_from_slice(&PROTO_IPV4.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(0x60); // IPv6 nibble
        out.extend_from_slice(&[0u8; 39]);
        assert!(decode(&out).is_none());
    }

    #[test]
    fn rejects_other_flags() {
        let inner = ipv4(1);
        let mut out = Vec::new();
        encode(1, &inner, &mut out);
        // Set the checksum bit: no longer the plain keyed header we accept.
        out[0] |= 0x80;
        assert!(decode(&out).is_none());
    }
}
