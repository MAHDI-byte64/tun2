//! Messages exchanged over an authenticated tunnel connection before relaying starts.
//!
//! ```text
//! entry -> exit : kind (1) | target_len (2, big-endian) | target      kind: 1 TCP, 2 UDP,
//!                                                                      4 speed test,
//!                                                                      5 health probe
//!                 [ | copies (1) | gap_ms (1) ]                        kind 3: UDP with
//!                                                                      duplication
//!                 [ | version (1) | family (1) | src ip | dst ip       kind 6: TCP with a
//!                   | src port (2) | dst port (2) ]                    PROXY header
//! exit  -> entry: status (1)                                           (not with mux)
//! ```
//!
//! After that, a TCP channel carries raw bytes. A UDP channel without mux carries
//! packets as `len (2, BE) | packet` in both directions (with mux, packets travel as
//! `DGRAM` frames instead, see `src/mux/`). With duplication (v0.5), every packet starts with a 4-byte sequence number (see `src/udp.rs`);
//! older exits reject kind 3 as unknown.
//!
//! In kind 6 (v2.5), `version` is the PROXY protocol version (1 or 2), `family` is 4 or 6
//! and the two addresses are 4 or 16 bytes long as it says: the user's, and the one they
//! connected to on the entry side. The exit side writes them to the target in a PROXY
//! header before any data (see `src/proxy_header.rs`); older exits reject kind 6 as
//! unknown.

use std::io;
use std::net::{IpAddr, SocketAddr};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proxy_header::{Addresses, ProxyHeader, ProxyVersion};

pub const KIND_TCP: u8 = 1;
/// A UDP flow (v0.3). v0.2 peers reject it as an unknown kind.
pub const KIND_UDP: u8 = 2;
/// A UDP flow with packet duplication (v0.5); decoded as [`KIND_UDP`] with
/// [`Open::duplicate`] set.
const KIND_UDP_DUPLICATED: u8 = 3;
/// A speed test stream (v0.6): the exit side does not dial anything, it produces,
/// consumes or echoes data as the target says (`down`, `up`, `echo`, `udp`), see
/// `src/speedtest.rs`. Older exits reject it as an unknown kind.
pub const KIND_SPEEDTEST: u8 = 4;
/// A health probe (v2.4): the exit side connects to the target (none if it is empty),
/// answers with one status byte, with mux too, and closes. Older exits reject it as an
/// unknown kind.
pub const KIND_PROBE: u8 = 5;
/// A TCP connection whose target gets a PROXY header (v2.5); decoded as [`KIND_TCP`] with
/// [`Open::proxy`] set.
const KIND_TCP_PROXY: u8 = 6;

/// Packet duplication of a UDP flow: each packet is sent `copies` times in all,
/// `gap_ms` apart, in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duplicate {
    pub copies: u8,
    pub gap_ms: u8,
}

pub const STATUS_OK: u8 = 0;
pub const STATUS_DIAL_FAILED: u8 = 1;
/// The exit side does not support this kind (for example UDP not enabled there).
pub const STATUS_UNSUPPORTED: u8 = 2;

/// Largest UDP payload (65,535 minus the IPv4 and UDP headers).
pub const MAX_DATAGRAM: usize = 65_507;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub kind: u8,
    pub target: String,
    /// UDP only: the flow's packet duplication.
    pub duplicate: Option<Duplicate>,
    /// TCP only: the PROXY header the exit side writes to the target first.
    pub proxy: Option<ProxyHeader>,
}

impl Open {
    pub fn tcp(target: impl Into<String>) -> Self {
        Self::of(KIND_TCP, target.into())
    }

    /// A TCP connection whose target is told, in a PROXY header, where it came from.
    pub fn tcp_proxied(target: impl Into<String>, proxy: ProxyHeader) -> Self {
        Self {
            proxy: Some(proxy),
            ..Self::tcp(target)
        }
    }

    pub fn udp(target: impl Into<String>, duplicate: Option<Duplicate>) -> Self {
        Self {
            duplicate,
            ..Self::of(KIND_UDP, target.into())
        }
    }

    /// A speed test stream; `command` is what the exit side does on it.
    pub fn speedtest(command: impl Into<String>) -> Self {
        Self::of(KIND_SPEEDTEST, command.into())
    }

    /// A health probe of `target` (empty: of the tunnel alone).
    pub fn probe(target: impl Into<String>) -> Self {
        Self::of(KIND_PROBE, target.into())
    }

    fn of(kind: u8, target: String) -> Self {
        Self {
            kind,
            target,
            duplicate: None,
            proxy: None,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let target = self.target.as_bytes();
        let kind = match (self.duplicate, self.proxy) {
            (Some(_), _) if self.kind == KIND_UDP => KIND_UDP_DUPLICATED,
            (_, Some(_)) if self.kind == KIND_TCP => KIND_TCP_PROXY,
            _ => self.kind,
        };
        out.push(kind);
        out.extend_from_slice(&(target.len() as u16).to_be_bytes());
        out.extend_from_slice(target);
        if kind == KIND_UDP_DUPLICATED {
            let d = self.duplicate.expect("kind 3 has duplication");
            out.extend_from_slice(&[d.copies, d.gap_ms]);
        }
        if kind == KIND_TCP_PROXY {
            put_proxy(&self.proxy.expect("kind 6 has a header"), out);
        }
    }

    pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Self> {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head).await?;
        check_kind(head[0])?;
        let len = u16::from_be_bytes([head[1], head[2]]) as usize;
        let mut rest = vec![0u8; len + options_len(head[0])];
        stream.read_exact(&mut rest).await?;
        if head[0] == KIND_TCP_PROXY {
            // The addresses follow, as long as the family byte (the last one read) says.
            let fixed = rest.len();
            rest.resize(fixed + addresses_len(rest[fixed - 1])?, 0);
            stream.read_exact(&mut rest[fixed..]).await?;
        }
        Self::with_rest(head[0], len, rest)
    }

    /// Decodes a complete open request, as carried in a mux `SYN`.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (head, rest) = bytes.split_at_checked(3).ok_or_else(malformed)?;
        check_kind(head[0])?;
        let len = u16::from_be_bytes([head[1], head[2]]) as usize;
        let fixed = len + options_len(head[0]);
        let whole = match head[0] {
            KIND_TCP_PROXY if rest.len() >= fixed => fixed + addresses_len(rest[fixed - 1])?,
            _ => fixed,
        };
        if rest.len() != whole {
            return Err(malformed());
        }
        Self::with_rest(head[0], len, rest.to_vec())
    }

    /// `rest`: the target (`target_len` bytes), then the options of `kind`.
    fn with_rest(kind: u8, target_len: usize, mut rest: Vec<u8>) -> io::Result<Self> {
        let options = rest.split_off(target_len);
        let target = String::from_utf8(rest)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target is not valid UTF-8"))?;
        match kind {
            KIND_UDP_DUPLICATED => {
                let (copies, gap_ms) = (options[0], options[1]);
                if !(2..=3).contains(&copies) || gap_ms > 50 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad duplication in open request",
                    ));
                }
                Ok(Self::udp(target, Some(Duplicate { copies, gap_ms })))
            }
            KIND_TCP_PROXY => Ok(Self::tcp_proxied(target, read_proxy(&options)?)),
            _ => Ok(Self::of(kind, target)),
        }
    }
}

/// Fixed bytes after the target in an open request of `kind` (kind 6 has more after
/// them, as its family byte says).
fn options_len(kind: u8) -> usize {
    match kind {
        KIND_UDP_DUPLICATED | KIND_TCP_PROXY => 2,
        _ => 0,
    }
}

/// Bytes of the two addresses and ports of a kind 6 request in `family`.
fn addresses_len(family: u8) -> io::Result<usize> {
    match family {
        4 => Ok(4 + 4 + 2 + 2),
        6 => Ok(16 + 16 + 2 + 2),
        _ => Err(malformed()),
    }
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed open request")
}

/// The options of a kind 6 request: version, family, addresses, ports.
fn put_proxy(proxy: &ProxyHeader, out: &mut Vec<u8>) {
    out.push(match proxy.version {
        ProxyVersion::V1 => 1,
        ProxyVersion::V2 => 2,
    });
    match proxy.addresses() {
        Addresses::V4(src, dst) => {
            out.push(4);
            out.extend_from_slice(&src);
            out.extend_from_slice(&dst);
        }
        Addresses::V6(src, dst) => {
            out.push(6);
            out.extend_from_slice(&src);
            out.extend_from_slice(&dst);
        }
    }
    out.extend_from_slice(&proxy.source.port().to_be_bytes());
    out.extend_from_slice(&proxy.destination.port().to_be_bytes());
}

/// Reads what [`put_proxy`] wrote (its length is already checked).
fn read_proxy(options: &[u8]) -> io::Result<ProxyHeader> {
    let version = match options[0] {
        1 => ProxyVersion::V1,
        2 => ProxyVersion::V2,
        _ => return Err(malformed()),
    };
    let (ips, ports) = options[2..].split_at(options.len() - 2 - 4);
    let (src, dst): (IpAddr, IpAddr) = match options[1] {
        4 => (
            <[u8; 4]>::try_from(&ips[..4]).expect("4 bytes").into(),
            <[u8; 4]>::try_from(&ips[4..]).expect("4 bytes").into(),
        ),
        _ => (
            <[u8; 16]>::try_from(&ips[..16]).expect("16 bytes").into(),
            <[u8; 16]>::try_from(&ips[16..]).expect("16 bytes").into(),
        ),
    };
    let port = |at: usize| u16::from_be_bytes([ports[at], ports[at + 1]]);
    Ok(ProxyHeader {
        version,
        source: SocketAddr::new(src, port(0)),
        destination: SocketAddr::new(dst, port(2)),
    })
}

fn check_kind(kind: u8) -> io::Result<()> {
    if matches!(
        kind,
        KIND_TCP | KIND_UDP | KIND_UDP_DUPLICATED | KIND_SPEEDTEST | KIND_PROBE | KIND_TCP_PROXY
    ) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported stream kind {kind}"),
        ))
    }
}

/// Writes a whole message and flushes it: channels may buffer writes (the record layer
/// does), and the peer waits for this message before sending anything back.
pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, msg: &[u8]) -> io::Result<()> {
    stream.write_all(msg).await?;
    stream.flush().await
}

pub async fn write_status<S: AsyncWrite + Unpin>(stream: &mut S, status: u8) -> io::Result<()> {
    send(stream, &[status]).await
}

pub async fn read_status<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    match status[0] {
        STATUS_OK => Ok(()),
        STATUS_DIAL_FAILED => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "exit side could not connect to the target",
        )),
        STATUS_UNSUPPORTED => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exit side does not support this kind of connection (older version?)",
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown status {other}"),
        )),
    }
}

/// Appends one UDP packet in the framing of UDP channels without mux. Several packets
/// can be gathered into one write this way.
pub fn put_datagram(packet: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    if packet.len() > MAX_DATAGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP packet larger than 65,507 bytes",
        ));
    }
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    Ok(())
}

/// Reads UDP packets framed by [`put_datagram`] from a stream, through one buffer: a
/// read brings as many packets as the stream has, and each packet is a slice of the
/// buffer rather than its own allocation.
pub struct DatagramReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> DatagramReader<R> {
    const CHUNK: usize = 64 * 1024;

    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(Self::CHUNK),
        }
    }

    /// The next packet; `None` when the stream ends cleanly between packets.
    pub async fn next(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.try_next()? {
                return Ok(Some(packet));
            }
            if self.buf.capacity() - self.buf.len() < Self::CHUNK / 4 {
                self.buf.reserve(Self::CHUNK);
            }
            if self.inner.read_buf(&mut self.buf).await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended inside a UDP packet",
                    ))
                };
            }
        }
    }

    /// A packet already read, if a whole one is buffered (to gather several into one
    /// send).
    pub fn try_next(&mut self) -> io::Result<Option<Bytes>> {
        let Some(head) = self.buf.get(..2) else {
            return Ok(None);
        };
        let len = u16::from_be_bytes([head[0], head[1]]) as usize;
        if len > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP packet larger than 65,507 bytes",
            ));
        }
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        self.buf.advance(2);
        Ok(Some(self.buf.split_to(len).freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_roundtrip() {
        let open = Open::tcp("example.com:443");
        let mut buf = Vec::new();
        open.encode(&mut buf);
        let decoded = Open::read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(decoded, open);
        assert_eq!(Open::decode(&buf).unwrap(), open);
        assert!(Open::decode(&buf[..buf.len() - 1]).is_err());
        buf.push(0);
        assert!(Open::decode(&buf).is_err());
    }

    #[tokio::test]
    async fn udp_open_roundtrip() {
        let open = Open::udp("[2001:db8::1]:53", None);
        let mut buf = Vec::new();
        open.encode(&mut buf);
        assert_eq!(buf[0], KIND_UDP);
        assert_eq!(Open::decode(&buf).unwrap(), open);
        buf[0] = 9;
        assert!(Open::decode(&buf).is_err());
    }

    #[tokio::test]
    async fn speedtest_open_roundtrip() {
        let open = Open::speedtest("down");
        let mut buf = Vec::new();
        open.encode(&mut buf);
        assert_eq!(buf[0], KIND_SPEEDTEST);
        assert_eq!(Open::decode(&buf).unwrap(), open);
        assert_eq!(Open::read(&mut &buf[..]).await.unwrap(), open);
    }

    #[tokio::test]
    async fn probe_open_roundtrip() {
        for target in ["127.0.0.1:443", ""] {
            let open = Open::probe(target);
            let mut buf = Vec::new();
            open.encode(&mut buf);
            assert_eq!(buf[0], KIND_PROBE);
            assert_eq!(Open::decode(&buf).unwrap(), open);
            assert_eq!(Open::read(&mut &buf[..]).await.unwrap(), open);
        }
    }

    fn proxied(version: ProxyVersion, source: &str, destination: &str) -> Open {
        let proxy = ProxyHeader {
            version,
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
        };
        Open::tcp_proxied("127.0.0.1:443", proxy)
    }

    #[tokio::test]
    async fn proxied_tcp_open_roundtrip() {
        for (open, family, options) in [
            (
                proxied(ProxyVersion::V1, "198.51.100.7:51234", "203.0.113.1:443"),
                4,
                2 + 12,
            ),
            (
                proxied(
                    ProxyVersion::V2,
                    "[2001:db8::7]:51234",
                    "[2001:db8::1]:8443",
                ),
                6,
                2 + 36,
            ),
        ] {
            let mut buf = Vec::new();
            open.encode(&mut buf);
            assert_eq!(buf[0], KIND_TCP_PROXY);
            let target_end = 3 + open.target.len();
            assert_eq!(buf.len(), target_end + options);
            assert_eq!(buf[target_end + 1], family);
            let decoded = Open::decode(&buf).unwrap();
            assert_eq!((decoded.kind, &decoded), (KIND_TCP, &open));
            assert_eq!(Open::read(&mut &buf[..]).await.unwrap(), open);
            // Cut short, with a byte too many, or of an unknown family or version, it is
            // malformed.
            assert!(Open::decode(&buf[..buf.len() - 1]).is_err());
            assert!(Open::read(&mut &buf[..buf.len() - 1]).await.is_err());
            let mut long = buf.clone();
            long.push(0);
            assert!(Open::decode(&long).is_err());
            for (at, value) in [(target_end + 1, 5), (target_end, 3), (target_end, 0)] {
                let mut bad = buf.clone();
                bad[at] = value;
                assert!(Open::decode(&bad).is_err(), "{at} {value}");
                assert!(Open::read(&mut &bad[..]).await.is_err(), "{at} {value}");
            }
        }
    }

    #[test]
    fn proxied_open_sends_mapped_addresses_as_ipv4() {
        // What a listener on [::] reports for an IPv4 user.
        let open = proxied(
            ProxyVersion::V2,
            "[::ffff:198.51.100.7]:5000",
            "[::ffff:10.0.0.1]:443",
        );
        let mut buf = Vec::new();
        open.encode(&mut buf);
        let proxy = Open::decode(&buf).unwrap().proxy.unwrap();
        assert_eq!(proxy.source, "198.51.100.7:5000".parse().unwrap());
        assert_eq!(proxy.destination, "10.0.0.1:443".parse().unwrap());
    }

    #[test]
    fn plain_tcp_open_has_no_header() {
        let open = Open::tcp("127.0.0.1:443");
        let mut buf = Vec::new();
        open.encode(&mut buf);
        assert_eq!(buf[0], KIND_TCP);
        assert_eq!(Open::decode(&buf).unwrap().proxy, None);
    }

    #[tokio::test]
    async fn duplicated_udp_open_roundtrip() {
        let open = Open::udp(
            "10.0.0.2:27015",
            Some(Duplicate {
                copies: 2,
                gap_ms: 5,
            }),
        );
        let mut buf = Vec::new();
        open.encode(&mut buf);
        assert_eq!(buf[0], KIND_UDP_DUPLICATED);
        assert_eq!(&buf[buf.len() - 2..], [2, 5]);
        let decoded = Open::decode(&buf).unwrap();
        assert_eq!((decoded.kind, &decoded), (KIND_UDP, &open));
        assert_eq!(Open::read(&mut &buf[..]).await.unwrap(), open);
        // Without its options, or with out-of-range ones, it is malformed.
        assert!(Open::decode(&buf[..buf.len() - 2]).is_err());
        for (copies, gap) in [(1, 5), (4, 5), (2, 51)] {
            let n = buf.len();
            let mut bad = buf.clone();
            bad[n - 2..].copy_from_slice(&[copies, gap]);
            assert!(Open::decode(&bad).is_err(), "{copies} {gap}");
        }
    }

    #[tokio::test]
    async fn datagram_framing_keeps_packet_boundaries() {
        let packets: Vec<Vec<u8>> = vec![
            vec![],
            vec![1],
            (0..1400).map(|i| i as u8).collect(),
            vec![7; MAX_DATAGRAM],
        ];
        let mut wire = Vec::new();
        for p in &packets {
            put_datagram(p, &mut wire).unwrap();
        }
        // Delivered in awkward pieces, as a stream would.
        let (r, mut w) = tokio::io::duplex(7);
        let writer = tokio::spawn(async move {
            for chunk in wire.chunks(5) {
                w.write_all(chunk).await.unwrap();
            }
        });
        let mut r = DatagramReader::new(r);
        for p in &packets {
            let got = r.next().await.unwrap().unwrap();
            assert_eq!(&got[..], &p[..]);
        }
        writer.await.unwrap();
        assert!(r.next().await.unwrap().is_none(), "clean end");
    }

    #[tokio::test]
    async fn a_reader_hands_out_what_is_already_buffered() {
        let mut wire = Vec::new();
        for p in [&b"ab"[..], b"", b"cde"] {
            put_datagram(p, &mut wire).unwrap();
        }
        let mut r = DatagramReader::new(&wire[..]);
        assert_eq!(r.try_next().unwrap(), None, "nothing read yet");
        assert_eq!(&r.next().await.unwrap().unwrap()[..], b"ab");
        // One read brought every packet: the rest come without waiting.
        assert_eq!(&r.try_next().unwrap().unwrap()[..], b"");
        assert_eq!(&r.try_next().unwrap().unwrap()[..], b"cde");
        assert_eq!(r.try_next().unwrap(), None);
        assert!(r.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn datagram_framing_limits() {
        let mut out = Vec::new();
        assert!(put_datagram(&vec![0; MAX_DATAGRAM + 1], &mut out).is_err());
        assert!(out.is_empty());
        // A length above the maximum, or a packet cut short, is an error.
        let too_long = (MAX_DATAGRAM as u16 + 1).to_be_bytes();
        assert!(DatagramReader::new(&too_long[..]).next().await.is_err());
        let cut = [0u8, 5, 1, 2];
        assert!(DatagramReader::new(&cut[..]).next().await.is_err());
        let half_header = [0u8];
        assert!(DatagramReader::new(&half_header[..]).next().await.is_err());
    }

    #[tokio::test]
    async fn unsupported_status() {
        let err = read_status(&mut &[STATUS_UNSUPPORTED][..])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
