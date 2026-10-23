//! QUIC endpoints (quinn) and the TLS identity both sides derive from the token.
//!
//! Authentication is mutual TLS 1.3 without certificate files: both sides derive the same
//! Ed25519 key pair from the token, each presents a self-signed certificate for it, and
//! each side accepts exactly that public key from the peer. The TLS handshake signature
//! proves the peer holds the key, so a valid peer is one that knows the token, as for
//! every other transport, with no extra round trip. Certificates travel encrypted in
//! TLS 1.3. Sessions (streams and datagrams over a connection) are in
//! `src/session/quic.rs`.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use socket2::SockRef;
use tokio::time::timeout;
use tracing::debug;

use crate::config::{Congestion, MuxSettings, QuicConfig, Tuning};
use crate::crypto::Psk;
use crate::transport::quic_obfs::{ObfsSocket, OVERHEAD as OBFS_OVERHEAD};

const IDENTITY_CONTEXT: &str = "kariz 2026-10 quic identity v1";
const RESET_KEY_CONTEXT: &str = "kariz 2026-10 quic stateless reset v1";
const CID_KEY_CONTEXT: &str = "kariz 2026-10 quic connection id v1";
const OBFS_KEY_CONTEXT: &str = "kariz 2026-10 quic obfs v1";
/// Largest UDP payload quinn probes for by default (Ethernet's MTU under IPv6).
const MAX_UDP_PAYLOAD: u16 = 1452;
/// PKCS#8 v1 wrapping of an Ed25519 seed (RFC 8410): this prefix, then the 32 bytes.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// Name in our self-signed certificates. Never checked (the key is), and never visible
/// on the wire (TLS 1.3 encrypts certificates).
const CERT_NAME: &str = "localhost";
/// Unidirectional streams a peer may have open: only the `GOAWAY` notice uses them.
const MAX_UNI_STREAMS: u32 = 4;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The TLS identity both sides derive from the token.
struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    /// SubjectPublicKeyInfo (DER) of the key: what a peer's certificate must carry.
    spki: Vec<u8>,
}

impl Identity {
    fn from_psk(psk: &Psk) -> io::Result<Self> {
        let seed = psk.subkey(IDENTITY_CONTEXT);
        let mut pkcs8 = ED25519_PKCS8_PREFIX.to_vec();
        pkcs8.extend_from_slice(&seed);
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_slice()).map_err(io::Error::other)?;
        let spki = rcgen::PublicKeyData::subject_public_key_info(&key_pair);
        let cert = rcgen::CertificateParams::new(vec![CERT_NAME.to_owned()])
            .and_then(|params| params.self_signed(&key_pair))
            .map_err(io::Error::other)?;
        Ok(Self {
            cert: cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(pkcs8.into()),
            spki,
        })
    }
}

/// The certificate's key is not the token's.
struct UnknownPeer;

impl std::fmt::Debug for UnknownPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("peer does not know the tunnel token")
    }
}

impl std::fmt::Display for UnknownPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for UnknownPeer {}

/// Accepts exactly the peer whose certificate carries the token's public key, in both
/// directions; handshake signatures are verified as usual.
#[derive(Debug)]
struct TokenPeer {
    spki: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl TokenPeer {
    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let parsed = ParsedCertificate::try_from(cert)?;
        if parsed.subject_public_key_info().as_ref() != self.spki.as_slice() {
            // A certificate error, so the peer gets a `bad_certificate` alert.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(UnknownPeer))),
            ));
        }
        Ok(())
    }
}

impl ServerCertVerifier for TokenPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("QUIC requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for TokenPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("QUIC requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Everything both endpoint kinds need: identity, transport tuning, reset key.
#[derive(Clone)]
pub struct QuicSettings {
    identity: Arc<Identity>,
    /// Accepts the peer holding the same identity.
    peer: Arc<TokenPeer>,
    reset_key: [u8; 32],
    cid_key: u64,
    alpn: Vec<u8>,
    /// Key that seals every UDP packet (`obfs`).
    obfs_key: Option<[u8; 32]>,
    transport: Arc<TransportConfig>,
    handshake_timeout: Duration,
    socket_buffer: usize,
}

impl QuicSettings {
    pub fn new(
        psk: &Psk,
        quic: &QuicConfig,
        mux: &MuxSettings,
        tuning: &Tuning,
    ) -> io::Result<Self> {
        let mut transport = TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(VarInt::from_u32(mux.max_streams as u32))
            .max_concurrent_uni_streams(VarInt::from_u32(MAX_UNI_STREAMS))
            .stream_receive_window(VarInt::from_u32(mux.stream_window as u32))
            // As with kmux, a peer silent for two ping intervals is dead. Pings go out
            // more often than kmux's: UDP NAT mappings often expire after 30 s.
            .keep_alive_interval(Some(mux.ping_interval / 3))
            .max_idle_timeout(Some(
                IdleTimeout::try_from(mux.ping_interval * 2).map_err(io::Error::other)?,
            ))
            .datagram_receive_buffer_size(Some(mux.datagram_buffer))
            .datagram_send_buffer_size(mux.datagram_buffer);
        if quic.obfs {
            // The seal makes every packet longer: what quinn may send is smaller by that
            // much (the first packets, 1200 bytes, stay within any path that carries IPv6).
            let mut mtu = MtuDiscoveryConfig::default();
            mtu.upper_bound(MAX_UDP_PAYLOAD - OBFS_OVERHEAD as u16);
            transport.mtu_discovery_config(Some(mtu));
        }
        match quic.congestion {
            Congestion::Cubic => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            Congestion::Bbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            Congestion::NewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
            Congestion::Fixed => {
                // `bandwidth_mbps` is required with `fixed` (checked in config validation).
                let cfg = crate::transport::quic_fixed::FixedConfig::from_mbps(
                    quic.bandwidth_mbps.unwrap_or(0),
                );
                // The connection's flow-control window must not cap the chosen rate before the
                // controller can: give it two seconds of the rate, within sane bounds. (The
                // peer's advertised stream window still applies, so a high rate on a long path
                // also wants a large `[tunnel.mux]` stream window / the throughput profile.)
                let window = (cfg.bytes_per_sec() * 2.0) as u64;
                let window = window.clamp(10 * 1024 * 1024, 256 * 1024 * 1024);
                transport
                    .congestion_controller_factory(Arc::new(cfg))
                    .send_window(window)
            }
        };
        let identity = Identity::from_psk(psk)?;
        Ok(Self {
            peer: Arc::new(TokenPeer {
                spki: identity.spki.clone(),
                algorithms: provider().signature_verification_algorithms,
            }),
            identity: Arc::new(identity),
            reset_key: psk.subkey(RESET_KEY_CONTEXT),
            cid_key: {
                let key = psk.subkey(CID_KEY_CONTEXT);
                u64::from_le_bytes(key[..8].try_into().expect("8 bytes"))
            },
            alpn: quic.alpn.as_bytes().to_vec(),
            obfs_key: quic.obfs.then(|| psk.subkey(OBFS_KEY_CONTEXT)),
            transport: Arc::new(transport),
            handshake_timeout: tuning.handshake_timeout,
            socket_buffer: tuning.udp.socket_buffer,
        })
    }

    /// A restarted endpoint on the same address tells a peer at once that its old
    /// connection is gone (a stateless reset) instead of leaving it to time out. That
    /// needs the same keys as before the restart, so both are derived from the token:
    /// the reset key, and the key that marks our connection IDs as ours (packets for
    /// connection IDs without the mark are dropped without an answer).
    fn endpoint_config(&self) -> EndpointConfig {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.reset_key);
        let mut config = EndpointConfig::new(Arc::new(key));
        let cid_key = self.cid_key;
        config.cid_generator(move || {
            Box::new(quinn_proto::HashedConnectionIdGenerator::from_key(cid_key))
        });
        config
    }

    fn server_config(&self) -> io::Result<quinn::ServerConfig> {
        let mut tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(self.peer.clone())
            .with_single_cert(
                vec![self.identity.cert.clone()],
                self.identity.key.clone_key(),
            )
            .map_err(io::Error::other)?;
        tls.alpn_protocols = vec![self.alpn.clone()];
        let crypto = QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(self.transport.clone());
        Ok(config)
    }

    fn client_config(&self) -> io::Result<quinn::ClientConfig> {
        let mut tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(self.peer.clone())
            .with_client_auth_cert(
                vec![self.identity.cert.clone()],
                self.identity.key.clone_key(),
            )
            .map_err(io::Error::other)?;
        tls.alpn_protocols = vec![self.alpn.clone()];
        let crypto = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(self.transport.clone());
        Ok(config)
    }

    fn endpoint(
        &self,
        addr: SocketAddr,
        server: Option<quinn::ServerConfig>,
    ) -> io::Result<Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let sock = SockRef::from(&socket);
        if let Err(e) = sock
            .set_recv_buffer_size(self.socket_buffer)
            .and_then(|_| sock.set_send_buffer_size(self.socket_buffer))
        {
            debug!(error = %e, "could not set QUIC socket buffers");
        }
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("QUIC needs a tokio runtime"))?;
        let Some(key) = &self.obfs_key else {
            return Endpoint::new(self.endpoint_config(), server, socket, runtime);
        };
        let socket = ObfsSocket::new(runtime.wrap_udp_socket(socket)?, key)?;
        Endpoint::new_with_abstract_socket(self.endpoint_config(), server, socket, runtime)
    }
}

/// Listening side: accepts QUIC connections from peers that know the token.
pub struct QuicListener {
    endpoint: Endpoint,
    handshake_timeout: Duration,
}

impl QuicListener {
    pub async fn bind(addr: &str, settings: &QuicSettings) -> io::Result<Self> {
        let addr = resolve(addr).await?;
        let endpoint = settings.endpoint(addr, Some(settings.server_config()?))?;
        Ok(Self {
            endpoint,
            handshake_timeout: settings.handshake_timeout,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// The next connection attempt; `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Accepting> {
        let incoming = self.endpoint.accept().await?;
        Some(Accepting {
            incoming,
            handshake_timeout: self.handshake_timeout,
        })
    }
}

/// A connection attempt whose handshake is still to be completed (in its own task).
pub struct Accepting {
    incoming: quinn::Incoming,
    handshake_timeout: Duration,
}

impl Accepting {
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }

    /// Completes the handshake; fails for peers without the token.
    pub async fn establish(self) -> io::Result<Connection> {
        let connecting = self.incoming.accept().map_err(io::Error::other)?;
        timeout(self.handshake_timeout, connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
            .map_err(connection_error)
    }
}

/// Dialing side: connects to `remote` (resolved on every attempt).
pub struct QuicDialer {
    remote: String,
    server_name: String,
    config: quinn::ClientConfig,
    settings: QuicSettings,
    /// One endpoint (UDP socket) per address family, made on first use.
    endpoints: Mutex<(Option<Endpoint>, Option<Endpoint>)>,
}

impl QuicDialer {
    pub fn new(remote: &str, sni: Option<&str>, settings: &QuicSettings) -> io::Result<Self> {
        let host = super::ws::upgrade::split_port(remote).0;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        Ok(Self {
            remote: remote.to_owned(),
            server_name: sni.unwrap_or(host).to_owned(),
            config: settings.client_config()?,
            settings: settings.clone(),
            endpoints: Mutex::new((None, None)),
        })
    }

    fn endpoint_for(&self, peer: SocketAddr) -> io::Result<Endpoint> {
        let mut endpoints = self.endpoints.lock().unwrap_or_else(|e| e.into_inner());
        let (slot, any): (&mut Option<Endpoint>, SocketAddr) = if peer.is_ipv4() {
            (&mut endpoints.0, (Ipv4Addr::UNSPECIFIED, 0).into())
        } else {
            (&mut endpoints.1, (Ipv6Addr::UNSPECIFIED, 0).into())
        };
        if let Some(e) = slot {
            return Ok(e.clone());
        }
        let endpoint = self.settings.endpoint(any, None)?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Connects and completes the handshake (bounded by the handshake timeout).
    pub async fn connect(&self) -> io::Result<Connection> {
        let peer = resolve(&self.remote).await?;
        let endpoint = self.endpoint_for(peer)?;
        let connecting = endpoint
            .connect_with(self.config.clone(), peer, &self.server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        timeout(self.settings.handshake_timeout, connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
            .map_err(connection_error)
    }
}

async fn resolve(addr: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{addr} has no address")))
}

/// Handshake failures because of the peer's identity read as authentication errors.
fn connection_error(e: quinn::ConnectionError) -> io::Error {
    let kind = match &e {
        quinn::ConnectionError::TransportError(_) | quinn::ConnectionError::ConnectionClosed(_) => {
            io::ErrorKind::PermissionDenied
        }
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::ConnectionAborted,
    };
    io::Error::new(kind, e)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Profile;

    pub(crate) fn settings(token: &str, quic: &QuicConfig) -> QuicSettings {
        let mux = MuxSettings {
            enabled: true,
            connections: 1,
            max_streams: 64,
            stream_window: 256 * 1024,
            max_lifetime: None,
            coalesce: true,
            ping_interval: Duration::from_secs(30),
            datagram_buffer: 256 * 1024,
            datagram_queue: 128,
            notsent_lowat: None,
        };
        let mut tuning = Tuning::for_profile(Profile::Balanced);
        tuning.handshake_timeout = Duration::from_secs(3);
        QuicSettings::new(&Psk::new(token), quic, &mux, &tuning).unwrap()
    }

    const TOKEN: &str = "0123456789abcdef0123";

    /// Connects a dialer with `client` settings to a listener with `server` settings;
    /// the dialer's and the listener's results.
    async fn handshake(
        client: &QuicSettings,
        server: &QuicSettings,
    ) -> (io::Result<Connection>, io::Result<Connection>) {
        let listener = QuicListener::bind("127.0.0.1:0", server).await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dialer = QuicDialer::new(&addr, None, client).unwrap();
        let accepted = async { listener.accept().await.unwrap().establish().await };
        tokio::join!(dialer.connect(), accepted)
    }

    /// Two connected ends (dialer, listener) for the same token.
    pub(crate) async fn pair(quic: &QuicConfig) -> (Connection, Connection) {
        let s = settings(TOKEN, quic);
        let (a, b) = handshake(&s, &s).await;
        (a.unwrap(), b.unwrap())
    }

    #[test]
    fn identity_follows_the_token() {
        let a = Identity::from_psk(&Psk::new(TOKEN)).unwrap();
        let b = Identity::from_psk(&Psk::new(TOKEN)).unwrap();
        let c = Identity::from_psk(&Psk::new("another token, also long")).unwrap();
        assert_eq!(a.spki, b.spki);
        assert_ne!(a.spki, c.spki);
        // The certificate carries the derived key, and the verifier accepts only it.
        let peer = settings(TOKEN, &QuicConfig::default()).peer;
        assert!(peer.check(&a.cert).is_ok());
        assert!(peer.check(&c.cert).is_err());
    }

    #[tokio::test]
    async fn same_token_connects() {
        let (client, server) = pair(&QuicConfig::default()).await;
        let alpn = |c: &Connection| {
            c.handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol)
        };
        assert_eq!(alpn(&client).as_deref(), Some(&b"h3"[..]));
        assert_eq!(alpn(&server).as_deref(), Some(&b"h3"[..]));
        // Both sides authenticated each other: the client presented a certificate too.
        assert!(server.peer_identity().is_some());
        assert!(client.peer_identity().is_some());
    }

    #[tokio::test]
    async fn wrong_token_is_rejected_both_ways() {
        let good = settings(TOKEN, &QuicConfig::default());
        let bad = settings("another token, also long", &QuicConfig::default());
        // The client checks the server's certificate first, so these two fail there.
        for (client, server) in [(&bad, &good), (&good, &bad)] {
            let (c, s) = handshake(client, server).await;
            let (c, s) = (c.unwrap_err(), s.unwrap_err());
            assert_eq!(c.kind(), io::ErrorKind::PermissionDenied, "{c}");
            assert_eq!(s.kind(), io::ErrorKind::PermissionDenied, "{s}");
            assert!(c.to_string().contains("tunnel token"), "{c}");
        }
        // A client that accepts the server but presents another key: the server's
        // check of client certificates rejects it.
        let impostor = QuicSettings {
            identity: bad.identity.clone(),
            ..good.clone()
        };
        let (c, s) = handshake(&impostor, &good).await;
        let s = s.unwrap_err();
        assert_eq!(s.kind(), io::ErrorKind::PermissionDenied, "{s}");
        assert!(s.to_string().contains("tunnel token"), "{s}");
        // TLS 1.3 clients finish before the server checks them, so the client learns of
        // it from the server's alert, at once or on first use.
        if let Ok(conn) = c {
            let err = conn.closed().await;
            assert!(err.to_string().contains("certificate"), "{err}");
        }
    }

    fn obfs() -> QuicConfig {
        QuicConfig {
            obfs: true,
            ..QuicConfig::default()
        }
    }

    #[tokio::test]
    async fn obfs_connects_and_carries_data() {
        let (client, server) = pair(&obfs()).await;
        let (mut send, _) = client.open_bi().await.unwrap();
        // Many packets, so batches and the smaller MTU are exercised (within the stream window,
        // as nothing reads before the write is done).
        let data = vec![0x5a; 200_000];
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        let (_, mut recv) = server.accept_bi().await.unwrap();
        assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), data);
        // The seal fits in the largest packet quinn may use.
        assert!(client.max_datagram_size().unwrap() < 1452 - OBFS_OVERHEAD);
    }

    #[tokio::test]
    async fn obfs_must_be_on_at_both_ends() {
        async fn dial_fails(client: &QuicSettings, server: &QuicSettings) {
            let listener = QuicListener::bind("127.0.0.1:0", server).await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let dialer = QuicDialer::new(&addr, None, client).unwrap();
            let (dialed, accepted) = tokio::join!(
                dialer.connect(),
                timeout(Duration::from_millis(1500), listener.accept())
            );
            assert_eq!(dialed.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert!(accepted.is_err(), "the listener took a connection");
        }
        let plain = settings(TOKEN, &QuicConfig::default());
        let sealed = settings(TOKEN, &obfs());
        tokio::join!(dial_fails(&plain, &sealed), dial_fails(&sealed, &plain));
    }

    #[tokio::test]
    async fn obfs_hides_quic_on_the_wire() {
        // A plain socket stands in for the peer and sees what the dialer sends.
        let wire = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = wire.local_addr().unwrap().to_string();
        let dialer = QuicDialer::new(&addr, None, &settings(TOKEN, &obfs())).unwrap();
        let dialing = tokio::spawn(async move { dialer.connect().await });
        let mut packet = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(2), wire.recv_from(&mut packet))
            .await
            .expect("nothing sent")
            .unwrap();
        // A QUIC Initial is at least 1200 bytes; sealed, it carries the seal on top.
        assert!(len >= 1200 + OBFS_OVERHEAD, "{len}");
        // Not QUIC to look at: no version 1 in the header.
        assert_ne!(packet[1..5], [0, 0, 0, 1]);
        // With the token's key it opens, and is one.
        let key = ring::aead::UnboundKey::new(
            &ring::aead::CHACHA20_POLY1305,
            &Psk::new(TOKEN).subkey(OBFS_KEY_CONTEXT),
        )
        .unwrap();
        let key = ring::aead::LessSafeKey::new(key);
        let (nonce, sealed) = packet[..len].split_at_mut(ring::aead::NONCE_LEN);
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).unwrap();
        let plain = key
            .open_in_place(nonce, ring::aead::Aad::empty(), sealed)
            .unwrap();
        assert!(plain[0] & 0x80 != 0, "not a long header");
        assert_eq!(plain[1..5], [0, 0, 0, 1], "not QUIC version 1");
        dialing.abort();
    }

    #[tokio::test]
    async fn a_restarted_listener_resets_old_connections() {
        let s = settings(TOKEN, &QuicConfig::default());
        // The old listener runs on a runtime of its own, so it can "die" without a word
        // (nothing is sent when a runtime is shut down), as a killed process does.
        let old = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = s.clone();
        old.spawn(async move {
            let listener = QuicListener::bind("127.0.0.1:0", &server).await.unwrap();
            let _ = tx.send(listener.local_addr().unwrap());
            let _conn = listener.accept().await.unwrap().establish().await;
            std::future::pending::<()>().await;
        });
        let addr = rx.await.unwrap().to_string();
        let client = QuicDialer::new(&addr, None, &s)
            .unwrap()
            .connect()
            .await
            .unwrap();
        old.shutdown_background();

        // A new listener with the same token takes the port: the client's next packet is
        // answered by a stateless reset, long before the idle timeout.
        let mut restarted = None;
        for _ in 0..100 {
            match QuicListener::bind(&addr, &s).await {
                Ok(l) => {
                    restarted = Some(l);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
                Err(e) => panic!("{e}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _restarted = restarted.expect("port still taken");
        let (mut send, _) = client.open_bi().await.unwrap();
        send.write_all(b"anyone?").await.unwrap();
        let err = timeout(Duration::from_secs(2), client.closed())
            .await
            .expect("no stateless reset");
        assert!(matches!(err, quinn::ConnectionError::Reset), "{err}");
    }

    #[tokio::test]
    async fn every_congestion_controller_connects() {
        for congestion in [
            Congestion::Cubic,
            Congestion::Bbr,
            Congestion::NewReno,
            Congestion::Fixed,
        ] {
            let quic = QuicConfig {
                congestion,
                bandwidth_mbps: (congestion == Congestion::Fixed).then_some(50),
                ..QuicConfig::default()
            };
            let (client, server) = pair(&quic).await;
            let (mut send, _) = client.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            let (_, mut recv) = server.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(16).await.unwrap(), b"ping");
        }
    }
}
