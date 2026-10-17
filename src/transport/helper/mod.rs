//! Managed external-helper transports: `naive`, `xhttp` and `reality`.
//!
//! Unlike the other transports, these do not implement a byte stream directly. The
//! **acceptor** runs a helper *server* (sing-box naive inbound, or Xray) on the public
//! tunnel address ([`Settings`] `addr`) and forwards authenticated traffic to a
//! Kariz-owned internal loopback listener; the **dialer** runs the helper *client*,
//! exposing a local SOCKS5 inbound ([`socks`]) that Kariz dials its tunnel connections
//! through. Inside the resulting stream Kariz still runs its own handshake, record
//! encryption and mux (both forced on, see `validate_helper`), so the proxies' half-close
//! semantics do not matter.
//!
//! The internal loopback target is derived from the token and the public port, so both
//! ends agree on it without extra configuration, and concurrent tunnels do not collide.
//! The helper server's routing only reaches that target; the dialer's SOCKS inbound only
//! routes to it.

#[cfg(feature = "helpers")]
pub mod install;
#[cfg(all(feature = "helpers", unix))]
mod render;
#[cfg(all(feature = "helpers", unix))]
mod socks;
#[cfg(all(feature = "helpers", unix))]
mod supervisor;

use std::io;

use crate::config::TransportKind;

#[cfg(feature = "helpers")]
use crate::config::HelperConfig;

/// The error returned for a helper transport that is not available on this build/platform.
pub fn unsupported(kind: TransportKind) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "transport \"{}\" is not available on this build",
            kind.name()
        ),
    )
}

/// The token-derived settings a helper transport needs besides the public address. Carried
/// in [`Settings::helper`](super::Settings::helper).
#[cfg(feature = "helpers")]
#[derive(Debug, Clone)]
pub struct HelperParams {
    pub config: HelperConfig,
    /// The tunnel token; the internal loopback target derives from it and the public port.
    pub token: String,
}

/// The loopback target the helper server forwards to and the dialer's SOCKS inbound reaches.
/// Derived from the token and the public port so both ends agree, in a range above the test
/// harness's ports.
#[cfg(all(feature = "helpers", unix))]
fn internal_target(token: &str, public_port: u16) -> std::net::SocketAddr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kariz 2026-10 helper internal v1");
    hasher.update(token.as_bytes());
    hasher.update(&public_port.to_be_bytes());
    let bytes = hasher.finalize();
    let n = u16::from_le_bytes([bytes.as_bytes()[0], bytes.as_bytes()[1]]);
    let port = 40000 + (n % 20000);
    std::net::SocketAddr::from(([127, 0, 0, 1], port))
}

/// The port of a `host:port` address (handling `[v6]:port`); 0 if it cannot be parsed.
#[cfg(all(feature = "helpers", unix))]
fn port_of(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// The host part of a `host:port` address, with any `[]` stripped.
#[cfg(all(feature = "helpers", unix))]
fn host_of(addr: &str) -> &str {
    let host = match addr.rfind(':') {
        Some(i) => &addr[..i],
        None => addr,
    };
    host.trim_start_matches('[').trim_end_matches(']')
}

#[cfg(all(feature = "helpers", unix))]
pub use real::{HelperDialer, HelperListener};

#[cfg(all(feature = "helpers", unix))]
mod real {
    use std::fs;
    use std::io;
    use std::net::SocketAddr;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    use super::supervisor::{Spawn, Supervisor};
    use super::{host_of, install, internal_target, port_of, render, socks, unsupported};
    use crate::config::{HelperConfig, TransportKind, Tuning};
    use crate::transport::{Settings, TunnelStream};

    /// Supervises the helper *server* and accepts tunnel connections from it over the
    /// Kariz-owned internal loopback listener.
    pub struct HelperListener {
        internal: TcpListener,
        _supervisor: Supervisor,
    }

    /// Supervises the helper *client* and dials tunnel connections through its local SOCKS5
    /// inbound.
    pub struct HelperDialer {
        socks: SocketAddr,
        internal: SocketAddr,
        timeout: Duration,
        _supervisor: Supervisor,
    }

    impl HelperListener {
        pub async fn bind(settings: &Settings, addr: &str, _tuning: &Tuning) -> io::Result<Self> {
            let params = params(settings)?;
            let h = &params.config;
            let public = resolve_addr(addr).await?;
            let internal = internal_target(&params.token, public.port());

            // Kariz's own loopback listener, bound before the helper starts.
            let internal_listener = TcpListener::bind(internal).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("could not bind the helper's internal listener {internal}: {e}"),
                )
            })?;

            let dir = config_dir()?;
            let (name, config_text) = match settings.kind {
                TransportKind::Naive => {
                    let cert = abs(h.certificate.as_deref(), "certificate")?;
                    let key = abs(h.key.as_deref(), "key")?;
                    let text = render::singbox_naive_server(
                        &public,
                        h.username.as_deref().unwrap_or_default(),
                        h.password.as_deref().unwrap_or_default(),
                        &cert,
                        &key,
                        &internal,
                    );
                    ("sing-box", text)
                }
                TransportKind::Xhttp => {
                    let cert = abs(h.certificate.as_deref(), "certificate")?;
                    let key = abs(h.key.as_deref(), "key")?;
                    let text = render::xray_server(false, &public, h, &cert, &key, &internal);
                    ("xray", text)
                }
                TransportKind::Reality => (
                    "xray",
                    render::xray_server(true, &public, h, "", "", &internal),
                ),
                kind => return Err(unsupported(kind)),
            };

            let config_path = write_config(&dir, "helper.json", &config_text)?;
            let spawn = Spawn {
                program: binary(h, name)?,
                args: run_args(name, &config_path),
                envs: Vec::new(),
                dir,
            };
            let supervisor = Supervisor::start(spawn);

            // Best effort: give the public listener a moment, so early dials are not wasted.
            wait_ready(public.port(), Duration::from_secs(3)).await;

            Ok(Self {
                internal: internal_listener,
                _supervisor: supervisor,
            })
        }

        pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
            self.internal.accept().await
        }

        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.internal.local_addr()
        }
    }

    impl HelperDialer {
        pub fn new(settings: &Settings, addr: &str, tuning: &Tuning) -> io::Result<Self> {
            let params = params(settings)?;
            let h = &params.config;
            let internal = internal_target(&params.token, port_of(addr));
            let socks = free_loopback_port()?;
            let server_host = host_of(addr).to_string();
            let server_port = port_of(addr);

            let dir = config_dir()?;
            let mut envs = Vec::new();
            let (name, config_text) = match settings.kind {
                TransportKind::Naive => {
                    let tls_name = h
                        .server_name
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(&server_host)
                        .to_string();
                    let user = h.username.as_deref().unwrap_or_default();
                    let pass = h.password.as_deref().unwrap_or_default();
                    let proxy = format!("https://{user}:{pass}@{tls_name}:{server_port}");
                    // Map the TLS name to the dialed IP when they differ and the dial
                    // target is a literal address.
                    let resolver = (tls_name != server_host
                        && server_host.parse::<std::net::IpAddr>().is_ok())
                    .then(|| format!("MAP {tls_name} {server_host}"));
                    if let Some(ca) = h.ca_file.as_deref() {
                        envs.push(("SSL_CERT_FILE".to_string(), abs(Some(ca), "ca_file")?));
                    }
                    let text = render::naive_client(&socks, &proxy, resolver.as_deref());
                    ("naive", text)
                }
                TransportKind::Xhttp => {
                    let ca = match h.ca_file.as_deref() {
                        Some(ca) => Some(abs(Some(ca), "ca_file")?),
                        None => None,
                    };
                    let text = render::xray_client(
                        false,
                        &socks,
                        &server_host,
                        server_port,
                        h,
                        ca.as_deref(),
                        &internal,
                    );
                    ("xray", text)
                }
                TransportKind::Reality => (
                    "xray",
                    render::xray_client(
                        true,
                        &socks,
                        &server_host,
                        server_port,
                        h,
                        None,
                        &internal,
                    ),
                ),
                kind => return Err(unsupported(kind)),
            };

            let config_path = write_config(&dir, "helper.json", &config_text)?;
            let spawn = Spawn {
                program: binary(h, name)?,
                args: run_args(name, &config_path),
                envs,
                dir,
            };
            let supervisor = Supervisor::start(spawn);
            Ok(Self {
                socks,
                internal,
                timeout: tuning.dial_timeout.max(Duration::from_secs(5)),
                _supervisor: supervisor,
            })
        }

        /// Dials a tunnel connection through the helper, writing `first` once the stream is
        /// up. Retries connecting to the local SOCKS inbound until it is ready or the dial
        /// timeout passes, so a just-started or just-restarted helper is tolerated.
        pub async fn dial_with(&self, first: &[u8]) -> io::Result<TunnelStream> {
            let deadline = Instant::now() + self.timeout;
            loop {
                match socks::connect(self.socks, self.internal).await {
                    Ok(mut stream) => {
                        if !first.is_empty() {
                            stream.write_all(first).await?;
                            stream.flush().await?;
                        }
                        return Ok(TunnelStream::Tcp(stream));
                    }
                    Err(e) => {
                        if Instant::now() >= deadline {
                            return Err(e);
                        }
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    fn params(settings: &Settings) -> io::Result<&super::HelperParams> {
        settings.helper.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a helper transport needs its [tunnel.helper] settings",
            )
        })
    }

    /// The helper binary: the configured override, else the installed pinned path.
    fn binary(h: &HelperConfig, name: &str) -> io::Result<PathBuf> {
        if let Some(path) = h.binary.as_deref() {
            return Ok(path.to_path_buf());
        }
        install::installed_binary(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("helper {name} is not installed; run `kariz helper install {name}`"),
            )
        })
    }

    /// The command-line arguments to run a helper with its config file. Keyed on the
    /// binary, not the transport: the naive acceptor runs sing-box (`run -c`), its dialer
    /// runs NaiveProxy (a bare config argument), and xhttp/reality run Xray (`run -c`).
    fn run_args(name: &str, config: &Path) -> Vec<String> {
        let path = config.to_string_lossy().into_owned();
        match name {
            "naive" => vec![path],
            _ => vec!["run".into(), "-c".into(), path],
        }
    }

    fn abs(path: Option<&Path>, what: &str) -> io::Result<String> {
        let path = path.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing tunnel.helper.{what}"),
            )
        })?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// An owner-only (0700) temporary directory for a helper's generated configuration.
    fn config_dir() -> io::Result<PathBuf> {
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).map_err(|e| io::Error::other(e.to_string()))?;
        let suffix: String = rand.iter().map(|b| format!("{b:02x}")).collect();
        let dir =
            std::env::temp_dir().join(format!("kariz-helper-{}-{suffix}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)?;
        Ok(dir)
    }

    /// Writes a 0600 config file in `dir` and returns its path.
    fn write_config(dir: &Path, name: &str, text: &str) -> io::Result<PathBuf> {
        let path = dir.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        std::io::Write::write_all(&mut file, text.as_bytes())?;
        Ok(path)
    }

    /// A free loopback TCP port, for the dialer's local SOCKS inbound.
    fn free_loopback_port() -> io::Result<SocketAddr> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()
    }

    /// Resolves the public address to a single socket address for the server config.
    async fn resolve_addr(addr: &str) -> io::Result<SocketAddr> {
        if let Ok(parsed) = addr.parse::<SocketAddr>() {
            return Ok(parsed);
        }
        tokio::net::lookup_host(addr).await?.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no address for {addr}"),
            )
        })
    }

    /// Waits until something accepts on loopback `port`, up to `budget`.
    async fn wait_ready(port: u16, budget: Duration) {
        let probe = SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if TcpStream::connect(probe).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}
