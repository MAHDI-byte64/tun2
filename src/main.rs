use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use kariz::config::{mode_name, role_name, Config, Dscp, Encryption, TransportKind};
use kariz::crypto::Cipher;
use kariz::speedtest::Options;

mod logging;
// Shown only by `kariz speedtest` and `kariz status`, which are Unix only (their tests
// run everywhere).
#[cfg_attr(not(unix), allow(dead_code))]
mod report;
#[cfg_attr(not(unix), allow(dead_code))]
mod status_view;

/// musl's allocator is built for size, not speed; mimalloc is much faster on the
/// many small allocations of the packet path.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "kariz", version, about = "High-performance tunnel core")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one side of the tunnel.
    Run {
        #[arg(short, long, default_value = "/etc/kariz/config.toml")]
        config: PathBuf,
    },
    /// Validate a config file and print a summary.
    Check {
        /// The config file, or `-` to read it from standard input.
        #[arg(short, long, default_value = "/etc/kariz/config.toml")]
        config: PathBuf,
        /// Print one JSON document instead: the settings, or the error and where it is.
        #[arg(long)]
        json: bool,
    },
    /// Show a running tunnel: whether the other side is connected, the round-trip time,
    /// the last error, and the traffic of each forwarded port. Works on either side.
    Status {
        #[arg(short, long, default_value = "/etc/kariz/config.toml")]
        config: PathBuf,
        /// Redraw every second until Ctrl+C.
        #[arg(long)]
        watch: bool,
        /// Print the daemon's status document (JSON) as is.
        #[arg(long)]
        json: bool,
    },
    /// Generate a random token for `tunnel.token`.
    Token,
    /// Print the `tunnel.tls.pin_sha256` value of a certificate (PEM file), for dialing
    /// a `wss` server with a self-signed certificate.
    Pin {
        /// The certificate file (`tunnel.tls.cert` of the listening side).
        cert: PathBuf,
    },
    /// Measure a running tunnel's speed and latency, through its own sessions. Run it
    /// on the entry side, in either mode, while the tunnel is up.
    Speedtest {
        #[arg(short, long, default_value = "/etc/kariz/config.toml")]
        config: PathBuf,
        /// Seconds each of the download and upload phases lasts (1-60).
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Parallel streams in those phases (1-16).
        #[arg(long, default_value_t = 4)]
        streams: usize,
        /// Skip the UDP test.
        #[arg(long)]
        no_udp: bool,
    },
    /// Install and inspect the pinned managed-helper binaries (sing-box / NaiveProxy /
    /// Xray), and the key utilities the helper transports need.
    #[cfg(feature = "helpers")]
    Helper {
        #[command(subcommand)]
        command: HelperCommand,
    },
    /// Find which forged source addresses survive the path to another server, for the
    /// `spoof` transport's pool. Run `receiver` on the destination server and `sender` on
    /// the source server (Linux, root). See `kariz spooftest --help`.
    #[cfg(feature = "rawlink")]
    Spooftest {
        #[command(subcommand)]
        command: SpooftestCommand,
    },
}

/// Subcommands of `kariz spooftest`.
#[cfg(feature = "rawlink")]
#[derive(Subcommand)]
enum SpooftestCommand {
    /// Receive and tally probes on the destination server; prints which source addresses
    /// got through. Start it just before the sender.
    Receiver {
        /// Address to receive on (`ip:port`); the port is used by the udp/tcp shapes.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,
        /// Packet shape to expect: udp, tcp, icmp, gre, ipip or proto58.
        #[arg(long, default_value = "udp")]
        shape: String,
        /// Seconds to capture (1-120).
        #[arg(long, default_value_t = 10)]
        seconds: u16,
        /// Run id to accept (must match the sender).
        #[arg(long, default_value_t = 1)]
        run_id: u32,
        /// Probes the sender emits per source (for scoring pass/fail).
        #[arg(long, default_value_t = 20)]
        expect: u16,
        /// Acceptable loss as a percentage; a source passes at `100 - loss`% arrival.
        #[arg(long, default_value_t = 20)]
        loss: u8,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Send probes from forged source addresses to the receiver's real address.
    Sender {
        /// The receiver's real address (`ip:port`).
        #[arg(long)]
        to: String,
        /// Packet shape to probe with: udp, tcp, icmp, gre, ipip or proto58.
        #[arg(long, default_value = "udp")]
        shape: String,
        /// Source addresses to forge: IPs, CIDR blocks or `a.b.c.d-e.f.g.h` ranges
        /// (repeatable or comma-separated).
        #[arg(long = "source", value_delimiter = ',', required = true)]
        sources: Vec<String>,
        /// Probes to send per source.
        #[arg(long, default_value_t = 20)]
        count: u16,
        /// Delay between probes, in milliseconds.
        #[arg(long, default_value_t = 5)]
        interval: u16,
        /// Run id (must match the receiver).
        #[arg(long, default_value_t = 1)]
        run_id: u32,
        /// Print the summary as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Subcommands of `kariz helper`.
#[cfg(feature = "helpers")]
#[derive(Subcommand)]
enum HelperCommand {
    /// Download, verify and unpack a pinned helper. Never overwrites an existing version.
    Install {
        /// The helper to install: `sing-box`, `naive` or `xray`.
        name: String,
        /// Install this local archive instead of downloading (still sha256-checked).
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// List the installed pinned helpers.
    Status,
    /// Generate a random UUID for `tunnel.helper.uuid`.
    Uuid,
    /// Generate a REALITY X25519 key pair with the installed `xray x25519`.
    RealityKeys,
}

fn main() -> Result<()> {
    kariz::allocator::tune();
    match Cli::parse().command {
        Command::Run { config } => run(Config::load(&config)?),
        Command::Check { config, json } => check(&config, json),
        Command::Status {
            config,
            watch,
            json,
        } => status(&config, watch, json),
        Command::Token => {
            let mut bytes = [0u8; 24];
            getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            Ok(())
        }
        Command::Pin { cert } => {
            println!("{}", kariz::transport::tls::pin_of_file(&cert)?);
            Ok(())
        }
        Command::Speedtest {
            config,
            seconds,
            streams,
            no_udp,
        } => {
            let options = Options {
                seconds,
                streams,
                udp: !no_udp,
            };
            speedtest(&Config::load(&config)?, options)
        }
        #[cfg(feature = "helpers")]
        Command::Helper { command } => helper(command),
        #[cfg(feature = "rawlink")]
        Command::Spooftest { command } => spooftest(command),
    }
}

/// `kariz spooftest <receiver|sender>`: probe which forged source addresses get through.
#[cfg(feature = "rawlink")]
fn spooftest(command: SpooftestCommand) -> Result<()> {
    use kariz::config::SpoofShape;
    use kariz::spooftest::{self, ReceiverOptions, SenderOptions};

    fn parse_shape(s: &str) -> Result<SpoofShape> {
        toml::from_str::<ShapeHolder>(&format!("shape = \"{s}\"\n"))
            .map(|h| h.shape)
            .map_err(|_| {
                anyhow::anyhow!("unknown shape {s:?}: use udp, tcp, icmp, gre, ipip or proto58")
            })
    }
    #[derive(serde::Deserialize)]
    struct ShapeHolder {
        shape: SpoofShape,
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        match command {
            SpooftestCommand::Receiver {
                bind,
                shape,
                seconds,
                run_id,
                expect,
                loss,
                json,
            } => {
                let opts = ReceiverOptions {
                    bind,
                    shape: parse_shape(&shape)?,
                    seconds: seconds.clamp(1, 120),
                    run_id,
                    expect,
                    loss_pct: loss.min(100),
                    interface: String::new(),
                };
                let report = spooftest::receiver(opts)
                    .await
                    .context("spoof test receiver failed")?;
                if json {
                    println!("{}", serde_json::to_string(&report)?);
                } else {
                    println!(
                        "spoof test ({}): {} of {} source(s) usable (>= {}% arrival)",
                        report.shape,
                        report.usable,
                        report.seen,
                        100u8.saturating_sub(report.loss_pct)
                    );
                    for r in &report.results {
                        println!(
                            "  {:<15} {:>3}/{:<3} {}",
                            r.ip,
                            r.received,
                            report.expect,
                            if r.ok { "ok" } else { "--" }
                        );
                    }
                    if report.seen == 0 {
                        println!("  (no probes arrived; the path may drop forged sources, or the sender did not run)");
                    }
                }
                Ok(())
            }
            SpooftestCommand::Sender {
                to,
                shape,
                sources,
                count,
                interval,
                run_id,
                json,
            } => {
                let opts = SenderOptions {
                    to,
                    shape: parse_shape(&shape)?,
                    sources,
                    count,
                    interval_ms: interval,
                    run_id,
                    interface: String::new(),
                };
                let report = spooftest::sender(opts)
                    .await
                    .context("spoof test sender failed")?;
                if json {
                    println!("{}", serde_json::to_string(&report)?);
                } else {
                    println!(
                        "spoof test sender ({}): sent {} probe(s) across {} source(s), run {}",
                        report.shape, report.sent, report.sources, report.run_id
                    );
                }
                Ok(())
            }
        }
    })
}

/// `kariz helper <install|status|uuid|reality-keys>`.
#[cfg(feature = "helpers")]
fn helper(command: HelperCommand) -> Result<()> {
    use kariz::transport::helper::install;
    match command {
        HelperCommand::Install { name, from } => {
            let path = install::install(&name, from.as_deref())?;
            println!("installed {name} at {}", path.display());
            Ok(())
        }
        HelperCommand::Status => {
            let installed = install::status();
            if installed.is_empty() {
                println!(
                    "no helpers installed under {}",
                    install::helper_dir().display()
                );
            } else {
                for (name, version) in installed {
                    println!("{name}\t{version}");
                }
            }
            Ok(())
        }
        HelperCommand::Uuid => {
            println!("{}", install::gen_uuid()?);
            Ok(())
        }
        HelperCommand::RealityKeys => {
            let (private, public) = install::reality_keys()?;
            println!("private_key = \"{private}\"");
            println!("public_key  = \"{public}\"");
            Ok(())
        }
    }
}

/// `kariz check`: validates a config (a file, or standard input for `-`) and prints its
/// summary, or with `json` one document for tools (the web panel).
fn check(path: &Path, json: bool) -> Result<()> {
    let name = if path == Path::new("-") {
        "standard input".to_string()
    } else {
        path.display().to_string()
    };
    let text = if path == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("failed to read standard input")
    } else {
        std::fs::read_to_string(path).with_context(|| format!("failed to read config file {name}"))
    };
    if !json {
        let text = text?;
        let config = Config::parse(&text).with_context(|| format!("invalid config file {name}"))?;
        print_summary(&config);
        return Ok(());
    }
    let doc = match text {
        Err(e) => check_error(&e, None),
        Ok(text) => match Config::parse(&text) {
            Ok(config) => check_ok(&config),
            Err(e) => check_error(&e, Some(&text)),
        },
    };
    println!("{doc}");
    if doc["ok"] == false {
        std::process::exit(1);
    }
    Ok(())
}

/// `kariz check --json` for a valid config.
fn check_ok(config: &Config) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "role": role_name(config.role),
        "mode": mode_name(config.mode),
        "profile": config.profile.name(),
        "transport": config.tunnel.transport.name(),
        "recv_transport": config.tunnel.recv_transport.map(|t| t.name()),
        "listen": config.tunnel.listen,
        "remote": config.tunnel.remote,
        "mux": config.mux().enabled,
        "forwards": config.forward.iter().map(|f| serde_json::json!({
            "listen": f.listen,
            "target": f.target,
            "protocol": f.protocol.name(),
        })).collect::<Vec<_>>(),
        "warnings": config.warnings(),
    })
}

/// `kariz check --json` for an invalid config: the message, the setting it names (every
/// validation message starts with one) and, for TOML syntax, where in the text it is.
fn check_error(e: &anyhow::Error, text: Option<&str>) -> serde_json::Value {
    let mut doc = serde_json::json!({ "ok": false, "error": format!("{e:#}") });
    let root = e.root_cause().to_string();
    let token: String = root
        .trim_start_matches('[')
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.'))
        .collect();
    if token.contains('.') && !token.ends_with('.') {
        doc["key"] = token.into();
    }
    if let Some(toml) = e.chain().find_map(|c| c.downcast_ref::<toml::de::Error>()) {
        doc["error"] = toml.message().into();
        if let (Some(span), Some(text)) = (toml.span(), text) {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            doc["line"] = line.into();
            doc["column"] = column.into();
        }
    }
    doc
}

/// `kariz status`: asks the running daemon of this config for its status and shows it.
#[cfg(unix)]
fn status(path: &Path, watch: bool, json: bool) -> Result<()> {
    use std::io::Write;
    use std::time::{Duration, Instant};

    let config = Config::load(path)?;
    let socket = config
        .control_socket()
        .context("this config has no control socket")?;
    let name = path
        .file_stem()
        .map_or("tunnel".into(), |s| s.to_string_lossy().into_owned());
    let style = logging::Style::detect(config.log.color, logging::local_offset());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ask = || {
        runtime.block_on(async {
            let connection = kariz::control::connect(&socket).await?;
            kariz::control::status(connection).await
        })
    };
    let first = match ask() {
        Ok(status) => (status, Instant::now()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            eprintln!(
                "kariz status: {name} is not running (nothing answers on {}); \
                 see `systemctl status kariz@{name}`",
                socket.display()
            );
            std::process::exit(3);
        }
        Err(e) => return Err(e).context("could not read the status"),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&first.0)?);
        return Ok(());
    }
    let mut before = first;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = ask().context("could not read the status")?;
        let secs = before.1.elapsed().as_secs_f64();
        let view = status_view::render(&style, &name, &now, Some((&before.0, secs)));
        if watch && style.color {
            print!("\x1b[2J\x1b[H");
        }
        print!("\n{view}");
        std::io::stdout().flush()?;
        if !watch {
            return Ok(());
        }
        before = (now, Instant::now());
    }
}

#[cfg(not(unix))]
fn status(_: &Path, _: bool, _: bool) -> Result<()> {
    bail!("`kariz status` needs a Linux server: it talks to the running daemon over a Unix socket")
}

/// `kariz speedtest`: asks the running daemon of this config for a test and shows it.
#[cfg(unix)]
fn speedtest(config: &Config, options: Options) -> Result<()> {
    use std::io::Write;

    use anyhow::Context;
    use kariz::config::Role;

    if config.role != Role::Entry {
        bail!(
            "run the speed test on the entry side (this is the exit side): the entry is where \
             users connect, and it is the one that can open test streams through the tunnel"
        );
    }
    options.validate()?;
    let socket = config
        .control_socket()
        .context("this config has no control socket")?;
    let style = logging::Style::detect(config.log.color, logging::local_offset());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let live = style.color;
    let report = runtime.block_on(async {
        let connection = kariz::control::connect(&socket).await?;
        kariz::control::request(connection, options, |line| {
            // Lines for programs (the panel) are not for a person.
            if line.starts_with(kariz::speedtest::RESULT_LINE) {
                return;
            }
            // One line, rewritten, on a terminal.
            if live {
                print!("\r\x1b[2K  {} {line}", style.paint(logging::TEAL, "⋯"));
                let _ = std::io::stdout().flush();
            } else {
                println!("  ⋯ {line}");
            }
        })
        .await
    });
    if live {
        print!("\r\x1b[2K");
    }
    let report = report.context("the speed test failed")?;
    print!("{}", report::render(&style, config, &report));
    Ok(())
}

#[cfg(not(unix))]
fn speedtest(_: &Config, _: Options) -> Result<()> {
    bail!(
        "`kariz speedtest` needs a Linux server: it talks to the running daemon over a Unix \
         socket"
    )
}

fn run(config: Config) -> Result<()> {
    // Still one thread here: the only time the local offset can be read.
    let style = logging::Style::detect(config.log.color, logging::local_offset());
    print!("{}", logging::banner(&style, &config));
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .event_format(logging::Pretty(style))
        .init();
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(threads) = config.tuning().threads {
        builder.worker_threads(threads);
    }
    let runtime = builder.enable_all().build()?;

    runtime.block_on(async move {
        tokio::select! {
            result = kariz::run(config) => result,
            _ = shutdown_signal() => {
                tracing::info!("shutting down");
                Ok(())
            }
        }
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn print_summary(config: &Config) {
    let tuning = config.tuning();
    println!("config OK");
    println!("  role      : {}", role_name(config.role));
    println!("  mode      : {}", mode_name(config.mode));
    println!("  profile   : {}", config.profile.name());
    println!("  transport : {}", config.tunnel.transport.name());
    if let Some(recv) = config.tunnel.recv_transport {
        // Asymmetric: send over `transport`, receive over `recv_transport`.
        println!("  receive   : {} (asymmetric)", recv.name());
    }
    if let Some(listen) = &config.tunnel.listen {
        println!("  listen    : {listen}");
    }
    if let Some(remote) = &config.tunnel.remote {
        println!("  remote    : {remote}");
    }
    let cipher = Cipher::for_config(config.tunnel.encryption);
    match config.tunnel.encryption {
        _ if config.tunnel.transport == TransportKind::Quic => {
            println!("  encryption: TLS 1.3 (QUIC), both sides authenticated by the token")
        }
        Encryption::Auto if config.is_acceptor() => {
            println!("  encryption: auto (accepts chacha20-poly1305 and aes-256-gcm)")
        }
        Encryption::Auto => println!("  encryption: auto ({} on this CPU)", cipher.name()),
        e => println!("  encryption: {}", e.name()),
    }
    let mux = config.mux();
    if mux.enabled {
        println!(
            "  mux       : connections={} max_streams={} window={}B ping={}s coalesce={}",
            mux.connections,
            mux.max_streams,
            mux.stream_window,
            mux.ping_interval.as_secs(),
            if mux.coalesce { "on" } else { "off" }
        );
        let lowat = mux
            .notsent_lowat
            .map_or("off".to_string(), |v| format!("{v}B"));
        println!(
            "              datagram_buffer={}B datagram_queue={} notsent_lowat={lowat}",
            mux.datagram_buffer, mux.datagram_queue
        );
    } else {
        println!("  mux       : off");
    }
    if matches!(
        config.tunnel.transport,
        TransportKind::Ws | TransportKind::Wss
    ) {
        let ws = config.tunnel.ws.as_ref();
        let path = ws.map_or("/", |w| w.path.as_str());
        let host = ws.and_then(|w| w.host.as_deref()).unwrap_or("-");
        println!("  ws        : path={path} host={host}");
    }
    if config.tunnel.transport == TransportKind::Quic {
        let quic = config.tunnel.quic.clone().unwrap_or_default();
        let sni = match &quic.sni {
            Some(sni) => format!(" sni={sni}"),
            None => String::new(),
        };
        let obfs = if quic.obfs { " obfs=on" } else { "" };
        println!(
            "  quic      : congestion={} alpn={}{sni}{obfs}",
            quic.congestion.name(),
            quic.alpn
        );
    }
    if config.tunnel.transport == TransportKind::Auto {
        println!("  auto      : tcpmux, kcp and ws together; the dialing side moves to the one that gets through");
    }
    if config.tunnel.transport == TransportKind::Kcp {
        let kcp = config.kcp();
        let t = kcp.timing();
        println!(
            "  kcp       : mode={} (nodelay={} interval={}ms resend={} no_congestion={}) \
             window={}/{} mtu={} fec={}, packets sealed with the token",
            kcp.mode.name(),
            t.nodelay,
            t.interval_ms,
            t.resend,
            t.no_congestion,
            kcp.send_window,
            kcp.recv_window,
            kcp.mtu,
            match kcp.fec() {
                Some((data, parity)) => format!("{data}+{parity}"),
                None => "off".into(),
            }
        );
    }
    if config.tunnel.transport == TransportKind::Wss {
        let tls = config.tunnel.tls.clone().unwrap_or_default();
        if let Some(cert) = &tls.cert {
            println!(
                "  tls cert  : {} (reloaded when it changes)",
                cert.display()
            );
        } else {
            let verify = if tls.pin_sha256.is_some() {
                "pinned certificate (pin_sha256)"
            } else if tls.insecure {
                "none (insecure)"
            } else {
                "Mozilla root certificates"
            };
            println!("  tls verify: {verify}");
            if let Some(sni) = &tls.sni {
                println!("  tls sni   : {sni}");
            }
        }
    }
    println!(
        "  tuning    : nodelay={} buffer={}B keepalive={}s",
        tuning.nodelay,
        tuning.buffer_size,
        tuning.keepalive.as_secs()
    );
    if let Some(dscp) = tuning.dscp {
        let name = Dscp::name_of(dscp).map_or(String::new(), |n| format!(" ({n})"));
        let sockets = if config.tunnel.transport == TransportKind::Quic {
            "UDP sockets to targets (not QUIC's)"
        } else {
            "tunnel sockets and UDP sockets to targets"
        };
        println!("  dscp      : {dscp}{name} on {sockets}");
    }
    if config.forward.iter().any(|f| f.protocol.has_udp()) {
        println!(
            "  udp       : timeout={}s max_flows={} per rule",
            tuning.udp.timeout.as_secs(),
            tuning.udp.max_flows
        );
    }
    for f in &config.forward {
        let copies = f
            .duplication()
            .map(|d| format!(", {} copies {} ms apart", d.copies, d.gap_ms))
            .unwrap_or_default();
        println!(
            "  forward   : {} -> {} ({}{copies})",
            f.listen,
            f.target,
            f.protocol.name()
        );
    }
    for warning in config.warnings() {
        println!("warning: {warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "role = \"entry\"\nmode = \"direct\"\n[tunnel]\ntransport = \"tcpmux\"\n\
                        remote = \"203.0.113.1:3080\"\ntoken = \"test-token-0123456789\"\n\
                        [[forward]]\nlisten = \"0.0.0.0:53\"\ntarget = \"127.0.0.1:53\"\n\
                        protocol = \"udp\"\n";

    #[test]
    fn check_json_describes_a_good_config() {
        let doc = check_ok(&Config::parse(GOOD).unwrap());
        assert_eq!(doc["ok"], true);
        assert_eq!(doc["role"], "entry");
        assert_eq!(doc["transport"], "tcpmux");
        assert_eq!(doc["remote"], "203.0.113.1:3080");
        assert_eq!(doc["listen"], serde_json::Value::Null);
        assert_eq!(doc["mux"], true);
        assert_eq!(doc["forwards"][0]["protocol"], "udp");
        assert!(doc["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn check_json_names_the_setting_at_fault() {
        let bad = GOOD.replace("test-token-0123456789", "short");
        let doc = check_error(&Config::parse(&bad).unwrap_err(), Some(&bad));
        assert_eq!(doc["ok"], false);
        assert_eq!(doc["key"], "tunnel.token");
        assert!(
            doc["error"].as_str().unwrap().contains("16 characters"),
            "{doc}"
        );
        assert!(doc.get("line").is_none(), "{doc}");

        let exit = GOOD.replace("role = \"entry\"", "role = \"exit\"");
        let doc = check_error(&Config::parse(&exit).unwrap_err(), Some(&exit));
        assert_eq!(doc["key"], "tunnel.listen", "{doc}");

        // A message that names no setting has no key.
        let bare = &GOOD[..GOOD.find("[[forward]]").unwrap()];
        let doc = check_error(&Config::parse(bare).unwrap_err(), Some(bare));
        assert!(
            doc["error"].as_str().unwrap().contains("[[forward]]"),
            "{doc}"
        );
        assert!(doc.get("key").is_none(), "{doc}");
    }

    #[test]
    fn check_json_points_at_a_syntax_error() {
        let broken = GOOD.replace("mode = \"direct\"", "mode = direct");
        let doc = check_error(&Config::parse(&broken).unwrap_err(), Some(&broken));
        assert_eq!(doc["ok"], false);
        assert_eq!(doc["line"], 2, "{doc}");
        assert_eq!(doc["column"], 8, "{doc}");
    }
}
