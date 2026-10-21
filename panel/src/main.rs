use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use kariz_panel::agent::{self, AgentConfig, DEFAULT_AGENT_CONFIG};
use kariz_panel::auth;
use kariz_panel::config::{Config, DEFAULT_CONFIG, DEFAULT_DATA_DIR};
use kariz_panel::db::Db;
use kariz_panel::http::{self, AppState};

#[derive(Parser)]
#[command(name = "kariz-panel", version, about = "The Kariz web panel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the panel.
    Serve {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Set the panel up: its settings (a random port and secret path), the database and
    /// the certificate. Safe to run again.
    Init {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Where the database and the certificate go.
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        /// The port, instead of a random one (20000-59999).
        #[arg(long)]
        port: Option<u16>,
        /// Use this certificate chain (PEM) instead of making a self-signed one; needs `--key-file`.
        #[arg(long, requires = "key_file")]
        cert_file: Option<PathBuf>,
        /// The key of `--cert-file`.
        #[arg(long, requires = "cert_file")]
        key_file: Option<PathBuf>,
        /// What this server is called in the panel (letters, digits, - _ . up to 40);
        /// default: its host name. Given again, it renames the server.
        #[arg(long)]
        name: Option<String>,
    },
    /// Run the agent that connects this server to a panel. The first time, give it the
    /// join code the panel shows (*Add server*); after that it remembers who it is.
    Agent {
        #[arg(short, long, default_value = DEFAULT_AGENT_CONFIG)]
        config: PathBuf,
        /// The join code from the panel.
        #[arg(long)]
        join: Option<String>,
        /// Only write the settings from `--join`, then stop (the installer runs the
        /// agent as a service).
        #[arg(long, requires = "join")]
        no_run: bool,
    },
    /// Make a one-time login link (valid for 60 minutes, works once).
    LoginLink {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// This server's address or domain, as the browser reaches it.
        #[arg(long, default_value = "<this-server>")]
        host: String,
    },
    /// Set a new admin password and sign every session out. Without --stdin, a random
    /// password is made and shown.
    ResetPassword {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Read the new password from the first line of standard input.
        #[arg(long)]
        stdin: bool,
    },
    /// Make a release signing key pair. The private key goes to a file (keep it secret: it
    /// becomes the repository secret KARIZ_SIGNING_KEY); the public key is printed.
    ReleaseKey {
        /// Where to write the private key (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a release's `.sha256` file: writes the `.sig` beside it (the archive's name
    /// with `.sig`). The private key is read from the environment variable.
    ReleaseSign {
        file: PathBuf,
        #[arg(long, default_value = "KARIZ_SIGNING_KEY")]
        key_env: String,
    },
    /// Check a downloaded archive against its `.sha256` and `.sig` beside it.
    ReleaseVerify {
        archive: PathBuf,
        /// The public key (hex), instead of the one built in.
        #[arg(long)]
        key: Option<String>,
    },
    /// What the panel runs, as a transient service, to swap in a new version (the panel
    /// starts it itself; there is no reason to run it by hand).
    #[command(hide = true)]
    UpdateApply {
        #[arg(long)]
        stage: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        panel_bin: PathBuf,
        #[arg(long)]
        kariz_bin: PathBuf,
        /// Seconds the new panel has to answer.
        #[arg(long, default_value_t = 30)]
        wait: u64,
        /// Seconds to wait before starting, so the panel can still answer the browser
        /// that the hand-over went well.
        #[arg(long, default_value_t = 0)]
        delay: u64,
    },
    /// What an agent runs, as a transient service, to swap in a new version (the agent
    /// starts it itself).
    #[command(hide = true)]
    AgentUpdateApply {
        #[arg(long)]
        stage: PathBuf,
        #[arg(long)]
        version: String,
        /// The file the agent touches each time it reaches the panel.
        #[arg(long)]
        stamp: PathBuf,
        #[arg(long)]
        panel_bin: PathBuf,
        #[arg(long)]
        kariz_bin: PathBuf,
        /// Seconds to wait before starting, so the agent can still answer the panel.
        #[arg(long, default_value_t = 0)]
        delay: u64,
    },
    /// Private network links on this server, by hand (what the agent does when the panel
    /// asks; for debugging and for the tests). Needs root and Linux.
    Net {
        #[command(subcommand)]
        command: NetCommand,
    },
}

#[derive(clap::Subcommand)]
enum NetCommand {
    /// Make the link described in a TOML file (fields of `NetSpec`).
    Up {
        file: PathBuf,
        /// Keep the link in this file so it can be made again (default: not kept).
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Remove a link's interface.
    Down { name: String },
    /// Ping the far end of a link (the link must be kept in `--state`).
    Ping {
        name: String,
        #[arg(long)]
        state: PathBuf,
    },
    /// Whether GRE can be made here.
    Status,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            config,
            data_dir,
            port,
            cert_file,
            key_file,
            name,
        } => {
            if let Some(name) = name.as_deref() {
                anyhow::ensure!(
                    kariz_panel::join::valid_name(name),
                    "the name is letters, digits, - _ . and at most 40 characters"
                );
            }
            let done =
                kariz_panel::init_with_cert(&config, &data_dir, port, cert_file.zip(key_file))?;
            if let Some(name) = name {
                kariz_panel::db::Db::open(&done.config.database())?
                    .set_meta("local_name", &name)?;
            }
            println!("panel set up");
            println!("  settings    : {}", config.display());
            println!("  listen      : {}", done.config.listen);
            println!("  secret path : /{}/", done.config.path);
            println!("  certificate : SHA-256 {}", done.fingerprint);
            Ok(())
        }
        Command::Serve { config } => serve(Config::load(&config)?, &config),
        Command::Net { command } => net_command(command),
        Command::UpdateApply {
            stage,
            version,
            config,
            panel_bin,
            kariz_bin,
            wait,
            delay,
        } => {
            std::thread::sleep(std::time::Duration::from_secs(delay));
            update_apply(&stage, &version, &config, panel_bin, kariz_bin, wait)
        }
        Command::AgentUpdateApply {
            stage,
            version,
            stamp,
            panel_bin,
            kariz_bin,
            delay,
        } => {
            std::thread::sleep(std::time::Duration::from_secs(delay));
            agent_update_apply(&stage, &version, stamp, panel_bin, kariz_bin)
        }
        Command::ReleaseKey { out } => release_key(&out),
        Command::ReleaseSign { file, key_env } => release_sign(&file, &key_env),
        Command::ReleaseVerify { archive, key } => release_verify(&archive, key.as_deref()),
        Command::Agent {
            config,
            join,
            no_run,
        } => run_agent(&config, join.as_deref(), no_run),
        Command::LoginLink { config, host } => {
            let config = Config::load(&config)?;
            let db = Db::open(&config.database())?;
            let token = auth::create_link(&db, auth::now())?;
            db.audit("cli", None, "made a login link")?;
            let port = config
                .listen
                .rsplit(':')
                .next()
                .unwrap_or_default()
                .to_owned();
            let host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host
            };
            println!("https://{host}:{port}/{}/#t={token}", config.path);
            eprintln!("valid for 60 minutes; it works once");
            Ok(())
        }
        Command::ResetPassword { config, stdin } => {
            let config = Config::load(&config)?;
            let db = Db::open(&config.database())?;
            let (password, shown) = if stdin {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                (line.trim_end_matches(&['\r', '\n'][..]).to_owned(), false)
            } else {
                (kariz_panel::config::random_hex(10)?, true)
            };
            auth::set_password(&db, &password, None)?;
            db.audit("cli", None, "reset the password")?;
            if shown {
                println!("{password}");
                eprintln!("the new admin password (every session was signed out)");
            } else {
                eprintln!("password set (every session was signed out)");
            }
            Ok(())
        }
    }
}

fn update_apply(
    stage: &std::path::Path,
    version: &str,
    config: &std::path::Path,
    panel: PathBuf,
    kariz: PathBuf,
    wait: u64,
) -> Result<()> {
    use kariz_panel::update::{self, SystemHost, Targets};
    let config = Config::load(config)?;
    let host = SystemHost {
        unit: "kariz-panel".into(),
        listen: config.listen.clone(),
        path: config.path.clone(),
        pin: kariz_panel::cert::fingerprint(&config.cert())?,
    };
    let outcome = update::apply(
        stage,
        &Targets { panel, kariz },
        version,
        &host,
        std::time::Duration::from_secs(wait),
        std::time::Duration::from_secs(1),
        auth::now(),
    );
    // Beside the downloads, for the panel to show when it is back.
    let dir = stage.parent().unwrap_or(stage);
    update::write_outcome(dir, &outcome)?;
    if let Ok(db) = Db::open(&config.database()) {
        let what = if outcome.ok {
            format!("the panel was updated to {version}")
        } else {
            format!(
                "the update to {version} failed and the old version was put back: {}",
                outcome.error.as_deref().unwrap_or("")
            )
        };
        let _ = db.audit("update", None, &what);
    }
    if outcome.ok {
        Ok(())
    } else {
        anyhow::bail!(outcome.error.unwrap_or_default())
    }
}

fn agent_update_apply(
    stage: &std::path::Path,
    version: &str,
    stamp: PathBuf,
    panel: PathBuf,
    kariz: PathBuf,
) -> Result<()> {
    use kariz_panel::agent_update::{AgentHost, WAIT};
    use kariz_panel::update::{self, Targets};
    let host = AgentHost {
        unit: "kariz-agent".into(),
        stamp,
        since: std::time::SystemTime::now(),
    };
    let outcome = update::apply(
        stage,
        &Targets { panel, kariz },
        version,
        &host,
        WAIT,
        std::time::Duration::from_secs(1),
        auth::now(),
    );
    update::write_outcome(stage.parent().unwrap_or(stage), &outcome)?;
    if outcome.ok {
        Ok(())
    } else {
        anyhow::bail!(outcome.error.unwrap_or_default())
    }
}

fn release_key(out: &std::path::Path) -> Result<()> {
    use kariz_panel::sign;
    if out.exists() {
        anyhow::bail!("{} exists already; it would be overwritten", out.display());
    }
    let (private, public) = sign::generate()?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)?
            .write_all(private.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(out, &private)?;
    println!("private key written to {} (keep it secret)", out.display());
    println!("public key (hex): {}", sign::hex(&public));
    println!("{}", sign::public_pem(&public));
    Ok(())
}

fn release_sign(file: &std::path::Path, key_env: &str) -> Result<()> {
    let key = std::env::var(key_env).map_err(|_| {
        anyhow::anyhow!("the signing key is not in the environment variable {key_env}")
    })?;
    let message = std::fs::read(file)?;
    let signature = kariz_panel::sign::sign(&key, &message)?;
    let name = file
        .to_str()
        .and_then(|n| n.strip_suffix(".sha256"))
        .ok_or_else(|| anyhow::anyhow!("give the .sha256 file of a release"))?;
    std::fs::write(format!("{name}.sig"), signature)?;
    println!("signed {}", file.display());
    Ok(())
}

fn release_verify(archive: &std::path::Path, key: Option<&str>) -> Result<()> {
    use kariz_panel::sign;
    let public = sign::release_key(key)?;
    let name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("no archive name"))?;
    let read = |suffix: &str| {
        let p = format!("{}{suffix}", archive.display());
        std::fs::read(&p).map_err(|e| anyhow::anyhow!("cannot read {p}: {e}"))
    };
    sign::verify_archive(
        &public,
        name,
        &std::fs::read(archive)?,
        &read(".sha256")?,
        &read(".sig")?,
    )?;
    println!("{name}: the signature and the checksum are good");
    Ok(())
}

fn net_command(command: NetCommand) -> Result<()> {
    use kariz_panel::net::Net;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        match command {
            NetCommand::Up { file, state } => {
                let spec: kariz_panel::wire::NetSpec =
                    toml::from_str(&std::fs::read_to_string(&file)?)?;
                let name = spec.name.clone();
                Net::new(state).up(spec).await?;
                println!("{name} is up");
            }
            NetCommand::Down { name } => {
                Net::new(None).down(&name).await?;
                println!("{name} is down");
            }
            NetCommand::Ping { name, state } => {
                let reply = Net::new(Some(state)).ping(&name).await;
                println!("{}", serde_json::to_string(&reply)?);
                if !reply.ok {
                    std::process::exit(1);
                }
            }
            NetCommand::Status => {
                println!("{}", serde_json::to_string(&Net::new(None).status().await)?);
            }
        }
        Ok(())
    })
}

fn serve(config: Config, config_path: &std::path::Path) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let db = Db::open(&config.database())?;
        config.ensure_cert()?;
        // The manager script of this release (an update from the panel does not swap it), and
        // for a panel set up before `panel heal`, its timer (a new IP address of the server
        // then gets the panel a certificate for it by itself).
        kariz_panel::manage::manager_in_place(config.services);
        if config.services == kariz_panel::manage::ServiceKind::Systemd {
            let path = config_path.to_path_buf();
            tokio::spawn(async move { kariz_panel::manage::ensure_heal_timer(&path).await });
        }
        let listener = tokio::net::TcpListener::bind(&config.listen)
            .await
            .with_context(|| format!("failed to listen on {}", config.listen))?;
        let hub = kariz_panel::hub::Hub::with_state_dir(
            db.clone(),
            config.kariz_dir.clone(),
            config.services.services(&config.kariz_dir),
            config.data_dir.clone(),
        );
        // Where updating finds its releases and the programs it replaces.
        hub.set_update_settings(kariz_panel::updater::UpdateSettings {
            api: config
                .release_api
                .clone()
                .unwrap_or_else(|| kariz_panel::update::DEFAULT_API.to_owned()),
            key: config.release_key.clone(),
            dir: config.data_dir.join("updates"),
            config: config_path.to_path_buf(),
            panel_bin: std::env::current_exe()?,
            kariz_bin: std::env::current_exe()?.with_file_name("kariz"),
        });
        tokio::spawn(hub.clone().run_local());
        // The servers the panel connects to (reverse) are dialed whether or not it takes
        // agents itself.
        hub.start_reverse_links();
        tokio::spawn(kariz_panel::telegram::run(hub.clone()));
        tokio::spawn(kariz_panel::schedule::run(hub.clone()));
        let mut state = AppState::new(db);
        state.hub = hub.clone();
        if let Some(listen) = &config.agent_listen {
            // Every link transport, so an agent can use the one that gets through its
            // network: tcpmux and kcp on the agents port (TCP and UDP), wss (TCP) and quic
            // (UDP, always sealed) on the next.
            let token = hub.link_token()?;
            let (cert, key) = (config.cert(), config.key());
            for acceptor in kariz_panel::agent_ports::bind(listen, &token, &cert, &key).await? {
                tokio::spawn(hub.clone().serve_agents(acceptor));
            }
            // Servers with an agents port of their own: the panel listens there too.
            hub.set_agent_listen(kariz_panel::agent_ports::AgentListen {
                listen: listen.clone(),
                web_port: config
                    .listen
                    .parse::<std::net::SocketAddr>()
                    .map_or(0, |a| a.port()),
                cert,
                key,
            });
            tokio::spawn({
                let hub = hub.clone();
                async move { hub.open_saved_agent_ports().await }
            });
            state.agent_port = config.agent_port();
        }
        let app = http::router(&config.path, state);
        tokio::select! {
            result = http::serve(listener, &config, app) => result,
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

fn run_agent(path: &std::path::Path, join: Option<&str>, no_run: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let config = match join {
        Some(code) => {
            // A server that joined a panel before joins the new one in its place: the old
            // identity goes (the panel it belonged to keeps listing this server as offline
            // until it is removed there).
            if path.exists() && AgentConfig::load(path).is_ok_and(|c| c.id.is_some()) {
                eprintln!("this server was joined to a panel already: the new code replaces that");
                let _ = std::fs::remove_file(path.with_file_name("link-transport"));
            }
            let config = agent::enroll_from_code(code, path)?;
            eprintln!("settings written to {}", path.display());
            if let Some(listen) = &config.listen {
                let port = listen.rsplit(':').next().unwrap_or_default();
                let next = port.parse::<u16>().map_or(0, |p| p.saturating_add(1));
                eprintln!(
                    "the panel connects to this server: the agent waits for it on port {port} (TCP and UDP) and {next} (TCP and UDP); let the panel's address through"
                );
            }
            config
        }
        None => AgentConfig::load(path)?,
    };
    if no_run {
        return Ok(());
    }
    // The manager script of this release: an update from the panel does not swap it.
    kariz_panel::manage::manager_in_place(config.services);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let services = config.services.services(&config.kariz_dir);
        let agent = agent::Agent::with_services(path, config, services);
        tokio::select! {
            result = agent.run() => result,
            _ = shutdown_signal() => Ok(()),
        }
    })
}
