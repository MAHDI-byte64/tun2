//! The Kariz web panel.

pub mod agent;
pub mod agent_ports;
pub mod agent_update;
pub mod alerts;
pub mod api;
pub mod auth;
pub mod backup;
pub mod bench;
pub mod cert;
pub mod collect;
pub mod config;
pub mod db;
pub mod history;
pub mod http;
pub mod hub;
pub mod iptest;
pub mod join;
pub mod manage;
pub mod manual;
pub mod metrics;
pub mod net;
pub mod netops;
pub mod networks;
pub mod pair;
pub mod proxy;
pub mod quota;
pub mod reverse;
pub mod schedule;
pub mod share;
pub mod sign;
pub mod specs;
pub mod telegram;
pub mod terminal;
pub mod update;
pub mod updater;
pub mod wire;

use std::path::Path;

/// This build's version. `KARIZ_BUILD_VERSION` at build time overrides Cargo's (the CI test
/// of updating builds a second panel that calls itself newer).
pub fn version() -> &'static str {
    option_env!("KARIZ_BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

use anyhow::{Context, Result};

use config::{random_hex, random_port, Config};

/// What `kariz-panel init` made.
pub struct Installed {
    pub config: Config,
    pub fingerprint: String,
}

/// Sets the panel up: the settings file (a random port and secret path unless
/// `config_path` already exists), the database and the certificate. Safe to run again:
/// it keeps what is there.
pub fn init(config_path: &Path, data_dir: &Path, port: Option<u16>) -> Result<Installed> {
    init_with_cert(config_path, data_dir, port, None)
}

/// Like [`init`], for a panel that uses a certificate that already exists (a Let's Encrypt
/// one: `(certificate chain, key)`), so no self-signed one is made.
pub fn init_with_cert(
    config_path: &Path,
    data_dir: &Path,
    port: Option<u16>,
    cert: Option<(std::path::PathBuf, std::path::PathBuf)>,
) -> Result<Installed> {
    let (cert_file, key_file) = cert.unzip();
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        let config = Config {
            listen: format!("0.0.0.0:{}", port.map_or_else(random_port, Ok)?),
            path: format!("k-{}", random_hex(4)?),
            data_dir: data_dir.to_path_buf(),
            agent_listen: Some(format!("0.0.0.0:{}", random_port()?)),
            kariz_dir: std::path::PathBuf::from("/etc/kariz"),
            services: Default::default(),
            terminal: false,
            cert_file,
            key_file,
            release_api: None,
            release_key: None,
        };
        config.validate()?;
        if let Some(dir) = config_path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        std::fs::write(config_path, toml::to_string_pretty(&config)?)
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        config
    };
    let db = db::Db::open(&config.database())?;
    db.audit("cli", None, "panel set up")?;
    let fingerprint = config.ensure_cert()?;
    Ok(Installed {
        config,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_makes_everything_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let (config_path, data) = (
            dir.path().join("etc").join("panel.toml"),
            dir.path().join("data"),
        );
        let first = init(&config_path, &data, Some(24_680)).unwrap();
        assert_eq!(first.config.listen, "0.0.0.0:24680");
        assert!(first.config.path.starts_with("k-") && first.config.path.len() == 10);
        assert!(config_path.exists() && first.config.database().exists());

        let second = init(&config_path, &data, Some(1)).unwrap();
        assert_eq!(second.config.listen, first.config.listen);
        assert_eq!(second.config.path, first.config.path);
        assert_eq!(second.fingerprint, first.fingerprint);
    }

    #[test]
    fn init_with_a_given_certificate_makes_no_self_signed_one() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("fullchain.pem"),
            dir.path().join("privkey.pem"),
        );
        // Made elsewhere (by Let's Encrypt, in real life).
        let pin = crate::cert::ensure(&cert, &key).unwrap();
        let config_path = dir.path().join("etc").join("panel.toml");
        let data = dir.path().join("data");
        let done = init_with_cert(
            &config_path,
            &data,
            Some(24_681),
            Some((cert.clone(), key.clone())),
        )
        .unwrap();
        assert_eq!(done.fingerprint, pin);
        assert_eq!(done.config.cert_file.as_deref(), Some(cert.as_path()));
        assert!(
            !data.join("cert.pem").exists(),
            "no self-signed certificate"
        );
        // A given certificate that is not there is an error, not a silent new one.
        std::fs::remove_file(&key).unwrap();
        let other = dir.path().join("other.toml");
        assert!(init_with_cert(&other, &data, Some(24_682), Some((cert, key))).is_err());
    }
}
