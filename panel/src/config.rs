//! The panel's settings: `/etc/kariz-panel/panel.toml`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = "/etc/kariz-panel/panel.toml";
pub const DEFAULT_DATA_DIR: &str = "/var/lib/kariz-panel";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the panel listens (`0.0.0.0:28443`, `[::]:28443`).
    pub listen: String,
    /// The secret path the panel answers under, without slashes (`k-7f3a9c`). Anything
    /// else gets a plain 404 page.
    pub path: String,
    /// The database and the certificate live here.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Where agents connect (`0.0.0.0:29001`); without it, no server can be added.
    #[serde(default)]
    pub agent_listen: Option<String>,
    /// Where this server's Kariz tunnel configs are.
    #[serde(default = "default_kariz_dir")]
    pub kariz_dir: PathBuf,
    /// How tunnels are started: `systemd` (default) or `process`.
    #[serde(default)]
    pub services: crate::manage::ServiceKind,
    /// The panel may open a terminal (a root shell) on its own server, from the Logs page.
    /// Off unless set here.
    #[serde(default)]
    pub terminal: bool,
    /// Your own certificate (PEM chain) and key, instead of the self-signed one made at
    /// install. Reloaded when the panel gets SIGHUP. Set both or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    /// Where releases are looked up: `https://api.github.com/repos/OWNER/REPO` (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_api: Option<String>,
    /// A release public key (hex) of your own, instead of the one built in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_key: Option<String>,
}

fn default_kariz_dir() -> PathBuf {
    PathBuf::from("/etc/kariz")
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.path.len() < 6
            || !self
                .path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("path must be 6 or more letters, digits, - or _ (no slashes)");
        }
        self.listen.parse::<std::net::SocketAddr>().map_err(|_| {
            anyhow::anyhow!("listen must be an address with a port, like 0.0.0.0:28443")
        })?;
        if let Some(listen) = &self.agent_listen {
            listen.parse::<std::net::SocketAddr>().map_err(|_| {
                anyhow::anyhow!("agent_listen must be an address with a port, like 0.0.0.0:29001")
            })?;
        }
        if self.cert_file.is_some() != self.key_file.is_some() {
            bail!("cert_file and key_file go together: set both or neither");
        }
        Ok(())
    }

    /// The port agents dial, if the panel takes agents.
    pub fn agent_port(&self) -> Option<u16> {
        self.agent_listen
            .as_deref()
            .and_then(|l| l.parse::<std::net::SocketAddr>().ok())
            .map(|a| a.port())
    }

    pub fn database(&self) -> PathBuf {
        self.data_dir.join("panel.db")
    }

    pub fn cert(&self) -> PathBuf {
        self.cert_file
            .clone()
            .unwrap_or_else(|| self.data_dir.join("cert.pem"))
    }

    pub fn key(&self) -> PathBuf {
        self.key_file
            .clone()
            .unwrap_or_else(|| self.data_dir.join("key.pem"))
    }

    /// The certificate is the user's own, not the one the panel makes for itself.
    pub fn own_cert(&self) -> bool {
        self.cert_file.is_some()
    }

    /// Makes the panel's own certificate if it is used and missing; with the user's own it
    /// only checks that the files are there. The certificate's fingerprint comes back.
    pub fn ensure_cert(&self) -> Result<String> {
        if self.own_cert() {
            for f in [self.cert(), self.key()] {
                if !f.exists() {
                    bail!("{} does not exist", f.display());
                }
            }
            return crate::cert::fingerprint(&self.cert());
        }
        crate::cert::ensure(&self.cert(), &self.key())
    }
}

/// A random lowercase-hex string of `bytes` random bytes.
pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A random port in 20000-59999, the range the installer picks from.
pub fn random_port() -> Result<u16> {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(20_000 + (u32::from_le_bytes(buf) % 40_000) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_is_checked() {
        let good = "listen = \"0.0.0.0:28443\"\npath = \"k-7f3a9c\"\n";
        let config: Config = toml::from_str(good).unwrap();
        config.validate().unwrap();
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(
            config.database(),
            PathBuf::from(DEFAULT_DATA_DIR).join("panel.db")
        );

        for (text, why) in [
            ("listen = \"0.0.0.0:1\"\npath = \"a/b/c/d/e\"\n", "path"),
            ("listen = \"0.0.0.0:1\"\npath = \"abc\"\n", "path"),
            ("listen = \"nowhere\"\npath = \"k-7f3a9c\"\n", "listen"),
        ] {
            let c: Config = toml::from_str(text).unwrap();
            assert!(
                c.validate().unwrap_err().to_string().contains(why),
                "{text}"
            );
        }
        assert!(toml::from_str::<Config>("listen = \"x\"\npath = \"y\"\nunknown = 1\n").is_err());
    }

    #[test]
    fn random_values_have_their_shape() {
        assert_eq!(random_hex(3).unwrap().len(), 6);
        assert_ne!(random_hex(16).unwrap(), random_hex(16).unwrap());
        for _ in 0..50 {
            assert!((20_000..60_000).contains(&random_port().unwrap()));
        }
    }
}
