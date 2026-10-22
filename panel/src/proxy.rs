//! The panel's outbound SOCKS5 proxy, set in Settings → Proxy and kept in the database. The
//! panel reaches the servers that are switched to it through the proxy (the reverse-mode
//! servers whose *through the panel proxy* switch is on, see [`crate::reverse`]), and, when
//! asked, the internet for release downloads.
//!
//! * **Server links** are per server: a reverse-mode server's `via_proxy` switch sends the
//!   panel's dials to it (and so the tunnel management on the link) through the proxy. SOCKS5
//!   carries TCP, so such a link is kept to the TCP transports (`tcpmux`, `wss`); `kcp`/`quic`
//!   are left out. The proxy is handed to that one dialer
//!   ([`kariz::link::Dialer::via_proxy`]): nothing else in the panel, and no tunnel, dials
//!   through it.
//! * **Panel internet** is a single switch: the panel's outbound HTTP (release downloads for
//!   updating) goes through the proxy as a `socks5://` URL handed to `ureq`
//!   ([`crate::update`]).

use std::sync::RwLock;

use anyhow::Result;
use kariz::transport::proxy::Socks5;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::Db;

const META: &str = "proxy";

/// The panel-internet `socks5://` URL for `ureq`, when that switch is on. The server links
/// read the settings from the database themselves, per dial.
static INTERNET_PROXY: RwLock<Option<String>> = RwLock::new(None);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    /// The proxy's address, `host:port`.
    pub addr: String,
    pub username: String,
    pub password: String,
    /// Reach the internet (release downloads) through the proxy.
    pub panel_internet: bool,
}

impl Settings {
    pub fn load(db: &Db) -> Settings {
        db.meta(META)
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, db: &Db) -> Result<()> {
        db.set_meta(META, &serde_json::to_string(self)?)
    }

    /// Checks the fields, returning an error key when something is wrong.
    pub fn check(&self) -> std::result::Result<(), &'static str> {
        if !self.enabled {
            return Ok(());
        }
        if !valid_host_port(&self.addr) {
            return Err("bad_addr");
        }
        if self.username.len() > 255 || self.password.len() > 255 {
            return Err("bad_auth");
        }
        // A password with no user (or a user with no password) is almost always a mistake.
        if self.username.is_empty() != self.password.is_empty() {
            return Err("bad_auth");
        }
        Ok(())
    }

    /// The SOCKS5 proxy these settings describe, or `None` when disabled or without an
    /// address: what a server switched to the proxy is dialed through.
    pub fn socks5(&self) -> Option<Socks5> {
        if !self.enabled || self.addr.is_empty() {
            return None;
        }
        let auth = if self.username.is_empty() {
            None
        } else {
            Some((self.username.clone(), self.password.clone()))
        };
        Some(Socks5 {
            addr: self.addr.clone(),
            auth,
        })
    }

    /// A `socks5://[user:pass@]host:port` URL for `ureq`, or `None` when disabled.
    fn url(&self) -> Option<String> {
        if !self.enabled || self.addr.is_empty() {
            return None;
        }
        let creds = if self.username.is_empty() {
            String::new()
        } else {
            format!(
                "{}:{}@",
                pct_encode(&self.username),
                pct_encode(&self.password)
            )
        };
        Some(format!("socks5://{creds}{}", self.addr))
    }

    /// Puts the panel-internet switch into effect for this process (into
    /// [`internet_proxy`]). Call at startup and after every change. The server links need
    /// nothing: each dial reads the settings.
    pub fn apply(&self) {
        let internet = if self.panel_internet {
            self.url()
        } else {
            None
        };
        if let Ok(mut g) = INTERNET_PROXY.write() {
            *g = internet;
        }
    }

    /// The settings for the API, with the password hidden.
    pub fn view(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "addr": self.addr,
            "username": self.username,
            "has_password": !self.password.is_empty(),
            "panel_internet": self.panel_internet,
        })
    }
}

/// The panel-internet `socks5://` URL, if that switch is on. [`crate::update`] consults this
/// when it builds its HTTP agent.
pub fn internet_proxy() -> Option<String> {
    INTERNET_PROXY.read().ok().and_then(|g| g.clone())
}

/// `host:port` with a real port and a plausible host (no spaces, not too long). An IPv6 host
/// must be bracketed (`[::1]:1080`): an unbracketed one is ambiguous with the port separator and
/// would break both the `ureq` proxy URL and the SOCKS5 dial, so it is rejected.
fn valid_host_port(v: &str) -> bool {
    let (host, port) = match v.strip_prefix('[') {
        Some(rest) => match rest.split_once("]:") {
            Some(hp) => hp,
            None => return false,
        },
        None => match v.rsplit_once(':') {
            // A bare colon-bearing host is an unbracketed IPv6: reject it.
            Some((host, _)) if host.contains(':') => return false,
            Some(hp) => hp,
            None => return false,
        },
    };
    !host.is_empty()
        && host.len() <= 100
        && !host.contains(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Percent-encodes a proxy username or password for use in a `socks5://user:pass@host` URL, so
/// a `:`, `@`, `/` or other special character does not break the URL's own structure.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> Settings {
        Settings {
            enabled: true,
            addr: "127.0.0.1:1080".into(),
            ..Settings::default()
        }
    }

    #[test]
    fn a_disabled_proxy_checks_out_and_dials_nothing() {
        let s = Settings::default();
        assert_eq!(s.check(), Ok(()));
        assert!(s.socks5().is_none());
        assert!(s.url().is_none());
        // Enabled without an address: nothing to dial through either.
        let blank = Settings {
            enabled: true,
            ..Settings::default()
        };
        assert!(blank.socks5().is_none());
    }

    #[test]
    fn an_enabled_proxy_needs_a_real_address() {
        assert_eq!(enabled().check(), Ok(()));
        assert_eq!(
            Settings {
                addr: "nope".into(),
                ..enabled()
            }
            .check(),
            Err("bad_addr")
        );
    }

    #[test]
    fn a_password_without_a_user_is_rejected() {
        assert_eq!(
            Settings {
                password: "secret".into(),
                ..enabled()
            }
            .check(),
            Err("bad_auth")
        );
    }

    #[test]
    fn the_socks5_and_url_carry_the_auth() {
        let s = Settings {
            username: "u".into(),
            password: "p".into(),
            ..enabled()
        };
        let sock = s.socks5().unwrap();
        assert_eq!(sock.addr, "127.0.0.1:1080");
        assert_eq!(sock.auth, Some(("u".into(), "p".into())));
        assert_eq!(s.url().unwrap(), "socks5://u:p@127.0.0.1:1080");
    }

    #[test]
    fn apply_sets_the_internet_proxy_only_when_asked() {
        Settings {
            panel_internet: true,
            ..enabled()
        }
        .apply();
        assert_eq!(internet_proxy().as_deref(), Some("socks5://127.0.0.1:1080"));
        Settings {
            panel_internet: false,
            ..enabled()
        }
        .apply();
        assert!(internet_proxy().is_none());
        Settings {
            panel_internet: true,
            ..Settings::default()
        }
        .apply();
        assert!(internet_proxy().is_none(), "disabled: no proxy");
    }

    #[test]
    fn the_view_hides_the_password() {
        let s = Settings {
            username: "u".into(),
            password: "secret".into(),
            ..enabled()
        };
        let v = s.view();
        assert_eq!(v["has_password"], json!(true));
        assert_eq!(v.get("password"), None);
    }

    #[test]
    fn host_port_accepts_ipv4_and_bracketed_ipv6() {
        assert!(valid_host_port("1.2.3.4:1080"));
        assert!(valid_host_port("[::1]:1080"));
        assert!(valid_host_port("[2001:db8::1]:1080"));
        assert!(valid_host_port("proxy.local:1080"));
        assert!(!valid_host_port("1.2.3.4"));
        assert!(!valid_host_port("1.2.3.4:0"));
        assert!(!valid_host_port("1.2.3.4:99999"));
        // An unbracketed IPv6 is ambiguous with the port separator: rejected.
        assert!(!valid_host_port("2001:db8::1:1080"));
        assert!(!valid_host_port("::1:1080"));
    }

    #[test]
    fn the_url_percent_encodes_special_characters_in_credentials() {
        let s = Settings {
            username: "u:ser".into(),
            password: "p@ss/1".into(),
            addr: "[2001:db8::1]:1080".into(),
            ..enabled()
        };
        assert_eq!(
            s.url().unwrap(),
            "socks5://u%3Aser:p%40ss%2F1@[2001:db8::1]:1080"
        );
    }
}
