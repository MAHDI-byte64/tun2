//! An outbound SOCKS5 proxy for the panel itself: the panel reaches the other servers
//! (and, when asked, the internet for updates) through it. It is set in the panel's
//! settings and kept in the database.
//!
//! Two scopes, each turned on on its own:
//!
//! * **Server links** — the panel's own connections to the other servers. Only the panel
//!   dials out in *reverse* mode (an agent dials the panel in the usual mode, so nothing on
//!   the panel is dialing then); those reverse dials, and so the tunnel management that
//!   rides the link, go through the proxy. SOCKS5 carries TCP, so with this scope on the
//!   reverse link is kept to the TCP transports (`tcpmux`, `wss`); `kcp`/`quic` (UDP) are
//!   left out, since a SOCKS5 proxy cannot carry them. This is wired by handing the proxy to
//!   [`kariz::transport::proxy::set_link_proxy`], which [`kariz::transport::tcp::connect`]
//!   (the one place a stream transport opens a TCP connection) then dials through.
//! * **Panel internet** — the panel's outbound HTTP (release downloads for updating). This
//!   is a `socks5://` URL that [`crate::update`] hands to `ureq`.
//!
//! Only the panel process sets either; a tunnel never does, so a tunnel's own transport
//! dials are never touched.

use std::sync::RwLock;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::Db;

const META: &str = "proxy";

/// The panel-internet `socks5://` URL for `ureq`, when that scope is on. The link scope is
/// held in the core's own global ([`kariz::transport::proxy`]); this is the HTTP side.
static INTERNET_PROXY: RwLock<Option<String>> = RwLock::new(None);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    /// The proxy's address, `host:port`.
    pub addr: String,
    pub username: String,
    pub password: String,
    /// Reach the other servers (reverse-mode dials and the tunnel management on the link)
    /// through the proxy.
    pub server_links: bool,
    /// Reach the internet (release downloads) through the proxy.
    pub panel_internet: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: String::new(),
            username: String::new(),
            password: String::new(),
            server_links: true,
            panel_internet: false,
        }
    }
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
        if !self.server_links && !self.panel_internet {
            return Err("no_scope");
        }
        Ok(())
    }

    /// The SOCKS5 proxy these settings describe (ignoring scope), or `None` when disabled or
    /// without an address.
    fn socks5(&self) -> Option<kariz::transport::proxy::Socks5> {
        if !self.enabled || self.addr.is_empty() {
            return None;
        }
        let auth = if self.username.is_empty() {
            None
        } else {
            Some((self.username.clone(), self.password.clone()))
        };
        Some(kariz::transport::proxy::Socks5 {
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
            format!("{}:{}@", self.username, self.password)
        };
        Some(format!("socks5://{creds}{}", self.addr))
    }

    /// Puts both scopes into effect for this process: the server-links proxy into the core's
    /// link dialer, and the internet proxy into [`internet_proxy`]. Call at startup and after
    /// every change.
    pub fn apply(&self) {
        let links = if self.server_links {
            self.socks5()
        } else {
            None
        };
        kariz::transport::proxy::set_link_proxy(links);
        let internet = if self.panel_internet {
            self.url()
        } else {
            None
        };
        if let Ok(mut g) = INTERNET_PROXY.write() {
            *g = internet;
        }
    }

    /// Whether the link scope is active (used to keep the reverse link on TCP transports).
    pub fn links_active(&self) -> bool {
        self.enabled && self.server_links && !self.addr.is_empty()
    }

    /// The settings for the API, with the password hidden.
    pub fn view(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "addr": self.addr,
            "username": self.username,
            "has_password": !self.password.is_empty(),
            "server_links": self.server_links,
            "panel_internet": self.panel_internet,
        })
    }
}

/// The panel-internet `socks5://` URL, if that scope is on. [`crate::update`] consults this
/// when it builds its HTTP agent.
pub fn internet_proxy() -> Option<String> {
    INTERNET_PROXY.read().ok().and_then(|g| g.clone())
}

/// `host:port` with a real port and a plausible host (no spaces, not too long).
fn valid_host_port(v: &str) -> bool {
    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    !host.is_empty()
        && host.len() <= 100
        && !host.contains(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|p| p > 0)
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
    fn a_disabled_proxy_checks_out_and_applies_nothing() {
        let s = Settings::default();
        assert_eq!(s.check(), Ok(()));
        assert!(s.socks5().is_none());
        assert!(s.url().is_none());
        assert!(!s.links_active());
    }

    #[test]
    fn an_enabled_proxy_needs_a_real_address_and_a_scope() {
        assert_eq!(enabled().check(), Ok(()));
        assert_eq!(
            Settings {
                addr: "nope".into(),
                ..enabled()
            }
            .check(),
            Err("bad_addr")
        );
        assert_eq!(
            Settings {
                server_links: false,
                panel_internet: false,
                ..enabled()
            }
            .check(),
            Err("no_scope")
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
    fn apply_routes_each_scope_to_its_own_place() {
        // Server links only: the core link proxy is set, the internet one is not.
        Settings {
            server_links: true,
            panel_internet: false,
            ..enabled()
        }
        .apply();
        assert!(kariz::transport::proxy::link_proxy().is_some());
        assert!(internet_proxy().is_none());

        // Internet only: the other way around.
        Settings {
            server_links: false,
            panel_internet: true,
            ..enabled()
        }
        .apply();
        assert!(kariz::transport::proxy::link_proxy().is_none());
        assert_eq!(internet_proxy().as_deref(), Some("socks5://127.0.0.1:1080"));

        // Disabled: both cleared.
        Settings::default().apply();
        assert!(kariz::transport::proxy::link_proxy().is_none());
        assert!(internet_proxy().is_none());
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
        assert!(valid_host_port("proxy.local:1080"));
        assert!(!valid_host_port("1.2.3.4"));
        assert!(!valid_host_port("1.2.3.4:0"));
        assert!(!valid_host_port("1.2.3.4:99999"));
    }
}
