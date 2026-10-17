//! Managed external-helper transports: `naive`, `xhttp` and `reality`.
//!
//! Unlike the other transports, these do not implement a byte stream directly. The
//! **acceptor** runs a helper *server* (sing-box naive inbound, or Xray) on the public
//! tunnel address and forwards authenticated traffic to a Kariz-owned internal loopback
//! listener; the **dialer** runs the helper *client*, exposing a local inbound that Kariz
//! dials its tunnel connections through. Inside the helper stream Kariz still runs its own
//! handshake, record encryption and mux, so the proxies' half-close semantics do not
//! matter.
//!
//! This module is the scaffold the helper unit fills. Its [`listen`]/[`dial`] entry points
//! return [`io::ErrorKind::Unsupported`] until then; the dispatch in [`super`] routes
//! `naive`/`xhttp`/`reality` here.

use std::io;

use crate::config::{TransportKind, Tuning};

use super::{Settings, TunnelStream};

/// The error the scaffold returns for a helper transport that is not built yet.
pub fn unsupported(kind: TransportKind) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("transport \"{}\" is not built yet", kind.name()),
    )
}

/// Supervises a helper *server* process and accepts tunnel connections from it (over the
/// Kariz-owned internal loopback listener).
///
/// The helper unit fills this in; the scaffold leaves it uninhabited so the match arms that
/// name it stay statically unreachable.
#[cfg(feature = "helpers")]
pub enum HelperListener {}

/// Supervises a helper *client* process and dials tunnel connections through its local
/// inbound.
#[cfg(feature = "helpers")]
pub enum HelperDialer {}

#[cfg(feature = "helpers")]
impl HelperListener {
    /// Starts the helper server and binds the internal listener.
    pub async fn bind(settings: &Settings, _addr: &str, _tuning: &Tuning) -> io::Result<Self> {
        Err(unsupported(settings.kind))
    }

    /// Accepts the next authenticated connection from the helper.
    pub async fn accept(&self) -> io::Result<TunnelStream> {
        match *self {}
    }
}

#[cfg(feature = "helpers")]
impl HelperDialer {
    /// Starts the helper client and waits for its local inbound to be ready.
    pub fn new(settings: &Settings, _addr: &str, _tuning: &Tuning) -> io::Result<Self> {
        Err(unsupported(settings.kind))
    }

    /// Dials a tunnel connection through the helper, sending `first` as the first bytes.
    pub async fn dial_with(&self, _first: &[u8]) -> io::Result<TunnelStream> {
        match *self {}
    }
}

/// The dispatch entry point used by [`super::Listener::bind`]. Returns [`Unsupported`]
/// until the helper unit lands.
///
/// [`Unsupported`]: io::ErrorKind::Unsupported
pub async fn listen(
    settings: &Settings,
    _addr: &str,
    _tuning: &Tuning,
) -> io::Result<TunnelStream> {
    Err(unsupported(settings.kind))
}

/// The dispatch entry point used by [`super::Dialer::new`]. Returns [`Unsupported`] until
/// the helper unit lands.
///
/// [`Unsupported`]: io::ErrorKind::Unsupported
pub async fn dial(settings: &Settings, _addr: &str, _tuning: &Tuning) -> io::Result<TunnelStream> {
    Err(unsupported(settings.kind))
}
