//! Tunnel cryptography: the handshake that authenticates both sides and agrees on
//! session keys, and the record layer that encrypts everything after it.
//!
//! The wire formats are in docs/ROADMAP.md (Protocol).

pub mod datagram;
pub mod handshake;
pub mod record;

use std::io;

use crate::config::Encryption;

pub use handshake::{Psk, ReplayFilter};
pub use record::Shaping;

/// Record cipher chosen by the dialing side and sent in the (authenticated) hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// Authentication only, records are not encrypted (`encryption = "none"`).
    None,
    Chacha20Poly1305,
    Aes256Gcm,
}

impl Cipher {
    fn id(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Chacha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
        }
    }

    fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::None),
            1 => Some(Self::Chacha20Poly1305),
            2 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }

    /// The cipher a dialer uses for `encryption`. `auto` prefers AES-256-GCM when the CPU
    /// accelerates it; ChaCha20-Poly1305 is faster everywhere else.
    pub fn for_config(encryption: Encryption) -> Self {
        match encryption {
            Encryption::Auto if has_aes_hardware() => Self::Aes256Gcm,
            Encryption::Auto | Encryption::Chacha20Poly1305 => Self::Chacha20Poly1305,
            Encryption::Aes256Gcm => Self::Aes256Gcm,
            Encryption::None => Self::None,
        }
    }

    /// Whether an acceptor configured with `encryption` takes a dialer using this cipher.
    fn allowed_by(self, encryption: Encryption) -> bool {
        match encryption {
            Encryption::Auto => self != Self::None,
            Encryption::Chacha20Poly1305 => self == Self::Chacha20Poly1305,
            Encryption::Aes256Gcm => self == Self::Aes256Gcm,
            Encryption::None => self == Self::None,
        }
    }
}

pub fn has_aes_hardware() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Everything one side needs to run handshakes: the shared secret and its cipher policy.
#[derive(Clone)]
pub struct Crypto {
    psk: Psk,
    encryption: Encryption,
    cipher: Cipher,
    mux: bool,
    /// Record-layer shaping for a `stealth` link; `None` on every other transport.
    stealth: Option<Shaping>,
}

impl Crypto {
    pub fn new(token: &str, encryption: Encryption) -> Self {
        Self {
            psk: Psk::new(token),
            encryption,
            cipher: Cipher::for_config(encryption),
            mux: false,
            stealth: None,
        }
    }

    /// Whether connections carry a mux session; announced and checked in the handshake.
    pub fn with_mux(mut self, mux: bool) -> Self {
        self.mux = mux;
        self
    }

    /// The record-layer shaping of a `stealth` link (padding and timing jitter); `None`
    /// leaves the record layer unshaped, as every other transport uses it.
    pub fn with_stealth(mut self, stealth: Option<Shaping>) -> Self {
        self.stealth = stealth;
        self
    }

    pub fn mux(&self) -> bool {
        self.mux
    }

    /// The record-layer shaping to apply, if this is a stealth link.
    pub fn shaping(&self) -> Option<Shaping> {
        self.stealth
    }

    pub fn psk(&self) -> &Psk {
        &self.psk
    }

    /// Cipher used when this side dials.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Whether this side accepts a dialer using `cipher`.
    pub fn allows(&self, cipher: Cipher) -> bool {
        cipher.allowed_by(self.encryption)
    }
}

pub(crate) fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

/// Uniform enough for padding lengths and delays; not for keys.
pub(crate) fn random_below(n: u32) -> io::Result<u32> {
    Ok(u32::from_le_bytes(random_bytes()?) % n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_ids_roundtrip() {
        for c in [Cipher::None, Cipher::Chacha20Poly1305, Cipher::Aes256Gcm] {
            assert_eq!(Cipher::from_id(c.id()), Some(c));
        }
        assert_eq!(Cipher::from_id(3), None);
    }

    #[test]
    fn acceptor_policy() {
        use Encryption as E;
        assert!(Cipher::Aes256Gcm.allowed_by(E::Auto));
        assert!(Cipher::Chacha20Poly1305.allowed_by(E::Auto));
        assert!(!Cipher::None.allowed_by(E::Auto));
        assert!(!Cipher::Aes256Gcm.allowed_by(E::Chacha20Poly1305));
        assert!(!Cipher::Chacha20Poly1305.allowed_by(E::None));
        assert!(Cipher::None.allowed_by(E::None));
        assert_ne!(Cipher::for_config(E::Auto), Cipher::None);
    }
}
