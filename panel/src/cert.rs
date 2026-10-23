//! The panel's TLS certificate: self-signed, made when the panel is set up, so that
//! the connection is always encrypted. The installer prints its fingerprint, so the
//! first visit can be checked against it.

use std::path::Path;

use anyhow::{Context, Result};

/// Makes the certificate and key if they are not there yet. Returns the SHA-256
/// fingerprint of the certificate (hex, as `kariz pin` prints it).
pub fn ensure(cert: &Path, key: &Path) -> Result<String> {
    if !cert.exists() || !key.exists() {
        let made = rcgen::generate_simple_self_signed(vec!["kariz-panel".to_owned()])
            .context("failed to make the certificate")?;
        if let Some(dir) = cert.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_private(key, made.signing_key.serialize_pem().as_bytes())?;
        std::fs::write(cert, made.cert.pem())?;
    }
    fingerprint(cert)
}

pub fn fingerprint(cert: &Path) -> Result<String> {
    Ok(kariz::transport::tls::pin_of_file(cert)?)
}

/// Makes a self-signed certificate and key in memory and returns them as PEM together with
/// the certificate's SHA-256 pin. Used for a `wss` tunnel side the panel cannot reach: the
/// panel pins the certificate on the reachable dialer and hands these files to the operator
/// to write on the manual side.
pub fn make() -> Result<(String, String, String)> {
    let made = rcgen::generate_simple_self_signed(vec!["kariz-panel".to_owned()])
        .context("failed to make the certificate")?;
    let pin = kariz::transport::tls::cert_sha256(made.cert.der().as_ref());
    Ok((made.cert.pem(), made.signing_key.serialize_pem(), pin))
}

/// Writes a file only its owner can read.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        let first = ensure(&cert, &key).unwrap();
        assert_eq!(first.len(), 64);
        assert!(std::fs::read_to_string(&key)
            .unwrap()
            .contains("PRIVATE KEY"));
        // A second call keeps the same certificate.
        assert_eq!(ensure(&cert, &key).unwrap(), first);
    }
}
