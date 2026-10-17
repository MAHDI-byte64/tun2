//! Signed releases. Every release archive has a `.sha256`
//! file (`HEX  NAME`) and a `.sig` file: an Ed25519 signature over that `.sha256` file's
//! exact bytes. Signing the file binds the archive's name to its hash, so an archive cannot
//! be swapped for another one of the same release (another CPU, say).
//!
//! The public key is built into the program (and into `scripts/kariz.sh`, which checks it
//! with `openssl`); the private key is a repository secret that only the release workflow
//! sees. A file whose signature does not verify is never run.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// The release public key: 32 raw bytes, hex. (`kariz-panel release-key` makes a pair.)
pub const RELEASE_KEY_HEX: &str =
    "6c9d592af287005492d62bf9f924630f216e72a4bf3c73d63f3ce906864cdeaa";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// A new key pair: the private key (PKCS#8, base64) and the public key (32 bytes).
pub fn generate() -> Result<(String, [u8; 32])> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow!("no randomness"))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| anyhow!("bad key"))?;
    let public: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("bad public key"))?;
    Ok((B64.encode(pkcs8.as_ref()), public))
}

/// The public key as a PEM (SubjectPublicKeyInfo), which `openssl pkeyutl` reads.
pub fn public_pem(public: &[u8; 32]) -> String {
    // The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo.
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(public);
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        B64.encode(der)
    )
}

/// Signs `message` with a private key made by [`generate`].
pub fn sign(private_b64: &str, message: &[u8]) -> Result<Vec<u8>> {
    let pkcs8 = B64
        .decode(private_b64.trim())
        .context("the signing key is not base64")?;
    let pair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| anyhow!("the signing key is not valid"))?;
    Ok(pair.sign(message).as_ref().to_vec())
}

/// Whether `signature` is `public`'s signature of `message`.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(message, signature)
        .is_ok()
}

/// The hex SHA-256 of some bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// The key releases are checked with: the built-in one, or `override_hex` (from the
/// settings) when the user pins their own.
pub fn release_key(override_hex: Option<&str>) -> Result<Vec<u8>> {
    let text = override_hex
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(RELEASE_KEY_HEX);
    let key = unhex(text).ok_or_else(|| anyhow!("no_release_key"))?;
    if key.len() != 32 {
        bail!("no_release_key");
    }
    Ok(key)
}

/// Checks a downloaded archive against its `.sha256` file and its `.sig`: the signature must
/// be the release key's over the `.sha256` file, the file must name this archive, and the
/// archive's SHA-256 must be the one in it. Errors are short codes.
pub fn verify_archive(
    public: &[u8],
    archive_name: &str,
    archive: &[u8],
    sha_file: &[u8],
    sig: &[u8],
) -> Result<()> {
    if !verify(public, sha_file, sig) {
        bail!("bad_signature");
    }
    let text = std::str::from_utf8(sha_file).map_err(|_| anyhow!("bad_signature"))?;
    let mut fields = text.split_whitespace();
    let (Some(want), Some(name), None) = (fields.next(), fields.next(), fields.next()) else {
        bail!("bad_checksum_file");
    };
    // `sha256sum` marks binary files with a leading `*` on the name.
    if name.trim_start_matches('*') != archive_name {
        bail!("wrong_archive");
    }
    if !want.eq_ignore_ascii_case(&sha256_hex(archive)) {
        bail!("bad_checksum");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> (String, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>) {
        let (private, public) = generate().unwrap();
        let archive = b"pretend this is a tar.gz".to_vec();
        let sha = format!(
            "{}  kariz-v0.11.0-x86_64-linux.tar.gz\n",
            sha256_hex(&archive)
        )
        .into_bytes();
        let sig = sign(&private, &sha).unwrap();
        (private, public, archive, sha, sig)
    }

    #[test]
    fn a_release_signed_with_the_key_verifies() {
        let (_, public, archive, sha, sig) = release();
        assert_eq!(sig.len(), 64);
        verify_archive(
            &public,
            "kariz-v0.11.0-x86_64-linux.tar.gz",
            &archive,
            &sha,
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn every_kind_of_tampering_is_refused_with_its_own_reason() {
        let (_, public, archive, sha, sig) = release();
        let name = "kariz-v0.11.0-x86_64-linux.tar.gz";
        let code = |r: Result<()>| format!("{:#}", r.unwrap_err());

        // another key
        let (_, other, ..) = release();
        assert_eq!(
            code(verify_archive(&other, name, &archive, &sha, &sig)),
            "bad_signature"
        );
        // a damaged signature
        let mut bad_sig = sig.clone();
        bad_sig[10] ^= 1;
        assert_eq!(
            code(verify_archive(&public, name, &archive, &sha, &bad_sig)),
            "bad_signature"
        );
        // a checksum file that was changed after signing (the attacker's own hash)
        let forged = format!("{}  {name}\n", sha256_hex(b"evil")).into_bytes();
        assert_eq!(
            code(verify_archive(&public, name, b"evil", &forged, &sig)),
            "bad_signature"
        );
        // the right, signed checksum file but another archive's bytes
        assert_eq!(
            code(verify_archive(&public, name, b"evil", &sha, &sig)),
            "bad_checksum"
        );
        // an archive of the same release for another CPU
        assert_eq!(
            code(verify_archive(
                &public,
                "kariz-v0.11.0-aarch64-linux.tar.gz",
                &archive,
                &sha,
                &sig
            )),
            "wrong_archive"
        );
        // no signature at all
        assert_eq!(
            code(verify_archive(&public, name, &archive, &sha, b"")),
            "bad_signature"
        );
    }

    #[test]
    fn a_checksum_file_of_the_wrong_shape_is_refused_even_if_signed() {
        let (private, public) = generate().unwrap();
        for bad in ["", "abc", "abc def ghi\n"] {
            let sig = sign(&private, bad.as_bytes()).unwrap();
            let r = verify_archive(&public, "x.tar.gz", b"data", bad.as_bytes(), &sig);
            assert_eq!(
                format!("{:#}", r.unwrap_err()),
                "bad_checksum_file",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn keys_round_trip_through_hex_and_pem() {
        let (_, public) = generate().unwrap();
        assert_eq!(unhex(&hex(&public)).unwrap(), public);
        assert!(unhex("xyz").is_none() && unhex("abc").is_none());
        let pem = public_pem(&public);
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----\n")
                && pem.ends_with("-----END PUBLIC KEY-----\n")
        );
        // the DER inside is the standard 44 bytes: a 12-byte prefix and the key
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = B64.decode(body).unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[12..], &public);
    }

    #[test]
    fn the_pinned_key_replaces_the_built_in_one() {
        let (_, public) = generate().unwrap();
        assert_eq!(release_key(Some(&hex(&public))).unwrap(), public);
        assert!(release_key(Some("nothex")).is_err());
        assert!(release_key(Some("abcd")).is_err(), "a key is 32 bytes");
    }

    #[test]
    fn the_key_built_into_the_program_is_a_valid_key() {
        assert_eq!(release_key(None).unwrap().len(), 32);
    }
}
