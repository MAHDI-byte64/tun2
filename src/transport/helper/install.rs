//! Installing and inspecting the pinned helper binaries, and the small key utilities the
//! `kariz helper` subcommands expose.
//!
//! `install` downloads a pinned release asset for the running CPU architecture from the
//! official GitHub release (or takes a local archive with `--from`), verifies its sha256
//! against the hash compiled in below, and unpacks it into
//! `<helpers-dir>/<name>/<version>-<arch>/` without ever overwriting an existing version
//! directory. The default helpers directory is `/usr/local/lib/kariz/helpers`, overridable
//! with `KARIZ_HELPERS_DIR` (used by the tests).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The default directory the pinned helpers are installed under.
pub const DEFAULT_DIR: &str = "/usr/local/lib/kariz/helpers";

/// One release asset: its file name within the release and its pinned sha256.
pub struct Asset {
    pub asset: &'static str,
    pub sha256: &'static str,
}

/// A pinned helper: where to download it, which version, the binary inside, and the per
/// architecture assets with their hashes.
pub struct Pin {
    /// Install name and directory (`naive`, `sing-box`, `xray`).
    pub name: &'static str,
    /// The `owner/repo` the release lives in.
    pub repo: &'static str,
    /// The release tag, also the version component of the install directory.
    pub version: &'static str,
    /// The executable to run, relative to the unpacked directory.
    pub binary: &'static str,
    pub amd64: Asset,
    pub arm64: Asset,
}

/// The pinned helper releases. The hashes were computed by downloading each asset from the
/// official release; see the unit's report. `reality-keys` and the Xray transports use
/// `xray`; the `naive` transport's acceptor runs `sing-box` and its dialer runs `naive`.
pub const PINS: &[Pin] = &[
    Pin {
        name: "sing-box",
        repo: "SagerNet/sing-box",
        version: "v1.14.2",
        binary: "sing-box",
        amd64: Asset {
            asset: "sing-box-1.14.2-linux-amd64.tar.gz",
            sha256: "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6",
        },
        arm64: Asset {
            asset: "sing-box-1.14.2-linux-arm64.tar.gz",
            sha256: "b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f",
        },
    },
    Pin {
        name: "naive",
        repo: "klzgrad/naiveproxy",
        version: "v154.0.8037.49-4",
        binary: "naive",
        amd64: Asset {
            asset: "naiveproxy-v154.0.8037.49-4-linux-x64.tar.xz",
            sha256: "9d765620b90f7c60eb40c7c68b2f82537757cc52a8693dee7a00f8ba8b13dfd0",
        },
        arm64: Asset {
            asset: "naiveproxy-v154.0.8037.49-4-linux-arm64.tar.xz",
            sha256: "dfa99dc36dafa1ee7f97f48bde14e9ee96bc4011e5cc10c7881fa7883859a036",
        },
    },
    Pin {
        name: "xray",
        repo: "XTLS/Xray-core",
        version: "v26.3.27",
        binary: "xray",
        amd64: Asset {
            asset: "Xray-linux-64.zip",
            sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        },
        arm64: Asset {
            asset: "Xray-linux-arm64-v8a.zip",
            sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
        },
    },
];

impl Pin {
    /// The asset for the running CPU; `None` on an unsupported architecture.
    fn asset_for_host(&self) -> Option<&Asset> {
        match std::env::consts::ARCH {
            "x86_64" => Some(&self.amd64),
            "aarch64" => Some(&self.arm64),
            _ => None,
        }
    }

    /// The download URL of the host's asset.
    fn url(&self, asset: &Asset) -> String {
        format!(
            "https://github.com/{}/releases/download/{}/{}",
            self.repo, self.version, asset.asset
        )
    }
}

/// Looks a pin up by its install name.
pub fn pin(name: &str) -> Option<&'static Pin> {
    PINS.iter().find(|p| p.name == name)
}

/// The helpers directory: `KARIZ_HELPERS_DIR` if set, otherwise [`DEFAULT_DIR`].
pub fn helper_dir() -> PathBuf {
    std::env::var_os("KARIZ_HELPERS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

/// The architecture component of an install directory (`x86_64`, `aarch64`, …).
fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// The version directory a helper is (or would be) installed in.
fn version_dir(pin: &Pin) -> PathBuf {
    helper_dir()
        .join(pin.name)
        .join(format!("{}-{}", pin.version, arch()))
}

/// The absolute path of an installed helper binary, if its pinned version is present.
pub fn installed_binary(name: &str) -> Option<PathBuf> {
    let pin = pin(name)?;
    let path = version_dir(pin).join(pin.binary);
    path.is_file().then_some(path)
}

/// Installs a pinned helper. With `from`, uses that local archive instead of downloading;
/// either way the sha256 must match the pin. Refuses to overwrite an existing version
/// directory. Returns the installed binary's path.
pub fn install(name: &str, from: Option<&Path>) -> Result<PathBuf> {
    let pin = pin(name).with_context(|| {
        format!(
            "unknown helper {name:?}; known helpers are {}",
            PINS.iter().map(|p| p.name).collect::<Vec<_>>().join(", ")
        )
    })?;
    let asset = pin
        .asset_for_host()
        .with_context(|| format!("no pinned {} build for this CPU ({})", pin.name, arch()))?;

    let dest = version_dir(pin);
    if dest.exists() {
        bail!(
            "{} {} is already installed at {}; remove it first to reinstall",
            pin.name,
            pin.version,
            dest.display()
        );
    }

    // Stage the archive and the unpacked tree in a temporary directory next to the
    // destination, so a failed install leaves nothing behind.
    let staging = helper_dir()
        .join(pin.name)
        .join(format!(".staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .with_context(|| format!("could not create {}", staging.display()))?;
    let result = (|| {
        let archive = staging.join(asset.asset);
        match from {
            Some(file) => {
                fs::copy(file, &archive)
                    .with_context(|| format!("could not read {}", file.display()))?;
            }
            None => download(&pin.url(asset), &archive)?,
        }
        verify_sha256(&archive, asset.sha256)?;
        let unpacked = staging.join("unpacked");
        fs::create_dir_all(&unpacked)?;
        unpack(&archive, &unpacked)?;
        let binary = find_file(&unpacked, pin.binary)
            .with_context(|| format!("the {} archive did not contain {}", pin.name, pin.binary))?;
        let source_dir = binary.parent().expect("a file has a parent directory");
        fs::create_dir_all(dest.parent().expect("version dir has a parent"))?;
        copy_dir(source_dir, &dest)?;
        let installed = dest.join(pin.binary);
        make_executable(&installed)?;
        Ok(installed)
    })();
    let _ = fs::remove_dir_all(&staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&dest);
    }
    result
}

/// What is installed, as `(name, version-arch)` pairs for each present version directory.
pub fn status() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for pin in PINS {
        let dir = helper_dir().join(pin.name);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if entry.path().join(pin.binary).is_file() {
                found.push((pin.name.to_string(), name));
            }
        }
    }
    found.sort();
    found
}

/// A random UUIDv4 in canonical form, for `tunnel.helper.uuid`.
pub fn gen_uuid() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("{e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// An X25519 key pair for `reality`, via the installed `xray x25519`. Returns
/// `(private_key, public_key)`, both unpadded base64url encoding 32 bytes.
pub fn reality_keys() -> Result<(String, String)> {
    let xray = installed_binary("xray")
        .context("xray is not installed; run `kariz helper install xray` first")?;
    let output = Command::new(&xray)
        .arg("x25519")
        .output()
        .with_context(|| format!("could not run {}", xray.display()))?;
    if !output.status.success() {
        bail!(
            "xray x25519 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut private = None;
    let mut public = None;
    for line in text.lines() {
        let value = line.rsplit(':').next().map(str::trim);
        let lower = line.to_ascii_lowercase();
        if lower.contains("private") {
            private = value.map(str::to_string);
        } else if lower.contains("password") || lower.contains("public") {
            // Later Xray prints `Password (PublicKey): <value>`; older prints `PublicKey:`.
            if public.is_none() {
                public = value.map(str::to_string);
            }
        }
    }
    match (private, public) {
        (Some(private), Some(public)) if !private.is_empty() && !public.is_empty() => {
            Ok((private, public))
        }
        _ => bail!("could not parse the key pair from `xray x25519` output:\n{text}"),
    }
}

fn download(url: &str, to: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args(["-fSL", "--retry", "2", "-o"])
        .arg(to)
        .arg(url)
        .status()
        .context("could not run curl to download the helper; install curl or use --from")?;
    if !status.success() {
        bail!("downloading {url} failed");
    }
    Ok(())
}

fn verify_sha256(file: &Path, expected: &str) -> Result<()> {
    let mut f =
        fs::File::open(file).with_context(|| format!("could not open {}", file.display()))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let got: String = ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != expected {
        bail!("sha256 mismatch: expected {expected}, got {got}");
    }
    Ok(())
}

fn unpack(archive: &Path, into: &Path) -> Result<()> {
    let name = archive.file_name().unwrap_or_default().to_string_lossy();
    let mut cmd = if name.ends_with(".zip") {
        let mut c = Command::new("unzip");
        c.arg("-oq").arg(archive).arg("-d").arg(into);
        c
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let mut c = Command::new("tar");
        c.arg("-xzf").arg(archive).arg("-C").arg(into);
        c
    } else if name.ends_with(".tar.xz") {
        let mut c = Command::new("tar");
        c.arg("-xJf").arg(archive).arg("-C").arg(into);
        c
    } else {
        bail!("unknown archive type for {name}");
    };
    let status = cmd
        .status()
        .with_context(|| format!("could not run the extractor for {name}"))?;
    if !status.success() {
        bail!("extracting {name} failed");
    }
    Ok(())
}

/// Depth-first search for a file named `name` under `root`.
fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|f| f == name) {
                return Some(path);
            }
        }
    }
    None
}

/// Recursively copies the contents of `from` into `to` (creating `to`).
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_well_formed() {
        assert_eq!(PINS.len(), 3);
        for pin in PINS {
            assert!(pin.repo.contains('/'), "{} repo", pin.name);
            assert!(pin.version.starts_with('v'), "{} version", pin.name);
            assert!(!pin.binary.is_empty());
            for asset in [&pin.amd64, &pin.arm64] {
                assert_eq!(asset.sha256.len(), 64, "{} sha len", pin.name);
                assert!(
                    asset.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{} sha hex",
                    pin.name
                );
                assert!(!asset.asset.is_empty());
            }
        }
        assert!(pin("xray").is_some());
        assert!(pin("nope").is_none());
    }

    #[test]
    fn uuid_is_canonical_v4() {
        let id = gen_uuid().unwrap();
        assert_eq!(id.len(), 36);
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(id.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
        assert_eq!(&id[14..15], "4"); // version nibble
    }
}
