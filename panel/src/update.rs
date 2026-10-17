//! Updating the panel from the panel: find a newer release, download it
//! once, check its signature, and swap the programs with a rollback if the new panel does
//! not come up.
//!
//! The parts that decide things are plain functions (which release is newer, is this
//! archive signed, did the swap work), so they are tested without a network or systemd.

use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::sign;

pub const DEFAULT_API: &str = "https://api.github.com/repos/MAHDI-byte64/tun2";
/// The biggest archive the panel will take (the releases are about 5 MB).
const MAX_ARCHIVE: u64 = 200 * 1024 * 1024;
const MAX_SMALL: u64 = 64 * 1024;
/// The most entries an archive may have, and the most the two programs may unpack to.
const MAX_ENTRIES: usize = 500;
const MAX_UNPACKED: u64 = 400 * 1024 * 1024;

// ---- versions ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// `beta` in `0.8.0-beta`; a release with one is older than the same without.
    pub pre: Option<String>,
}

impl Version {
    /// `0.11.0`, `v0.8.0-beta`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_start_matches('v');
        let (core, pre) = match text.split_once('-') {
            Some((c, p)) if !p.is_empty() => (c, Some(p.to_owned())),
            Some(_) => return None,
            None => (text, None),
        };
        let mut parts = core.split('.');
        let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major: a.parse().ok()?,
            minor: b.parse().ok()?,
            patch: c.parse().ok()?,
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_pre(a, b),
            })
    }
}

/// Orders the parts after the dash as semver does: dot-separated, numbers by value (so
/// `beta.10` comes after `beta.9`), a number before a word, and fewer parts first when
/// the rest are equal (`beta` before `beta.1`).
fn cmp_pre(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        let (x, y) = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => (x, y),
        };
        let numeric = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        let order = match (numeric(x), numeric(y)) {
            // Longer digit strings are bigger numbers (leading zeros aside).
            (true, true) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                x.len().cmp(&y.len()).then_with(|| x.cmp(y))
            }
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---- finding a release ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    #[default]
    Stable,
    Beta,
}

impl Channel {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Asset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub notes: String,
    pub prerelease: bool,
    #[serde(skip)]
    pub assets: Vec<Asset>,
    /// The listing came from a repository on this machine (`http://127.0.0.1...`, which only
    /// the tests use): its files may be fetched from there too. From anywhere else only
    /// `https` addresses are followed, so a listing cannot point the panel at a service of
    /// this server.
    #[serde(skip)]
    pub from_local_api: bool,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

/// The releases in the answer of GitHub's `/releases`, drafts left out.
pub fn parse_releases(json: &str) -> Result<Vec<Release>> {
    let list: Vec<ApiRelease> = serde_json::from_str(json).context("bad_release_list")?;
    Ok(list
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let v = Version::parse(&r.tag_name)?;
            Some(Release {
                version: format!(
                    "{}.{}.{}{}",
                    v.major,
                    v.minor,
                    v.patch,
                    v.pre.map(|p| format!("-{p}")).unwrap_or_default()
                ),
                tag: r.tag_name,
                notes: r.body.unwrap_or_default(),
                prerelease: r.prerelease,
                assets: r
                    .assets
                    .into_iter()
                    .map(|a| Asset {
                        name: a.name,
                        url: a.browser_download_url,
                    })
                    .collect(),
                from_local_api: false,
            })
        })
        .collect())
}

/// The newest release of a channel: stable takes only releases that are not prereleases,
/// beta takes any.
pub fn pick(releases: Vec<Release>, channel: Channel) -> Option<Release> {
    releases
        .into_iter()
        .filter(|r| channel == Channel::Beta || (!r.prerelease && !r.version.contains('-')))
        .max_by_key(|r| Version::parse(&r.version))
}

/// Whether installing `latest` over `current` is an update, and if it is one that needs
/// the user's word (a new major version). Downgrades and the same version are refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Newer { major: bool },
    Same,
    Older,
}

pub fn compare(current: &str, latest: &str) -> Step {
    match (Version::parse(current), Version::parse(latest)) {
        (Some(c), Some(l)) if l > c => Step::Newer {
            major: l.major > c.major,
        },
        (Some(c), Some(l)) if l == c => Step::Same,
        _ => Step::Older,
    }
}

/// This machine's name in the archives.
pub fn arch_name() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        "arm" => Some("armv7"),
        _ => None,
    }
}

/// The assets of `tag` for `arch`: the archive, its checksum file and its signature.
pub fn asset_names(tag: &str, arch: &str) -> [String; 3] {
    let base = format!("kariz-{tag}-{arch}-linux.tar.gz");
    [
        base.clone(),
        format!("{base}.sha256"),
        format!("{base}.sig"),
    ]
}

// ---- downloading ----

fn get(url: &str, limit: u64, local: bool) -> Result<Vec<u8>> {
    if !(url.starts_with("https://") || (local && url.starts_with("http://127.0.0.1"))) {
        bail!("bad_url");
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .redirects(5)
        .build();
    let response = agent
        .get(url)
        .set(
            "User-Agent",
            concat!("kariz-panel/", env!("CARGO_PKG_VERSION")),
        )
        .set(
            "Accept",
            "application/vnd.github+json, application/octet-stream",
        )
        .call()
        .map_err(|e| anyhow!("download_failed: {e}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(limit + 1)
        .read_to_end(&mut body)
        .context("download_failed")?;
    if body.len() as u64 > limit {
        bail!("too_large");
    }
    Ok(body)
}

/// The releases of the repository behind `api` (`.../repos/OWNER/REPO`).
pub fn fetch_releases(api: &str) -> Result<Vec<Release>> {
    let local = api.starts_with("http://127.0.0.1");
    let body = get(
        &format!("{}/releases?per_page=20", api.trim_end_matches('/')),
        2 * 1024 * 1024,
        local,
    )?;
    let mut releases =
        parse_releases(std::str::from_utf8(&body).map_err(|_| anyhow!("bad_release_list"))?)?;
    for r in &mut releases {
        r.from_local_api = local;
    }
    Ok(releases)
}

/// Takes `kariz` and `kariz-panel` out of a release archive into `dir`, marked executable.
/// Only those two files, straight under the archive's one top folder, are read.
pub fn extract(archive: &[u8], dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut found = 0;
    let mut total = 0u64;
    for (seen, entry) in tar.entries().context("bad_archive")?.enumerate() {
        // A release has a few dozen files: an archive of thousands, or one that unpacks to
        // far more than it should, is not a release (a decompression bomb).
        if seen >= MAX_ENTRIES {
            bail!("bad_archive");
        }
        let mut entry = entry.context("bad_archive")?;
        let path = entry.path().context("bad_archive")?.into_owned();
        let parts: Vec<_> = path.components().collect();
        let name = match parts.as_slice() {
            [_, last] => last.as_os_str().to_str().unwrap_or_default(),
            _ => continue,
        };
        if !matches!(name, "kariz" | "kariz-panel") || !entry.header().entry_type().is_file() {
            continue;
        }
        let mut data = Vec::new();
        entry.by_ref().take(MAX_ARCHIVE).read_to_end(&mut data)?;
        total += data.len() as u64;
        if total > MAX_UNPACKED {
            bail!("bad_archive");
        }
        let out = dir.join(name);
        std::fs::write(&out, &data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755))?;
        }
        found += 1;
    }
    if found != 2 {
        bail!("bad_archive");
    }
    Ok(())
}

/// Downloads a release for this machine, checks its signature and checksum, and unpacks
/// the two programs into `stage/VERSION/`. Steps are reported through `step` as they
/// start, for the browser to show.
pub fn download(
    release: &Release,
    key_override: Option<&str>,
    stage: &Path,
    step: &dyn Fn(&str),
) -> Result<PathBuf> {
    let arch = arch_name().ok_or_else(|| anyhow!("no_build_for_this_cpu"))?;
    let names = asset_names(&release.tag, arch);
    let url = |name: &str| {
        release
            .assets
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.url.clone())
            .ok_or_else(|| anyhow!("missing_asset:{name}"))
    };
    let key = sign::release_key(key_override)?;
    step("upd_download");
    let archive = get(&url(&names[0])?, MAX_ARCHIVE, release.from_local_api)?;
    let sha = get(&url(&names[1])?, MAX_SMALL, release.from_local_api)?;
    let sig = get(&url(&names[2])?, MAX_SMALL, release.from_local_api)
        .map_err(|_| anyhow!("unsigned"))?;
    step("upd_verify");
    sign::verify_archive(&key, &names[0], &archive, &sha, &sig)?;
    step("upd_stage");
    let dir = stage.join(&release.version);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    extract(&archive, &dir)?;
    // The archive and its proofs stay too: the agents of other servers are given the same
    // files (and check them again themselves).
    let keep = dir.join("release");
    std::fs::create_dir_all(&keep)?;
    for (name, data) in names.iter().zip([&archive, &sha, &sig]) {
        std::fs::write(keep.join(name), data)?;
    }
    Ok(dir)
}

// ---- swapping ----

/// The installed programs the update replaces.
#[derive(Debug, Clone)]
pub struct Targets {
    pub panel: PathBuf,
    pub kariz: PathBuf,
}

/// What restarting and asking the panel is, so the swap can be tested without systemd.
pub trait Host {
    fn restart(&self) -> Result<()>;
    /// Whether the panel answers, and is at `version`.
    fn answers(&self, version: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub version: String,
    pub ok: bool,
    pub rolled_back: bool,
    pub error: Option<String>,
    pub at: i64,
}

fn previous(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".previous");
    PathBuf::from(p)
}

/// Puts `src` at `dst` in one step (a temporary file beside it, then a rename), so a program
/// is never half written.
fn install(src: &Path, dst: &Path) -> Result<()> {
    let mut tmp = dst.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    std::fs::copy(src, &tmp).with_context(|| format!("failed to copy {}", src.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, dst).with_context(|| format!("failed to replace {}", dst.display()))
}

/// Swaps in the staged programs, restarts, and waits for the new panel to answer; if it does
/// not within `wait`, puts the old programs back and restarts again. The old ones stay as
/// `NAME.previous` either way.
pub fn apply(
    stage: &Path,
    targets: &Targets,
    version: &str,
    host: &dyn Host,
    wait: Duration,
    poll: Duration,
    now: i64,
) -> Outcome {
    let done = |ok: bool, rolled_back: bool, error: Option<String>| Outcome {
        version: version.to_owned(),
        ok,
        rolled_back,
        error,
        at: now,
    };
    let pairs = [
        (stage.join("kariz-panel"), &targets.panel),
        (stage.join("kariz"), &targets.kariz),
    ];
    for (new, _) in &pairs {
        if !new.is_file() {
            return done(false, false, Some(format!("missing {}", new.display())));
        }
    }
    // The old programs are kept first; nothing is replaced if that fails.
    for (_, old) in &pairs {
        if old.exists() {
            if let Err(e) = std::fs::copy(old, previous(old)) {
                return done(
                    false,
                    false,
                    Some(format!("could not keep {}: {e}", old.display())),
                );
            }
        }
    }
    let restore = |host: &dyn Host| {
        for (_, old) in &pairs {
            let keep = previous(old);
            if keep.exists() {
                let _ = std::fs::rename(&keep, old);
            }
        }
        let _ = host.restart();
    };
    for (new, old) in &pairs {
        if let Err(e) = install(new, old) {
            restore(host);
            return done(false, true, Some(format!("{e:#}")));
        }
    }
    if let Err(e) = host.restart() {
        restore(host);
        return done(
            false,
            true,
            Some(format!("the panel did not restart: {e:#}")),
        );
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        if host.answers(version) {
            return done(true, false, None);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(poll);
    }
    restore(host);
    done(
        false,
        true,
        Some(format!(
            "the new panel did not answer as {version} within {} s",
            wait.as_secs()
        )),
    )
}

/// The real host: `systemctl restart UNIT`, and the panel's own `/api/version` asked over
/// TLS with the panel's certificate pinned (it is self-signed).
pub struct SystemHost {
    pub unit: String,
    /// `panel.toml`'s `listen`, `path` and the certificate's SHA-256.
    pub listen: String,
    pub path: String,
    pub pin: String,
}

impl Host for SystemHost {
    fn restart(&self) -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["restart", &self.unit])
            .status()
            .context("failed to run systemctl")?;
        if status.success() {
            Ok(())
        } else {
            bail!("systemctl restart {} failed", self.unit)
        }
    }

    fn answers(&self, version: &str) -> bool {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return false;
        };
        let asked = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                panel_version(&self.listen, &self.path, &self.pin),
            )
            .await
        });
        matches!(asked, Ok(Ok(v)) if v == version)
    }
}

/// The version a panel reports at `listen`, asked with a pinned certificate.
pub async fn panel_version(listen: &str, path: &str, pin: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = listen.rsplit(':').next().unwrap_or("0");
    let host = if listen.starts_with('[') {
        "[::1]"
    } else {
        "127.0.0.1"
    };
    let tcp = tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;
    let tls = kariz::transport::tls::Client::new(
        Some(&kariz::config::TlsConfig {
            pin_sha256: Some(pin.to_owned()),
            ..Default::default()
        }),
        "kariz-panel",
    )?;
    let mut stream = tls.connect(tcp).await?;
    stream
        .write_all(
            format!("GET /{path}/api/version HTTP/1.1\r\nHost: kariz-panel\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut reply = Vec::new();
    stream.take(64 * 1024).read_to_end(&mut reply).await.ok();
    let text = String::from_utf8_lossy(&reply);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    let doc: serde_json::Value = serde_json::from_str(body.trim()).context("not the panel")?;
    doc["version"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no version"))
}

pub const RESULT_FILE: &str = "last-update.json";

pub fn write_outcome(dir: &Path, outcome: &Outcome) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(RESULT_FILE), serde_json::to_vec_pretty(outcome)?)?;
    Ok(())
}

pub fn read_outcome(dir: &Path) -> Option<Outcome> {
    serde_json::from_slice(&std::fs::read(dir.join(RESULT_FILE)).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(v("v0.11.0"), v("0.11.0"));
        assert!(v("0.11.0") > v("0.10.9"));
        assert!(v("0.10.0") > v("0.9.9"), "0.10 is after 0.9, not before");
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.8.0") > v("0.8.0-beta"), "a release beats its own beta");
        assert!(v("0.8.0-beta") > v("0.7.9"));
        // Betas in order, also past nine.
        let betas = [
            "2.4.0-beta",
            "2.4.0-beta.1",
            "2.4.0-beta.2",
            "2.4.0-beta.9",
            "2.4.0-beta.10",
            "2.4.0-rc.1",
            "2.4.0",
        ];
        for pair in betas.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert!(v("2.4.0-1") < v("2.4.0-beta"), "a number before a word");
        assert_eq!(v("2.4.0-beta.01"), v("2.4.0-beta.01"));
        for bad in ["", "1.2", "1.2.3.4", "a.b.c", "1.2.3-", "latest"] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
    }

    fn release(tag: &str, pre: bool) -> Release {
        Release {
            tag: tag.into(),
            version: tag.trim_start_matches('v').into(),
            notes: String::new(),
            prerelease: pre,
            assets: vec![],
            from_local_api: false,
        }
    }

    #[test]
    fn a_channel_picks_the_newest_release_it_may() {
        let all = vec![
            release("v0.10.0", false),
            release("v0.11.0-beta", true),
            release("v0.9.0", false),
        ];
        assert_eq!(pick(all.clone(), Channel::Stable).unwrap().tag, "v0.10.0");
        assert_eq!(pick(all, Channel::Beta).unwrap().tag, "v0.11.0-beta");
        assert!(pick(vec![release("v0.8.0-beta", true)], Channel::Stable).is_none());
        assert!(pick(vec![], Channel::Beta).is_none());
        assert_eq!(Channel::parse("beta"), Some(Channel::Beta));
        assert_eq!(Channel::parse("nightly"), None);
    }

    #[test]
    fn only_a_newer_release_is_an_update_and_a_new_major_is_marked() {
        assert_eq!(compare("0.10.0", "0.11.0"), Step::Newer { major: false });
        assert_eq!(compare("0.10.0", "0.10.0"), Step::Same);
        assert_eq!(compare("0.11.0", "0.10.0"), Step::Older, "no downgrades");
        assert_eq!(compare("0.10.0", "0.10.0-beta"), Step::Older);
        assert_eq!(compare("0.9.0", "1.0.0"), Step::Newer { major: true });
        assert_eq!(compare("1.4.0", "2.0.0"), Step::Newer { major: true });
        assert_eq!(compare("junk", "1.0.0"), Step::Older);
    }

    #[test]
    fn github_s_list_is_read_without_drafts() {
        let json = r#"[
            {"tag_name":"v0.11.0","body":"notes","prerelease":false,"draft":false,
             "assets":[{"name":"kariz-v0.11.0-x86_64-linux.tar.gz","browser_download_url":"https://example.test/a"}]},
            {"tag_name":"v0.12.0","prerelease":false,"draft":true,"assets":[]},
            {"tag_name":"nightly","prerelease":true,"assets":[]},
            {"tag_name":"v0.10.0-beta","prerelease":true,"assets":[]}
        ]"#;
        let list = parse_releases(json).unwrap();
        assert_eq!(
            list.iter().map(|r| r.tag.as_str()).collect::<Vec<_>>(),
            ["v0.11.0", "v0.10.0-beta"]
        );
        assert_eq!(list[0].notes, "notes");
        assert_eq!(list[0].assets[0].url, "https://example.test/a");
        assert!(parse_releases("not json").is_err());
    }

    #[test]
    fn asset_names_follow_the_release_workflow() {
        assert_eq!(
            asset_names("v0.11.0", "aarch64"),
            [
                "kariz-v0.11.0-aarch64-linux.tar.gz",
                "kariz-v0.11.0-aarch64-linux.tar.gz.sha256",
                "kariz-v0.11.0-aarch64-linux.tar.gz.sig"
            ]
        );
    }

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn only_the_two_programs_are_taken_from_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let a = archive(&[
            ("kariz-v1/kariz", b"core"),
            ("kariz-v1/kariz-panel", b"panel"),
            ("kariz-v1/README.md", b"docs"),
            ("kariz-v1/scripts/kariz.sh", b"script"),
            ("other-folder/deep/kariz", b"not this one"),
        ]);
        extract(&a, dir.path()).unwrap();
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["kariz", "kariz-panel"]);
        assert_eq!(
            std::fs::read(dir.path().join("kariz-panel")).unwrap(),
            b"panel"
        );
        // a release without one of them is refused
        let dir2 = tempfile::tempdir().unwrap();
        assert!(extract(&archive(&[("kariz-v1/kariz", b"core")]), dir2.path()).is_err());
        assert!(extract(b"not an archive", dir2.path()).is_err());
    }

    /// A fake host: restarts are counted, and the panel answers when told to.
    struct Fake {
        restarts: Cell<u32>,
        answers_after: u32,
        log: RefCell<Vec<String>>,
        fail_restart: bool,
    }

    impl Host for Fake {
        fn restart(&self) -> Result<()> {
            self.restarts.set(self.restarts.get() + 1);
            self.log.borrow_mut().push("restart".into());
            if self.fail_restart && self.restarts.get() == 1 {
                bail!("systemctl failed");
            }
            Ok(())
        }
        fn answers(&self, _: &str) -> bool {
            self.restarts.get() >= self.answers_after && self.restarts.get() > 0
        }
    }

    fn setup() -> (tempfile::TempDir, PathBuf, Targets) {
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("kariz-panel"), b"NEW panel").unwrap();
        std::fs::write(stage.join("kariz"), b"NEW core").unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("kariz-panel"), b"OLD panel").unwrap();
        std::fs::write(bin.join("kariz"), b"OLD core").unwrap();
        let targets = Targets {
            panel: bin.join("kariz-panel"),
            kariz: bin.join("kariz"),
        };
        (root, stage, targets)
    }

    fn read(p: &Path) -> String {
        String::from_utf8(std::fs::read(p).unwrap()).unwrap()
    }

    #[test]
    fn a_good_update_replaces_both_programs_and_keeps_the_old_ones() {
        let (_root, stage, t) = setup();
        let host = Fake {
            restarts: Cell::new(0),
            answers_after: 1,
            log: RefCell::default(),
            fail_restart: false,
        };
        let o = apply(
            &stage,
            &t,
            "0.11.0",
            &host,
            Duration::from_secs(2),
            Duration::from_millis(5),
            7,
        );
        assert!(o.ok && !o.rolled_back && o.error.is_none(), "{o:?}");
        assert_eq!(read(&t.panel), "NEW panel");
        assert_eq!(read(&t.kariz), "NEW core");
        assert_eq!(read(&previous(&t.panel)), "OLD panel");
        assert_eq!(read(&previous(&t.kariz)), "OLD core");
        assert_eq!(host.restarts.get(), 1);
    }

    #[test]
    fn a_new_panel_that_does_not_answer_is_rolled_back() {
        let (_root, stage, t) = setup();
        let host = Fake {
            restarts: Cell::new(0),
            answers_after: 99,
            log: RefCell::default(),
            fail_restart: false,
        };
        let o = apply(
            &stage,
            &t,
            "0.11.0",
            &host,
            Duration::from_millis(60),
            Duration::from_millis(5),
            7,
        );
        assert!(!o.ok && o.rolled_back, "{o:?}");
        assert!(o.error.unwrap().contains("did not answer"));
        assert_eq!(read(&t.panel), "OLD panel");
        assert_eq!(read(&t.kariz), "OLD core");
        assert_eq!(
            host.restarts.get(),
            2,
            "restarted once to try, once to go back"
        );
    }

    #[test]
    fn a_restart_that_fails_is_rolled_back_too() {
        let (_root, stage, t) = setup();
        let host = Fake {
            restarts: Cell::new(0),
            answers_after: 1,
            log: RefCell::default(),
            fail_restart: true,
        };
        let o = apply(
            &stage,
            &t,
            "0.11.0",
            &host,
            Duration::from_millis(60),
            Duration::from_millis(5),
            7,
        );
        assert!(!o.ok && o.rolled_back);
        assert_eq!(read(&t.panel), "OLD panel");
    }

    #[test]
    fn nothing_is_replaced_when_a_staged_program_is_missing() {
        let (_root, stage, t) = setup();
        std::fs::remove_file(stage.join("kariz")).unwrap();
        let host = Fake {
            restarts: Cell::new(0),
            answers_after: 1,
            log: RefCell::default(),
            fail_restart: false,
        };
        let o = apply(
            &stage,
            &t,
            "0.11.0",
            &host,
            Duration::from_millis(50),
            Duration::from_millis(5),
            7,
        );
        assert!(!o.ok && !o.rolled_back);
        assert_eq!(read(&t.panel), "OLD panel");
        assert_eq!(host.restarts.get(), 0);
    }

    #[test]
    fn the_result_is_kept_for_the_panel_to_show() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_outcome(dir.path()).is_none());
        let o = Outcome {
            version: "0.11.0".into(),
            ok: false,
            rolled_back: true,
            error: Some("x".into()),
            at: 5,
        };
        write_outcome(dir.path(), &o).unwrap();
        assert_eq!(read_outcome(dir.path()), Some(o));
    }

    #[test]
    fn urls_that_are_not_https_are_refused() {
        for bad in [
            "http://example.com/x",
            "file:///etc/passwd",
            "ftp://x",
            "//x",
        ] {
            assert!(get(bad, 10, false).is_err(), "{bad}");
            assert!(get(bad, 10, true).is_err(), "{bad}");
        }
        // A repository on this machine is for the tests: from a real listing, a file on
        // this server's own ports is out of reach (no request to an internal service).
        for internal in ["http://127.0.0.1:1/x", "http://127.0.0.1/secret"] {
            assert_eq!(
                format!("{:#}", get(internal, 10, false).unwrap_err()),
                "bad_url"
            );
        }
    }

    #[test]
    fn an_archive_of_thousands_of_files_is_not_a_release() {
        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..(MAX_ENTRIES + 5) {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("kariz-x/file{i}"), &b"x"[..])
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = extract(&gz.finish().unwrap(), dir.path()).unwrap_err();
        assert_eq!(format!("{err:#}"), "bad_archive");
    }
}
