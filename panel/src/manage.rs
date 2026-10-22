//! What an agent does to its server's tunnels when the panel asks: check and write a config from a structured spec, read it back, control its
//! service, delete it, list the listening ports, read the log, run the speed test.
//!
//! Nothing here takes a command, a path or a piece of config text from the panel: the file
//! is rendered from typed fields (so a value cannot add a line to it), the name is checked
//! against a strict pattern, and the programs that run get fixed arguments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use kariz::config::{mode_name, role_name, Config, Role};

use crate::wire::{CheckReply, ForwardInfo, PortOwner, Spec, SpeedReply, TextReply};

const PLACEHOLDER_TOKEN: &str = "0000000000000000000000000000000000000000000000000000";

/// A tunnel's name is its file name and its service (`kariz@NAME`): small letters, digits
/// and dashes, and it starts with a letter or a digit.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn config_path(dir: &Path, name: &str) -> Result<PathBuf> {
    if !valid_name(name) {
        bail!("a tunnel name is 1 to 32 characters: small letters, digits and dashes");
    }
    Ok(dir.join(format!("{name}.toml")))
}

/// The token a config already holds.
fn existing_token(path: &Path) -> Option<String> {
    let value: toml::Value = toml::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    Some(value.get("tunnel")?.get("token")?.as_str()?.to_owned())
}

/// The config file for a spec, with `token` in it.
pub fn render(spec: &Spec, token: &str, cert_files: Option<(&Path, &Path)>) -> Result<String> {
    use toml::{Table, Value};
    let text = |s: &str| Value::String(s.to_owned());
    let mut root = Table::new();
    root.insert("role".into(), text(&spec.role));
    root.insert("mode".into(), text(&spec.mode));
    if let Some(profile) = &spec.profile {
        root.insert("profile".into(), text(profile));
    }
    // The `l3` tile is the panel's name for the GRE direct-tunnel mode: it has no core
    // transport of its own (the carrier lives in `[l3]`), so `[tunnel].transport` is left
    // at its default and the address and forward rules move into `[l3]`.
    let is_l3 = spec.transport == "l3";
    let mut tunnel = Table::new();
    if !is_l3 {
        tunnel.insert("transport".into(), text(&spec.transport));
    }
    if let Some(cipher) = spec.encryption.as_deref().filter(|c| *c != "auto") {
        tunnel.insert("encryption".into(), text(cipher));
    }
    if spec.quic_obfs && spec.transport == "quic" {
        let mut quic = Table::new();
        quic.insert("obfs".into(), Value::Boolean(true));
        tunnel.insert("quic".into(), Value::Table(quic));
    }
    if let Some(s) = spec.stealth.as_ref().filter(|s| !s.is_empty()) {
        if spec.transport == "stealth" {
            let mut t = Table::new();
            if let Some(v) = s.padding {
                t.insert("padding".into(), Value::Boolean(v));
            }
            if let Some(v) = s.pad_max {
                t.insert("pad_max".into(), Value::Integer(i64::from(v)));
            }
            if let Some(v) = s.jitter_ms {
                t.insert("jitter_ms".into(), Value::Integer(i64::from(v)));
            }
            tunnel.insert("stealth".into(), Value::Table(t));
        }
    }
    if let Some(f) = spec.faketcp.as_ref().filter(|f| !f.is_empty()) {
        if spec.transport == "faketcp" {
            let mut t = Table::new();
            if let Some(flags) = &f.flags {
                t.insert("flags".into(), text(flags));
            }
            if let Some(v) = f.manage_firewall {
                t.insert("manage_firewall".into(), Value::Boolean(v));
            }
            tunnel.insert("faketcp".into(), Value::Table(t));
        }
    }
    if let Some(i) = spec.icmp.as_ref().filter(|i| !i.is_empty()) {
        if spec.transport == "icmp" {
            let mut t = Table::new();
            if let Some(v) = i.manage_firewall {
                t.insert("manage_firewall".into(), Value::Boolean(v));
            }
            tunnel.insert("icmp".into(), Value::Table(t));
        }
    }
    if let Some(s) = spec.spoof.as_ref().filter(|s| !s.is_empty()) {
        if spec.transport == "spoof" {
            let mut t = Table::new();
            if let Some(shape) = &s.shape {
                t.insert("shape".into(), text(shape));
            }
            if !s.pool.is_empty() {
                let pool = s.pool.iter().map(|p| text(p)).collect::<Vec<_>>();
                t.insert("pool".into(), Value::Array(pool));
            }
            if let Some(peer) = &s.peer {
                t.insert("peer".into(), text(peer));
            }
            if let Some(v) = s.manage_firewall {
                t.insert("manage_firewall".into(), Value::Boolean(v));
            }
            tunnel.insert("spoof".into(), Value::Table(t));
        }
    }
    if let Some(h) = spec.helper.as_ref().filter(|h| !h.is_empty()) {
        if matches!(spec.transport.as_str(), "naive" | "xhttp" | "reality") {
            tunnel.insert("helper".into(), Value::Table(helper_table(h, text)));
        }
    }
    if !is_l3 {
        if let Some(listen) = &spec.listen {
            tunnel.insert("listen".into(), text(listen));
        }
        if let Some(remote) = &spec.remote {
            tunnel.insert("remote".into(), text(remote));
        }
    }
    tunnel.insert("token".into(), text(token));
    if let Some(pool) = spec.pool {
        tunnel.insert("pool".into(), Value::Integer(i64::from(pool)));
    }
    if spec.ws_path.is_some() || spec.ws_host.is_some() {
        let mut ws = Table::new();
        if let Some(path) = &spec.ws_path {
            ws.insert("path".into(), text(path));
        }
        if let Some(host) = &spec.ws_host {
            ws.insert("host".into(), text(host));
        }
        tunnel.insert("ws".into(), Value::Table(ws));
    }
    if let Some(mux) = spec.mux.as_ref().filter(|m| !m.is_empty()) {
        let mut t = Table::new();
        let int = |v: u64| Value::Integer(i64::try_from(v).unwrap_or(i64::MAX));
        if let Some(v) = mux.enabled {
            t.insert("enabled".into(), Value::Boolean(v));
        }
        if let Some(v) = mux.connections {
            t.insert("connections".into(), int(v.into()));
        }
        if let Some(v) = mux.max_streams {
            t.insert("max_streams".into(), int(v.into()));
        }
        if let Some(v) = mux.stream_window {
            t.insert("stream_window".into(), int(v.into()));
        }
        if let Some(v) = mux.max_lifetime_secs {
            t.insert("max_lifetime_secs".into(), int(v));
        }
        if let Some(v) = mux.ping_interval_secs {
            t.insert("ping_interval_secs".into(), int(v));
        }
        if let Some(v) = mux.coalesce {
            t.insert("coalesce".into(), Value::Boolean(v));
        }
        tunnel.insert("mux".into(), Value::Table(t));
    }
    if let Some((cert, key)) = cert_files {
        // A listening wss side serves the certificate this agent made for it.
        let mut tls = Table::new();
        tls.insert("cert".into(), text(&cert.to_string_lossy()));
        tls.insert("key".into(), text(&key.to_string_lossy()));
        tunnel.insert("tls".into(), Value::Table(tls));
    } else if spec.tls_sni.is_some() || spec.tls_pin.is_some() {
        let mut tls = Table::new();
        if let Some(sni) = &spec.tls_sni {
            tls.insert("sni".into(), text(sni));
        }
        if let Some(pin) = &spec.tls_pin {
            tls.insert("pin_sha256".into(), text(pin));
        }
        tunnel.insert("tls".into(), Value::Table(tls));
    }
    root.insert("tunnel".into(), Value::Table(tunnel));
    let mut tuning = Table::new();
    if let Some(limit) = spec.max_conns_per_ip.filter(|v| *v > 0) {
        tuning.insert("max_conns_per_ip".into(), Value::Integer(i64::from(limit)));
    }
    if let Some(flows) = spec.udp_max_flows.filter(|v| *v > 0) {
        tuning.insert("udp_max_flows".into(), Value::Integer(i64::from(flows)));
    }
    if !tuning.is_empty() {
        root.insert("tuning".into(), Value::Table(tuning));
    }
    let forwards: Vec<Value> = spec
        .forwards
        .iter()
        .map(|f| {
            let mut t = Table::new();
            t.insert("listen".into(), text(&f.listen));
            t.insert("target".into(), text(&f.target));
            t.insert("protocol".into(), text(&f.protocol));
            // PROXY headers are for TCP: a UDP rule would refuse the setting.
            if let Some(v) = &spec.proxy_protocol {
                if matches!(f.protocol.as_str(), "tcp" | "tcp+udp") {
                    t.insert("proxy_protocol".into(), text(v));
                }
            }
            Value::Table(t)
        })
        .collect();
    if is_l3 {
        // The GRE tunnel carries whole packets: its address, carrier and the (optional)
        // forward rules over the TUN link all live in `[l3]`, not the port-forwarding tables.
        let l3 = spec
            .l3
            .as_ref()
            .ok_or_else(|| anyhow!("the l3 tunnel is missing its [l3] settings"))?;
        let mut t = Table::new();
        t.insert(
            "mode".into(),
            text(if is_acceptor(spec) { "listen" } else { "dial" }),
        );
        let addr = if is_acceptor(spec) {
            spec.listen.as_deref()
        } else {
            spec.remote.as_deref()
        };
        t.insert(
            "addr".into(),
            text(addr.ok_or_else(|| anyhow!("the l3 tunnel is missing its address"))?),
        );
        t.insert("carrier".into(), text(&l3.carrier));
        if let Some(v) = l3.layer {
            t.insert("layer".into(), Value::Integer(i64::from(v)));
        }
        if let Some(ip) = &l3.local_ip {
            t.insert("local_ip".into(), text(ip));
        }
        if let Some(ip) = &l3.peer_ip {
            t.insert("peer_ip".into(), text(ip));
        }
        if let Some(v) = l3.gre_key {
            t.insert("gre_key".into(), Value::Integer(i64::from(v)));
        }
        if let Some(v) = l3.mtu {
            t.insert("mtu".into(), Value::Integer(i64::from(v)));
        }
        if l3.accept_udp {
            t.insert("accept_udp".into(), Value::Boolean(true));
        }
        if !forwards.is_empty() {
            t.insert("ports".into(), Value::Array(forwards));
        }
        root.insert("l3".into(), Value::Table(t));
    } else if !forwards.is_empty() {
        root.insert("forward".into(), Value::Array(forwards));
    }
    toml::to_string_pretty(&root).context("failed to render the config")
}

/// The `[tunnel.helper]` table for a managed-helper side. Only the keys this side needs are
/// present (the acceptor's spec carries the server secrets, the dialer's the client ones);
/// `render` writes whatever is set.
fn helper_table(h: &crate::wire::HelperSpec, text: impl Fn(&str) -> toml::Value) -> toml::Table {
    let mut t = toml::Table::new();
    let mut put = |key: &str, v: &Option<String>| {
        if let Some(s) = v {
            t.insert(key.into(), text(s));
        }
    };
    put("binary", &h.binary);
    put("username", &h.username);
    put("password", &h.password);
    put("uuid", &h.uuid);
    put("path", &h.path);
    put("server_name", &h.server_name);
    put("host", &h.host);
    put("short_id", &h.short_id);
    put("private_key", &h.private_key);
    put("public_key", &h.public_key);
    put("target", &h.target);
    put("certificate", &h.certificate);
    put("key", &h.key);
    put("ca_file", &h.ca_file);
    t
}

/// Renders and validates a spec (the token of an existing file is kept when the spec has
/// none). The text and the parsed config come back.
fn build(dir: &Path, spec: &Spec, for_check: bool) -> Result<(String, Config)> {
    let path = config_path(dir, &spec.name)?;
    let token = match (&spec.token, existing_token(&path)) {
        (Some(t), _) => t.clone(),
        (None, Some(t)) => t,
        (None, None) if for_check => PLACEHOLDER_TOKEN.to_owned(),
        (None, None) => bail!("a new tunnel needs a token"),
    };
    if token.len() < 16 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("the token is too short or has characters it should not");
    }
    plain_text(spec)?;
    let files = cert_files(dir, spec);
    let text = render(
        spec,
        &token,
        files.as_ref().map(|(c, k)| (c.as_path(), k.as_path())),
    )?;
    let config = Config::parse(&text)?;
    Ok((text, config))
}

/// Whether this side of the spec listens for the tunnel.
fn is_acceptor(spec: &Spec) -> bool {
    matches!(
        (spec.role.as_str(), spec.mode.as_str()),
        ("entry", "reverse") | ("exit", "direct")
    )
}

/// The certificate and key of a listening wss side, beside its config.
fn cert_files(dir: &Path, spec: &Spec) -> Option<(PathBuf, PathBuf)> {
    if !(spec.transport == "wss" && is_acceptor(spec)) {
        return None;
    }
    if let Some(own) = own_cert(spec) {
        return Some(own);
    }
    Some((
        dir.join(format!("{}.crt", spec.name)),
        dir.join(format!("{}.key", spec.name)),
    ))
}

/// Where Let's Encrypt keeps the certificates the manager gets (the only place a spec may
/// name a certificate from: the agent never reads another file on the panel's say).
const LIVE: &str = "/etc/letsencrypt/live/";

/// Whether `path` is a certificate or key file under [`LIVE`].
pub fn valid_cert_path(path: &str) -> bool {
    path.starts_with(LIVE)
        && path.ends_with(".pem")
        && !path.contains("..")
        && path.len() < 200
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
}

/// The files of a real certificate a spec names, if it names a valid pair.
fn own_cert(spec: &Spec) -> Option<(PathBuf, PathBuf)> {
    let (cert, key) = (spec.tls_cert.as_deref()?, spec.tls_key.as_deref()?);
    (valid_cert_path(cert) && valid_cert_path(key))
        .then(|| (PathBuf::from(cert), PathBuf::from(key)))
}

/// Every text field of a spec is one plain line: no control characters, so nothing a
/// panel sends can break out of its value.
fn plain_text(spec: &Spec) -> Result<()> {
    if spec.tls_cert.is_some() != spec.tls_key.is_some() {
        bail!("a certificate needs its key too");
    }
    if let (Some(cert), Some(key)) = (&spec.tls_cert, &spec.tls_key) {
        if !valid_cert_path(cert) || !valid_cert_path(key) {
            bail!("a certificate must be one the manager got (under {LIVE})");
        }
    }
    // A managed helper's acceptor certificate and key are read by the helper, so they must
    // be under the same trusted directory as a wss certificate.
    if let Some(h) = &spec.helper {
        for path in [&h.certificate, &h.key, &h.ca_file].into_iter().flatten() {
            if !valid_cert_path(path) {
                bail!("a helper certificate must be one the manager got (under {LIVE})");
            }
        }
    }
    let optional = [
        &spec.encryption,
        &spec.profile,
        &spec.listen,
        &spec.remote,
        &spec.ws_path,
        &spec.ws_host,
        &spec.tls_sni,
        &spec.tls_pin,
        &spec.proxy_protocol,
    ];
    let helper = spec.helper.iter().flat_map(|h| {
        [
            &h.binary,
            &h.username,
            &h.password,
            &h.uuid,
            &h.path,
            &h.server_name,
            &h.host,
            &h.short_id,
            &h.private_key,
            &h.public_key,
            &h.target,
        ]
    });
    let l3 = spec.l3.iter().flat_map(|l| {
        std::iter::once(&l.carrier)
            .chain(l.local_ip.as_ref())
            .chain(l.peer_ip.as_ref())
    });
    let stealth_flags = spec.faketcp.iter().filter_map(|f| f.flags.as_ref());
    let fields = [&spec.role, &spec.mode, &spec.transport]
        .into_iter()
        .chain(optional.into_iter().flatten())
        .chain(helper.flatten())
        .chain(l3)
        .chain(stealth_flags)
        .chain(
            spec.forwards
                .iter()
                .flat_map(|f| [&f.listen, &f.target, &f.protocol]),
        );
    for value in fields {
        if value.len() > 512 || value.chars().any(char::is_control) {
            bail!("a value is too long or has control characters in it");
        }
    }
    Ok(())
}

/// The protocol the accepting side listens with, from the transport (for `l3`, from its
/// carrier). `icmp` answers raw echoes and `proto47` rides raw protocol 47, so they bind no
/// port and have none.
fn listen_proto(spec: &Spec) -> Option<&'static str> {
    let carrier = if spec.transport == "l3" {
        spec.l3.as_ref().map_or("udp", |l| l.carrier.as_str())
    } else {
        spec.transport.as_str()
    };
    match carrier {
        "icmp" | "proto47" => None,
        "quic" | "kcp" | "udp" => Some("udp"),
        _ => Some("tcp"),
    }
}

/// The (protocol, port) pairs a spec listens on.
pub fn wanted_ports(spec: &Spec) -> Vec<(&'static str, u16)> {
    let mut out = Vec::new();
    let port =
        |addr: &str| -> Option<u16> { addr.rsplit_once(':').map_or(addr, |(_, p)| p).parse().ok() };
    if is_acceptor(spec) {
        if let (Some(proto), Some(p)) = (listen_proto(spec), spec.listen.as_deref().and_then(port))
        {
            out.push((proto, p));
            // Auto listens for all of its transports: UDP on the port too, and a
            // WebSocket on the next one.
            if spec.transport == "auto" {
                out.push(("udp", p));
                if let Some(next) = p.checked_add(1) {
                    out.push(("tcp", next));
                }
            }
        }
    }
    if spec.role == "entry" {
        for f in &spec.forwards {
            let Some(p) = port(&f.listen) else { continue };
            if f.protocol.contains("tcp") || f.protocol.is_empty() {
                out.push(("tcp", p));
            }
            if f.protocol.contains("udp") {
                out.push(("udp", p));
            }
        }
    }
    out
}

/// Validates a spec on this server and says which of its ports are taken by others.
pub fn check(dir: &Path, owners: &[PortOwner], spec: &Spec) -> CheckReply {
    let config = match build(dir, spec, true) {
        Ok((_, c)) => c,
        Err(e) => {
            return CheckReply {
                ok: false,
                error: Some(format!("{e:#}")),
                ..Default::default()
            }
        }
    };
    // What the tunnel of this name holds now is not a conflict: it is being replaced.
    let own: Vec<(&str, u16)> = get(dir, &spec.name)
        .map(|old| wanted_ports(&old))
        .unwrap_or_default();
    let conflicts: Vec<PortOwner> = wanted_ports(spec)
        .into_iter()
        .filter(|w| !own.contains(w))
        .flat_map(|(proto, port)| {
            owners
                .iter()
                .filter(move |o| o.proto == proto && o.port == port)
                .cloned()
        })
        .collect();
    CheckReply {
        ok: conflicts.is_empty(),
        error: (!conflicts.is_empty()).then(|| "a port is already in use".to_owned()),
        warnings: config.warnings().iter().map(|w| (*w).to_owned()).collect(),
        conflicts,
    }
}

/// Writes the config (0600), keeping the previous file as `NAME.toml.bak`. A listening wss
/// side gets a self-signed certificate made for it (once); its pin comes back, for the
/// dialing side.
pub fn put(dir: &Path, spec: &Spec) -> Result<Option<String>> {
    let (text, _) = build(dir, spec, false)?;
    let path = config_path(dir, &spec.name)?;
    let pin = match cert_files(dir, spec) {
        // A real certificate: its files must be there; nothing is pinned (the other side
        // checks the certificate against the web's roots).
        Some((cert, key)) if own_cert(spec).is_some() => {
            if !cert.exists() || !key.exists() {
                bail!("the certificate files are not there: get the certificate again");
            }
            None
        }
        Some((cert, key)) => Some(crate::cert::ensure(&cert, &key)?),
        None => None,
    };
    if path.exists() {
        let mut bak = path.as_os_str().to_owned();
        bak.push(".bak");
        let old = std::fs::read(&path)?;
        crate::agent::write_private(Path::new(&bak), &old)?;
    }
    crate::agent::write_private(&path, text.as_bytes())?;
    Ok(pin)
}

/// The spec of an existing tunnel, without its token.
pub fn get(dir: &Path, name: &str) -> Result<Spec> {
    let path = config_path(dir, name)?;
    let c = Config::load(&path)?;
    // The GRE direct-tunnel mode is the `l3` tile: its address and forward rules live in
    // `[l3]`, so they are read from there and the carrier stands in for the transport name.
    let (transport, listen, remote) = match &c.l3 {
        Some(l3) if matches!(l3.mode, kariz::config::L3Mode::Listen) => {
            ("l3".to_owned(), Some(l3.addr.clone()), None)
        }
        Some(l3) => ("l3".to_owned(), None, Some(l3.addr.clone())),
        None => (
            c.tunnel.transport.name().to_owned(),
            c.tunnel.listen.clone(),
            c.tunnel.remote.clone(),
        ),
    };
    Ok(Spec {
        name: name.to_owned(),
        role: role_name(c.role).to_owned(),
        mode: mode_name(c.mode).to_owned(),
        transport,
        profile: Some(c.profile.name().to_owned()),
        listen,
        remote,
        token: None,
        pool: Some(u32::try_from(c.tunnel.pool).unwrap_or(8)),
        ws_path: c.tunnel.ws.as_ref().map(|w| w.path.clone()),
        ws_host: c.tunnel.ws.as_ref().and_then(|w| w.host.clone()),
        encryption: (c.tunnel.encryption != kariz::config::Encryption::Auto)
            .then(|| c.tunnel.encryption.name().to_owned()),
        quic_obfs: c.tunnel.quic.as_ref().is_some_and(|q| q.obfs),
        max_conns_per_ip: c.tuning.max_conns_per_ip.filter(|v| *v > 0),
        udp_max_flows: c.tuning.udp_max_flows.and_then(|v| u32::try_from(v).ok()),
        // The panel writes the same one on every TCP rule.
        proxy_protocol: c
            .forward
            .iter()
            .find(|f| f.protocol.has_tcp())
            .and_then(|f| f.proxy_protocol)
            .map(|v| v.name().to_owned()),
        mux: Some(crate::wire::MuxSpec {
            enabled: c.tunnel.mux.enabled,
            connections: c.tunnel.mux.connections.and_then(|v| u32::try_from(v).ok()),
            max_streams: c.tunnel.mux.max_streams.and_then(|v| u32::try_from(v).ok()),
            stream_window: c
                .tunnel
                .mux
                .stream_window
                .and_then(|v| u32::try_from(v).ok()),
            max_lifetime_secs: c.tunnel.mux.max_lifetime_secs,
            ping_interval_secs: c.tunnel.mux.ping_interval_secs,
            coalesce: c.tunnel.mux.coalesce,
        })
        .filter(|m| !m.is_empty()),
        tls_sni: c.tunnel.tls.as_ref().and_then(|t| t.sni.clone()),
        tls_cert: c
            .tunnel
            .tls
            .as_ref()
            .and_then(|t| t.cert.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|p| valid_cert_path(p)),
        tls_key: c
            .tunnel
            .tls
            .as_ref()
            .and_then(|t| t.key.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|p| valid_cert_path(p)),
        tls_pin: c.tunnel.tls.as_ref().and_then(|t| {
            t.pin_sha256.clone().or_else(|| {
                t.cert
                    .as_deref()
                    .and_then(|p| crate::cert::fingerprint(p).ok())
            })
        }),
        // The l3 mode keeps its forward rules in `[l3] ports`; every other transport uses
        // the top-level `[[forward]]` tables.
        forwards: c
            .l3
            .as_ref()
            .map_or(c.forward.as_slice(), |l3| l3.ports.as_slice())
            .iter()
            .map(|f| ForwardInfo {
                listen: f.listen.clone(),
                target: f.target.clone(),
                protocol: f.protocol.name().to_owned(),
            })
            .collect(),
        stealth: c.tunnel.stealth.as_ref().map(|s| crate::wire::StealthSpec {
            padding: Some(s.padding),
            pad_max: Some(s.pad_max),
            jitter_ms: Some(s.jitter_ms),
        }),
        faketcp: c.tunnel.faketcp.as_ref().map(|f| crate::wire::FaketcpSpec {
            flags: Some(f.flags.clone()),
            manage_firewall: Some(f.manage_firewall),
        }),
        icmp: c.tunnel.icmp.as_ref().map(|i| crate::wire::IcmpSpec {
            manage_firewall: Some(i.manage_firewall),
        }),
        spoof: c.tunnel.spoof.as_ref().map(|s| crate::wire::SpoofSpec {
            shape: Some(s.shape.name().to_owned()),
            pool: s.pool.clone(),
            peer: s.peer.clone(),
            manage_firewall: Some(s.manage_firewall),
            ..Default::default()
        }),
        helper: c.tunnel.helper.as_ref().map(|h| {
            let path = |p: &Option<PathBuf>| {
                p.as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .filter(|p| valid_cert_path(p))
            };
            crate::wire::HelperSpec {
                binary: h.binary.as_ref().map(|p| p.to_string_lossy().into_owned()),
                username: h.username.clone(),
                password: h.password.clone(),
                uuid: h.uuid.clone(),
                path: h.path.clone(),
                server_name: h.server_name.clone(),
                host: h.host.clone(),
                short_id: h.short_id.clone(),
                private_key: h.private_key.clone(),
                public_key: h.public_key.clone(),
                target: h.target.clone(),
                certificate: path(&h.certificate),
                key: path(&h.key),
                ca_file: path(&h.ca_file),
            }
        }),
        l3: c.l3.as_ref().map(|l3| crate::wire::L3Spec {
            carrier: l3.carrier.name().to_owned(),
            layer: Some(l3.layer),
            local_ip: l3.local_ip.clone(),
            peer_ip: l3.peer_ip.clone(),
            gre_key: Some(l3.gre_key),
            mtu: Some(l3.mtu),
            accept_udp: l3.accept_udp,
        }),
    })
}

/// Removes the config, its backup and its control socket (the service is stopped first by
/// the caller).
pub fn remove_files(dir: &Path, name: &str) -> Result<()> {
    let path = config_path(dir, name)?;
    for p in [
        path.clone(),
        path.with_extension("toml.bak"),
        path.with_extension("sock"),
        path.with_extension("traffic"),
        path.with_extension("traffic.tmp"),
        path.with_extension("crt"),
        path.with_extension("key"),
    ] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to remove {}", p.display())),
        }
    }
    Ok(())
}

// ---- listening ports ----

fn parse_addr(hex: &str) -> Option<String> {
    match hex.len() {
        8 => {
            let n = u32::from_str_radix(hex, 16).ok()?;
            Some(std::net::Ipv4Addr::from(n.swap_bytes()).to_string())
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.swap_bytes().to_be_bytes());
            }
            Some(std::net::Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

/// The listening sockets in a `/proc/net/{tcp,tcp6,udp,udp6}` file: (address, port, inode).
pub fn parse_proc_net(text: &str, udp: bool) -> Vec<(String, u16, u64)> {
    let listening = if udp { "07" } else { "0A" };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[3] != listening {
                return None;
            }
            let (addr, port) = f[1].split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            if port == 0 {
                return None;
            }
            Some((parse_addr(addr)?, port, f[9].parse().ok()?))
        })
        .collect()
}

/// Which process holds each socket inode, from `/proc/*/fd`.
#[cfg(target_os = "linux")]
fn inode_owners(wanted: &[u64]) -> HashMap<u64, (u32, String)> {
    let mut found = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in procs.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.filter_map(Result::ok) {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let link = link.to_string_lossy();
            let Some(inode) = link
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if wanted.contains(&inode) && !found.contains_key(&inode) {
                let comm = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|c| c.trim().to_owned())
                    .unwrap_or_default();
                found.insert(inode, (pid, comm));
            }
        }
    }
    found
}

#[cfg(not(target_os = "linux"))]
fn inode_owners(_: &[u64]) -> HashMap<u64, (u32, String)> {
    HashMap::new()
}

/// Every TCP and UDP port this server listens on, with the process that owns it.
pub fn ports() -> Vec<PortOwner> {
    let mut sockets = Vec::new();
    for (file, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ] {
        if let Ok(text) = std::fs::read_to_string(file) {
            for (addr, port, inode) in parse_proc_net(&text, proto == "udp") {
                sockets.push((proto, addr, port, inode));
            }
        }
    }
    let owners = inode_owners(&sockets.iter().map(|s| s.3).collect::<Vec<_>>());
    let mut out: Vec<PortOwner> = sockets
        .into_iter()
        .map(|(proto, addr, port, inode)| {
            let owner = owners.get(&inode);
            PortOwner {
                proto: proto.to_owned(),
                addr,
                port,
                process: owner.map(|o| o.1.clone()).filter(|c| !c.is_empty()),
                pid: owner.map(|o| o.0),
            }
        })
        .collect();
    out.sort_by(|a, b| (a.port, &a.proto, &a.addr).cmp(&(b.port, &b.proto, &b.addr)));
    out.dedup();
    out
}

// ---- systemd, the journal, the speed test ----

/// The `systemctl` arguments for an action on a tunnel's service.
pub fn ctl_args(name: &str, action: &str) -> Result<Vec<String>> {
    if !valid_name(name) {
        bail!("a tunnel name is 1 to 32 characters: small letters, digits and dashes");
    }
    let unit = format!("kariz@{name}");
    Ok(match action {
        "start" | "stop" | "restart" => vec![action.to_owned(), unit],
        "enable" | "disable" => vec![action.to_owned(), "--now".to_owned(), unit],
        _ => bail!("unknown action {action}"),
    })
}

/// Runs a program with fixed arguments and a time limit; its output, or why it failed.
pub(crate) async fn run(program: &str, args: &[String], limit: Duration) -> Result<(bool, String)> {
    let mut command = tokio::process::Command::new(program);
    command.args(args).kill_on_drop(true);
    let output = tokio::time::timeout(limit, command.output())
        .await
        .map_err(|_| anyhow!("{program} took longer than {} s", limit.as_secs()))?
        .with_context(|| format!("failed to run {program}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.truncate(512 * 1024);
    Ok((output.status.success(), text))
}

/// The program that gets certificates (the manager script, installed with Kariz).
const MANAGER: &str = "/usr/local/bin/kariz-manager";

/// The manager script of this release. An update swaps the programs but not the script, so
/// the installed one can be older than the commands sent to it (one without `tunnel-cert`
/// only prints its usage).
const MANAGER_SCRIPT: &str = include_str!("../../scripts/kariz.sh");

/// Makes the installed manager the one of this release, when it is missing or different.
fn sync_manager(path: &Path) -> Result<()> {
    if std::fs::read(path).is_ok_and(|have| have == MANAGER_SCRIPT.as_bytes()) {
        return Ok(());
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, MANAGER_SCRIPT)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))
}

/// Puts the manager of this release in place when the panel or the agent starts, if the one
/// there is missing or different. An update from the panel swaps the programs and restarts
/// them, but not the script: a server set up long ago and updated only from the panel went on
/// showing the menu of the release it was installed with. Only on a systemd host (not where the
/// tests run the programs, which name a manager of their own); a failure only goes to the log.
pub fn manager_in_place(services: ServiceKind) {
    if !cfg!(target_os = "linux")
        || services != ServiceKind::Systemd
        || std::env::var_os("KARIZ_MANAGER").is_some()
    {
        return;
    }
    let path = Path::new(MANAGER);
    if std::fs::read(path).is_ok_and(|have| have == MANAGER_SCRIPT.as_bytes()) {
        return;
    }
    match sync_manager(path) {
        Ok(()) => tracing::info!("put the kariz-manager script of this release in place"),
        Err(e) => tracing::warn!("the manager script could not be updated: {e:#}"),
    }
}

/// The manager's timer for `panel heal`: when the server's IP address changes and the panel's
/// certificate was for the old one, it gets one for the new address by itself.
const HEAL_TIMER: &str = "/etc/systemd/system/kariz-panel-heal.timer";

/// Whether the panel's Let's Encrypt certificate (the manager keeps what it is for in
/// `domain`, next to the settings) has no `panel heal` timer yet: a panel set up before the
/// manager had it.
fn heal_timer_missing(domain: &Path, timer: &Path) -> bool {
    std::fs::read_to_string(domain).is_ok_and(|d| !d.trim().is_empty()) && !timer.exists()
}

/// Sets up the `panel heal` timer on a panel that was set up before it existed, with the
/// manager of this release (put in place first: [`manager_in_place`]): a panel updated from the
/// panel gets it without the manager being run by hand. Nothing when the timer is there; a
/// failure only goes to the log.
pub async fn ensure_heal_timer(config: &Path) {
    if !cfg!(target_os = "linux") || std::env::var_os("KARIZ_MANAGER").is_some() {
        return;
    }
    let domain = config.with_file_name("domain");
    if !heal_timer_missing(&domain, Path::new(HEAL_TIMER))
        || !std::fs::read(MANAGER).is_ok_and(|have| have == MANAGER_SCRIPT.as_bytes())
    {
        return;
    }
    let args = ["panel".to_owned(), "heal-setup".to_owned()];
    match run(MANAGER, &args, Duration::from_secs(30)).await {
        Ok((true, _)) => {
            tracing::info!("set up the timer that follows a new IP address of this server")
        }
        Ok((false, out)) => {
            tracing::warn!("kariz-manager panel heal-setup failed: {}", out.trim())
        }
        Err(e) => tracing::warn!("kariz-manager panel heal-setup failed: {e:#}"),
    }
}

/// Whether `host` is a domain name or an IPv4 address the manager may ask a certificate for.
pub fn valid_cert_host(host: &str) -> bool {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && !host
            .split('.')
            .next_back()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

/// Gets a Let's Encrypt certificate for `host` through the manager, which stops whatever
/// holds port 80 for a few seconds, asks, and starts it again. The certificate renews by
/// itself; a tunnel that names its files reloads it.
pub async fn issue_cert(host: &str, email: Option<&str>) -> crate::wire::CertReply {
    let failed = |e: String| crate::wire::CertReply {
        ok: false,
        error: Some(e),
        ..Default::default()
    };
    let host = host.trim().to_ascii_lowercase();
    if !valid_cert_host(&host) {
        return failed("bad_host".into());
    }
    if let Some(mail) = email {
        let ok = mail.len() <= 120
            && mail.contains('@')
            && mail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@.-_+".contains(&b));
        if !ok {
            return failed("bad_email".into());
        }
    }
    let program = match std::env::var("KARIZ_MANAGER") {
        Ok(program) => program,
        Err(_) => {
            if let Err(e) = sync_manager(Path::new(MANAGER)) {
                tracing::warn!("the manager script could not be updated: {e:#}");
            }
            MANAGER.to_owned()
        }
    };
    if !Path::new(&program).exists() {
        return failed("no_manager".into());
    }
    let mut args = vec!["tunnel-cert".to_owned()];
    args.push(
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            "--ip"
        } else {
            "--domain"
        }
        .into(),
    );
    args.push(host.clone());
    if let Some(mail) = email.filter(|m| !m.is_empty()) {
        args.extend(["--email".into(), mail.to_owned()]);
    }
    let (ok, text) = match run(&program, &args, Duration::from_secs(600)).await {
        Ok(v) => v,
        Err(e) => return failed(format!("{e:#}")),
    };
    let found = |key: &str| {
        text.lines()
            .rev()
            .find_map(|l| l.strip_prefix(key))
            .map(|p| p.trim().to_owned())
            .filter(|p| valid_cert_path(p))
    };
    match (ok, found("cert="), found("key=")) {
        (true, Some(cert), Some(key)) => crate::wire::CertReply {
            ok: true,
            error: None,
            cert: Some(cert),
            key: Some(key),
        },
        _ => {
            // The last lines say why (Let's Encrypt's own words).
            let tail: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            let tail = tail[tail.len().saturating_sub(6)..].join(" | ");
            failed(if tail.is_empty() {
                "failed".into()
            } else {
                tail
            })
        }
    }
}

/// How a server runs its tunnels: `systemd` (the default) or `process`, as child
/// processes of the panel or the agent, for a host that has no systemd.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    #[default]
    Systemd,
    Process,
}

impl ServiceKind {
    pub fn services(self, dir: &Path) -> std::sync::Arc<dyn Services> {
        match self {
            Self::Systemd => std::sync::Arc::new(Systemd),
            Self::Process => std::sync::Arc::new(Processes::new(dir, &kariz_binary())),
        }
    }
}

pub type Fut<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// How a server starts, stops and asks about its tunnels' services. The agent uses
/// systemd; a host without it (a container) can run the daemons as child processes, and
/// the tests do.
pub trait Services: Send + Sync {
    /// `start`, `stop`, `restart`, `enable` or `disable` (the last two also start and
    /// stop).
    fn ctl(&self, name: String, action: String) -> Fut<Result<()>>;
    /// Whether the tunnel runs; `None` when this cannot be known.
    fn active(&self, name: String) -> Fut<Option<bool>>;
}

/// The services of a Linux server with systemd: `kariz@NAME`.
pub struct Systemd;

impl Services for Systemd {
    fn ctl(&self, name: String, action: String) -> Fut<Result<()>> {
        Box::pin(async move {
            let args = ctl_args(&name, &action)?;
            let (ok, text) = run("systemctl", &args, Duration::from_secs(30)).await?;
            if ok {
                Ok(())
            } else {
                bail!("systemctl {action} failed: {}", text.trim())
            }
        })
    }

    #[cfg(target_os = "linux")]
    fn active(&self, name: String) -> Fut<Option<bool>> {
        Box::pin(async move {
            let args = [
                "is-active".to_owned(),
                "--quiet".to_owned(),
                format!("kariz@{name}"),
            ];
            match run("systemctl", &args, Duration::from_secs(3)).await {
                Ok((ok, _)) => Some(ok),
                Err(_) => None,
            }
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn active(&self, _: String) -> Fut<Option<bool>> {
        Box::pin(async { None })
    }
}

/// Daemons run as child processes of the agent, for hosts without systemd. They stop
/// with the agent.
pub struct Processes {
    dir: PathBuf,
    binary: PathBuf,
    children: std::sync::Mutex<HashMap<String, tokio::process::Child>>,
}

impl Processes {
    pub fn new(dir: &Path, binary: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            binary: binary.to_path_buf(),
            children: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn start(&self, name: &str) -> Result<()> {
        let mut children = self.children.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = children.get_mut(name) {
            if matches!(child.try_wait(), Ok(None)) {
                return Ok(());
            }
        }
        let child = tokio::process::Command::new(&self.binary)
            .arg("run")
            .arg("-c")
            .arg(config_path(&self.dir, name)?)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", self.binary.display()))?;
        children.insert(name.to_owned(), child);
        Ok(())
    }

    fn stop(&self, name: &str) {
        let child = self
            .children
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
        if let Some(mut child) = child {
            let _ = child.start_kill();
        }
    }
}

impl Services for Processes {
    fn ctl(&self, name: String, action: String) -> Fut<Result<()>> {
        let result = ctl_args(&name, &action).and_then(|_| match action.as_str() {
            "start" | "enable" => self.start(&name),
            "stop" | "disable" => {
                self.stop(&name);
                Ok(())
            }
            _ => {
                self.stop(&name);
                self.start(&name)
            }
        });
        Box::pin(async move { result })
    }

    fn active(&self, name: String) -> Fut<Option<bool>> {
        let running = self
            .children
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&name)
            .map(|c| matches!(c.try_wait(), Ok(None)));
        Box::pin(async move { Some(running.unwrap_or(false)) })
    }
}

/// Stops the service, then removes the files.
pub async fn delete(dir: &Path, services: &dyn Services, name: &str) -> Result<()> {
    config_path(dir, name)?;
    // A tunnel that was never started has no service to stop; that is not a failure.
    let _ = services.ctl(name.to_owned(), "disable".to_owned()).await;
    remove_files(dir, name)
}

fn text_failed(error: String) -> TextReply {
    TextReply {
        ok: false,
        error: Some(error),
        text: String::new(),
    }
}

pub async fn logs(name: &str, lines: u32) -> TextReply {
    if !valid_name(name) {
        return text_failed("bad tunnel name".into());
    }
    let args = vec![
        "-u".to_owned(),
        format!("kariz@{name}"),
        "-n".to_owned(),
        lines.clamp(1, 1000).to_string(),
        "--no-pager".to_owned(),
        "-o".to_owned(),
        "short-iso".to_owned(),
    ];
    match run("journalctl", &args, Duration::from_secs(10)).await {
        Ok((true, text)) => TextReply {
            ok: true,
            error: None,
            text,
        },
        Ok((false, text)) => text_failed(text.trim().to_owned()),
        Err(e) => text_failed(format!("{e:#}")),
    }
}

/// The `kariz` program: beside this one, or where the installer puts it.
pub fn kariz_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join(format!("kariz{}", std::env::consts::EXE_SUFFIX)))
        })
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/kariz"))
}

/// Runs the tunnel's speed test through its running daemon (the control socket, as
/// `kariz speedtest` does) and returns the numbers.
pub async fn speedtest(
    dir: &Path,
    name: &str,
    seconds: u32,
    streams: u32,
    udp: bool,
) -> SpeedReply {
    speedtest_with(dir, name, seconds, streams, udp, |_: &str| {}).await
}

/// The entry config of a tunnel and the test's settings, or why there is no test.
pub fn speedtest_setup(
    dir: &Path,
    name: &str,
    seconds: u32,
    streams: u32,
    udp: bool,
) -> Result<(Config, kariz::speedtest::Options)> {
    let path = config_path(dir, name)?;
    let config = match Config::load(&path) {
        Ok(c) if c.role == Role::Entry => c,
        Ok(_) => bail!("the speed test runs on the entry side"),
        Err(e) => return Err(e),
    };
    let options = kariz::speedtest::Options {
        seconds: u64::from(seconds.clamp(1, kariz::speedtest::MAX_SECONDS as u32)),
        streams: (streams as usize).clamp(1, kariz::speedtest::MAX_STREAMS),
        udp,
    };
    Ok((config, options))
}

/// Like [`speedtest`], and every progress line of the test goes to `on_progress` as it comes.
pub async fn speedtest_with(
    dir: &Path,
    name: &str,
    seconds: u32,
    streams: u32,
    udp: bool,
    on_progress: impl FnMut(&str),
) -> SpeedReply {
    let failed = |error: String| SpeedReply {
        ok: false,
        error: Some(error),
        text: String::new(),
        report: None,
    };
    let (config, options) = match speedtest_setup(dir, name, seconds, streams, udp) {
        Ok(v) => v,
        Err(e) => return failed(format!("{e:#}")),
    };
    let limit = Duration::from_secs(options.seconds * 3 + 40);
    match tokio::time::timeout(limit, measure(&config, options, on_progress)).await {
        Ok(Ok(report)) => SpeedReply {
            ok: true,
            error: None,
            text: String::new(),
            report: Some(report),
        },
        Ok(Err(e)) => failed(format!("{e:#}")),
        Err(_) => failed("the speed test took too long".into()),
    }
}

#[cfg(unix)]
async fn measure(
    config: &Config,
    options: kariz::speedtest::Options,
    on_progress: impl FnMut(&str),
) -> Result<kariz::speedtest::Report> {
    let socket = config
        .control_socket()
        .context("this tunnel has no control socket")?;
    let connection = kariz::control::connect(&socket)
        .await
        .context("the tunnel is not running")?;
    Ok(kariz::control::request(connection, options, on_progress).await?)
}

#[cfg(not(unix))]
async fn measure(
    _: &Config,
    _: kariz::speedtest::Options,
    _: impl FnMut(&str),
) -> Result<kariz::speedtest::Report> {
    bail!("the speed test needs a Linux server")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> Spec {
        Spec {
            name: name.into(),
            role: "entry".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            listen: Some("0.0.0.0:3080".into()),
            token: Some("a".repeat(48)),
            forwards: vec![ForwardInfo {
                listen: "0.0.0.0:8443".into(),
                target: "127.0.0.1:443".into(),
                protocol: "tcp".into(),
            }],
            ..Default::default()
        }
    }

    /// A directory that goes away with the test.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).unwrap();
            let p = std::env::temp_dir().join(format!(
                "kariz-manage-{}",
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn names_are_strict() {
        for good in ["a", "main", "tehran-1", "0x"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "-a", "A", "a b", "../x", "a/b", "a.b", &"x".repeat(33)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_spec_makes_a_config_that_reads_back() {
        let d = Dir::new();
        put(&d.0, &spec("main")).unwrap();
        let got = get(&d.0, "main").unwrap();
        assert_eq!(got.role, "entry");
        assert_eq!(got.transport, "tcpmux");
        assert_eq!(got.listen.as_deref(), Some("0.0.0.0:3080"));
        assert_eq!(got.forwards.len(), 1);
        assert!(got.token.is_none(), "the token is never handed back");
        assert_eq!(existing_token(&d.0.join("main.toml")), Some("a".repeat(48)));
    }

    #[test]
    fn a_spoof_spec_renders_and_reads_back() {
        let d = Dir::new();
        let mut s = spec("spoofy");
        s.transport = "spoof".into();
        s.spoof = Some(crate::wire::SpoofSpec {
            shape: Some("icmp".into()),
            pool: vec!["203.0.113.10".into(), "203.0.113.0/30".into()],
            peer: Some("198.51.100.9".into()),
            manage_firewall: Some(true),
            ..Default::default()
        });
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "spoofy").unwrap();
        assert_eq!(got.transport, "spoof");
        let spoof = got.spoof.expect("spoof table read back");
        assert_eq!(spoof.shape.as_deref(), Some("icmp"));
        assert_eq!(spoof.peer.as_deref(), Some("198.51.100.9"));
        assert_eq!(
            spoof.pool,
            vec!["203.0.113.10".to_string(), "203.0.113.0/30".to_string()]
        );
        assert_eq!(spoof.manage_firewall, Some(true));
        // The rendered file carries a [tunnel.spoof] table the core accepts.
        let text = std::fs::read_to_string(d.0.join("spoofy.toml")).unwrap();
        assert!(text.contains("[tunnel.spoof]"), "{text}");
    }

    #[test]
    fn an_edit_without_a_token_keeps_the_token_and_the_old_file() {
        let d = Dir::new();
        put(&d.0, &spec("main")).unwrap();
        let mut edit = spec("main");
        edit.token = None;
        edit.listen = Some("0.0.0.0:3081".into());
        put(&d.0, &edit).unwrap();
        assert_eq!(existing_token(&d.0.join("main.toml")), Some("a".repeat(48)));
        assert!(std::fs::read_to_string(d.0.join("main.toml.bak"))
            .unwrap()
            .contains("3080"));
        let mut fresh = spec("other");
        fresh.token = None;
        assert!(put(&d.0, &fresh).is_err(), "a new tunnel needs a token");
    }

    #[test]
    fn values_cannot_write_lines_into_the_file() {
        let d = Dir::new();
        let mut s = spec("main");
        s.listen = Some("0.0.0.0:3080\"\n[control]\nsocket = \"/etc/passwd".into());
        assert!(put(&d.0, &s).is_err());
        assert!(!d.0.join("main.toml").exists());
    }

    #[test]
    fn a_bad_spec_is_refused_with_a_reason() {
        let d = Dir::new();
        let mut s = spec("main");
        s.role = "root".into();
        let r = check(&d.0, &[], &s);
        assert!(!r.ok && r.error.is_some());
        assert!(put(&d.0, &s).is_err());
        assert!(put(&d.0, &spec("../evil")).is_err());
        let mut short = spec("main");
        short.token = Some("abc".into());
        assert!(put(&d.0, &short).is_err());
    }

    #[test]
    fn mux_settings_are_written_and_read_back_and_an_empty_set_writes_nothing() {
        let d = Dir::new();
        let mut s = spec("tuned");
        s.mux = Some(crate::wire::MuxSpec {
            connections: Some(6),
            stream_window: Some(512 * 1024),
            ping_interval_secs: Some(5),
            coalesce: Some(false),
            ..Default::default()
        });
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "tuned").unwrap();
        assert_eq!(got.mux, s.mux);
        let text = std::fs::read_to_string(d.0.join("tuned.toml")).unwrap();
        assert!(text.contains("[tunnel.mux]") && text.contains("connections = 6"));
        // Back to the profile's values.
        s.mux = Some(Default::default());
        put(&d.0, &s).unwrap();
        assert_eq!(get(&d.0, "tuned").unwrap().mux, None);
        assert!(!std::fs::read_to_string(d.0.join("tuned.toml"))
            .unwrap()
            .contains("[tunnel.mux]"));
        // A value the core refuses is refused here, before anything is written.
        s.mux = Some(crate::wire::MuxSpec {
            max_streams: Some(0),
            ..Default::default()
        });
        assert!(put(&d.0, &s).is_err());
    }

    #[test]
    fn mux_can_be_turned_off_for_a_transport_that_multiplexes_by_default() {
        let d = Dir::new();
        let mut s = spec("plain-ws");
        s.transport = "ws".into();
        s.mux = Some(crate::wire::MuxSpec {
            enabled: Some(false),
            ..Default::default()
        });
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "plain-ws").unwrap();
        assert_eq!(got.mux.and_then(|m| m.enabled), Some(false));
        // tcpmux cannot be turned off: the core refuses it before anything is written.
        let mut s = spec("bad-tcpmux");
        s.mux = Some(crate::wire::MuxSpec {
            enabled: Some(false),
            ..Default::default()
        });
        assert!(put(&d.0, &s).is_err());
    }

    #[test]
    fn only_certificates_the_manager_got_can_be_named() {
        let live = "/etc/letsencrypt/live/kariz-panel-tun-example-com/";
        assert!(valid_cert_path(&format!("{live}fullchain.pem")));
        assert!(valid_cert_path(&format!("{live}privkey.pem")));
        for bad in [
            "/etc/passwd",
            "/etc/letsencrypt/live/../../shadow.pem",
            "/etc/letsencrypt/live/x/key.txt",
            "/etc/letsencrypt/live/x y/key.pem",
            "/etc/kariz/main.toml",
            "relative.pem",
        ] {
            assert!(!valid_cert_path(bad), "{bad}");
        }
        for ok in ["tun.example.com", "a-b.example.org", "203.0.113.5"] {
            assert!(valid_cert_host(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "-a.example.com",
            "a..com",
            "a b.com",
            "x.com/../",
            "1.2.3",
            "999.1.1.1",
            "a.com;rm",
        ] {
            assert!(!valid_cert_host(bad), "{bad}");
        }
    }

    #[test]
    fn a_wss_side_can_use_a_real_certificate_and_pins_nothing() {
        let d = Dir::new();
        let live = "/etc/letsencrypt/live/kariz-panel-tun-example-com/";
        let mut s = spec("real");
        s.transport = "wss".into();
        s.tls_cert = Some(format!("{live}fullchain.pem"));
        s.tls_key = Some(format!("{live}privkey.pem"));
        let (text, _) = build(&d.0, &s, true).unwrap();
        assert!(
            text.contains("fullchain.pem") && text.contains("privkey.pem"),
            "{text}"
        );
        // The files are not on this machine: nothing is written, and no self-signed one is made.
        let err = put(&d.0, &s).unwrap_err();
        assert!(format!("{err:#}").contains("certificate files"), "{err:#}");
        assert!(!d.0.join("real.crt").exists() && !d.0.join("real.toml").exists());
        // A cert and key go together, and only from the manager's directory.
        let mut half = s.clone();
        half.tls_key = None;
        assert!(build(&d.0, &half, true).is_err());
        let mut other = s.clone();
        other.tls_cert = Some("/etc/passwd".into());
        assert!(build(&d.0, &other, true).is_err());
    }

    #[test]
    fn the_cipher_is_written_and_read_back_and_auto_writes_nothing() {
        let d = Dir::new();
        let mut s = spec("cipher");
        s.encryption = Some("chacha20-poly1305".into());
        put(&d.0, &s).unwrap();
        assert_eq!(
            get(&d.0, "cipher").unwrap().encryption.as_deref(),
            Some("chacha20-poly1305")
        );
        assert!(std::fs::read_to_string(d.0.join("cipher.toml"))
            .unwrap()
            .contains("encryption = \"chacha20-poly1305\""));
        // Back to auto: the line goes.
        s.encryption = Some("auto".into());
        put(&d.0, &s).unwrap();
        assert_eq!(get(&d.0, "cipher").unwrap().encryption, None);
        assert!(!std::fs::read_to_string(d.0.join("cipher.toml"))
            .unwrap()
            .contains("encryption"));
        // The core refuses a cipher QUIC cannot have, before anything is written.
        let mut q = spec("quic-none");
        q.transport = "quic".into();
        q.encryption = Some("none".into());
        assert!(put(&d.0, &q).is_err());
        assert!(!d.0.join("quic-none.toml").exists());
    }

    #[test]
    fn sealed_quic_is_written_and_read_back_and_only_for_quic() {
        let d = Dir::new();
        let mut s = spec("sealed");
        s.transport = "quic".into();
        s.quic_obfs = true;
        put(&d.0, &s).unwrap();
        assert!(get(&d.0, "sealed").unwrap().quic_obfs);
        let text = std::fs::read_to_string(d.0.join("sealed.toml")).unwrap();
        assert!(
            text.contains("[tunnel.quic]") && text.contains("obfs = true"),
            "{text}"
        );
        // Off again: the table goes.
        s.quic_obfs = false;
        put(&d.0, &s).unwrap();
        assert!(!get(&d.0, "sealed").unwrap().quic_obfs);
        assert!(!std::fs::read_to_string(d.0.join("sealed.toml"))
            .unwrap()
            .contains("obfs"));
        // Over another transport it is not written (the core refuses [tunnel.quic] there).
        let mut other = spec("tcp-sealed");
        other.quic_obfs = true;
        put(&d.0, &other).unwrap();
        assert!(!get(&d.0, "tcp-sealed").unwrap().quic_obfs);
        // A spec without it reads as before: the field is left out of what is sent.
        let json = serde_json::to_string(&get(&d.0, "tcp-sealed").unwrap()).unwrap();
        assert!(!json.contains("quic_obfs"), "{json}");
    }

    #[test]
    fn stealth_padding_is_written_and_read_back_and_only_for_stealth() {
        use crate::wire::StealthSpec;
        let d = Dir::new();
        let mut s = spec("stlth");
        s.transport = "stealth".into();
        s.stealth = Some(StealthSpec {
            padding: Some(true),
            pad_max: Some(512),
            jitter_ms: Some(20),
        });
        put(&d.0, &s).unwrap();
        let text = std::fs::read_to_string(d.0.join("stlth.toml")).unwrap();
        assert!(
            text.contains("[tunnel.stealth]") && text.contains("pad_max = 512"),
            "{text}"
        );
        let got = get(&d.0, "stlth").unwrap().stealth.unwrap();
        assert_eq!((got.pad_max, got.jitter_ms), (Some(512), Some(20)));
        // Over another transport the table is not written (the core refuses it there).
        let mut other = spec("tcp-pad");
        other.stealth = Some(StealthSpec {
            pad_max: Some(99),
            ..Default::default()
        });
        put(&d.0, &other).unwrap();
        assert!(!std::fs::read_to_string(d.0.join("tcp-pad.toml"))
            .unwrap()
            .contains("stealth"));
    }

    #[test]
    fn faketcp_and_icmp_knobs_are_written_and_read_back() {
        use crate::wire::{FaketcpSpec, IcmpSpec};
        let d = Dir::new();
        let mut f = spec("ftcp");
        f.transport = "faketcp".into();
        f.faketcp = Some(FaketcpSpec {
            flags: Some("PA,A".into()),
            manage_firewall: Some(false),
        });
        put(&d.0, &f).unwrap();
        let text = std::fs::read_to_string(d.0.join("ftcp.toml")).unwrap();
        assert!(
            text.contains("[tunnel.faketcp]")
                && text.contains("flags = \"PA,A\"")
                && text.contains("manage_firewall = false"),
            "{text}"
        );
        let got = get(&d.0, "ftcp").unwrap().faketcp.unwrap();
        assert_eq!(got.flags.as_deref(), Some("PA,A"));
        assert_eq!(got.manage_firewall, Some(false));

        let mut i = spec("icmp1");
        i.transport = "icmp".into();
        i.icmp = Some(IcmpSpec {
            manage_firewall: Some(false),
        });
        put(&d.0, &i).unwrap();
        assert!(std::fs::read_to_string(d.0.join("icmp1.toml"))
            .unwrap()
            .contains("[tunnel.icmp]"));
        assert_eq!(
            get(&d.0, "icmp1").unwrap().icmp.unwrap().manage_firewall,
            Some(false)
        );
    }

    #[test]
    fn a_managed_helper_dialer_writes_its_credentials() {
        use crate::wire::HelperSpec;
        let d = Dir::new();
        // A dialing xhttp side (exit in reverse mode) only needs the client identity.
        let mut s = spec("xh");
        s.role = "exit".into();
        s.mode = "reverse".into();
        s.listen = None;
        s.remote = Some("example.com:443".into());
        s.transport = "xhttp".into();
        s.forwards.clear();
        s.helper = Some(HelperSpec {
            uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
            path: Some("/stream".into()),
            server_name: Some("example.com".into()),
            ..Default::default()
        });
        put(&d.0, &s).unwrap();
        let text = std::fs::read_to_string(d.0.join("xh.toml")).unwrap();
        assert!(
            text.contains("[tunnel.helper]") && text.contains("/stream"),
            "{text}"
        );
        let got = get(&d.0, "xh").unwrap().helper.unwrap();
        assert_eq!(
            got.uuid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(got.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn an_l3_tunnel_renders_its_gre_table_and_reads_back() {
        use crate::wire::L3Spec;
        let d = Dir::new();
        // The accepting side of a direct l3 tunnel listens; its address and the forward
        // rule move into [l3].
        let mut s = spec("gre1");
        s.role = "exit".into();
        s.mode = "direct".into();
        s.transport = "l3".into();
        s.listen = Some("0.0.0.0:51820".into());
        s.l3 = Some(L3Spec {
            carrier: "udp".into(),
            layer: Some(3),
            local_ip: Some("10.10.7.1/30".into()),
            peer_ip: Some("10.10.7.2".into()),
            gre_key: Some(42),
            mtu: Some(1400),
            accept_udp: false,
        });
        put(&d.0, &s).unwrap();
        let text = std::fs::read_to_string(d.0.join("gre1.toml")).unwrap();
        assert!(
            text.contains("[l3]")
                && text.contains("carrier = \"udp\"")
                && text.contains("mode = \"listen\"")
                && text.contains("addr = \"0.0.0.0:51820\"")
                && text.contains("local_ip = \"10.10.7.1/30\"")
                && !text.contains("transport ="),
            "{text}"
        );
        // The forward rule is written under [l3], not as a top-level [[forward]].
        assert!(
            text.contains("[[l3.ports]]") && !text.contains("[[forward]]"),
            "{text}"
        );
        let got = get(&d.0, "gre1").unwrap();
        assert_eq!(got.transport, "l3");
        assert_eq!(got.listen.as_deref(), Some("0.0.0.0:51820"));
        let l3 = got.l3.unwrap();
        assert_eq!(l3.carrier, "udp");
        assert_eq!(l3.local_ip.as_deref(), Some("10.10.7.1/30"));
        assert_eq!(l3.gre_key, Some(42));
        assert_eq!(got.forwards.len(), 1, "the l3 forward rule reads back");
    }

    #[test]
    fn the_udp_flow_limit_is_written_and_read_back_beside_the_per_address_one() {
        let d = Dir::new();
        let mut s = spec("busy");
        s.udp_max_flows = Some(8192);
        s.max_conns_per_ip = Some(300);
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "busy").unwrap();
        assert_eq!(
            (got.udp_max_flows, got.max_conns_per_ip),
            (Some(8192), Some(300))
        );
        let text = std::fs::read_to_string(d.0.join("busy.toml")).unwrap();
        assert!(
            text.contains("udp_max_flows = 8192") && text.matches("[tuning]").count() == 1,
            "{text}"
        );
        // The core reads it.
        let config = kariz::config::Config::parse(&text).unwrap();
        assert_eq!(config.tuning().udp.max_flows, 8192);
        // Left out: no [tuning] at all, and an older agent is not sent the field.
        s.udp_max_flows = None;
        s.max_conns_per_ip = None;
        put(&d.0, &s).unwrap();
        let text = std::fs::read_to_string(d.0.join("busy.toml")).unwrap();
        assert!(!text.contains("[tuning]"), "{text}");
        let json = serde_json::to_string(&get(&d.0, "busy").unwrap()).unwrap();
        assert!(!json.contains("udp_max_flows"), "{json}");
    }

    #[test]
    fn the_per_address_limit_is_written_and_read_back() {
        let d = Dir::new();
        let mut s = spec("limited");
        s.max_conns_per_ip = Some(300);
        put(&d.0, &s).unwrap();
        assert_eq!(get(&d.0, "limited").unwrap().max_conns_per_ip, Some(300));
        let text = std::fs::read_to_string(d.0.join("limited.toml")).unwrap();
        assert!(
            text.contains("[tuning]") && text.contains("max_conns_per_ip = 300"),
            "{text}"
        );
        // Off: nothing written, and an older agent is not sent a field it does not know.
        s.max_conns_per_ip = None;
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "limited").unwrap();
        assert_eq!(got.max_conns_per_ip, None);
        let json = serde_json::to_string(&got).unwrap();
        assert!(!json.contains("max_conns_per_ip"), "{json}");
    }

    #[test]
    fn the_proxy_header_goes_on_tcp_rules_and_is_read_back() {
        let d = Dir::new();
        let mut s = spec("proxied");
        let rule = |port: u16, protocol: &str| ForwardInfo {
            listen: format!("0.0.0.0:{port}"),
            target: "127.0.0.1:443".into(),
            protocol: protocol.into(),
        };
        s.forwards = vec![rule(8443, "tcp"), rule(9443, "tcp+udp"), rule(53, "udp")];
        s.proxy_protocol = Some("v2".into());
        put(&d.0, &s).unwrap();
        assert_eq!(
            get(&d.0, "proxied").unwrap().proxy_protocol.as_deref(),
            Some("v2")
        );
        let config = Config::load(&d.0.join("proxied.toml")).unwrap();
        let written: Vec<_> = config.forward.iter().map(|f| f.proxy_protocol).collect();
        let v2 = Some(kariz::config::ProxyVersion::V2);
        assert_eq!(written, [v2, v2, None], "nothing on the UDP rule");
        // Only v1 or v2: the agent's config check refuses anything else.
        s.proxy_protocol = Some("v3".into());
        assert!(put(&d.0, &s).is_err());
        // Off: nothing written, and an older agent is not sent a field it does not know.
        s.proxy_protocol = None;
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "proxied").unwrap();
        assert_eq!(got.proxy_protocol, None);
        let text = std::fs::read_to_string(d.0.join("proxied.toml")).unwrap();
        assert!(!text.contains("proxy_protocol"), "{text}");
        let json = serde_json::to_string(&got).unwrap();
        assert!(!json.contains("proxy_protocol"), "{json}");
    }

    #[test]
    fn an_auto_tunnel_wants_its_three_ports() {
        let mut s = spec("a");
        s.transport = "auto".into();
        let own: Vec<_> = wanted_ports(&s)
            .into_iter()
            .filter(|(_, p)| *p < 8000)
            .collect();
        assert_eq!(own, vec![("tcp", 3080), ("udp", 3080), ("tcp", 3081)]);
        let (text, _) = build(&Dir::new().0, &s, true).unwrap();
        assert!(text.contains("transport = \"auto\""));
    }

    #[test]
    fn the_wss_side_and_its_pin_render() {
        let d = Dir::new();
        let s = Spec {
            name: "secure".into(),
            role: "entry".into(),
            mode: "direct".into(),
            transport: "wss".into(),
            remote: Some("203.0.113.5:443".into()),
            token: Some("b".repeat(48)),
            ws_path: Some("/x".into()),
            tls_pin: Some("ab".repeat(32)),
            forwards: vec![ForwardInfo {
                listen: "0.0.0.0:2222".into(),
                target: "127.0.0.1:22".into(),
                protocol: "tcp".into(),
            }],
            ..Default::default()
        };
        put(&d.0, &s).unwrap();
        let got = get(&d.0, "secure").unwrap();
        assert_eq!(got.ws_path.as_deref(), Some("/x"));
        assert_eq!(got.tls_pin, Some("ab".repeat(32)));
    }

    #[test]
    fn a_listening_wss_side_gets_its_own_certificate_and_reports_the_pin() {
        let d = Dir::new();
        let s = Spec {
            name: "secure-exit".into(),
            role: "exit".into(),
            mode: "direct".into(),
            transport: "wss".into(),
            listen: Some("0.0.0.0:443".into()),
            token: Some("d".repeat(48)),
            ws_path: Some("/x".into()),
            ..Default::default()
        };
        let pin = put(&d.0, &s).unwrap().expect("a pin");
        assert_eq!(pin.len(), 64);
        assert!(d.0.join("secure-exit.crt").exists() && d.0.join("secure-exit.key").exists());
        // the same certificate on an edit, and the pin can be read back for the other side
        assert_eq!(put(&d.0, &s).unwrap(), Some(pin.clone()));
        assert_eq!(get(&d.0, "secure-exit").unwrap().tls_pin, Some(pin));
        remove_files(&d.0, "secure-exit").unwrap();
        assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 0);
    }

    #[test]
    fn ports_a_spec_wants() {
        let mut s = spec("main");
        s.forwards.push(ForwardInfo {
            listen: "[::]:5000".into(),
            target: "127.0.0.1:5000".into(),
            protocol: "tcp+udp".into(),
        });
        assert_eq!(
            wanted_ports(&s),
            vec![("tcp", 3080), ("tcp", 8443), ("tcp", 5000), ("udp", 5000)]
        );
        s.transport = "kcp".into();
        assert_eq!(wanted_ports(&s)[0], ("udp", 3080));
        let mut exit = spec("main");
        exit.role = "exit".into();
        exit.forwards.clear();
        assert!(
            wanted_ports(&exit).is_empty(),
            "an exit dials in reverse mode"
        );
    }

    #[test]
    fn the_new_transports_listen_on_the_right_protocol() {
        use crate::wire::L3Spec;
        let listen = |t: &str| {
            let mut s = spec("p");
            s.transport = t.into();
            s.forwards.clear();
            wanted_ports(&s)
        };
        // faketcp rides TCP; raw udp rides UDP; icmp binds no port at all.
        assert_eq!(listen("faketcp"), vec![("tcp", 3080)]);
        assert_eq!(listen("udp"), vec![("udp", 3080)]);
        assert!(listen("icmp").is_empty(), "icmp answers raw echoes");
        assert_eq!(listen("stealth"), vec![("tcp", 3080)]);
        // l3 follows its carrier.
        let l3 = |carrier: &str| {
            let mut s = spec("p");
            s.transport = "l3".into();
            s.forwards.clear();
            s.l3 = Some(L3Spec {
                carrier: carrier.into(),
                ..Default::default()
            });
            wanted_ports(&s)
        };
        assert_eq!(l3("udp"), vec![("udp", 3080)]);
        assert_eq!(l3("faketcp"), vec![("tcp", 3080)]);
        assert!(l3("icmp").is_empty());
    }

    fn owner(proto: &str, port: u16, process: &str) -> PortOwner {
        PortOwner {
            proto: proto.into(),
            addr: "0.0.0.0".into(),
            port,
            process: Some(process.into()),
            pid: Some(1),
        }
    }

    #[test]
    fn a_taken_port_is_named_but_the_tunnels_own_is_not_a_conflict() {
        let d = Dir::new();
        let owners = [owner("tcp", 8443, "nginx"), owner("udp", 3080, "wg")];
        let r = check(&d.0, &owners, &spec("main"));
        assert!(!r.ok);
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].process.as_deref(), Some("nginx"));
        // once the tunnel exists, its own listening ports are not a conflict on an edit
        put(&d.0, &spec("main")).unwrap();
        let held = [owner("tcp", 8443, "kariz"), owner("tcp", 3080, "kariz")];
        assert!(check(&d.0, &held, &spec("main")).ok);
        assert!(!check(&d.0, &held, &spec("second")).ok);
    }

    #[test]
    fn proc_net_lines_are_read() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:1F91 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(
            parse_proc_net(tcp, false),
            vec![("127.0.0.1".to_string(), 8080, 12345)]
        );
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(
            parse_proc_net(tcp6, false),
            vec![("::1".to_string(), 22, 777)]
        );
        let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2 0000000000000000 0\n";
        assert_eq!(
            parse_proc_net(udp, true),
            vec![("0.0.0.0".to_string(), 53, 999)]
        );
    }

    #[test]
    fn service_actions_are_a_short_list() {
        assert_eq!(
            ctl_args("main", "restart").unwrap(),
            vec!["restart", "kariz@main"]
        );
        assert_eq!(
            ctl_args("main", "enable").unwrap(),
            vec!["enable", "--now", "kariz@main"]
        );
        assert!(ctl_args("main", "mask").is_err());
        assert!(ctl_args("main; reboot", "start").is_err());
        assert!(ctl_args("a@b", "start").is_err());
    }

    #[test]
    fn deleting_removes_every_file() {
        let d = Dir::new();
        put(&d.0, &spec("main")).unwrap();
        put(&d.0, &spec("main")).unwrap();
        std::fs::write(d.0.join("main.sock"), b"").unwrap();
        remove_files(&d.0, "main").unwrap();
        assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 0);
        assert!(remove_files(&d.0, "main").is_ok(), "twice is fine");
    }

    #[test]
    fn an_old_or_missing_manager_is_replaced_by_this_release_s() {
        let d = Dir::new();
        let path = d.0.join("kariz-manager");
        assert!(MANAGER_SCRIPT.contains("tunnel-cert) shift && cmd_tunnel_cert"));
        sync_manager(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MANAGER_SCRIPT);
        // One from before `tunnel-cert` only printed its usage to the panel.
        std::fs::write(
            &path,
            "#!/usr/bin/env bash
echo Usage: kariz-manager
",
        )
        .unwrap();
        sync_manager(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MANAGER_SCRIPT);
        sync_manager(&path).unwrap();
        assert!(!d.0.join("kariz-manager.new").exists());
    }

    #[test]
    fn a_lets_encrypt_panel_without_the_heal_timer_gets_it() {
        let d = Dir::new();
        let (domain, timer) = (d.0.join("domain"), d.0.join("kariz-panel-heal.timer"));
        assert!(MANAGER_SCRIPT.contains("heal-setup)"));
        // A certificate of your own: the manager keeps no `domain`.
        assert!(!heal_timer_missing(&domain, &timer));
        std::fs::write(&domain, "\n").unwrap();
        assert!(!heal_timer_missing(&domain, &timer));
        std::fs::write(&domain, "203.0.113.5\n").unwrap();
        assert!(heal_timer_missing(&domain, &timer));
        std::fs::write(&timer, "[Timer]\n").unwrap();
        assert!(!heal_timer_missing(&domain, &timer));
    }
}
