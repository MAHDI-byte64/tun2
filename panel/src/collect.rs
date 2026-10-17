//! What a server reports about itself: its health (from `/proc`, on Linux) and its Kariz
//! tunnels (the config files, systemd, the running daemons' control sockets). The panel
//! runs this for its own server; agents run it for theirs.

use std::path::Path;
use std::time::{Duration, Instant};

use kariz::config::{mode_name, role_name, Config};

use crate::manage::Services;
use crate::wire::{ForwardInfo, Health, TunnelInfo};

/// This server's name.
pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "this-server".to_owned())
}

// ---- health ----

/// Busy and total CPU time from the first line of `/proc/stat`.
pub fn parse_cpu(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let values: Vec<u64> = fields.take(8).filter_map(|f| f.parse().ok()).collect();
    if values.len() < 4 {
        return None;
    }
    let total: u64 = values.iter().sum();
    // idle and iowait are not busy.
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

/// Total and used memory in bytes from `/proc/meminfo`.
pub fn parse_mem(meminfo: &str) -> Option<(u64, u64)> {
    let kb = |key: &str| -> Option<u64> {
        meminfo.lines().find_map(|l| {
            l.strip_prefix(key)?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()
        })
    };
    let total = kb("MemTotal:")?;
    let available = kb("MemAvailable:")?;
    Some((total * 1024, total.saturating_sub(available) * 1024))
}

/// Bytes received and sent over every interface but the loopback, from `/proc/net/dev`.
pub fn parse_net(dev: &str) -> (u64, u64) {
    let mut rx = 0;
    let mut tx = 0;
    for line in dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();
        if fields.len() >= 9 {
            rx += fields[0];
            tx += fields[8];
        }
    }
    (rx, tx)
}

fn first_number(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// Takes health samples; rates and the CPU share need the previous sample.
#[derive(Default)]
pub struct Sampler {
    cpu: Option<(u64, u64)>,
    net: Option<((u64, u64), Instant)>,
    /// The server's addresses and when they were looked up (they change rarely).
    ips: Option<(Instant, Option<String>, Option<String>)>,
}

/// The address a route to `probe` leaves from. A UDP socket is only connected, never
/// written to: nothing goes out on the network.
fn route_source(bind: &str, probe: &str) -> Option<String> {
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then(|| ip.to_string())
}

/// This server's own IPv4 and IPv6 addresses (each `None` where there is no route).
pub fn local_ips() -> (Option<String>, Option<String>) {
    (
        route_source("0.0.0.0:0", "1.1.1.1:80"),
        route_source("[::]:0", "[2606:4700:4700::1111]:80"),
    )
}

/// Whether an IPv4 address is one the internet can reach (not private, loopback,
/// link-local, shared or reserved).
pub fn public_ip4(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b)))
}

/// Whether an IPv6 address is a global one (not link-local, unique local or loopback).
pub fn public_ip6(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<std::net::Ipv6Addr>() else {
        return false;
    };
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80)
}

/// The files a sample reads (all `None` where there is no `/proc`).
#[derive(Default)]
pub struct Proc {
    pub stat: Option<String>,
    pub meminfo: Option<String>,
    pub net_dev: Option<String>,
    pub uptime: Option<String>,
    pub loadavg: Option<String>,
    pub route: Option<String>,
}

impl Proc {
    pub fn read() -> Self {
        let read = |p: &str| std::fs::read_to_string(p).ok();
        Self {
            stat: read("/proc/stat"),
            meminfo: read("/proc/meminfo"),
            net_dev: read("/proc/net/dev"),
            uptime: read("/proc/uptime"),
            loadavg: read("/proc/loadavg"),
            route: read("/proc/net/route"),
        }
    }
}

impl Sampler {
    pub fn sample(&mut self) -> Health {
        let now = Instant::now();
        let mut health = self.sample_from(&Proc::read(), now);
        let fresh = self
            .ips
            .as_ref()
            .is_some_and(|(at, ..)| now.duration_since(*at) < Duration::from_secs(60));
        if !fresh {
            let (v4, v6) = local_ips();
            self.ips = Some((now, v4, v6));
        }
        if let Some((_, v4, v6)) = &self.ips {
            health.ip4 = v4.clone();
            health.ip6 = v6.clone();
        }
        health
    }

    pub fn sample_from(&mut self, p: &Proc, now: Instant) -> Health {
        let mut health = Health::default();
        if let Some(cpu) = p.stat.as_deref().and_then(parse_cpu) {
            if let Some((busy0, total0)) = self.cpu {
                let total = cpu.1.saturating_sub(total0);
                if total > 0 {
                    health.cpu_pct =
                        Some(cpu.0.saturating_sub(busy0) as f64 * 100.0 / total as f64);
                }
            }
            self.cpu = Some(cpu);
        }
        if let Some((total, used)) = p.meminfo.as_deref().and_then(parse_mem) {
            health.mem_total = Some(total);
            health.mem_used = Some(used);
        }
        if let Some(dev) = p.net_dev.as_deref() {
            let now_bytes = parse_net(dev);
            if let Some(((rx0, tx0), at)) = self.net {
                let secs = now.duration_since(at).as_secs_f64();
                if secs > 0.05 {
                    health.rx_bps = Some(now_bytes.0.saturating_sub(rx0) as f64 / secs);
                    health.tx_bps = Some(now_bytes.1.saturating_sub(tx0) as f64 / secs);
                }
            }
            self.net = Some((now_bytes, now));
        }
        health.uptime_secs = p.uptime.as_deref().and_then(first_number).map(|s| s as u64);
        health.load1 = p.loadavg.as_deref().and_then(first_number);
        health.routes = p.route.as_deref().map(parse_routes).unwrap_or_default();
        health
    }
}

/// The IPv4 networks in `/proc/net/route` that are up, without the default route and the
/// `kz-` interfaces of Kariz's own private links, as `a.b.c.d/p`, sorted and without repeats.
pub fn parse_routes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 || f[0].starts_with("kz-") {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            // Bit 0 is RTF_UP; the addresses are in memory (network) order, read as
            // a little-endian number.
            if flags & 1 == 0 {
                return None;
            }
            let dest = u32::from_str_radix(f[1], 16).ok()?.swap_bytes();
            let mask = u32::from_str_radix(f[7], 16).ok()?.swap_bytes();
            if mask == 0 || mask.count_zeros() != mask.trailing_zeros() {
                return None;
            }
            Some(format!(
                "{}/{}",
                std::net::Ipv4Addr::from(dest & mask),
                mask.count_ones()
            ))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

// ---- tunnels ----

/// The tunnels configured in `dir` (`/etc/kariz`), with their state. Slow parts (systemd,
/// the control sockets) are asked with short time limits, so a stuck daemon does not
/// stall the report.
pub async fn tunnels(dir: &Path, services: &dyn Services) -> Vec<TunnelInfo> {
    let mut files: Vec<_> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    // All at once: a tunnel that does not answer costs its own time limit, not the sum of
    // them (the panel gives a whole request 10 s, and a stuck daemon or two was enough to
    // go over it and end the link).
    join_all(files.iter().map(|path| {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        async move { tunnel(&name, path, services).await }
    }))
    .await
}

/// Runs the futures side by side; their outputs come back in the order they were given.
async fn join_all<F: std::future::Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    use std::pin::Pin;
    use std::task::Poll;
    let mut pending: Vec<Option<Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut done: Vec<Option<F::Output>> = (0..pending.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut left = 0;
        for (slot, out) in pending.iter_mut().zip(done.iter_mut()) {
            if let Some(f) = slot {
                match f.as_mut().poll(cx) {
                    Poll::Ready(v) => {
                        *out = Some(v);
                        *slot = None;
                    }
                    Poll::Pending => left += 1,
                }
            }
        }
        if left == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    done.into_iter().flatten().collect()
}

async fn tunnel(name: &str, path: &Path, services: &dyn Services) -> TunnelInfo {
    let config = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            return TunnelInfo {
                name: name.to_owned(),
                role: String::new(),
                mode: String::new(),
                transport: String::new(),
                profile: String::new(),
                encryption: String::new(),
                listen: None,
                remote: None,
                forwards: Vec::new(),
                active: None,
                status: None,
                error: Some(format!("{e:#}")),
            }
        }
    };
    let (status, active) = tokio::join!(tunnel_status(&config), services.active(name.to_owned()));
    TunnelInfo {
        name: name.to_owned(),
        role: role_name(config.role).to_owned(),
        mode: mode_name(config.mode).to_owned(),
        // The l3 / GRE mode has no core transport of its own; the panel shows it as "l3".
        transport: if config.l3.is_some() {
            "l3".to_owned()
        } else {
            config.tunnel.transport.name().to_owned()
        },
        profile: config.profile.name().to_owned(),
        encryption: config.tunnel.encryption.name().to_owned(),
        // The l3 mode keeps its address in [l3]: the listening side has it as `listen`, the
        // dialing side as `remote`, so the list and the edit page line up with other tunnels.
        listen: match &config.l3 {
            Some(l3) if matches!(l3.mode, kariz::config::L3Mode::Listen) => Some(l3.addr.clone()),
            Some(_) => None,
            None => config.tunnel.listen.clone(),
        },
        remote: match &config.l3 {
            Some(l3) if matches!(l3.mode, kariz::config::L3Mode::Dial) => Some(l3.addr.clone()),
            Some(_) => None,
            None => config.tunnel.remote.clone(),
        },
        forwards: config
            .forward
            .iter()
            .map(|f| ForwardInfo {
                listen: f.listen.clone(),
                target: f.target.clone(),
                protocol: f.protocol.name().to_owned(),
            })
            .collect(),
        active,
        status,
        error: None,
    }
}

#[cfg(unix)]
async fn tunnel_status(config: &Config) -> Option<kariz::stats::Status> {
    let socket = config.control_socket()?;
    let ask = async {
        let connection = kariz::control::connect(&socket).await.ok()?;
        kariz::control::status(connection).await.ok()
    };
    tokio::time::timeout(Duration::from_secs(2), ask)
        .await
        .ok()
        .flatten()
}

#[cfg(not(unix))]
async fn tunnel_status(_: &Config) -> Option<kariz::stats::Status> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses_are_told_from_private_ones() {
        for ip in ["8.8.8.8", "185.10.20.30", "100.63.0.1", "172.32.0.1"] {
            assert!(public_ip4(ip), "{ip}");
        }
        for ip in [
            "10.0.0.5",
            "192.168.1.9",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "nope",
        ] {
            assert!(!public_ip4(ip), "{ip}");
        }
        assert!(public_ip6("2606:4700:4700::1111"));
        for ip in [
            "fe80::1", "fd00::1", "fc00::1", "::1", "::", "ff02::1", "nope",
        ] {
            assert!(!public_ip6(ip), "{ip}");
        }
    }

    #[test]
    fn routes_are_read_without_the_default_and_our_own_links() {
        let text =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n\
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
kz-ab12c\t0000004D\t00000000\t0001\t0\t0\t0\t0000F0FF\t0\t0\t0\n\
eth1\t0000000A\t00000000\t0000\t0\t0\t0\t000000FF\t0\t0\t0\n";
        // eth1's route is not up; the kz- link is ours; the default route is skipped.
        assert_eq!(
            parse_routes(text),
            vec!["172.17.0.0/16".to_string(), "192.168.0.0/16".to_string()]
        );
        assert!(parse_routes("").is_empty());
    }

    const STAT_1: &str = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\n";
    const STAT_2: &str = "cpu  200 0 200 750 150 0 0 0 0 0\n";
    const NET_1: &str = "Inter-|   Receive |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 10 0 0 0 0 0 0\n  eth1:  500  5 0 0 0 0 0 0  300  5 0 0 0 0 0 0\n";
    const NET_2: &str = "    lo: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0\n  eth0: 3000 10 0 0 0 0 0 0 6000 10 0 0 0 0 0 0\n  eth1:  500  5 0 0 0 0 0 0  300  5 0 0 0 0 0 0\n";

    #[test]
    fn proc_files_are_parsed() {
        // busy = user+nice+system; idle = idle+iowait.
        assert_eq!(parse_cpu(STAT_1), Some((200, 1000)));
        assert_eq!(parse_cpu("nonsense"), None);
        assert_eq!(parse_cpu("cpu 1 2"), None);
        let mem =
            "MemTotal:       8000000 kB\nMemFree:         100000 kB\nMemAvailable:   2000000 kB\n";
        assert_eq!(parse_mem(mem), Some((8_000_000 * 1024, 6_000_000 * 1024)));
        assert_eq!(parse_mem("MemTotal: 1 kB\n"), None);
        // The loopback is left out.
        assert_eq!(parse_net(NET_1), (1500, 2300));
        assert_eq!(first_number("12345.67 8901.23"), Some(12345.67));
    }

    #[test]
    fn a_sample_needs_the_previous_one_for_shares_and_rates() {
        let mut sampler = Sampler::default();
        let t0 = Instant::now();
        let first = sampler.sample_from(
            &Proc {
                stat: Some(STAT_1.into()),
                meminfo: Some("MemTotal: 1000 kB\nMemAvailable: 250 kB\n".into()),
                net_dev: Some(NET_1.into()),
                uptime: Some("3600.5 100.0".into()),
                loadavg: Some("0.52 0.40 0.30 1/200 999".into()),
                route: None,
            },
            t0,
        );
        assert_eq!((first.cpu_pct, first.rx_bps), (None, None));
        assert_eq!(
            (first.mem_total, first.mem_used),
            (Some(1_024_000), Some(768_000))
        );
        assert_eq!((first.uptime_secs, first.load1), (Some(3600), Some(0.52)));

        let second = sampler.sample_from(
            &Proc {
                stat: Some(STAT_2.into()),
                net_dev: Some(NET_2.into()),
                ..Proc::default()
            },
            t0 + Duration::from_secs(2),
        );
        // busy 200 -> 400 of total 1000 -> 1300: 200 of 300.
        assert!((second.cpu_pct.unwrap() - 66.666).abs() < 0.1, "{second:?}");
        // eth0 +2000 rx, +4000 tx in 2 s.
        assert_eq!((second.rx_bps, second.tx_bps), (Some(1000.0), Some(2000.0)));
        assert_eq!(second.mem_total, None);
    }

    #[tokio::test]
    async fn tunnels_are_read_from_config_files_without_their_tokens() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.toml"),
            "role = \"entry\"\nmode = \"reverse\"\nprofile = \"gaming\"\n[tunnel]\ntransport = \"tcpmux\"\n\
             listen = \"0.0.0.0:3080\"\ntoken = \"a-secret-token-0123456789\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n\
             [[forward]]\nlisten = \"0.0.0.0:53\"\ntarget = \"10.0.0.1:53\"\nprotocol = \"udp\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("broken.toml"), "role = \"nobody\"\n").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let list = tunnels(dir.path(), &crate::manage::Systemd).await;
        assert_eq!(
            list.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["broken", "main"]
        );
        let main = &list[1];
        assert_eq!(
            (
                main.role.as_str(),
                main.mode.as_str(),
                main.transport.as_str()
            ),
            ("entry", "reverse", "tcpmux")
        );
        assert_eq!(main.profile, "gaming");
        assert_eq!(main.listen.as_deref(), Some("0.0.0.0:3080"));
        assert_eq!(main.forwards.len(), 2);
        assert_eq!(main.forwards[1].protocol, "udp");
        assert!(main.error.is_none());
        assert!(list[0].error.is_some());
        // The token is never in what is reported.
        assert!(!serde_json::to_string(&list)
            .unwrap()
            .contains("a-secret-token"));
        assert!(
            tunnels(&dir.path().join("missing"), &crate::manage::Systemd)
                .await
                .is_empty()
        );
    }
}
