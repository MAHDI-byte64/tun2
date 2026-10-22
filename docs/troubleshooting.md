# Troubleshooting

Start with `kariz check -c /etc/kariz/config.toml` on both sides: it validates the file,
prints the values in effect and lists warnings. On a running tunnel, `kariz status -c ...`
says whether the other side is connected and, if not, the last error
([Status](status.md)); `kariz reload -c ...` applies a changed set of forward rules to the
running entry without a restart, or says why it cannot
([details](configuration.md#reloading-the-forward-rules)). Then read the logs:

```bash
journalctl -u kariz -f                      # with systemd
journalctl -u kariz -p warning              # warnings and errors only
RUST_LOG=kariz=debug kariz run -c ...       # more detail
```

## It does not start at all

| Log message | Cause | Fix |
|---|---|---|
| `kariz@NAME.service: Main process exited, code=killed, status=4/ILL`, or *Illegal instruction* when run by hand; the tunnel restarts every few seconds | the binary needs a newer CPU than the server has: the x86_64 builds of 2.9.2 and 2.10.0–2.10.2 contain AVX2 instructions, and this CPU has none (`grep -c avx2 /proc/cpuinfo` prints `0`) | update to 2.9.3 or later (`kariz-manager update`); until then `kariz-manager update --version v2.9.1` |

## The sides do not connect

| Log message | Cause | Fix |
|---|---|---|
| `could not connect to the entry side` / `could not connect to the exit side` | the listening side is unreachable | check `listen` / `remote`, the firewall, and the cloud security group (UDP for `quic` and `kcp`) |
| `tunnel handshake failed: invalid hello tag` (listening side), `rejected the tunnel connection` / `entry side rejected us or failed authentication` (dialing side) | different tokens | copy the same token to both sides |
| `hello timestamp out of range` | the servers' clocks differ by minutes | enable NTP (`timedatectl set-ntp true`) |
| `peer has mux on but this side has it off` | mux differs | set `[tunnel.mux] enabled` the same on both sides |
| `peer uses encryption ..., which tunnel.encryption on this side does not allow` | one side has `encryption = "none"` | set it on both sides or neither |
| a `404` from a `ws` / `wss` listener | wrong `ws.path` or `ws.host` | make `ws.path` match; check `ws.host` on the listener |
| `bad_certificate` (`quic`) | different tokens | copy the same token to both sides |

## It connects, but

**Users connect and are dropped at once.** The exit could not reach the target. The exit
logs `could not connect to target`. `target` is dialed from the exit, so
`127.0.0.1:443` is port 443 on the exit.

**UDP does not work.** Check that the rule says `protocol = "udp"` or `"tcp+udp"`, and
that mux is on (`kariz check` warns otherwise). A v0.2 exit does not support UDP at all.
A rule with `duplicate` needs the exit at v0.5 or newer.

**It is slow.**

- **On a lossy path,** TCP-based transports collapse; try `kcp`, or `quic` with
  `congestion = "bbr"`.
- **On a clean path,** one stream is capped at one window per round trip: use
  `profile = "ultraspeed"` or raise `tunnel.mux.stream_window`.
- See [Performance](performance.md#tuning-for-speed).

**Games lag under load.** Use `profile = "gaming"` on both sides and `kcp`. TCP-based
transports make game packets wait for every lost segment. See
[UDP forwarding and games](udp-and-games.md).

**Behind a CDN, connections drop after about 100 s idle.** Keep
`tunnel.mux.ping_interval_secs` (or `tuning.keepalive_secs`) at 90 or less.

**`quic` or `kcp` never connects.** UDP may be blocked or throttled on the path, UDP on
port 443 in particular. Try another port, or fall back to `tcpmux` or `wss`. If `kcp`
connects and `quic` does not, the path is probably recognising QUIC: set
`obfs = true` in `[tunnel.quic]` on both sides. With `obfs` on one side only, the connect
times out.

**A server joined with *QUIC* never shows up.** The link uses UDP on the port after the
panel's agents port, so that UDP port has to be open on the panel's server and in any cloud
firewall. If UDP is blocked on the path altogether, choose *Auto* (or *TCP* or *WSS*) in *Add
server*. More in [The web panel](panel.md#troubleshooting).

## Warnings from `kariz check`

| Warning | Meaning |
|---|---|
| `tunnel.encryption = "none"` | traffic is readable on the wire |
| ping interval above 90 s over `ws` / `wss` | a CDN will cut idle connections |
| UDP forwarded without mux | every UDP flow takes a whole tunnel connection |
| `forward.duplicate has no effect here` | copies are only sent over `kcp` (with mux) and `quic` |
| `quic.congestion = "bbr"` | experimental in quinn; fills queues |
| `tls.insecure = true` | the server certificate is not verified |
| `tuning.dscp` over QUIC or on Windows | the mark does not reach the wire there |
