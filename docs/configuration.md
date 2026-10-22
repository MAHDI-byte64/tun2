# Configuration reference

One TOML file per side, `/etc/kariz/config.toml` by default. Only `role`, `mode` and
`[tunnel]` (with its `token`) are required; everything else has a default, and most
defaults come from the [profile](profiles.md). `kariz check -c <file>` validates a file
and prints the values in effect.

Unknown keys are errors, so a typo is caught rather than ignored.

## Top level

| Key | Values | Default | Notes |
|---|---|---|---|
| `role` | `entry`, `exit` | required | The entry owns the `[[forward]]` rules. |
| `mode` | `reverse`, `direct` | required | `reverse`: the exit dials the entry. `direct`: the entry dials the exit. |
| `profile` | `balanced`, `ultraspeed`, `gaming` | `balanced` | See [Profiles](profiles.md). `throughput` is accepted as the old name of `ultraspeed`. |

## `[tunnel]`

| Key | Values | Default | Notes |
|---|---|---|---|
| `transport` | `tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`, `stealth`, `wsmux`, `wssmux`, `udp`, `faketcp` (alias `pck`), `icmp` (alias `xdi`), `naive`, `xhttp`, `reality`, `auto` | `tcp` | Same on both sides. See [Transports](transports.md). `stealth`, `udp`, `faketcp`, `icmp` and the managed helpers force `encryption` on. `faketcp`, `icmp` are Linux + root. |
| `listen` | `host:port` | | Listening side: entry in reverse mode, exit in direct mode. |
| `remote` | `host:port` | | Dialing side: the other side's address (or a CDN edge). Resolved on every attempt. |
| `token` | at least 16 characters | required | Same on both sides. Generate with `kariz token`. |
| `encryption` | `auto`, `chacha20-poly1305`, `aes-256-gcm`, `none` | `auto` | `auto` dials with AES-256-GCM on CPUs with AES instructions, else ChaCha20-Poly1305, and accepts either. `none` only authenticates; set it on both sides or neither. `quic` always uses TLS 1.3: leave `auto`. |
| `pool` | at least 1 | `8` | Reverse mode without mux: idle connections the exit keeps open. |
| `speedtest` | `true`, `false` | `true` | The exit answers speed test streams from `kariz speedtest` on the entry side (at most 32 at once). They only produce, read and echo data. See [Speed test](speedtest.md). |
| `fallback_transports` | a list of transport names | `[]` (off) | Transports the tunnel falls back to, in order, when the primary cannot be established (the primary is tried first). Same list, same order, on both sides. Cannot contain `auto` or `udp`, repeat the primary, or list a helper transport; not allowed with `transport = "auto"`. See [Transports](transports.md#transport-fallback). |
| `fallback_dwell_secs` | at least 10 | `60` | How long each fallback candidate is held while it tries to connect. |

## `[tunnel.mux]`

Many user connections as streams over a few long-lived tunnel connections. Must be on
or off on both sides.

| Key | Values | Default | Notes |
|---|---|---|---|
| `enabled` | `true`, `false` | on for `tcpmux`, `ws`, `wss`, `kcp`, `quic`; off for `tcp` | `tcpmux` and `quic` cannot turn it off. |
| `connections` | 1-64 | profile (`quic`: 2) | Long-lived connections the dialing side keeps. |
| `max_streams` | 1-16384 | 4096 | Concurrent streams per connection. A stream is one user connection or UDP flow; when every connection has this many, new ones wait and then fail (*every tunnel connection is full* in the log), while the open ones keep working. Each side checks its own limit. |
| `stream_window` | 16 KiB - 16 MiB | profile | Bytes a stream may have in flight. One stream moves at most one window per round trip. |
| `max_lifetime_secs` | at least 60 | off | Replace each connection after this long (streams on it finish first). |
| `coalesce` | `true`, `false` | on (`gaming`: off) | Gather frames into larger writes (speed) or write each at once (latency). |
| `ping_interval_secs` | 1-600 | `tuning.keepalive_secs` | Pings; a peer silent for twice this long is dead. Also QUIC's keep-alive. Keep it at 90 or less behind a CDN. |
| `datagram_buffer` | 16 KiB - 64 MiB | profile | UDP bytes a session queues for sending; more are dropped. |
| `datagram_queue` | 8-65536 | profile | UDP packets each flow queues on the receiving side; the oldest are dropped. |
| `notsent_lowat` | 0, or 4 KiB - 16 MiB | 16384 | `TCP_NOTSENT_LOWAT` on TCP connections carrying mux, so UDP and new data are not stuck behind a kernel backlog. 0 turns it off. Linux only. |

## `[tunnel.ws]` (`ws`, `wss`)

| Key | Side | Default | Notes |
|---|---|---|---|
| `path` | both | `/` | Must match on both sides; any other path gets a `404` page. |
| `host` | both | | Dialer: the `Host` header (and SNI for `wss`), so `remote` can be a CDN IP. Listener: requests for any other host are rejected. |
| `early_data` | dialer | `false` | Put the tunnel hello inside the upgrade request, saving a round trip. The listener always accepts it. |
| `user_agent` | dialer | a desktop Chrome | |
| `headers` | dialer | | Extra request headers, e.g. `{ "Accept-Language" = "en-US,en;q=0.9" }`. Headers Kariz sets itself cannot be overridden. |

## `[tunnel.tls]` (`wss`)

| Key | Side | Notes |
|---|---|---|
| `cert`, `key` | listener | PEM certificate chain and private key. Reloaded when the files change, so certificate renewals need no restart. |
| `sni` | dialer | Server name in the TLS handshake. Default: `ws.host`, then the host in `remote`. |
| `pin_sha256` | dialer | Accept only this certificate (for self-signed ones). Print it with `kariz pin cert.pem`. |
| `insecure` | dialer | Accept any certificate. Warned; prefer `pin_sha256`. |

Without `pin_sha256` or `insecure`, the dialer checks the certificate against the Mozilla
root certificates.

## `[tunnel.quic]` (`quic`)

| Key | Default | Notes |
|---|---|---|
| `congestion` | `cubic` | `cubic`, `bbr` or `newreno`. BBR keeps its speed under random loss but is experimental in quinn and fills queues (warned). |
| `sni` | the host in `remote` (none for an IP) | Dialer only. |
| `alpn` | `h3` | Must match on both sides. |
| `obfs` | `false` | Seal every UDP packet with a key derived from the token, so the traffic does not look like QUIC (see [Transports](transports.md#obfs)). Must be the same on both sides. Costs 28 bytes a packet, and some CPU. |

## `[tunnel.kcp]` (`kcp`)

| Key | Values | Default | Notes |
|---|---|---|---|
| `mode` | `normal`, `fast`, `fast2`, `fast3`, `manual` | `fast2` | Presets from gentle to aggressive (below). |
| `nodelay`, `interval_ms`, `resend`, `no_congestion` | | from `fast2` | `manual` mode only. `interval_ms` 10-1000, `resend` at most 10. |
| `send_window` | 16-32768 packets | 1024 | About bandwidth x RTT / 1300 fills the path; smaller queues less but keeps less speed under loss. |
| `recv_window` | 128-32768 packets | 1024 | |
| `mtu` | 576-1443 | 1350 | KCP packet size; at most 1429 with FEC. |
| `fec_data`, `fec_parity` | 1-64 and 1-32, or both 0 | off (`gaming`: 10 and 3) | Reed-Solomon FEC per sending side: `fec_parity` parity packets per `fec_data` data packets. Both 0 turns it off. |
| `datagrams` | `true`, `false` | `true` | UDP flows travel beside KCP. `false`: inside its reliable stream, as in v0.4 (never lost, but they wait for retransmissions). |

| Preset | nodelay | interval | resend | congestion control |
|---|---|---|---|---|
| `normal` | off | 40 ms | 2 | off |
| `fast` | off | 30 ms | 2 | off |
| `fast2` | on | 20 ms | 2 | off |
| `fast3` | on | 10 ms | 2 | off |

`[tunnel.kcp]` also applies to the KCP carriers `udp`, `faketcp` and `icmp`.

## `[tunnel.stealth]` (`stealth`)

Record-length padding and timing jitter; applied only to stealth links, so no other
transport's wire is touched.

| Key | Values | Default | Notes |
|---|---|---|---|
| `padding` | `true`, `false` | `true` | Add random padding inside each AEAD record so record sizes do not leak the traffic shape. |
| `pad_max` | 1 - 4096 | `256` | Largest padding added to a record, in bytes. |
| `jitter_ms` | 0 - 1000 | `0` | Random delay before flushing a record, in milliseconds. Costs latency; leave at 0 unless a timing classifier is the concern. |

## `[tunnel.faketcp]` (`faketcp`)

The raw-socket fake-TCP carrier. Linux + root (CAP_NET_RAW); all keys optional.

| Key | Values | Default | Notes |
|---|---|---|---|
| `flags` | `A`, `PA`, `PA,A`, `PA,A,PA,PAU` | `PA` | This end's TCP flag pattern; each end sets only its own. |
| `interface` | name | auto | Override the auto-detected egress interface (for virtualised networks). |
| `gateway_mac` | `aa:bb:cc:dd:ee:ff` | auto | Override the auto-detected next-hop MAC. |
| `manage_firewall` | `true`, `false` | `true` | Install and remove the RST-drop and NOTRACK iptables rules (RAII). Off: the tunnel still runs but is unreliable under load. |

## `[tunnel.icmp]` (`icmp`)

The raw ICMP-echo carrier. Linux + root.

| Key | Values | Default | Notes |
|---|---|---|---|
| `manage_firewall` | `true`, `false` | `true` | Install and remove the iptables rules that suppress the kernel's automatic echo replies (RAII). Off: the tunnel still runs but pays an extra uplink. |

## `[tunnel.proto47]` (the `proto47` [l3] carrier)

The raw IP protocol-47 / keyed-GRE carrier. Available only as an `[l3] carrier`, not as a
standalone `[tunnel] transport`. Linux + root (CAP_NET_RAW).

| Key | Values | Default | Notes |
|---|---|---|---|
| `manage_firewall` | `true`, `false` | `true` | Install and remove the best-effort `-p gre -j ACCEPT` iptables rule (RAII), so protocol 47 survives a default-DROP INPUT policy. Off: the tunnel still runs unless such a policy blocks it. |

## `[tunnel.helper]` (`naive`, `xhttp`, `reality`)

Credentials and paths for a managed helper transport. Which keys are required depends on the
transport and the side (acceptor vs dialer). All file paths must be absolute; `insecure` is
not allowed. See [Transports](transports.md#managed-helper-transports-naive-xhttp-reality).

| Key | Transport | Side | Notes |
|---|---|---|---|
| `binary` | all | both | Override the helper binary path. Default: the installed pinned path. |
| `username`, `password` | `naive` | both | The naive credential. |
| `uuid` | `xhttp`, `reality` | both | The VLESS client UUID, canonical form (`kariz helper uuid`). |
| `path` | `xhttp` | both | The HTTP path. |
| `server_name` | `xhttp`, `reality` | both | The TLS server name (the cover host for `reality`). |
| `host` | `xhttp` | dialer | The HTTP `Host` header. |
| `short_id` | `reality` | both | Hex, even length, at most 16 characters. |
| `private_key` | `reality` | acceptor | X25519 private key, base64url, 32 bytes (`kariz helper reality-keys`). |
| `public_key` | `reality` | dialer | X25519 public key, base64url, 32 bytes. |
| `target` | `reality` | acceptor | The cover target, `host:port`. |
| `certificate`, `key` | `naive`, `xhttp` | acceptor | PEM certificate chain and private key for the helper's TLS. |
| `ca_file` | all | dialer | Optional CA bundle (PEM) to verify the helper server against. |

## `[l3]` (the layer-3 / GRE direct tunnel)

Present instead of the `[[forward]]` rules: the tunnel creates a TUN (or TAP) device and
carries whole IP packets (or Ethernet frames), GRE-encapsulated and sealed inside the tunnel's
own session. Linux only, root. See [Transports](transports.md#l3--gre-direct-tunnel).

| Key | Values | Default | Notes |
|---|---|---|---|
| `mode` | `dial`, `listen` | required | `dial` reaches out; `listen` waits for the inbound connection. Either host may dial. |
| `addr` | `host:port` | required | `listen`: the address to listen on. `dial`: the peer's address. |
| `token` | at least 16 characters | `[tunnel].token` | Shared secret; defaults to the tunnel token. |
| `layer` | `3`, `2` | `3` | `3`: a TUN device carrying IP packets. `2`: a TAP device carrying Ethernet frames (an encrypted GRETAP). |
| `local_ip` | CIDR, e.g. `10.10.0.1/30` | required for `layer = 3` | This end's address on the tunnel. Optional for `layer = 2`. |
| `peer_ip` | IP, e.g. `10.10.0.2` | required for `layer = 3` | The peer's address on the tunnel. Optional for `layer = 2`. |
| `carrier` | `udp`, `quic`, `faketcp`, `icmp`, `proto47` | required | The carrier the sealed GRE packets ride. Reliable carriers are rejected (TCP-over-TCP meltdown). `proto47` is Linux + root and puts (encrypted) IP protocol 47 on the wire; see [Transports](transports.md#l3--gre-direct-tunnel). |
| `gre_key` | a 32-bit number | `0` | RFC 2890 key; both ends compare it. Lets several logical tunnels share a carrier. |
| `iface` | interface name | next free `kzN` | The device name to create. |
| `mtu` | 576 - 1500 | `1400` | The TUN/TAP interface MTU. |
| `fec_data`, `fec_parity` | 1-64 and 1-32, or both 0 | off | Reed-Solomon FEC over the carrier. |
| `ports` | `[[l3.ports]]` rules | none | Optional port forwarding over the link (the `[[forward]]` syntax). |
| `accept_udp` | `true`, `false` | `false` | Accept forwarded UDP over the link. |
| `encap` | `gre` | `gre` | The encapsulation; both ends compare it. |

## `[[forward]]` (entry only)

One table per rule; as many as needed.

| Key | Values | Default | Notes |
|---|---|---|---|
| `listen` | `host:port` | required | Where users connect, on the entry. |
| `target` | `host:port` | required | Resolved and dialed on the exit. |
| `protocol` | `tcp`, `udp`, `tcp+udp` | `tcp` | `tcp+udp` serves both on the same port. Use mux for UDP. |
| `duplicate` | 1-3 | 1 | UDP: send each packet this many times in all, both ways. Copies go only where packets may be lost (`kcp`, `quic`). |
| `duplicate_gap_ms` | 0-50 | 5 | Time between the copies of a packet. |
| `proxy_protocol` | `v1`, `v2` | off | TCP rules (`tcp`, `tcp+udp`): the exit starts every connection to the target with a PROXY protocol header carrying the user's address. See below. |

### Real user addresses (`proxy_protocol`)

Without it, every user reaches the target from the exit server's own Kariz process, so
Xray sees `127.0.0.1` for everyone: per-account IP and device limits in 3x-ui or
Marzban, Xray's access log, IP routing rules and fail2ban on the exit server all see one
address. With `proxy_protocol`, the exit writes a PROXY header (HAProxy's format, `v1`
text or `v2` binary) to the target before any user data, naming the user's address and
port and the entry port they connected to. Xray reads both versions; `v2` is the
smaller.

```toml
[[forward]]
listen = "0.0.0.0:443"
target = "127.0.0.1:443"
proxy_protocol = "v2"
```

> **Warning:** the target must expect the header. In Xray turn on
> `"acceptProxyProtocol": true` in the inbound's `streamSettings.sockopt` (in 3x-ui: the
> inbound's **Proxy Protocol** switch) for exactly the ports behind these rules. A target
> that does not expect it reads the header as the start of the user's traffic, and every
> connection through that port breaks. Turn it on in Xray and in Kariz together.

- Both servers need Kariz 2.5 or newer: the entry sends the user's address with each
  connection, and an older exit refuses such connections.
- TCP only. UDP flows never get a header (Xray does not take one on UDP), so a
  `tcp+udp` rule sends one on its TCP connections only, and a `udp` rule refuses the
  setting.
- The health probe only connects to the target and closes, sending nothing, so it does
  not trip a target that expects headers.

## `[tuning]`

Overrides of the profile's values.

| Key | Values | Default | Notes |
|---|---|---|---|
| `nodelay` | `true`, `false` | `true` | `TCP_NODELAY` on user and target connections. |
| `buffer_size` | at least 1024 bytes | profile | Relay buffer per connection. |
| `keepalive_secs` | | 30 (`gaming`: 10) | TCP keep-alive, and the default ping interval. QUIC and KCP ping every third of it. |
| `dial_timeout_secs` | | 10 | Connecting to the other side or a target. |
| `handshake_timeout_secs` | | 10 | The tunnel handshake. |
| `threads` | at least 1 | one per CPU core | Worker threads. |
| `udp_timeout_secs` | 5-3600 | 60 | A UDP flow ends after this long without packets. |
| `udp_max_flows` | 1-65536 | 4096 | UDP flows (client addresses) per rule; packets from more clients are dropped (existing flows go on). Each flow is one stream of a tunnel connection. In the panel: *UDP clients per port* in the wizard and on a tunnel's edit page (2.6.0-beta.4 or newer on the entry server). |
| `max_conns_per_ip` | 0 or more | 0 (off) | Entry side: user connections and UDP flows one client address may have open, over all rules; more are closed at once. Users on mobile networks often share one address, so keep it well above what one person uses. |
| `dscp` | a name (`ef`, `af41`, `cs4`, ...) or 0-63 | off | DSCP mark on tunnel sockets and the exit's UDP sockets to targets. Not on QUIC sockets. See [UDP and games](udp-and-games.md#dscp). |

## `[control]`

A local socket on each side, through which `kariz status` reads the running daemon's
counters (both sides, see [Status](status.md)) and `kariz speedtest` uses its sessions
(the entry side, see [Speed test](speedtest.md)). Linux only.

| Key | Default | Notes |
|---|---|---|
| `socket` | the config file's path with `.sock` (`/etc/kariz/main.toml` gives `/etc/kariz/main.sock`) | Owner only. If it cannot be made, the tunnel runs without it and logs a warning. |
| `traffic_file` | the config file's path with `.traffic` (`/etc/kariz/main.traffic`) | Where the byte counters (`status`'s `bytes_up` / `bytes_down`) are kept across restarts: written every 5 s while traffic flows and at shutdown, read back when the tunnel starts. Owner only. A file that cannot be written is logged, and the counters start at zero next time. |

## `[log]`

| Key | Values | Default |
|---|---|---|
| `level` | `error`, `warn`, `info`, `debug`, `trace` | `info` |
| `color` | `auto`, `always`, `never` | `auto` |

`RUST_LOG=kariz=debug` in the environment overrides `level`. With `color = "auto"`, log
lines are coloured on a terminal unless `NO_COLOR` is set.

`kariz run` starts with a banner: the version, and what this side is about to do (its
role and mode, transport, profile, addresses and forward rules). On a terminal, each
line then shows the local time, a coloured level badge and the fields. Under systemd,
lines carry systemd's priority prefix instead, so `journalctl` highlights warnings and
errors itself and `journalctl -u kariz -p warning` shows only those.

## Settings that must match on both sides

`transport`, `token`, mux on or off, `ws.path`, `quic.alpn`, `quic.obfs`, and `encryption = "none"`
(both or neither). A mismatch fails the handshake with an error saying which setting
differs, where the protocol can tell. For the managed helpers the shared credentials
(`helper.uuid` / `username` / `short_id` / `server_name` and the matching key pair) must
agree. `fallback_transports` must be the same list in the same order on both sides. For the
`[l3]` mode, `carrier`, `layer`, `gre_key` and `encap` must match (the ends compare `encap`
in the handshake and refuse a mismatch by name). The `[tunnel.stealth]` padding and jitter are
per side and need not match.
