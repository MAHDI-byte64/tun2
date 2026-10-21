# Changelog

## 2.10.2 - 2026-10-21

### Fixed

- **The x86_64 binaries run on older CPUs again.** The 2.10.1 release build emitted AVX2
  instructions that CPUs without AVX2 (for example Ivy Bridge Xeons such as the E5-2600 v2
  series) cannot execute, so `kariz` and `kariz-panel` crashed on start with an illegal
  instruction (`SIGILL`, `status=4/ILL`). The x86_64 release is now pinned to the baseline
  `x86-64` target so it runs on any 64-bit Intel/AMD CPU. The crypto libraries still select
  AES-NI/AVX2 at run time through their own CPU detection, so throughput on modern servers is
  unchanged.

## 2.10.1 - 2026-10-21

### Fixed

- **Asymmetric transport with `wss` on the receive direction now works.** The TLS certificate
  was dropped when `wss` was the receive link rather than the primary transport, so the tunnel
  could not start: core `validate_tls`, the panel's config rendering and the wizard/edit TLS UI
  now all recognise `wss` on either direction. (Both servers still need 2.10.)
- **Asymmetric `ws`/`wss` links no longer deadlock with `early_data`.** A split tunnel's handshake
  hung when `[tunnel.ws] early_data` was on, because the one-way links never flushed the held-back
  HTTP 101; `early_data` is now turned off on a split tunnel's ws/wss legs (the first bytes it
  sends are tiny, so the saved round trip did not matter).
- **Asymmetric `ws`/`wss` links answer WebSocket control frames.** Each leg's otherwise-idle
  direction is now serviced in the background, so a `ping` from a CDN or reverse proxy is answered
  and a close is noticed; a plain `tcp` leg needs nothing and is untouched.
- **The one-time login link displays correctly.** A long login URL overflowed its settings cell
  and spilled past the card; the control column is now capped so the URL scrolls within it.
- **The panel proxy accepts IPv6 and special characters.** An IPv6 proxy address must now be
  bracketed (`[::1]:1080`), and a username or password with a `:`/`@`/`/` is percent-encoded in
  the internet-scope proxy URL, so neither breaks the connection.

## 2.10.0 - 2026-10-21

### Added

- **Asymmetric (split) transport — a different transport each way.** A tunnel can now send over
  one transport and receive over another, carried as two paired connections joined into one
  logical stream, for paths that filter upload and download differently. Set `[tunnel]
  recv_transport` (one of `tcp`, `ws`, `wss`, different from `transport`); the receive link uses
  the primary listen/dial port + 1 by default (`recv_listen` / `recv_remote` to override).
  Encryption, mux and the handshake ride the combined stream unchanged, and it always muxes over
  the one pair. For a `spoof` tunnel the asymmetry is per on-wire shape instead — `[tunnel.spoof]
  recv_shape` forges one shape and accepts another over the single KCP session. The tunnel wizard
  gains a **"different transport each way"** switch for every connection kind (direct, reverse,
  source spoofing), with a two-direction picker and a flow diagram. Both servers need 2.10.
- **Outbound SOCKS5 proxy for the panel.** Settings → Proxy lets the panel reach out through a
  SOCKS5 proxy, with a selectable scope: **server connections** (the panel's reverse-mode dials
  to the other servers and the tunnel management on those links — kept to the TCP transports
  `tcpmux`/`wss`, since SOCKS5 cannot carry UDP) and/or **panel internet** (release downloads for
  updating). Optional username/password; the password is kept in the panel and never shown again.
  Changing it rebuilds the reverse links so the new route takes effect at once.
- **Offline install in the manager script.** `kariz-manager install --archive FILE` installs from
  a release `.tar.gz` already on disk, and `--offline` finds a copied-over
  `kariz-*-<arch>-linux.tar.gz` (next to the script, in the current folder, `/root` or
  `/opt/kariz`) on its own; the interactive **Install** also falls back to a local archive when it
  cannot reach GitHub. The checksum and signature are verified exactly as for a download, so an
  air-gapped install is no less safe.

### Changed

- The panel **IP Tester** presents its results as a scorecard (usable / arrived / tested) with a
  colour-coded per-source arrival meter, instead of a plain table.

## 2.9.1 - 2026-10-20

### Fixed

- **`spoof` transport now gives each server its own forged-source list.** The tunnel wizard
  used to send a single pool to both ends, but an address that gets through from one side can
  be dropped from the other (the two paths meet different BCP38/uRPF rules), so the two servers
  must not share a list. The spoof wizard now shows one list per server (named after each
  server), the pair layer gives each side its own `[tunnel.spoof] pool`, and both lists are
  required. The on-wire per-side config is unchanged, so a 2.9.0 agent still runs these tunnels.
- **IP Tester now shows why a run failed instead of a blank “internal”.** A sender/receiver
  failure (no `CAP_NET_RAW`/root on an agent, a refused egress, an older agent) was collapsed
  into a generic 500, so the page showed nothing useful; the real reason is now surfaced.
- **IP Tester honours a 0% loss threshold.** An explicit `0` asked for strict 100% arrival but
  was silently treated as the 20% default, which could mark a lossy source “usable”. The empty
  field still means the default.

## 2.9.0 - 2026-10-20

### Added

- **`spoof` transport — mutual source-IP spoofing.** A new tunnel transport (the sixteenth)
  that rides the KCP stack inside crafted packets whose **source IP is forged and rotated from
  a pool**, so the traffic blends into ordinary background traffic and defeats stateful DPI.
  Both ends forge their source and are told the other's real address, so it is strictly
  point-to-point. The on-wire packet shape is chosen with `[tunnel.spoof] shape`: `udp`
  (lowest overhead, the default), `tcp`, `icmp`, `gre`, `ipip` or `proto58`. Encryption is
  mandatory, and mux, FEC and the KCP fast modes all apply, so with the `ultraspeed` profile
  and the `udp` shape it runs at full tilt. Linux + root; `[tunnel.spoof] manage_firewall`
  controls the best-effort iptables rules. It only works where the path does not filter
  forged-source packets (no BCP38 / uRPF).
- **IP spoof tester.** `kariz spooftest sender|receiver` and a panel **IP Tester** page probe
  which forged source addresses survive the path between two servers (any shape, single IPs /
  CIDR blocks / ranges, with a loss threshold), so a spoof tunnel's pool can be filled with
  addresses that get through. The panel page copies the usable addresses straight into a pool.
- The tunnel wizard gains a third connection kind, **source spoofing**, beside direct and
  reverse: picking it swaps the transport tiles for the six spoof shapes and adds the
  forged-source pool field. Both sides of a tunnel need this version for the `spoof` transport.

## 2.8.0 - 2026-10-18

### Added

- **`proto47` l3 carrier** — the `[l3]` / GRE tunnel can now ride a raw IP protocol-47
  (keyed-GRE) socket (`[l3] carrier = "proto47"`), beside `udp`, `quic`, `faketcp` and `icmp`.
  Kariz's sealed, authenticated session is the GRE payload, so it stays encrypted end to end;
  this is **not** bare cleartext GRE and is **not** interoperable with standard/kernel GRE. It
  looks like protocol 47 on the wire, so it does **not** traverse NAT and does **not** evade a
  DPI network — use it only on a trusted link where a proto-47 path or the lower overhead is
  what you want. Linux + root; `[tunnel.proto47] manage_firewall` controls the best-effort
  iptables rule that lets protocol 47 through a default-DROP policy.

### Fixed

- The `l3` / GRE direct tunnel now serves its control socket and reports the peer's
  connected / last-error state, as the entry and exit modes do. Pairing an l3 tunnel from the
  panel waits for both sides to report connected, but an l3 process served no status, so the
  panel timed out ("the two sides did not connect in time") even when the link was up. It now
  sees the tunnel connect — and shows the real reason when a side cannot.
- The panel no longer offers its (mux-stream) speed test for an `l3` / GRE tunnel, which has
  no stream path: it explains to measure throughput over the `kzN` interface instead (for
  example iperf3 between the tunnel IPs), rather than failing with a confusing error.

## 2.7.0 - 2026-10-18

Nine new transports, from padded TCP to protocols that borrow a real HTTPS site, and a new
**direct layer-3 / GRE tunnel** that carries whole IP packets (or Ethernet frames) between two
hosts — all sealed inside Kariz's own encryption, none of them sending anything in the clear on
an untrusted path. The chooser and the transports page now cover which of them evade a network
that fights back, and which have a UDP shape that such a network can throttle. Both sides of a
tunnel need this version for any of the new transports.

### Added

- **Nine new transports** (fifteen in all), each encrypted end to end like the rest:
  - **`stealth`** — an encrypted TCP stream with **record-length padding** (random padding
    inside each AEAD record so record sizes do not leak the traffic shape) and optional
    **timing jitter**. No handshake fingerprint, no fixed bytes; the acceptor stays silent on
    bad authentication. `[tunnel.stealth]`: `padding`, `pad_max`, `jitter_ms`.
  - **`wsmux`** and **`wssmux`** — `ws` and `wss` with mux forced on, as `tcpmux` is to `tcp`.
    Same `[tunnel.ws]` / `[tunnel.tls]` tables and CDN behaviour.
  - **`udp`** — the tunnel rides plain sealed UDP datagrams; forwarded packets take the
    unreliable datagram path (no retransmit), which suits real-time services. UDP forward rules
    only.
  - **`faketcp`** (alias `pck`) — the KCP stack over a raw-socket fake-TCP carrier; looks like a
    TCP flow of random bytes. Linux + root. `[tunnel.faketcp]`, RAII iptables rules.
  - **`icmp`** (alias `xdi`) — the KCP stack inside ICMP echo (ping), getting through where a
    port is filtered. Linux + root. `[tunnel.icmp]`, RAII iptables rules.
  - **`naive`**, **`xhttp`**, **`reality`** — managed external helpers (NaiveProxy / sing-box,
    Xray) that give the tunnel a proven HTTPS disguise, with Kariz's own handshake, encryption
    and mux run inside the helper stream. `reality` borrows a real cover site's TLS handshake.
    `[tunnel.helper]` holds the credentials; install the pinned binaries with
    `kariz helper install <naive|sing-box|xray>` (`kariz helper status`,
    `kariz helper reality-keys`, `kariz helper uuid`).
- **Direct layer-3 / GRE tunnel** (`[l3]`). Instead of forwarding ports, Kariz creates a TUN
  interface (`kz0`, `kz1`, …) on each host and carries whole IP packets — a GRE tunnel (RFC 2784
  header + RFC 2890 key) sealed inside the encrypted Kariz session, never bare IP proto 47 on the
  wire. `layer = 2` carries Ethernet frames over a TAP instead (an encrypted GRETAP, for
  bridging). Either host may dial (`mode = "dial" | "listen"`), only DPI-resistant carriers are
  allowed (`udp`, `quic`, `faketcp`, `icmp`), MSS is clamped on TCP SYNs leaving the link, and
  the device and its rules are torn down on stop. Linux + root. `[l3]`: `mode`, `addr`, `token`,
  `layer`, `local_ip`, `peer_ip`, `carrier`, `gre_key`, `mtu`, `fec_data` / `fec_parity`,
  `ports` / `accept_udp`.
- **Transport fallback** (`[tunnel] fallback_transports`, `fallback_dwell_secs`). A tunnel can
  fall back through an ordered list of transports when the primary cannot be established; both
  sides use the same list, the active one is shown in the status and the panel. Unlike `auto`
  (which picks among a fixed set), the list may include `wss`, `reality`, `faketcp` and the rest.
- **Mandatory encryption** on the transports that have no transport-level crypto of their own
  (`stealth`, `udp`, `faketcp`, `icmp`, the managed helpers and the `[l3]` mode): `encryption =
  "none"` is rejected rather than left to the user.
- **The panel** gained the new transports in the tunnel wizard, and a new *Direct L3 / GRE*
  tunnel kind (carrier choice, an auto-picked `10.10.N.0/30` address block, token).
- **Sample configs** for every new transport and an L3 pair, and the panel benchmark and speed
  test cover them (root-only and helper-requiring ones are skipped with a clear reason when they
  cannot run).

## 2.6.1 - 2026-10-16

The stable release after 2.5.1, with everything of the four betas
([2.6.0-beta.1](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta1---2026-10-15),
[2.6.0-beta.2](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta2---2026-10-15),
[2.6.0-beta.3](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta3---2026-10-15) and
[2.6.0-beta.4](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta4---2026-10-16)); there is no 2.6.0. Private networks
can be **VXLAN**, not only GRE, for servers where GRE does not get through but UDP does, and an
agent can be added over either link. A server can have **an agents port of its own**, the servers
can be **arranged in the order you want**, a tunnel takes **4096 UDP clients per port** by
default (set from the panel), and the panel is calmer.

Update the panel first, then the agents from the panel (or `kariz-manager update` on each
server). Both servers of a VXLAN link need this version, and so does the entry server of a tunnel
that carries UDP. A server on one of the betas is offered 2.6.1 on either channel; the details of
each change are in the beta entries below.

## 2.6.0-beta.4 - 2026-10-16

A **beta**, like [2.6.0-beta.3](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta3---2026-10-15):
only panels on the *Beta* channel are offered it; `kariz-manager update` and the stable channel
stay on 2.5.1. To try it on a server by hand: `kariz-manager install --version v2.6.0-beta.4`.

A server added over a GRE or VXLAN link can now have an agents port of its own too, you can
**arrange the servers in the order you want**, and the panel is calmer: tabs on a tunnel's page and
what needs a hand on top of the dashboard. A tunnel now takes **4096 UDP clients per port** by
default, set from the panel: update the entry server of a tunnel that carries UDP; the panel and the
rest need nothing else.

### Added

- **Servers in the order you choose.** *Arrange* on the Servers page turns the cards into short
  rows you drag by a handle (mouse or touch) or move with their buttons and Alt+Up/Down. The order
  is used by every list: the Servers page, the map, the dashboard, the pickers and Telegram.
  Backups carry it, and old backups still restore. API: `POST /api/servers/order`.
- **UDP clients per port in the panel.** In the wizard and on the edit page of a tunnel that
  forwards UDP, beside *Connections per user address*. Before, the panel rewrote the config on
  every edit of the tunnel, so a hand-set `udp_max_flows` was lost; now the panel keeps it. The
  entry server needs 2.6.0-beta.4 or newer (otherwise the panel says which one to update). Empty:
  the default.
- **An agents port of its own for servers added over GRE or VXLAN.** *Add server* **Over a GRE
  link** and **Over a VXLAN link** now have *Agents port* too, as over the internet: the panel
  listens on it (and the next one) for that server's agent alone before the link is made, and the
  agent dials it across the link. A port that is taken is refused before anything is made. A
  reconnect over a new link also keeps a port of its own the server has (it used to send the
  agent to the main port). API: `port` in `join-gre`.

### Changed

- **4096 UDP clients per port by default, up from 1024** (`tuning.udp_max_flows`). A busy tunnel
  carrying TCP and UDP kept logging *too many UDP flows* and turned new UDP clients away
  ([#80](https://github.com/Erfan-XRay/Kariz/issues/80)). 1024 dated from when a tunnel connection
  took only 512 streams; every UDP flow is one stream, and since 2.4 a connection takes 4096. It
  applies on the entry server, so update that one. The log line now names the setting and says
  that the clients already connected go on.

- **A calmer panel.** A tunnel's page is split into Overview, Tests (speed test, benchmark) and
  Schedule; *New token* and *Delete* moved into a *More actions* menu. The dashboard opens with
  *Needs attention* when something does. The low-power button left the top bar (it is in Settings
  and the palette). A page change takes 200 ms instead of 560.

## 2.6.0-beta.3 - 2026-10-15

A **beta**, like [2.6.0-beta.2](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta2---2026-10-15):
only panels on the *Beta* channel are offered it; `kariz-manager update` and the stable channel
stay on 2.5.1. To try it on a server by hand: `kariz-manager install --version v2.6.0-beta.3`.

A new server can now have **an agents port of its own**: the panel listens there for that
server's agent alone, for when the main agents port is filtered from that server's network.
Only the panel needs this version; the agents do not.

### Added

- **An agents port of a server's own.** *Add server* (over the internet) now has *Agents port*.
  Left empty, nothing changes. With a port, the panel also listens on it and on the next one
  (TCP and UDP) for that server's agent alone, and the join code sends the agent there: for a
  server whose network filters the main agents port. The server is listed at once, waiting for
  its agent; another agent on that port is turned away. *Edit* changes or clears it, removing
  the server closes it, a backup keeps it, and a port that the panel's page, its agents ports or
  another server has, or that something else listens on, is refused with the reason. API: `port`
  in `join-code` and `reconnect`. See [the panel](https://github.com/Erfan-XRay/Kariz/blob/main/docs/panel.md).

### Fixed

- The backup test failed now and then for nothing: it checked that the encrypted file did not
  contain the two letters `k1`, which random bytes sometimes spelled.

## 2.6.0-beta.2 - 2026-10-15

A **beta**, like [2.6.0-beta.1](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#260-beta1---2026-10-15):
only panels on the *Beta* channel are offered it; `kariz-manager update` and the stable channel
stay on 2.5.1. To try it on a server by hand: `kariz-manager install --version v2.6.0-beta.2`.

VXLAN now also where an agent is set up, and in the benchmark: a server that GRE does not reach
the panel's server from but UDP does can be added **over a VXLAN link**, and a benchmark measures
GRE and VXLAN links each on their own. Update the panel first, then the agents from the panel.

### Added

- **An agent over a VXLAN link.** *Add server* now has **Over a VXLAN link** beside **Over a GRE
  link**, for a server that GRE does not reach the panel's server from but UDP does. The link's
  addresses come from the first VXLAN network, or the panel makes one (`kariz-vxlan`, UDP 4789,
  on the first pool free beside the others); its own end comes up at once and the command makes
  the server's end before the agent connects across it. *The panel connects to it* (*Across a
  private link*) and a server's *Edit* ask GRE or VXLAN for a new link too. API: `kind` (`gre`
  or `vxlan`) in `join-gre`, and in the `gre` of `join-reverse` and `reconnect`.
- **VXLAN in the benchmark.** A benchmark now measures the VXLAN link between two servers too
  (`tcp` with mux, `kcp` and `quic`), marked *VXLAN*, beside the GRE link when there are both.
  Before, only the first link of any kind was measured, and called *GRE*. Using such a result
  puts the tunnel on that link's network.

## 2.6.0-beta.1 - 2026-10-15

A **beta**: a prerelease that only panels on the *Beta* channel are offered (*Settings,
Updates, Channel*); `kariz-manager update` and the stable channel stay on 2.5.1. To try it on
a server by hand: `kariz-manager install --version v2.6.0-beta.1`. On a server that runs the
beta, `kariz-manager update` installs the latest stable release (2.5.1) again: update it from
the panel instead.

Private networks can now be **VXLAN** as well as GRE: for two servers between which GRE
(protocol 47) does not pass but UDP does. Both servers of a VXLAN link need this version:
update the panel first, then the agents from the panel. The GRE networks and links you have
stay as they are.

### Added

- **VXLAN private networks.** In *Networks*, *New network* now asks for the link type: GRE, or
  VXLAN over a UDP port (4789 by default; every network has its own, so when one port is
  blocked, make another network on another port). Each link of a VXLAN network is a one-peer
  VXLAN interface (`ip link add kz-XXXXX type vxlan id VNI local A remote B dstport PORT`) with
  an MTU of 1450, and the panel gives it a VNI that no other VXLAN link of either server has.
  Everything a GRE network does works over VXLAN too: mesh and hub and spoke, tunnels that listen
  on and dial the private addresses, an agent that reaches the panel across a link, adding a
  server over a link, and links that come back after a reboot. Before it makes anything the panel
  checks that both servers can make VXLAN (the `vxlan` module) and run 2.6 or newer, and it pings
  across each link before it keeps it; a UDP port blocked on the way is named, with the iptables
  line that opens it.
  See [private networks](https://github.com/Erfan-XRay/Kariz/blob/main/docs/networks.md#gre-or-vxlan).

### Changed

- A network's card shows its kind (and, for VXLAN, its port), the links table the VNI, and the
  wizard's network list, the panel's addresses and the server chips (*via VXLAN · network*) say
  which kind a link is.

## 2.5.1 - 2026-10-14

The stable release after 2.3.0, with everything of the two betas
([2.4.0-beta.1](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#240-beta1---2026-10-14) and
[2.5.0-beta.1](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#250-beta1---2026-10-14));
there is no 2.5.0. Built for busy evenings: a tunnel takes **4096 streams per connection**
instead of 512, says so when it is full, a **health probe** tells whether a new connection gets
through, and Xray behind a tunnel can see **each user's real address** (PROXY protocol), so
device limits in 3x-ui or Marzban work behind a tunnel too.

Update the panel first, then the agents from the panel (or `kariz-manager update` on each
server): each side checks its own stream limit, and the probe and the PROXY header need this
version on both servers. A server on one of the betas is offered 2.5.1 on either channel.

### Added

- **Real user addresses for Xray (PROXY protocol).** Every user reached the target from the exit
  server's own Kariz process, so Xray saw `127.0.0.1` for everyone: per-account IP and device
  limits in 3x-ui or Marzban, Xray's logs, IP routing rules and fail2ban on the exit server all
  saw one address. A forward rule can now have `proxy_protocol = "v1"` or `"v2"`: the exit side
  starts each TCP connection to the target with a PROXY header carrying the user's address and
  port (UDP flows never get one). In the panel: *Real user IPs (PROXY protocol)* in the wizard
  and on the edit page, written to every TCP port of the tunnel. **The target must expect the
  header**: turn on `acceptProxyProtocol` on the Xray inbound behind those ports (in 3x-ui, the
  inbound's *Proxy Protocol* switch), or every connection through them breaks. Both servers need
  2.5 or newer; the panel refuses the setting while either runs an older version.
  See [configuration](https://github.com/Erfan-XRay/Kariz/blob/main/docs/configuration.md#real-user-addresses-proxy_protocol).
- **A health probe: does a new connection get through?** A tunnel could be connected, moving
  60-100 Mbit/s for the users already on it, while every new connection failed: a busy evening
  had taken every stream, or the target (Xray) was down. Every 15 seconds the entry side now
  opens a connection the way a user's is opened and has the exit side connect to a forwarded
  target. `kariz status` shows the result on a `health` line, the status document has it as
  `probe`, the tunnel's page in the panel has a **Health** card, *Needs attention* lists such a
  tunnel, and the Telegram bot tells when three probes in a row fail (and when it is fixed). An
  exit side older than 2.4 is shown as not answering probes, never as a failure.
- **How full a tunnel is.** The status document has `streams` and `streams_max` (with mux), and
  `full`: new connections that failed because every connection was full. The panel draws it as a
  bar, lists a tunnel at 80 % in *Needs attention* and the Telegram bot tells once.
- **A limit per user address** (`tuning.max_conns_per_ip`, off by default): connections and UDP
  flows one client address may hold open, over all forwarded ports; more are closed at once and
  counted (`refused_per_ip`). In the panel: *Connections per user address* in the wizard and on
  the edit page. Users on mobile networks often share one address, so it stays off unless set.

### Changed

- **4096 streams per connection by default, up from 512** (`tunnel.mux.max_streams`, now up to
  16384). With four connections a tunnel took only 2048 user connections and UDP flows at once
  (1024 with the gaming profile or QUIC), which a busy server reaches; then new connections waited
  20 seconds and failed while the open ones kept working. A stream that is not in use costs
  nothing. Each side checks its own limit, so update both servers.
- **A full tunnel says so.** A connection that found every session full failed with *no tunnel
  connection available (is the other side running?)*, at debug level. Now it says *every tunnel
  connection is full (N streams open)* with what to raise, as a warning (at most every 30
  seconds).

### Fixed

- **The panel names the server to update.** When a tunnel used something one server was too old
  for (a chosen cipher, sealed QUIC, the 2.4 limits), checking or saving it failed with
  *internal* instead of saying which server to update.
- **Betas past nine.** The panel's updater compared `2.4.0-beta.10` and `2.4.0-beta.9` as text,
  so the tenth beta looked older and was not offered. The parts after the dash are compared as
  semver does now.
- The panel's mux form showed 4 connections as QUIC's default; it is 2.

## 2.5.0-beta.1 - 2026-10-14

A **beta**: a prerelease that only panels on the *Beta* channel are offered (*Settings,
Updates, Channel*); `kariz-manager update` and the stable channel stay on 2.3.0. To try it on
a server by hand: `kariz-manager install --version v2.5.0-beta.1`. On a server that runs the
beta, `kariz-manager update` installs the latest stable release (2.3.0) again: update it from
the panel instead.

Xray behind a tunnel can now see **each user's real address** (PROXY protocol), so device
limits in 3x-ui or Marzban work behind a tunnel too. It is off unless chosen, and **Xray must be set to
expect it first** (`acceptProxyProtocol`), or every connection through those ports breaks.
Both servers need this version: update the panel first, then the agents from the panel. It
also carries everything of [2.4.0-beta.1](https://github.com/Erfan-XRay/Kariz/blob/main/CHANGELOG.md#240-beta1---2026-10-14) (4096 streams per
connection, the health probe, the per-address limit).

### Added

- **Real user addresses for Xray (PROXY protocol).** Every user reached the target from the exit
  server's own Kariz process, so Xray saw `127.0.0.1` for everyone: per-account IP and device
  limits in 3x-ui or Marzban, Xray's logs, IP routing rules and fail2ban on the exit server all
  saw one address. A forward rule can now have `proxy_protocol = "v1"` or `"v2"`: the exit side
  starts each TCP connection to the target with a PROXY header carrying the user's address and
  port (UDP flows never get one). In the panel: *Real user IPs (PROXY protocol)* in the wizard
  and on the edit page, written to every TCP port of the tunnel. **The target must expect the
  header**: turn on `acceptProxyProtocol` on the Xray inbound behind those ports (in 3x-ui, the
  inbound's *Proxy Protocol* switch), or every connection through them breaks. Both servers need
  2.5 or newer; the panel refuses the setting while either runs an older version.
  See [configuration](https://github.com/Erfan-XRay/Kariz/blob/main/docs/configuration.md#real-user-addresses-proxy_protocol).

### Fixed

- **The panel names the server to update.** When a tunnel used something one server was too old
  for (a chosen cipher, sealed QUIC, the 2.4 limits), checking or saving it failed with
  *internal* instead of saying which server to update.

## 2.4.0-beta.1 - 2026-10-14

A **beta**: a prerelease that only panels on the *Beta* channel are offered (*Settings,
Updates, Channel*); `kariz-manager update` and the stable channel stay on 2.3.0. To try it on
a server by hand: `kariz-manager install --version v2.4.0-beta.1`. On a server that runs the
beta, `kariz-manager update` installs the latest stable release (2.3.0) again: update it from
the panel instead.

Built for busy evenings: a tunnel takes **4096 streams per connection** instead of 512, says so
when it is full, and a **health probe** tells whether a new connection gets through, not only
whether the tunnel is connected. Update the panel first, then the agents from the panel:
each side checks its own stream limit, and the probe needs 2.4 on both servers (with an older
exit side it is shown as not checked, never as a failure).

### Added

- **A health probe: does a new connection get through?** A tunnel could be connected, moving
  60-100 Mbit/s for the users already on it, while every new connection failed: a busy evening
  had taken every stream, or the target (Xray) was down. Every 15 seconds the entry side now
  opens a connection the way a user's is opened and has the exit side connect to a forwarded
  target. `kariz status` shows the result on a `health` line, the status document has it as
  `probe`, the tunnel's page in the panel has a **Health** card, *Needs attention* lists such a
  tunnel, and the Telegram bot tells when three probes in a row fail (and when it is fixed). An
  exit side older than 2.4 is shown as not answering probes, never as a failure.
- **How full a tunnel is.** The status document has `streams` and `streams_max` (with mux), and
  `full`: new connections that failed because every connection was full. The panel draws it as a
  bar, lists a tunnel at 80 % in *Needs attention* and the Telegram bot tells once.
- **A limit per user address** (`tuning.max_conns_per_ip`, off by default): connections and UDP
  flows one client address may hold open, over all forwarded ports; more are closed at once and
  counted (`refused_per_ip`). In the panel: *Connections per user address* in the wizard and on
  the edit page. Users on mobile networks often share one address, so it stays off unless set.

### Changed

- **4096 streams per connection by default, up from 512** (`tunnel.mux.max_streams`, now up to
  16384). With four connections a tunnel took only 2048 user connections and UDP flows at once
  (1024 with the gaming profile or QUIC), which a busy server reaches; then new connections waited
  20 seconds and failed while the open ones kept working. A stream that is not in use costs
  nothing. Each side checks its own limit, so update both servers.
- **A full tunnel says so.** A connection that found every session full failed with *no tunnel
  connection available (is the other side running?)*, at debug level. Now it says *every tunnel
  connection is full (N streams open)* with what to raise, as a warning (at most every 30
  seconds).

### Fixed

- **Betas past nine.** The panel's updater compared `2.4.0-beta.10` and `2.4.0-beta.9` as text,
  so the tenth beta looked older and was not offered. The parts after the dash are compared as
  semver does now.
- The panel's mux form showed 4 connections as QUIC's default; it is 2.

## 2.3.0 - 2026-10-11

The **benchmark** now measures **IPv6** (when both servers have an address), tries `wss` **with
a server name** to show whether a filter judges TLS by it, and measures `quic` across GRE; its
card is much lighter to read. A tunnel dialed at an IPv6 address now connects. Nothing changes
for 2.2.0 agents. Update the panel first (*Settings, Updates*), then the agents from the panel:
the IPv6 and server-name tests need both servers on 2.3.0 (an older agent is reported as one).

### Added

- **The benchmark measures IPv6 too.** When both servers have a public IPv6 address, every
  transport is also tried between the two IPv6 addresses, side by side with IPv4 on the same
  port, so a run takes no longer; the best over IPv4 and the best over IPv6 are both measured
  for speed. When one server has no IPv6 address, the result says which. Using an IPv6 result
  puts the IPv6 address in the tunnel and has it listen on every address (`[::]`).
- **`wss` with a server name in the benchmark.** A `wss` test sent no server name (SNI), as for
  an IP address, while a tunnel with a domain sends one. Now the tunnel's own name (or one
  typed) has `wss` tried once more with it, to show whether a filter judges TLS by its name.
- **`quic` across GRE in the benchmark**, beside `tcp` with mux and `kcp`.

### Changed

- **A lighter benchmark.** Before a run, one line and the button; while it runs, one bar and a
  chip per test; after it, the recommendation with three numbers (the rest under *Details*), the
  next two, and everything else folded under one line. At most one note is shown, the one that
  matters most.

### Fixed

- **A tunnel dialed at an IPv6 address.** The wizard offers a server's IPv6 address to dial, but
  the tunnel listened on every IPv4 address only, so it never connected. It now listens on every
  address (`[::]`) when it is dialed at an IPv6 one.

## 2.2.0 - 2026-10-10

The panel now **follows a new IP address of its server**: when the address it had is filtered
and the provider gives a new one, the panel gets a certificate for the new address by itself and
opens there with no browser warning. And a server that was only ever updated from the panel gets
the manager menu of its release. Nothing changes for 2.1.0 agents. Update the panel first
(*Settings, Updates*), then the agents from the panel: each program that starts as 2.2.0 puts
the manager of 2.2.0 in place on its server.

### Added

- **The panel follows a new IP address of its server.** When the server's IP address changes
  (the old one was filtered and the provider gave a new one) and the panel's certificate was for
  the old address, the browser refused it and the panel looked down. Now a timer
  (`kariz-panel-heal.timer`, a minute after boot and every 10 minutes) runs
  `kariz-manager panel heal`: it sees that the certificate's address is no longer on the server,
  gets a Let's Encrypt certificate for the new one, switches the panel to it and removes the old
  one. It asks for nothing unless the address changed, and waits an hour after a failure (Let's
  Encrypt limits failed attempts). Behind NAT, and for a domain, the change cannot be seen from
  the server: run `panel cert`. A panel set up before this gets the timer when it starts after
  the update.
- **The manager says when the certificate no longer fits.** The menu shows a line when the
  certificate is for an address the server does not have any more, the login link uses the new
  address, and item 6 (now *New IP, domain or certificate*) says what the certificate is for,
  whether its domain still points at this server, and offers the IP address first when the
  certificate was for one.

### Fixed

- **The manager's menu of an old release on a server updated from the panel.** An update from
  the panel swaps the programs but not `/usr/local/bin/kariz-manager`, so a server set up long
  ago and only ever updated from the panel went on showing the menu of the release it was
  installed with. The panel and the agent now put the manager of their own release in place each
  time they start (an update restarts them), when the one there is missing or different. And
  `kariz-manager update` fetches the script of the release it installed instead of the newest
  one on main, so the two ways of updating agree.

## 2.1.0 - 2026-10-06

Two new things, both working with the agents you have: the **benchmark** finds the transport
that gets through best between two servers before a tunnel is built, and the panel can **connect
to a server across a GRE link**. The panel had a UX review, and getting a certificate for a wss
tunnel works on servers set up with an older Kariz. The benchmark and the GRE link need the agents
on both servers to be 2.1.0: update them from the panel (*Settings, Updates*) after the panel.

### Added

- **The panel can connect to a server across a GRE link.** *Add server*, *The panel connects to
  it* has **Across a GRE link**: type the new server's public IPv4 address, and the panel makes a
  GRE link to it (its own end at once; the code carries the other) and dials the server's private
  address on the link. *Edit* has the same choice for a server the panel connects to: one of the
  links it has with the panel's server, or a new one. A code for a server the panel dials across
  a link carries the link, so the agent makes it again before it listens; such a link cannot be
  removed while the panel uses it. API: `gre: {ip, network}` in `POST /api/servers/join-reverse`
  and `POST /api/servers/reconnect`.
- **Benchmark: which transport gets through best between two servers.** In the wizard's *Kind*
  step and on every tunnel's page. In about 20 seconds, without making a tunnel, it tries every
  transport in both directions (and across a GRE link between the two, if there is one) on the
  tunnel's port, measures the speed of the best three, and scores each from 0 to 100 (speed,
  latency, stability; weighted by the profile). It recommends one with the reason, ranks the
  others, explains what did not get through, and says when a direction is blocked. *Use this*
  fills the wizard in; *Edit with this* opens a tunnel's edit page with it. The last result of
  each pair is kept. Core: `kariz::bench` (test links over any tunnel transport, measured like
  the speed test). Agents: `BenchListen` and `BenchDial`. API: `POST /api/bench`,
  `GET /api/bench?id=`, `POST /api/bench/stop`, `GET /api/bench/last`.

### Changed

- **A clearer panel, after a UX review** (heuristics, error states, accessibility, wording):
  - The tunnel filters show their counts as badges. In Persian, "· ۱" read as "۱۰" (the Persian
    zero is a dot); the same separator next to Persian digits elsewhere is now a short line.
  - Latin names in the Persian layout are cut at their end ("iran-…") instead of losing their
    first letters, the table keeps room for a tunnel's name and its two servers, and on a narrow
    window the switches are never cut off.
  - The tunnel wizard names the tunnel after its two servers until you type a name, and says what
    is missing (the servers, an empty name, a name in use) next to the field, which it focuses.
  - Screen readers hear the top bar, the navigation and the command palette in the panel's
    language; the copy button says *Copy* (and *Copied* after), and a copy that fails says so.
  - Every page names itself in the browser tab ("iran-eu — Tunnels — Kariz").
  - The log level filter says *All levels*, and *Follow* explains itself; the Persian settings
    say *دستگاه‌های واردشده* instead of mixing in "session", and "@BotFather" keeps its direction.

### Fixed

- **Getting a certificate for a wss tunnel on a server set up with an older Kariz.** An update
  swaps the programs but not the manager script, so a server installed before `tunnel-cert`
  answered with its usage text ("certificate not obtained: ... Set GITHUB_TOKEN ..."). The panel
  and the agent now carry the manager of their own release and put it in place (in
  `/usr/local/bin/kariz-manager`) before they ask it for a certificate.

## 2.0.0 - 2026-10-05

A new major version: servers can now join three ways (over the internet, over a GRE link alone,
or with the panel connecting to them), and join codes and agent settings gain fields that older
agents do not know. Panels update to it only when you confirm (*Settings, Updates*); update the
agents from the panel after it.

### Added

- **Add a server over GRE alone.** *Add server* asks how the new server reaches the panel: *Over
  the internet* (as before) or **Over a GRE link**, for a server that can reach the panel's server
  only over GRE. Type its public IPv4 address and the panel lists the server (*waiting for its
  agent*), gives the link a `/30` of a private network (it makes `kariz`, `10.77.0.0/16`, when
  there is none) and makes its own end of the GRE link at once; the join code carries the other
  end, which the agent makes before it dials the panel's private address across it. *New command*
  on the waiting server's card makes another code, *Remove* undoes it all. A reconnect code through
  the panel's GRE address carries the link too, so an agent that lost it can make it again. New
  API: `POST /api/servers/join-gre`; `GET /api/servers/panel-addresses` has `gre_local`. A server
  whose agent never connected raises no *server down* alert.
- **The panel can connect to a server (reverse).** For a server that cannot reach the panel but that
  the panel can reach, *Add server* has a third way, **The panel connects to it**: type its address
  and a port, run the command on it, and its agent listens there (the same four transports as a
  panel's agents port, on the port and the next) while the panel dials it and keeps the link up,
  trying again by itself when it drops. The agent proves who it is as always; one that turns out
  to be another server is let go. *Reconnect* and *Edit* can switch a server either way
  (*Who makes the connection*). It works on a panel that takes no agents, and backups keep where
  the panel dials each server. New API: `POST /api/servers/join-reverse`, `reverse` in
  `POST /api/servers/reconnect` and in `GET /api/servers`; agents get `listen` in `agent.toml`.

### Fixed

- **A `wss` tunnel with a Let's Encrypt certificate failed with `BadCertificate`** when the dialing
  side checked the certificate against another name than the one it was issued for: a server name
  typed while *Self-signed* was chosen, a WebSocket *Host*, or a dial address that is not the
  certificate's (a private GRE address, for one). The dialing side now always checks it against
  the certificate's own domain or address, and a failed tunnel shows the dialing side's error with
  a word on what to do.

## 1.9.6 - 2026-10-05

### Added

- **A server's agent can reach the panel through a private (GRE) network.** *Edit* and *Reconnect* on
  a server that has a GRE link to the panel's own server offer the panel's address on the link
  (*GRE · network*) beside the public ones, and choose it for a server whose agent already comes in
  that way; *Add server* lists the panel's GRE addresses too. A server whose agent comes through a
  link shows *via GRE*, and that link cannot be deleted while the agent depends on it (the panel
  would lose the only way it has to ask that server anything). `GET /api/servers/panel-addresses`
  has the new `gre` list and `GET /api/servers` a `gre` field.

## 1.9.5 - 2026-10-05

### Added

- **A video tutorial on the website.** A page of about two minutes (*Video tutorial*, under *Get
  started*) shows the panel from a bare server to a running tunnel, with chapters that jump to
  their place in it. The captions on the screen are in Persian.

- **A server that goes offline can be brought back from the panel.** Its card says since when and
  why (the link ended, or an agent came with a key the panel does not accept) and has a
  **Reconnect** button. The dialog says what to look at on that server, lets you choose how the
  agent reaches the panel (*Auto*, *TCP*, *KCP*, *WSS* or *QUIC*), and makes a join code **for that
  same server**: the new agent becomes the server again, with its name, its tunnels and its
  private network links; nothing is deleted or made twice. The old agent's key stops working.
  Online servers have the same dialog as **Edit**, and the server can be renamed there.
- **Automatic restarts.** A tunnel (its page) or all the running tunnels of a server (its card)
  can restart on a timer: every 10 minutes to 30 days, or every day at a time. The panel keeps the
  timers and uses the same requests as the *Restart* button, so no cron is set up on the servers.
  A tunnel that was stopped stays stopped; a server that is offline is restarted as soon as it is
  back; each restart is an event. New API: `GET/POST /api/schedules`, `/api/schedules/delete`,
  `/api/schedules/run`, `/api/servers/reconnect`, `/api/servers/rename`. A server's `last_seen` and
  `last_error` are in `GET /api/servers`.

### Fixed

- **The low-power button on the website works when the system asks for less motion.** It could not
  bring the animation back on a computer with "reduce motion" set; now it can, and the choice is
  kept.

## 1.9.2 - 2026-10-03

### Changed

- **The Telegram channel link is small now.** The card in the side bar and the line above the
  credit line are gone. The top bar has one small Telegram icon beside the language and theme
  buttons (the sign-in page has it in the same place), and the name in the credit line, now
  `Erfan_Xray`, opens the channel. The command palette still has "Open the Telegram channel".

## 1.9.1 - 2026-10-03

### Added

- **A link to the Telegram channel in the panel.** The channel (@Erfan_Xray) is on a card in the
  side bar, above Sign out, and on a line above the credit line at the foot of every page and under
  the sign-in form (which is where a phone, with no side bar, sees it). The command palette has
  "Open the Telegram channel". It opens in a new tab.
- **QR codes for the donation addresses.** The [Support](docs/support.md) page shows a QR code
  under each address (USDT on TRON, Gram on TON, Bitcoin), to scan with a wallet app. The pictures
  are in `docs/images/` and the website serves its own copy.

## 1.9.0 - 2026-10-03

### Added

- **Alerts and status in Telegram.** In **Settings > Telegram** the panel takes your own bot's token
  and tells a connected chat when a server goes offline or a tunnel goes down, and when it is back
  (with how long it was down). A thing has to stay down for a wait (60 s for a server, 30 s for a
  tunnel, both settable) before it is told, nothing is said in the first minute after the panel
  starts, a server's tunnels are named in its one message, and a tunnel that keeps going down is
  called unstable and then left alone. The bot answers `/status`, `/servers`, `/server NAME`,
  `/tunnels`, `/tunnel NAME`, `/mute 2h` and `/unmute` (read-only: nothing changes a tunnel), and
  can send the status by itself every 6, 12 or 24 hours. A chat is connected with a one-time code
  (`/start CODE`); no one else is answered. Where Telegram is blocked the panel can go through an
  HTTP or SOCKS5 proxy, through a local port that a tunnel forwards to `api.telegram.org:443`, or
  through a relay of your own. The token is never shown again, is kept out of backups, and is
  removed from errors. Messages are in Persian or English. See [Telegram alerts](docs/telegram.md).

## 1.8.1 - 2026-10-02

### Fixed

- **The manager script now updates itself.** Updating the core, the panel and the agent left the
  `kariz-manager` command on its old version in two cases: a new script copied to the server and run
  from a file was installed only while something else was being installed, and an update from the open
  menu wrote the new script to disk but went on showing the old menu. A script run from a file now
  replaces the installed `kariz-manager` at once, the menu reopens as the new script after an update
  replaced it, and a failed download of the script is said out loud.

### Added

- **A tab icon** for the website and the web panel (a simpler drawing of the logo that stays readable
  at 16 pixels), and a **Support** page with the ways to donate, linked from the footer and the READMEs.

## 1.8.0 - 2026-10-02

### Fixed

- **A private GRE network no longer goes dead when the panel's server is updated.** After the panel
  restarted, nothing was connected yet, so a link whose other end had no address was left out of the
  list its server was sent, and the agent removes every link that is not in the list: the panel's own
  server lost its links and never got them back. The panel now keeps the address each server was last
  known by, never sends a partial list (if an address is missing it sends none, and the agent keeps
  what it has), and tells the servers at the other end of a link when one connects. An agent that is
  only restarted (an update) leaves GRE interfaces the kernel already has alone, instead of deleting
  and making them again, so the tunnels over them keep their connections.

### Added

- **A private GRE network for a reverse tunnel too.** The wizard offers the network for both kinds of
  tunnel; the tunnel listens on and dials the private address of the server that accepts its
  connections (the entry when reverse, the exit when direct).
- **GRE on the edit page.** It shows the network a tunnel runs over, lets you move a tunnel onto a
  network or off it (it then goes back to the public addresses; the link stays for other tunnels), and
  makes the link first if the two servers have none. A link made for an edit that fails is removed again.
- **Sealed QUIC in the tunnel wizard and the edit page.** When the transport is `quic`, a switch *Seal
  every packet (obfs)* writes `[tunnel.quic] obfs = true` on both sides. It is on by default in the
  wizard, since that is what makes QUIC usable on a network that filters it; turn it off to get plain
  QUIC. The edit page shows what a tunnel has, and both servers need Kariz 1.7 or newer (the wizard
  says which one is behind).

## 1.7.0 - 2026-10-02

### Added

- **`quic` as a link between the panel and a server, always sealed.** *Add server* now offers *QUIC*
  beside *TCP*, *KCP* and *WSS*, and *Auto* tries it after them. The link runs over UDP on the port
  after the agents port (open UDP there too). Every packet is sealed with a key from the link token:
  there is no setting, so a link is never plain QUIC. A network that filters QUIC does not recognise
  it, and the port answers nothing that was not made with the token. An agent from before this
  release simply does not try it.
- **`obfs = true` in `[tunnel.quic]`** does the same for a tunnel. Each UDP packet is sealed with a key
  derived from the token (ChaCha20-Poly1305, as `kcp` does), so the wire shows no QUIC header, version
  or server name. It is off by default and must match on both sides. It costs 28 bytes a packet (QUIC's
  packet size is lowered to match) and a little CPU; GSO and GRO keep working.
- **Click an address to copy it.** On a server's card the IPv4, the IPv6 and an address you set for
  the server are buttons: one click or tap copies the address, the button shows a check, and a note
  says what was copied (if the browser refuses, the note shows the address to copy by hand). It also
  works on a page opened over plain http. On a phone each address is a full-width row at least 44 px
  tall, a long IPv6 wraps inside it, and the card's footer wraps instead of overflowing.
- **A new look for the install script's menu**, in the style of XRayMesh. Move with the arrow keys (or
  `j` and `k`) and press Enter; a number jumps to its item, `q` or Esc leaves, and the line under the
  list says what the highlighted item does. The items are grouped (Kariz, Web panel, Agent, System),
  what runs here (core, panel, agent) is shown at the top, and the list scrolls on a small terminal.
  Every item opens on a cleared screen and ends with "Press any key"; Ctrl+C in it returns to the menu.
  Questions with options are lists to move in too, and Esc cancels them. Without a terminal (a pipe,
  the tests) the menu and the questions are numbered as before.

### Changed

- **The tunnel wizard picks a free port.** A new tunnel's port starts at 3080 and moves up past the ports
  the accepting server's other tunnels already hold (their own ports, an auto tunnel's next port, and
  the ports they forward): 3080 for the first tunnel, 3081 for the second, 3082 for the third. The wizard
  says so when it moved the port, and leaves the port alone once you type one. A port held by something
  that is not a Kariz tunnel is still caught at the review step.
- **The documentation and the README were rewritten** around the website. The README is now a short
  introduction that points to the site; the Persian pages were edited to read as Persian, not as a
  translation.

### Fixed

- **The delete dialog closes by itself.** After a tunnel was deleted, the dialog where its name is typed
  stayed on screen until it was closed by hand. It now closes a moment after the deletion is done. If a
  server was offline it stays, so that the note about it can be read.

## 1.6.0 - 2026-10-02

### Added

- **A nicer manager.** A banner with a box, the version and the project's address; cards with
  the panel's address and sign-in link, and links in the colour of links (underlined) so they
  stand out; headings with a rule. The look follows the terminal's width.
- **You set the panel's admin password while installing it**, instead of a random one: it is
  asked twice (hidden) and must have at least 12 characters, three of the four kinds (lower case,
  UPPER CASE, digits, symbols), no common word and no run of one character. Or choose only the
  one-time sign-in link. `kariz-manager panel password` asks the same way (`--random` makes one,
  `--stdin` reads it) and `panel install --password-file F` reads it from a file.
- **The manager asks once, when this server has the core but no panel and no agent, whether to
  install the web panel** (the answer is remembered; `KARIZ_NO_OFFER=1` turns the question off).
- **Choose a tunnel's encryption in the panel.** The wizard and the edit page offer *Automatic*
  (recommended: AES-256-GCM where the CPU has AES instructions, ChaCha20-Poly1305 where it does
  not), *AES-256-GCM*, *ChaCha20-Poly1305* and *No encryption*. No encryption is shown in red
  with what it means (the traffic can be read on the way, and a network that looks for tunnels
  spots it more easily) and has to be confirmed; QUIC always uses TLS 1.3, so there is nothing to
  choose there. The same cipher is written on both sides; the tunnel's page shows it, and a tunnel
  without encryption is tagged. Needs a newer agent on both servers (the panel says which one to
  update).

- **A speed test can be stopped.** While it runs the button becomes *Stop the test*; the test
  streams end within half a second (a test that is cut off no longer leaves streams pumping
  data), and leaving the page stops it too. An older agent runs the test to the end.
- **Private networks use the address a server connected with** by default (its public IPv4,
  else its IPv6), so nothing has to be typed: the *Addresses* card shows it, with a button for
  each address the server has (IPv4 and IPv6) and a field for any other; *Use the default* undoes
  a saved one.
- **© ErfanXRay** at the foot of every page and under the sign-in form, linking to the project.

- **You choose the name of the panel's own server.** Installing the panel asks what this server
  should be called in the panel, with its host name as the default (Enter keeps it);
  `kariz-manager panel install --name NAME` gives it without asking, and `kariz-manager panel
  name [NAME]` renames it later (`kariz-panel init --name`). A joining server never takes that
  name.


## 1.5.2 - 2026-10-02

### Fixed

- **The speed test's gauge is readable while it runs.** The water that runs behind the gauge went
  through its numbers, and the number pulsed in a colour that was hard to read. The numbers now
  sit on a plate with an outline, in the normal text colour, and do not pulse.
- **The `auto → kcp` tag on a tunnel's page** (and in the tunnel list) overlapped the other tags on
  a phone: a style of the top bar's live indicator reached it. It is its own style now, and the
  tags wrap onto the next line instead of overlapping.

## 1.5.1 - 2026-10-02

### Added

- **A live speed test.** The entry server runs the test in the background and the panel follows
  it: the phase it is in, the rate every half second (with the best so far and a small chart),
  and the result of each step the moment it ends, instead of a loading animation until the
  end. Older agents still work: their test shows its numbers at the end.
- **Speed test settings to find the most a tunnel carries:** *Quick*, *Standard* and *Max*
  (16 streams for 20 s), and *Custom* with up to 32 streams and 60 s.
- **`wss` with a real certificate.** A wss tunnel can use a self-signed certificate (pinned, as
  before) or a Let's Encrypt one for a domain or a public IPv4 address, got with one button on
  the server that listens (`kariz-manager tunnel-cert`: port 80 is freed for a moment, the
  renewal timer does the rest, the tunnel reloads the renewed files).
- **An auto tunnel says which transport it uses now**, in the tunnel list and on its page
  (`auto → kcp`), from the live sessions (`kariz status` shows `via kcp` too).
- **Ready-made address pools** for a new private network (five, with how many links each
  holds; one a server already routes is greyed out).
- **Mux is a switch, and `tcpmux` is just `tcp`.** The transports are `auto`, `tcp`, `ws`,
  `wss`, `quic` and `kcp`; *Mux* is on or off for `tcp`, `ws`, `wss` and `kcp` (always on for
  `auto` and `quic`) and its settings show only while it is on. `tcp` with mux on is what the
  core calls `tcpmux`; existing tunnels keep working and show as `tcp`.

- **The manager offers updates.** Opening the menu (or `kariz-manager status`) looks for a newer
  release and, if the core, the panel or the agent here is older, says which and asks to update
  them all. `--agent CODE` updates an older program first (an old agent refuses what a newer
  panel sends), and `update` fetches the newest `kariz-manager` script too.
  `KARIZ_NO_UPDATE_CHECK=1` turns the look off.

### Fixed

- **A tunnel with `auto` (or mux settings) on a server that runs an older Kariz** failed with
  `unknown variant auto` from that server. The panel now says which server is too old and to
  update it first, before anything is written.
- **Typing in a dialog jumped to its first field** every time the panel refreshed (every 2 s): the
  dialog moved the focus on each render. It sets the focus once, when it opens.
- Small controls (the tunnel switches, name links, the breadcrumb) have a bigger touch area on
  phones.

## 1.5.0 - 2026-10-01

Servers stay connected when a daemon is slow, a tunnel can be edited completely, and the manager
script is friendlier.

### Added

- **`transport = "auto"`.** One tunnel over `tcpmux`, `kcp` and `ws` at once: the listening side
  opens all three (TCP port, UDP port, TCP port + 1) and the dialing side moves to the one that
  gets through when a link stalls (a stalled link is noticed in about 4 s). In the panel it is
  the first transport in the wizard and the edit page.
- **Mux settings in the panel**: connections, streams per connection, stream window, ping
  interval, connection lifetime and write gathering, in the wizard and the edit page, with the
  profile's values as the placeholders.
- **A tunnel is edited on one page**, not in the wizard: how it connects (mode, transport,
  profile), where, ports, mux settings and a new token, with Save enabled once something
  changed. The wizard only makes tunnels.
- **A tunnel can be deleted while one of its servers is offline.** The reachable side is
  removed at once, the tunnel leaves the lists, and the other side is removed when that server's
  agent connects again (the panel says so, and that `kariz-manager uninstall` on that server
  does it now). Start, stop and restart also work from the side that is reachable. The name
  stays taken until the delete is done.
- **The join code is one command** that installs Kariz first if the server does not have it:
  `bash <(curl -fsSL .../kariz.sh) --agent CODE`.
- **The manager installs the core on the first run**, then asks whether this server should also
  get the web panel, or join a panel that exists. Its banner and menu show the server's IPv4 and
  IPv6 addresses and the project's GitHub; `kariz-manager status` prints what runs here.
- **IPv4 and IPv6 of every server** are shown on its card in the panel (the address the agent
  leaves from, or the one its link is seen coming from, when that is a private one).
- **Choose the tunnel profile** with a description of each: *Balanced* (default), *Ultra speed*
  and *Gaming*.
- **Editing a tunnel is complete**: the WebSocket Host header, the TLS server name and the pool
  are kept and can be changed, and the edit can make a new token for both sides.
- A new tunnel's *address to dial* is filled in from the server's known address (and the
  addresses can be picked with a click); a direct tunnel says which port must be open.

### Changed

- **Update the agents too.** A tunnel made or edited with `auto` or with mux settings needs 1.5
  on both servers (an older agent refuses the settings it does not know). Update the panel, then
  its servers from *Settings, Updates*.
- **`kariz-manager uninstall` removes everything**: tunnels, the agent (its service, identity and
  private network links), the web panel and the programs. `agent remove` cleans up the same
  files.
- **Joining a server that has an agent already** no longer fails: the manager tells you, asks,
  removes the old agent and starts the new one in its place (`--agent CODE --yes` skips the
  question). `kariz-panel agent --join` replaces the old registration the same way.

### Fixed

- **Servers going offline by themselves.** The panel asked every tunnel's daemon one after the
  other; a few that answered slowly went over the 10 s a request is allowed and the panel
  dropped the link. They are asked side by side now, a late list of tunnels no longer ends a
  link that answers everything else, and both ends close a finished link so the agent comes back
  at once. Both ends now log why a link ended (`journalctl -u kariz-panel` and `-u kariz-agent`).
- **A direct tunnel with the plain `tcp` transport never showed as connected** (nothing keeps a
  connection open there), so the panel gave up creating it after 30 s. The entry now looks for
  the exit every 10 s.

## 1.4.0 - 2026-09-30

The panel has a new look, servers can join over IPv6 or with a transport you choose (now also
`wss`), and signing in with a link no longer flashes the form.

### Added

- **Join over IPv6.** *Add server* offers the panel's own public IPv4 and IPv6 addresses to
  put in the join code, and the agents port now listens on IPv6 as well as IPv4.
- **Choose the link's transport.** *Add server* has *Auto* (the default), *TCP*, *KCP* and
  *WSS*. A fixed choice goes into the join code and the agent uses only that transport.
- **`wss` for the panel link:** WebSocket over TLS with the panel's own certificate, on the
  agents port + 1. It looks like an ordinary HTTPS site. The agent does not check the
  certificate (the token handshake inside proves the panel), so a self-signed or an IP
  certificate works. *Auto* now tries `tcpmux`, `kcp`, then `wss`. Open TCP on the agents
  port + 1 for it.

### Changed

- **The panel has a new look.** Cards on a calmer page, a sidebar with names next to the
  icons, and a top bar that says whether the panel is answering (and a notice when it stops,
  with the last numbers kept). The map page is now an overview: the key numbers with a line
  of the last minutes' throughput, the map, the tunnels with their rate, a *Needs attention*
  list (broken tunnels, offline servers, a busy CPU, servers behind on the version) and each
  server's load. Servers are cards with their CPU, memory, network, uptime and link;
  Settings has a list of its sections. Pages show placeholders while the first numbers come,
  and say what to do when they are empty.
- The address follows the page (`#/tunnels/main`): Back works, and a reload stays where it
  was. **Ctrl+K** also opens a tunnel by its name. Clicking a tunnel on the map opens it.
- Signing in has tabs for the password and the one-time link, warns about Caps Lock, and
  keeps the form in place while it checks.

### Fixed

- Opening a one-time link showed the sign-in form for a moment, with the "no password yet"
  hint in red as if something had failed, before the dashboard. The link now signs in on
  the loading screen, and the form appears only if the link is refused.
- The rate on the map's channels stayed at its first value (and so did a tunnel's state and
  its flow of particles) until the window was resized; it now follows every reading.
- The CPU and memory figures of the servers had no labels (two style rules clashed), a
  chart's hover picked the mirrored point in Persian, and a dialog opened during the page's
  entrance could be cut off.

- An agent drops a link on which the panel has asked nothing for 20 s (it asks every 2 s),
  so a stalled TCP path is given up and KCP tried in about 40 s. 1.2.0 waited for the
  keepalive, 90 s a link, because on such a path the panel's close does not get through.
- A server whose enrollment is cut off (the agent got its identity but the answer was lost,
  or never got it) is no longer deleted by the panel: the join code gives the same identity
  again until it expires, so the agent comes back as that server. 1.2.0 deleted it, and an
  agent that had kept the identity was then refused for ever.

## 1.2.0 - 2026-09-30

The panel reaches servers on networks that stall TCP, and each tunnel has a page of its own
with a new speed test.

### Changed

- **The agents' link picks its transport by itself.** The panel's agents port now takes
  `tcpmux` over TCP and `kcp` over UDP (the same port number: open both in the firewall). An
  agent starts with `tcpmux`; after two links in a row that connect but carry no requests
  (networks that let TCP connect and then stall it, as on some Iranian routes) it moves to
  `kcp`, and back, and remembers the one that worked (`/etc/kariz-panel/link-transport`).
  *Servers* shows which transport each server uses.
- **A tunnel has a page of its own** instead of a dialog: the channel between its two
  servers, what is wrong when it is broken or stopped and how to fix it, live numbers,
  traffic charts, its ports and both sides, and every action. The list has filters by
  state, a search and an on/off switch per tunnel. Deleting asks for the tunnel's name.
- **A new speed test** on the tunnel's page: water runs through the channel in the
  direction being measured, the steps (latency, download, upload, UDP) tick off, and a gauge
  fills to the measured download and upload, with peak rates, latency idle and under load,
  jitter and UDP loss. The agent now returns the numbers themselves (an older agent's printed
  report is still shown).

### Fixed

- A join code is no longer used up when the agent's link drops while it is being
  registered: the half-made server is removed and the code works again (it used to leave a
  server that stayed offline and an agent that was refused for ever).
- Why the panel refused an agent (a used code, an unknown identity, no answer) is now logged
  at `warn`, not only at `debug`.

## 1.1.0 - 2026-09-30

Everything about servers and tunnels is now done in the web panel, and Kariz has a license.

### Changed

- **The manager script no longer makes or runs tunnels.** `kariz-manager` keeps `install`,
  `update`, `uninstall`, `panel ...`, `agent ...` and `--agent CODE`; its menu is now install or
  update, web panel and agent, uninstall. The commands `add`, `list`, `status`, `start`, `stop`,
  `restart`, `logs`, `speedtest`, `edit`, `remove` and `net` are gone: use the panel. Tunnel
  configs and services (`/etc/kariz/NAME.toml`, `kariz@NAME`) are unchanged, and the panel still
  reads tunnels that were made before.
- The panel's empty-list and hint texts no longer point to the manager.

### Fixed

- **Signing in.** The panel checks that the browser kept the session cookie before it opens the
  dashboard, and says so when it did not (Safari over the self-signed certificate does this),
  instead of silently returning to the sign-in page. The panel's address without the closing slash
  (`/k-7f3a9c`) is sent to the slash, where its page can find its files and API.

### Removed

- The design documents of the phases (`docs/PHASE*.md`); the layers and the protocol stay in
  `docs/ROADMAP.md`, now "Design and protocol". The history is in git.
- `docs/compatibility.md`: Kariz is not publicly released yet, so it makes no compatibility
  promise.

### Added

- **The panel always has a trusted certificate.** `kariz-manager panel install` asks for a domain
  name or, without one, the server's public IP address, and gets a Let's Encrypt certificate for
  it (certbot, standalone on port 80; IP address certificates last 6 days). No self-signed
  certificate is made any more for a new panel. A timer renews it, and the panel loads the new one
  without a restart. If a service holds port 80 the manager says which one, stops it for a moment
  and starts it again, at the first request and at every renewal. `panel cert --domain D | --ip A`
  changes it later; `--cert-file/--key-file` uses your own.

## 1.0.0 - 2026-09-30

The first stable release. Nothing changes for a 0.11 install except what is
listed here; update the panel and its agents together as usual.

### Added

- **A security review of the panel, its agents and its update path**, with everything it found
  fixed and tested (docs/security-review.md): connections that say nothing are closed (TLS
  handshake within 10 seconds, request headers within 15, at most 512 connections); every answer
  under the secret path carries hardening headers (a strict Content-Security-Policy, no framing,
  no sniffing, no referrer, HSTS) while the 404 for any other address stays exactly nginx's; the
  database is `0600` in a `0700` folder whatever the umask; downloads follow `https` only, and an
  archive is limited to 500 entries and 400 MB; password checks run four at a time at most;
  tunnels with many IPv6 ports are no longer refused for their size; the audit log is kept for a
  year. `cargo audit` runs in CI.
- **Browser tests** (Playwright, on a real panel and a real agent, in CI): signing in with a
  link and a password, the lockout, the secret path and its headers, adding a server, making a
  tunnel with the wizard and sending traffic through it, editing, stopping, starting and deleting
  it, a tunnel that cannot connect being undone on both servers, both languages and themes, and a
  phone-sized screen with no sideways scroll.
- **Accessibility checked on every change** (axe, WCAG 2.1 A and AA, on every page and dialog in
  English and Persian, Night and Dawn; the keyboard; reduced motion), with what it found fixed:
  secondary text now has the contrast it needs in both themes, dialogs, the wizard and the command
  palette **keep Tab inside themselves** and give focus back, the map and the page area have names
  and keyboard access, and the command palette is a proper combobox (docs/accessibility.md).
- **The guides in Persian** (docs/fa): getting started, the manager, the panel, private networks,
  security and troubleshooting.

### Changed

- The manager script no longer speaks of a private repository; `GITHUB_TOKEN` is only there to
  lift GitHub's download limit.
- A request from the panel to an agent may be up to 60 KB (it was 16 KB).

## 0.11.0 - 2026-09-30

**Updating from the panel, and signed releases** (docs/panel.md). Backward
compatibility is not kept before 1.0. Servers on 0.10 or older have to be updated once by hand
(`kariz-manager update`); from 0.11 on they can be updated from the panel.

### Added

- **Releases are signed.** Each archive has a `.sha256` and a `.sig` (an Ed25519 signature of the
  checksum file, which names the archive). The release workflow signs with a repository secret and
  checks every signature with the key built into the program before it publishes. `kariz-manager
  install|update` checks the signature with `openssl` and the key in the script (a release without
  one is refused from 0.11), `kariz-panel release-verify` checks a download by hand, and
  `release_key` pins a key of your own.
- **Update the panel from the panel:** a notice in the top bar and *Settings, Updates* when a newer
  release is out (a check once a day, or *Check now*; stable or beta channel). One button downloads
  the release once, checks its signature and checksum, and hands over to a helper that swaps the
  programs, restarts the panel and waits for it to answer as the new version, **putting the old
  programs back if it does not within 30 seconds**. No downgrades, and a new major version asks for
  confirmation. Tested for real on a systemd host in CI: a release that does not come up is rolled
  back, and a good one takes.
- **Update the other servers:** the panel sends the release it downloaded over the link to each
  agent that is behind, in pieces, one server at a time. Each agent checks the signature again with
  its own key, swaps its programs, restarts, and reaches the panel again (or is put back). Their
  tunnels can be restarted afterwards **one at a time**, each waited for, so a pair never loses both
  sides together. Also tested for real in CI.
- `release_api`, `release_key` in `panel.toml` and `release_key` in `agent.toml`.

### Fixed

- An agent could reset the stream of a request it had answered if the answer was quick (a stream
  dropped before the panel's end-of-stream frame arrived). It now waits for that frame, and a request
  that fails inside the agent is answered with an error and logged.

### Changed

- Web app: 116 KB compressed script.

## 0.10.0 - 2026-09-30

**Private networks with GRE** (docs/networks.md). Backward compatibility is
not kept before 1.0: update the panel and its agents together.

### Added

- **Networks page** in the panel: make a network (a pool of private addresses), set each
  server's address, add links between servers as a mesh or hub and spoke, and remove them.
  Every link takes its own /30, so no two addresses are ever the same; the database enforces it
  (`UNIQUE` on every subnet, address and interface name), and eight threads making 80 links at
  once are tested to get 160 different addresses. A pool must be private, /24 or larger, and
  must not overlap another network or a route a connected server already has (the panel says
  which server and which route). A second link between the same pair gets its own GRE key.
- **GRE from the agent:** `net_up`, `net_down`, `net_ping`, `net_status` and `net_sync`, as data
  requests with every field checked, fixed `ip` invocations and only `kz-` interfaces. The
  links are kept in `net.toml` and made again when the agent starts; the panel sends the whole
  list when an agent connects. A path test (`ping` across the link) runs before a link is
  kept, and a failed one is removed on both servers with the reason (a filtered protocol 47,
  a server that cannot make GRE).
- **The wizard** has *Use a private GRE network* for direct tunnels: the tunnel listens on and
  dials the private addresses, and the panel makes the link between the two servers first if
  it is not there (and removes it if the tunnel cannot be made).
- **`health` reports `routes`** (the IPv4 networks a server already routes), used to keep new
  private networks from overlapping them.
- **`kariz-manager net list | status NAME`** (read only) on a server; `kariz-panel net
  up|down|ping|status` for debugging.
- **CI:** a `gre` job builds two network namespaces and tests real GRE links between them
  (private addresses ping, two links at once, a filtered path fails, a Kariz tunnel works over
  the private addresses).

### Changed

- The agent protocol has new requests; a panel and agent of different versions may not
  understand each other's network requests.

## 0.9.0 - 2026-09-30

The panel can now **make and manage tunnels**, and shows what they do (docs/panel.md). Backward compatibility is not kept before 1.0: the agent protocol changed,
so update the panel and its agents together (`kariz-manager update` on each server).

### Added

- **Make a tunnel from the panel:** a five-step wizard (servers, kind, connection, ports,
  build) for a pair of servers. The panel checks both servers (settings valid, ports free, and
  who holds a port that is not), writes the accepting side first, starts both, waits for them
  to connect, and **undoes everything on both servers if any step fails**. Edit (both sides in
  step, the old settings put back if they do not reconnect), start, stop, restart, a new token
  and delete, for a pair. Tunnels made with `kariz-manager` can be edited the same way.
- **Live monitoring:** charts of a tunnel's throughput and round trip (1 hour, 24 hours,
  7 days, 30 days; the last hour in memory, five-minute averages in SQLite for 30 days), a
  **Logs** page that interleaves both sides of a tunnel by time with a level filter, search and
  follow, and an **Events** list (a server offline or back, a tunnel losing or regaining its
  connection).
- **Speed test** from a tunnel's page (run by the entry server).
- **Backup and restore** of the servers a panel knows, locked with a passphrase (Argon2id and
  ChaCha20-Poly1305); the restore refuses to replace servers unless told to.
- **Your own certificate** (`cert_file` and `key_file` in `panel.toml`), reloaded on SIGHUP.
- **`services = "process"`** for hosts without systemd: the panel or agent runs tunnels as
  child processes.

### Changed

- **The agent** answers a longer fixed list of requests (check, write, read and delete a
  tunnel, control its service, listening ports, log, speed test). A tunnel's settings travel as
  typed fields and the agent renders the file, refusing control characters; the programs it runs
  get fixed arguments and a checked name. The panel never keeps a tunnel's token.
- Web app: 106 KB compressed script, 10 KB style.

## 0.8.0-beta - 2026-09-29

The first release of the **web panel** (docs/panel.md). It is a beta: a
prerelease that GitHub's "latest release" does not pick, so `kariz-manager update` on a
running server stays on 0.7.0 until a stable release. To try it:
`kariz-manager install --version v0.8.0-beta`, then `kariz-manager panel install`.
The tunnel core is the 0.7 one, with the same wire format; it works with v0.4 to v0.7 peers.

### Added

- **`kariz-panel`**, a second program in the release archives (all three architectures):
  `serve` runs the panel, `agent` connects another server to it, `init`, `login-link`
  and `reset-password` set it up and look after it. One static binary, SQLite inside, the
  web app inside; nothing is fetched from the internet.
- **The panel** answers only under a secret path over TLS (a self-signed certificate,
  its fingerprint printed at install); any other address gets a plain nginx 404. Sign-in
  with an Argon2id password and/or one-time links (60 minutes, work once, in the address
  fragment so they never reach a log); sessions in the database (only hashes stored) with a
  `__Host-` cookie, a CSRF header, a lockout after five failed tries, a list of sessions
  you can revoke, and an audit log.
- **The web app**, in the design of phase 9: a loader and a login scene that descends into
  the dashboard, Persian (RTL) and English, Night and Dawn, low-power mode, `Ctrl+K`.
  Map (the servers as wells, the tunnels as channels of water with their traffic), Servers
  (CPU, memory and network of each, add and remove), Settings (password, login links,
  sessions, appearance). About 280 KB compressed.
- **Agents:** *Add server* makes a join code (works once, 10 minutes);
  `kariz-manager --agent CODE` (or `kariz-panel agent --join CODE`) on the other server
  connects it. The link is Kariz's own (`kariz::link`): the tunnels' handshake, encryption
  and mux, so it resists DPI like a tunnel; the agent dials the panel, so the new server
  opens no port. A leaked link token alone opens nothing: each agent also proves a key of its
  own. Agents answer four fixed requests (hello, enroll, health, tunnels): there is no
  remote shell, and tunnel tokens are never reported.
- **What the panel shows of each server:** CPU, memory, network and uptime (from
  `/proc`), and its Kariz tunnels: the config files, systemd's state and the running
  daemon's `kariz status`. A tunnel whose entry and exit are both connected is drawn on the
  map, in the state its daemon reports.
- **kariz-manager:** `panel install [--port N] [--host H]` (settings, database,
  certificate, service, then the address, the certificate's fingerprint and a login link),
  `panel link`, `panel password`, `panel status`, `panel logs`, `panel uninstall`;
  `--agent CODE`, `agent status | logs | remove`; a "Web panel and agent" entry in the menu
  (`w`); `install` and `update` handle the panel binary and restart the panel and agent.
- **`kariz::link`** in the core library (an authenticated mux session between two Kariz
  programs); the tunnels do not use it.

### Not yet (phase 12)

Making and editing tunnels from the panel, logs, speed tests, updates and backups from the
panel, sign-in with a second factor, Let's Encrypt, and an agent that the panel dials
(instead of the agent dialing the panel).

## 0.7.0 - 2026-09-29

Status for the coming web panel, and for people on the server. Nothing
changes between the two sides: v0.7 works with v0.6, v0.5 and v0.4 peers over every
transport.

### Added

- **`kariz status`** on either server: whether the other side is connected (sessions,
  for how long), the round-trip time, failed handshakes and the last error, and for each
  forwarded port the open connections, UDP flows and live rates up and down; on the exit
  side, the traffic to the targets, streams served and targets that could not be reached.
  `--watch` redraws every second; `--json` prints the daemon's document. Exit code 3 when
  the tunnel is not running (docs/status.md).
- **A control socket on the exit side too**, answering `status` (the entry's also runs
  speed tests). The `status` document is JSON with a version number, for tools.
- **Live counters:** bytes are counted as they flow, not when a connection ends, so a
  connection open for hours shows up at once. UDP flows add theirs in batches (every 64
  packets and at least once a second), so busy flows on many cores do not share one
  counter per packet.
- **Round-trip time** from the mux pings the sides already exchange (no wire change, so
  it works against older peers too), and from QUIC's own estimate.
- **`kariz check --json`**: one document with the settings in effect, or the error with
  the setting it names (`key`) and, for TOML syntax errors, the `line` and `column`.
  `kariz check -c -` reads the config from standard input.
- **kariz-manager:** `status [NAME] [--watch]` runs `kariz status` for a tunnel, or for
  every tunnel without a name; the menu's status action shows it too (systemd's view for
  a stopped tunnel, or with Kariz older than 0.7).

### Changed

- The design of the web panel is in the repository: its plan for phases 9 to 13
 , the design system (design/) and an interactive prototype of every
  screen (design/prototype/). Nothing of it runs yet.

## 0.6.1 - 2026-09-29

A kariz-manager release: the `kariz` binary is the same as 0.6.0 apart from its version
number, and works with the same peers (v0.6, v0.5 and v0.4, every transport). To update
the manager on a server, fetch the script again into `/usr/local/bin/kariz-manager`
(docs/manager.md).

### Changed (kariz-manager)

- **A friendlier New tunnel wizard:** six numbered steps; every choice is a numbered
  list with a hint per option (type the number or the word, Enter for the default); a
  summary before anything is created. It checks ports, addresses and that a port is not
  already in use.
- **Ports as a list:** `443, 8080-8090, 2053=53, 3000-3005=4000-4005, 5000-5010=443`
  (single ports, ranges, mappings, many onto one), per protocol and target host, several
  groups per tunnel, up to 1,000 ports. On the command line: `--ports`, `--protocol`,
  `--to`. `--forward` still takes one rule in full.
- **IPv6 everywhere:** addresses are IPv4, IPv6 (with or without brackets) or domains,
  with an optional port. On servers with IPv6, the tunnel and the forwarded ports listen
  on `[::]` (IPv4 and IPv6); the wizard asks, and `--ipv4-only` keeps IPv4. The address
  printed for the other server can be this server's IPv6. `--listen` takes a bare port.
- **Ctrl+C** during an action goes straight back to the menu, with no Enter; at the menu
  it leaves.
- The menu shows the version and how many tunnels run; `list` shows each tunnel's number
  of forwarded ports. A tunnel that stops right after starting is reported.

### Fixed

- **kariz-manager's menu did not show its questions.** Opening the terminal for input
  also sent the script's error output to `/dev/null`, and the questions, warnings and
  errors went with it: *New tunnel* seemed to take no input. Every question now shows,
  and an answer that never comes ends the script instead of repeating the question.
- **The menu's tunnel actions** (start / stop, logs, speed test, edit, remove) took the
  printed list of tunnels for the tunnel's name. They now list the tunnels by number and
  take the number or the name.
- Ctrl-C in a tunnel's log returns to the menu instead of ending it.
- `kariz-manager edit` opens the editor on the terminal also when the script was piped
  in, and falls back to `vi` without `nano`.
- The script runs when piped into bash (`curl ... | bash`); it used to exit silently.
- The wizard checks the port, and asks again for an empty address, token or pin.
- CI drives the menu through a real terminal (tests/manager_tty.py), installed and piped
  in; the scripted answers of the other tests could not catch the hidden questions.

## 0.6.0 - 2026-09-29

Works with v0.5 and v0.4 over every transport. `kariz speedtest` needs the exit side at
v0.6 too (an older exit cannot answer the test streams).

### Added

- **Releases for three architectures:** static musl builds for x86_64, aarch64 (ARM64
  servers and boards, Raspberry Pi 4 and 5) and armv7 (32-bit ARM), one archive each,
  `kariz-<version>-<arch>-linux.tar.gz` with its SHA-256. CI builds the ARM targets and
  runs the library tests for them under QEMU on every change.
- **`kariz speedtest`:** measures download and upload speed, latency (idle and during
  each transfer) and UDP loss and jitter, through the running tunnel's own sessions: the
  same transport, encryption, mux and profile as users' traffic. It works in both
  modes: the entry side's daemon serves a local control socket (`[control] socket`,
  default next to the config file, owner only, Linux only) and runs the test over its
  live sessions. Options: `--seconds`, `--streams`, `--no-udp`. The exit side answers
  the test streams (`tunnel.speedtest = false` turns that off; at most 32 at once) and
  must be v0.6 or newer. `kariz-manager speedtest NAME`, and option 6 of its menu.
  See docs/speedtest.md.
- **mimalloc** as the global allocator of the `kariz` binary (cargo feature
  `mimalloc`, on by default). Static musl builds run 34 % faster on average across 28
  benchmark setups (25 to 100 % with mux, `wss`, `quic` and `kcp`; plain `tcp` is
  unchanged), for about 2 MiB more memory idle (8.1 against 6.0 MiB): Kariz commits
  mimalloc's arena on demand, which cut the idle 15.6 MiB of its default. Memory grows
  more with many idle UDP flows (+6 to +9 MiB per 1,000, against +4). Build with
  `--no-default-features --features quic,kcp` for the least memory.
- **A startup banner and new log lines.** `kariz run` starts with the Kariz logo, the
  version, the author and a summary of this side's setup. On a terminal, log lines
  carry the local time, coloured level badges and highlighted fields. Under systemd
  they carry priority prefixes instead, so `journalctl` highlights warnings and errors
  and `-p warning` filters them. `[log] color = "auto" | "always" | "never"`; `NO_COLOR`
  is respected.
- **The manager script** (`scripts/kariz.sh`, installed as `kariz-manager`): a
  one-line install for x86_64, aarch64 and armv7, with the release's checksum checked.
  - A menu, and the same actions as commands: add, list, start / stop / restart,
    status, logs, edit (checked before it is applied), remove, update, uninstall.
  - Each tunnel is `/etc/kariz/<name>.toml`, run by the systemd template
    `kariz@<name>` (`systemd/kariz@.service`), so one server can run several.
  - Adding a tunnel prints the exact command for the other server. For `wss` the
    listening side makes a self-signed certificate and passes its pin along.

## 0.5.1 - 2026-09-29

Works with v0.5 and v0.4 as before; the new settings only change the side they are set on.

### Added

- **More mux settings in `[tunnel.mux]`**, each defaulting to what it was before (the
  profile's value): `coalesce`, `ping_interval_secs` (default `tuning.keepalive_secs`;
  also QUIC's keep-alive), `datagram_buffer`, `datagram_queue` and `notsent_lowat` (0
  turns it off). `kariz check` shows the values in effect.
- **Documentation** in [`docs/`](docs/README.md): getting started, a configuration
  reference with every setting, transports, profiles, UDP and games, performance,
  security and troubleshooting.
- **A logo and a new README** (English and Persian).

### Changed

- **The `throughput` profile is now `ultraspeed`.** `profile = "throughput"` is still
  accepted.
- The stealth profile (planned for later) is dropped from the roadmap.

## 0.5.0 - 2026-09-28

The gaming release. Works with v0.4 over every transport: the new datagram path over
`kcp` is negotiated inside the session and stays off with a v0.4 peer. UDP rules with
`duplicate` need the exit at v0.5 (a v0.4 exit rejects those flows, and the entry logs
it).

### Added

- **Datagram path over `kcp`:** UDP flows travel beside KCP instead of inside its
  reliable stream, so a lost packet never holds up the ones behind it. On an emulated
  60 ms path the p99 round trip of game traffic stays at the path's RTT under loss
  (64 ms, against 141 ms at 1 % loss and 236 ms at 5 % in v0.4).
  - Sealed with keys from the handshake (forward secrecy, as everything else) and an
    explicit packet number; replays and copies are dropped.
  - Protected by FEC when FEC is on.
  - Packets too large for one KCP packet (above about 1,300 bytes) still go through
    the stream.
- **Packet duplication per forward rule:** `duplicate = 2 | 3` and `duplicate_gap_ms`
  (default 5). Each UDP packet is sent again, both ways, where it may be lost (KCP's
  datagram path, QUIC datagrams); the receiver drops the copies. Over a path losing
  10 % each way, echoed game packets lost 0.5-3.5 % of round trips with 2 copies,
  against 21-23 % without.
- **DSCP:** `[tuning] dscp = "ef"` (or `af41`, `cs4`, ..., or 0-63) marks TCP tunnel
  sockets, KCP sockets and the exit's UDP sockets to targets. Off by default: most of
  the internet clears or ignores the mark. QUIC sockets are not marked (quinn sets the
  TOS byte of every packet itself); `kariz check` says so.
- **`[tunnel.kcp] datagrams`** (default `true`): `false` keeps UDP flows in the
  reliable stream, as in v0.4.
- **Samples:** `entry-gaming.toml` / `exit-gaming.toml`.
- **Game-traffic benchmark:** 128-byte packets at 64 Hz, echoed, on an idle tunnel and
  next to four downloads, at 0 / 1 / 5 % and bursty loss (`cargo test --release --test
  tunnel game_traffic -- --ignored --nocapture`). Results in the README.

### Changed

- **UDP over `kcp` can now lose packets, as UDP does**, rather than waiting for
  retransmissions. On a link that a bulk transfer keeps full (the balanced profile's
  large windows over `kcp`), UDP packets are dropped at the link's queue instead of
  waiting behind it (5-13 % lost in the phase 4 benchmark, p99 about 115 ms instead of
  200-340 ms). `[tunnel.kcp] datagrams = false` restores the old behaviour.
- **The gaming profile turns FEC 10 / 3 on over `kcp`**, unless `[tunnel.kcp]` sets
  `fec_data` or `fec_parity` (0 and 0 turn it off). At 5 % loss 99 % of game packets
  came back instead of 90 %, and downloads next to the game went 2.3x faster.
- `kariz check` shows each rule's duplication and the DSCP mark, and warns where they
  have no effect.
- Roadmap: the `icmp` transport (phase 5) is dropped; the stealth profile and
  active-probe fallback are later work, not scheduled.

## 0.4.0 - 2026-09-28

Works with v0.3 over `tcp`, `tcpmux`, `ws` and `wss` (their wire format is unchanged);
the new transports need both sides at v0.4.

### Added

- **`transport = "quic"`** (quinn), in both modes:
  - Each user connection is a QUIC stream. UDP flows travel as QUIC datagrams, so a lost
    packet delays nothing else. Packets above the datagram limit (about 1,200 bytes,
    depending on the path) go on the flow's stream instead: they still arrive, just
    reliably.
  - Mutual TLS 1.3 with an identity derived from the token. There are no certificate
    files, and a wrong token fails the handshake in both directions.
  - `[tunnel.quic]`: `congestion` (`cubic`, the default, `bbr` or `newreno`), `sni`
    (dialer; default: the remote host), `alpn` (default `h3`).
  - A restarted endpoint resets the old connections at once (stateless resets with a key
    from the token).
  - No 0-RTT: sessions are pooled before users arrive, and early data could be replayed.
- **`transport = "kcp"`**, in both modes, with or without mux:
  - KCP (an ARQ protocol over UDP that keeps its rate under loss) as a stream under the
    usual handshake, encryption and mux.
  - Every UDP packet is sealed with a key from the token. The port answers nothing else
    (probes, other tokens, tampered packets), and KCP's headers are hidden.
  - Conversations have an explicit open, half-close and close, and keep-alive with a
    silence timeout. A restarted listener closes old conversations at once.
  - `[tunnel.kcp]`: `mode` (`normal`, `fast`, `fast2` (default), `fast3` or `manual` with
    `nodelay`, `interval_ms`, `resend`, `no_congestion`), `send_window`, `recv_window`,
    `mtu`.
  - **FEC**: `fec_data` / `fec_parity` (off by default; `10` / `3` to start). A lost
    packet is rebuilt from Reed-Solomon parity instead of resent. On a lossy link this
    halves the p99 latency of sparse traffic; bulk throughput does not improve.
- **Cargo features** `quic` and `kcp` (both on by default), to build without them.
- **Samples:** `entry-quic-direct.toml` / `exit-quic-direct.toml` (with WireGuard over
  datagrams), `entry-kcp-reverse.toml` / `exit-kcp-reverse.toml`.
- **Lossy-link benchmark:** the tests carry a UDP and a TCP link emulator (delay,
  jitter, random or bursty loss, reordering, a rate-limited bottleneck with a queue).
  The TCP one models the sender's TCP, so loss slows `tcpmux` as it would on a real
  path. See the Performance section of the README.

### Changed

- A session layer between entry / exit and the multiplexers (kmux, QUIC). No behaviour
  change for the existing transports.

## 0.3.0 - 2026-09-28

Works with v0.2 for TCP; UDP forwarding needs both sides at v0.3 (a v0.2 exit rejects
UDP flows, and the entry logs that the exit side does not support UDP).

### Added

- **UDP forwarding:** `[[forward]] protocol = "udp"` or `"tcp+udp"` (both on one port),
  over every transport and in both modes.
  - Each client address is a flow: a mux stream carrying `DGRAM` frames, or without mux
    a whole tunnel connection carrying length-prefixed packets. On the exit, each flow
    has its own socket connected to the target.
  - Flows end after `tuning.udp_timeout_secs` (default 60) without packets.
    `tuning.udp_max_flows` (default 1024 per rule) limits clients.
  - A client whose flow cannot be opened is ignored for 5 s instead of retried on every
    packet.
- **Mux datagrams:** `DGRAM` frames need no flow-control credit. They are sent ahead of
  stream data, but take at most half of a write while streams wait, so UDP cannot starve
  TCP. They are dropped instead of queued when the session's buffer is full (new packets
  on send, the oldest on receive).
- **`TCP_NOTSENT_LOWAT` (16 KiB)** on tunnel connections that carry mux, so the kernel
  does not hold a backlog that datagrams would wait behind. Over a throttled 20 Mbit/s
  link with four bulk transfers, UDP round trips went from about 340 ms to about 60 ms.
  No throughput cost measured.
- **Wire format:** open kind 2 (UDP), status 2 and reset reason 4 ("unsupported").
- **Samples and checks:**
  - `entry-udp-reverse.toml` / `exit-udp-reverse.toml` (WireGuard, a game server on
    TCP+UDP).
  - `kariz check` shows UDP settings and warns when UDP is forwarded without mux.
- **Tests and benchmarks:**
  - A UDP echo scenario in every row of the end-to-end matrix; idle flows, max flows,
    UDP through nginx.
  - Benchmarks for packets per second, idle latency, and latency under load over a
    throttled link.
  - `scripts/rss.sh` measures UDP flows.
  - `KARIZ_TEST_LOG=1` shows the sides' logs in end-to-end tests.

### Fixed

- The mux writer sends pending `SYN`s in stream id order before any datagram or data. A
  first datagram could otherwise pull its stream's `SYN` ahead of an older stream's,
  and the peer closed the session for an invalid id. This came from the phase 3 work,
  so no release is affected.
- An empty payload (a 0-byte datagram) no longer adds an empty buffer to a vectored
  write, which read as a dead connection.

## 0.2.0 - 2026-09-27

**Breaking:** the wire format changed. v0.2 and v0.1 cannot talk to each other; upgrade
both servers together. Config files from v0.1 still work and get encryption
automatically.

### Added

- **Encryption:**
  - A new handshake with mutual authentication (shared token) and X25519 forward
    secrecy. The hello is masked and randomly padded, so it has no fixed bytes and no
    fixed length.
  - AEAD records after the handshake (`tunnel.encryption`: `auto`, `chacha20-poly1305`,
    `aes-256-gcm`, `none`), with one key per direction.
  - 0-RTT open requests in direct mode.
  - A failed handshake is drained for a random 5-30 s instead of being closed at once.
- **Mux** (`transport = "tcpmux"`, `[tunnel.mux]`):
  - Many user connections over a few long-lived connections, with per-stream flow
    control and no round trip to open a stream.
  - Pings to detect dead connections, and optional rotation (`max_lifetime_secs`).
  - Reconnects with backoff, in both modes.
- **`ws` transport:**
  - A browser-like WebSocket upgrade (path, Host, User-Agent and extra headers are
    configurable).
  - An nginx-style `404` for anything else.
  - Early data (`ws.early_data`): the hello rides in the upgrade request, and an upgrade
    whose hello does not verify gets a `404` too.
- **`wss` transport:**
  - TLS with rustls (ring). The dialer checks the server against the Mozilla roots,
    one pinned certificate (`tls.pin_sha256`) or none (`tls.insecure`, warned).
  - Separate connect address and SNI, for CDN edge IPs.
  - The listener reloads `tls.cert` / `tls.key` when they change.
- **Commands and checks:**
  - `kariz pin <cert.pem>` prints a certificate's pin.
  - `kariz check` shows the new settings and warns about `encryption = "none"`,
    `tls.insecure`, and keepalives above 90 s on WebSocket transports.
- **Docs and samples:**
  - Samples for mux, `wss` with a pinned certificate, and `wss` through a CDN.
  - [docs/CDN.md](docs/CDN.md) with a Cloudflare checklist.
- **Tests and CI:**
  - An end-to-end test matrix over modes, transports, mux and ciphers.
  - A CI job that runs the tunnel through nginx as a stand-in CDN (idle timeouts,
    TLS termination).
  - A test that the sample configs are valid and paired.
  - `scripts/rss.sh` for memory measurements.
  - A release workflow: a tag push publishes a static x86_64 Linux binary (musl) with
    the samples and docs.

### Changed

- The token is turned into a key with BLAKE3 and a version label; the v0.1 `ts | nonce
  | tag` hello is gone.

## 0.1.0

- First release: CLI (`run`, `check`, `token`), TOML config with profiles, mutual
  authentication, plain `tcp` transport, reverse and direct modes.
