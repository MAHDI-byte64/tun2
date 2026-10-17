# The web panel

A web panel for Kariz: connect your servers, make and manage tunnels between them, and watch
their traffic live, from one page. **Everything is done here**; the [manager script](manager.md)
only installs Kariz and the panel. New to it? Start with [Using the panel](using-the-panel.md),
a walk through the screens in the order you need them.

## Install

On the server that will run the panel, as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh) install
kariz-manager panel install
```

`panel install` first asks how you will open the panel and gets a certificate for it (below),
then writes the settings, makes the database, starts the service `kariz-panel`, and prints:

```text
  address       https://203.0.113.5:28443/k-7f3a9c2e/
  certificate   /etc/letsencrypt/live/kariz-panel-203-0-113-5/fullchain.pem
  agents        port 22230: TCP and UDP, and TCP and UDP 22231 (open them for the servers you add)
  sign in       https://203.0.113.5:28443/k-7f3a9c2e/#t=...
```

- **The address** has a secret path: the panel answers only there. Any other address gets
  the plain "404 Not Found" page of an nginx, so a scanner finds nothing.
- **The certificate** is a real one from Let's Encrypt, so the browser shows no warning (and
  Safari keeps the sign-in cookie). See *The certificate* below.
- **The sign-in link** works once, for 60 minutes. Open it in the browser: it signs you in
  and disappears from the address bar. Make another any time with
  `kariz-manager panel link`.
- **The ports** are random (above 20000). `--port N` chooses the panel's. Open both the
  panel's port (for you) and the agents' port (for your other servers: TCP and UDP, and TCP and UDP on the next port
  for `wss` and `quic`) in the firewall.

The installer asks for an admin password of your own (at least 12 characters, three of: lower
case, UPPER CASE, digits, symbols); or choose the one-time sign-in link only. Change it in *Settings*
(10 characters or more), or from the server: `kariz-manager panel password` (asks the same way;
`--random` makes one and shows it, `--stdin` reads yours).

## The certificate

The panel is served only over a certificate the browser trusts, from Let's Encrypt. The installer
asks which of two you want:

- **A domain name** that points at this server (an A record). The certificate lasts 90 days.
- **The server's own public IP address**, if you have no domain. Let's Encrypt issues these for
  6 days at a time, so they are renewed more often. The address must be public (not `10.x`,
  `192.168.x` and so on).

```bash
kariz-manager panel install --domain panel.example.com      # or: --ip 203.0.113.5
kariz-manager panel cert --domain other.example.com         # change it later; --ip ADDRESS too
```

`panel cert` (also in the manager's menu) gets the new certificate, points the panel at it and
removes the old one; run it any time to change the domain, or to move from an IP address to a
domain. Add `--email you@example.com` to be told before a certificate expires.

- **Renewal is automatic:** a timer (`kariz-cert-renew.timer`) checks twice a day, and the panel
  loads the new certificate without a restart.
- **A new IP address is followed by itself.** When the server's IP address changes (the old one
  was filtered and the provider gave a new one) and the certificate was for the old address,
  `kariz-manager panel heal` gets one for the new address and switches the panel to it, within
  10 minutes of the change and with no browser warning. A timer runs it (`kariz-panel-heal.timer`:
  a minute after boot, then every 10 minutes); it asks Let's Encrypt for nothing unless the
  address changed, and after a failure (port 80 closed) it tries again an hour later. Open the
  panel at `https://NEW-IP:PORT/PATH/`, as before; the menu and `kariz-manager panel link` show
  the new address. It cannot see a change behind NAT (the server only has a private address, and
  the public one was typed at install) or for a domain: there, run `panel cert` (for a domain,
  change its A record first, and the certificate keeps working). A panel set up before this gets
  the timer when it is updated (from the panel or with the manager).
- **A filtered domain or a new certificate:** run `kariz-manager panel cert` (menu item 6, *New IP,
  domain or certificate*). It says what the certificate is for now and whether that still fits
  this server, and gets one for the new domain or for the IP address.
- **Port 80.** Let's Encrypt has to reach port 80 for a few seconds, at the first request and at
  each renewal. If a service holds it (nginx, a tunnel...), the manager says which one, asks to
  stop it for a moment and starts it again right after; the same happens at each renewal by
  itself. A process that is not a systemd service (a Docker container) cannot be stopped for you:
  free the port yourself. Open port 80 in the firewall.
- **certbot 5.4 or later** does this (IP address certificates need it). If the system has none
  that new, the manager installs one for itself in `/opt/kariz-certbot` with pip.
- **A certificate of your own:** `kariz-manager panel cert --cert-file F --key-file K` (Kariz does
  not renew it).

## Connect another server

In the panel: *Servers*, *Add server*. Give it a name if you like, and check the address
(the panel's address as the new server reaches it). The panel makes a join code and shows a
command. On the other server, as root:

```bash
kariz-manager --agent kz1_...
```

(If Kariz is not installed there yet, this installs it first.) The server appears in the
panel within seconds.

- **The agent dials the panel**, so the new server opens no port. It needs to reach the
  panel's *agents* port.
- **Choose the address.** *Add server* offers the panel's own public IPv4 and IPv6
  addresses. A server with only IPv6, or whose IPv4 route is filtered, can join over IPv6:
  the agents port listens on both. A server that has a private (GRE) link to the panel's server
  can go through it: its *Edit* offers the panel's address on the link
  ([details](networks.md#the-agents-link-over-a-network)).
- **An agents port of its own.** *Agents port* (optional) under the address: left empty, the
  agent dials the panel's agents port, as every agent does. With a port (say `8443`), the panel
  also listens on that port and the next one (`8444`), TCP and UDP, for this server's agent
  alone, so a server whose network filters the main agents port can use one that gets through;
  open both in the panel server's firewall. The server is listed at once, waiting for its agent,
  and its card shows *agents port 8443*. Another agent on that port is turned away. *Edit*
  changes it (empty: back to the main port); removing the server closes the port. The port and
  the next must be free of the panel's page, its agents ports and other servers' own ports, and
  nothing else may listen there. A backup keeps it. **Over a GRE link** and **Over a VXLAN
  link** have the same field: the agent then dials that port across the link. API: `port` in
  `POST /api/servers/join-code`, `POST /api/servers/join-gre` and `POST /api/servers/reconnect`.
- **Only GRE gets through?** Choose **Over a GRE link** and type the new server's public IPv4
  address: the panel makes its end of a GRE link at once, and the command makes the other end
  before the agent connects across it ([details](networks.md#add-a-server-over-gre)).
- **GRE is blocked but UDP passes?** Choose **Over a VXLAN link**: the same, with a VXLAN link
  over UDP (4789 unless the network says otherwise).
- **The new server cannot reach the panel at all?** Choose **The panel connects to it**: its
  agent listens on a port of its own and the panel dials it ([below](#the-panel-connects-to-the-server-reverse)).
- **The link's transport is automatic by default.** The panel takes agents over `tcpmux`
  (TCP on the agents port), `kcp` (UDP on the same port) and `wss` (WebSocket over TLS with
  the panel's certificate, on the next port; it looks like an ordinary HTTPS site) and
  `quic` (UDP on the next port, **always sealed**: every packet is encrypted with a key from
  the link token, so a network that filters QUIC does not recognise it, and the port answers
  nothing that was not made with the token; there is no setting for it, it is never plain
  QUIC). With *Auto*, an agent tries them in that order, moves on after two links in a row that carry no
  requests (it drops a link the panel has been quiet on for 20 s), and remembers the one
  that worked in `/etc/kariz-panel/link-transport`. Pick *TCP*, *KCP*, *WSS* or *QUIC* instead to
  make the code use only that one (the agent must be 1.4 or newer, and newer than 1.6 for
  *QUIC*). *Servers* shows which one each server uses.
- **A code works once**, for 10 minutes. It carries a token, so keep it as secret as a
  password until it is used.
- The agent runs as the service `kariz-agent`: `kariz-manager agent status | logs | remove`.
- **Remove a server** in the panel (*Servers*, *Remove*): it leaves the panel and its link
  closes. Nothing is deleted on it; its tunnels keep running.

### The panel connects to the server (reverse)

Usually the agent dials the panel. When the new server cannot reach the panel (the panel's
server takes no connections from outside, or the way in is filtered) but the panel can reach
the new server, turn it round: *Add server*, **The panel connects to it**, and type the new
server's address (an IP or a domain) and the port its agent is to listen on (`29001` unless you
change it).

1. The panel lists the server (*waiting for its agent*) and starts trying to connect to it.
2. You run the command it shows on the new server, as root. Its agent starts listening on the
   port and the next one, over the same transports as a panel's agents port (`tcpmux` and `kcp`
   on the port, TCP and UDP; `wss` and `quic` on the next), and the panel connects within
   seconds. Open those ports for the panel's address (the dialog lists them).
3. From then on the panel keeps the link up: when it drops, the panel connects again by itself
   (every few seconds at first, then up to every 30 s; with *Auto* it moves on to the next
   transport when one keeps failing). The card says *panel connects · address*.

The link is made the same way as the other way round: the token handshake, the encryption, and
the agent still proves who it is with its key. A server that answers at that address as another
server is let go. The panel does not need an agents port of its own for this, so it works on a
panel that takes no agents. *Reconnect* and *Edit* have the same choice (*Who makes the
connection*), so a server can be switched either way; the address and port can be changed there.
A backup keeps where the panel dials each such server.

**Across a private link.** When only GRE (or only UDP) gets through between the two servers,
tick **Across a private link (GRE or VXLAN)**, pick GRE or VXLAN, and type the new server's
public IPv4 address instead of an address to dial. As with
*Over a GRE link*, the panel gives the link a `/30` of a private network (it makes `kariz`,
`10.77.0.0/16`, when there is none) and makes its own end at once; the code carries the other
end, which the command makes on the new server before its agent starts listening. The panel then
dials the server's private address on the link, so only GRE (IP protocol 47), or for VXLAN UDP to
the network's port, has to pass between the public addresses. In *Edit* (*The panel connects to
the agent*), **Across a private link to the panel's server** offers the server's end of every link it has with the panel's server, or **A new
link** (GRE or VXLAN, its public IPv4 address and a network), which the panel makes in the same way. A link the
panel dials a server across cannot be removed until the server is moved off it. New API fields:
`gre: {ip, network, kind}` in `POST /api/servers/join-reverse` and in `POST /api/servers/reconnect`,
and `kind` in `POST /api/servers/join-gre` (`gre` or `vxlan`; without a network, the first one of
that kind, or a new one).

### A server that goes offline

The agent's link to the panel and the tunnels are separate things: when a server shows
*offline*, its tunnels may well be running; the panel just cannot reach it. The server's card
says so, with when the panel last heard from it and, if it knows, why the link ended, and has a
**Reconnect** button (an online server has **Edit** instead). It opens a dialog that:

- tells you what to look at on that server first: `kariz-manager agent status`, and
  `systemctl restart kariz-agent` if the agent is stopped;
- lets you **choose how the agent reaches the panel** (*Auto*, *TCP*, *KCP*, *WSS* or *QUIC*),
  for a network that filters one of them;
- makes a **join code for that same server**: run `kariz-manager --agent kz1_...` on it and the
  new agent *is* that server again, with the same name, the same tunnels and the same private
  network links (nothing is deleted or made twice). The old agent's key stops working, so it
  is also the way out when an agent was reinstalled, lost its settings, or the panel says an
  agent came with a key it does not accept. The code works once, for 10 minutes;
- renames the server.

While a server is offline, a tunnel with its other side online can still be started, stopped
and restarted from that side; editing a tunnel needs both sides connected.

## Restart on a timer

A tunnel, or all the running tunnels of a server, can be restarted by themselves: on the
tunnel's page (*Auto restart*) or on the server's card (*Auto restart*). Pick **every** so many
minutes, hours or days (10 minutes to 30 days, counted from when you save and then from each
restart), or **every day at** a time (the browser's time). The panel keeps the timers and does
the restarts itself, with the same requests as the *Restart* button, so no cron is set up on the
servers. Good to know:

- A **tunnel** is restarted on both sides, the accepting side first. A **server** restarts each
  running tunnel on it, one after the other; the agent itself is not restarted.
- What you **stopped** stays stopped.
- A server that is **offline** is not restarted: the panel tries again as soon as it is back (a
  daily time that the panel itself slept through is skipped, unless it is back within the hour).
- *Restart now* tries it at once; the card shows when the next restart is and how the last one
  went. Each restart is in *Events* and the audit log. The timers need the panel to be running,
  and are not part of the backup.

## Make a tunnel

*Tunnels*, *New tunnel* opens the wizard (it needs two connected servers):

1. **Servers:** a name (small letters, digits, dashes) and which server is the *entry* (where
   your users connect) and which the *exit* (which reaches the real services).
2. **Kind:** *reverse* (the exit dials the entry, so the exit opens no port) or *direct* (the
   entry dials the exit), the transport (`tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`) and the
   profile (`balanced`, `ultraspeed`, `gaming`). For `quic` there is a switch, on by default, to
   **seal every packet** (`obfs`, see [Transports](transports.md#obfs)); both servers need Kariz
   1.7 or newer for it.
3. **Connection:** the port the accepting side listens on and its address as the other side
   reaches it. For `ws`/`wss`, the path. In *direct* mode you can tick **Use a private network
   (GRE or VXLAN)** and the tunnel runs over private addresses the panel hands out
   ([networks.md](networks.md)).
4. **Ports:** what the entry opens: `443, 8080-8090, 2053=53`, with TCP, UDP or both, and the
   host the exit reaches them at (default `127.0.0.1`).
5. **Build:** the review, then the panel does it on both servers, in order, and you watch each
   step: both servers check the settings and that the ports are free (a port that something
   else holds is named, with the program), the accepting side is written and started first,
   then the dialing side, and the panel waits (up to 30 seconds) until both report *connected*.

**If any step fails, everything made so far is removed from both servers**, and the wizard says
which step and why (a refused connection, a wrong token, a port in use...). A `wss` accepting
side gets a self-signed certificate made by its own server, and the other side is given its pin
automatically; or a real one from Let's Encrypt
([details](transports.md#wss-with-a-real-certificate)).

Open a tunnel (click its row) to see both sides, its charts, and to **edit** it (the same
wizard, filled in; both sides change together and are restarted, and if they do not connect
again the old settings are put back), **start / stop / restart** it, give it **a new token**, run
a **speed test**, or **delete** it (both sides).

The panel never keeps a tunnel's token: it makes one, sends it to the two servers over the link
and forgets it. So *a new token* cannot be undone if it fails half way; run it again.

### Benchmark: which transport gets through best

Not sure which transport (or which direction) to use between two servers? The **Kind** step of
the wizard, and every tunnel's page, have a **Benchmark**. It takes about 20 seconds, makes no
tunnel and changes nothing on the servers:

1. **Quick check.** Every transport (`tcp` with mux, `kcp`, `ws`, `wss`, `quic`) in **both
   directions** (which server takes the connection): one server listens for a short test
   session, the other dials it, and the panel notes whether it got through, how long the
   handshake took and the round trips. It uses the port the tunnel would get, since filters
   often go by port.
   - **Over IPv6 too**, when both servers have a public IPv6 address: the same transports
     between the two IPv6 addresses, side by side with IPv4 on the same port, so the run takes
     no longer. When one of them has none, the result says which.
   - **Across the GRE link and across the VXLAN link**, for each kind the two servers have a
     link of: `tcp` with mux, `kcp` and `quic`, marked *GRE* or *VXLAN*. A filter sees the GRE or
     VXLAN packets, not what is inside them, so the transports differ there only by their own
     cost (`ws` and `wss` would only add theirs). Using such a result puts the tunnel on that
     link's network.
   - **`wss` with a server name.** Without one, a `wss` test sends no server name (SNI), as a
     tunnel dialing an IP address does. A tunnel's own name (or one typed under *Try WSS with a
     server name*) has `wss` tried once more with it, to show whether a filter judges TLS by its
     name.
2. **Speed.** The best three of those move data each way for two seconds, and the best over
   IPv4 and over IPv6 when they are not among them.

Each one gets a **score from 0 to 100**: speed, latency and stability (lost round trips, a slow
handshake, latency that grows while data moves), weighted by the profile: *gaming* counts
latency most, *ultra speed* speed. The panel shows the recommended one with why ("the fastest,
1.4× the speed of WSS"), the others ranked, what did not get through and the likely reason, and
says when nothing got through in one direction (that server takes no connections from the
other: use the other mode). The rest (the others that got through, what did not and why) is
folded under one line. **Use this** fills the wizard in (for an IPv6 result, the IPv6 address to
dial, and the tunnel listens on every address, `[::]`); on a tunnel's page **Edit with
this** opens the edit page with it filled in, to look over and save. The last result of each pair
of servers is kept. A benchmark is a snapshot: some filters start only after minutes or at busy
hours. Both servers need this release (`POST /api/bench`, `GET /api/bench?id=`,
`POST /api/bench/stop`, `GET /api/bench/last?entry=&exit=`).

## What you see

- **Map:** each server is a well on the horizon; each tunnel whose entry and exit servers
  are both connected is a channel of water between them. Flowing water is traffic (the
  particles follow the throughput); a dashed empty channel is a stopped tunnel; a red pulse
  is one that is broken. Hover for details.
- **Servers:** CPU, memory, network, uptime and the number of tunnels of each server. (On
  Linux; nothing is shown where there is no `/proc`.)
- **Tunnels** come from the `*.toml` files in `/etc/kariz` on each server, with systemd's
  state and the running daemon's `kariz status`. A tunnel is drawn when its entry and exit
  have **the same name**, which is how the panel names the two sides. Each tunnel's page
  has charts of its throughput and round trip over 1 hour, 24 hours, 7 days and 30 days. The
  last hour is kept in memory; five-minute averages are stored in the database for 30 days.
- **Networks:** private GRE networks between your servers, with addresses that are never
  repeated ([networks.md](networks.md)).
- **Logs:** pick a tunnel and read the log of **both sides interleaved by time**, filtered by
  level or text, with *Follow*. The *Events* tab lists a server going offline or back, a tunnel
  losing its connection or getting it back.
- **Speed test:** on a tunnel's page. The entry server measures download, upload and UDP
  through the tunnel ([Speed test](speedtest.md)); it uses the tunnel for the
  seconds you choose.
- **Settings:** the password, one-time login links, the sessions (each device, its address,
  when it was last used, and *Revoke*), the backup, and the appearance.

Persian and English, Night and Dawn, and a low-power mode (also on when your browser asks for
less motion) are in the top bar and in *Settings*. `Ctrl+K` opens commands.

## Security

- Everything is over TLS, under a secret path; plain HTTP gets nothing.
- The password is stored as an Argon2id hash. Login links, session cookies and the CSRF
  values are random 32-byte tokens stored as hashes only, so the database alone opens
  nothing. The cookie is `__Host-kariz` (`Secure`, `HttpOnly`, `SameSite=Strict`).
- Five failed tries from one address (wrong password, wrong or spent link) lock it out for
  15 minutes.
- Agents talk to the panel over Kariz's own link (the tunnels' handshake, encryption and
  mux). A token alone is not enough: each agent also proves a key of its own, made when it
  joined. **Agents answer a fixed list of requests**: who are you, keep this identity, health,
  tunnels, check / write / read / delete a tunnel, start / stop / restart it, listening ports,
  the log, the speed test. **There is no remote shell:** a request carries data (a tunnel's
  settings as typed fields, which the agent turns into the file itself, refusing anything with a
  control character in it), never a command or a path, and the programs an agent runs
  (`systemctl`, `journalctl`, `kariz speedtest`) get fixed arguments and a checked name.
- A tunnel's token is made by the panel, sent once to its two servers inside the encrypted
  link, and written there with mode 0600. The panel does not keep it and never shows it.
- The database (`/var/lib/kariz-panel`, root only) holds the agents' keys, because the
  panel needs them to check the proofs. Guard it like the tunnel configs.

## Commands

```bash
kariz-manager panel install [--port N] [--host H]   # settings, service, address and a link
kariz-manager panel link [--host H]                 # a new one-time login link
kariz-manager panel password [--stdin | --random]  # a new admin password (asked twice, hidden)
kariz-manager panel status | logs                   # the service, its address / follow the log
kariz-manager panel uninstall [--yes]
kariz-manager --agent CODE                          # connect this server to a panel
kariz-manager agent status | logs | remove
```

The menu has the same (items 3 to 10). Without the manager: `kariz-panel init`, `serve`,
`login-link`, `reset-password`, `agent --join CODE` (see `kariz-panel --help`).

## Backup and restore

*Settings*, *Download a backup* gives one file, locked with a passphrase you choose (10
characters or more; Argon2id and ChaCha20-Poly1305). It holds the servers this panel knows,
with the keys they prove themselves with, and the token they dial with. It does **not** hold
tunnels (they live on the servers, in their own files, and the panel reads them from there),
sessions or login links. Keep the passphrase: without it the file cannot be opened.

To move to a new server: install the panel there, sign in, *Restore a backup*, then
`systemctl restart kariz-panel` so the agents can connect with the restored token. They dial
the panel's address, so point that name at the new server (or run `kariz-panel agent` again on
each server with a new join code if the address changed).

## Your own certificate

Set both in `panel.toml` and restart, or reload without dropping anything:

```toml
cert_file = "/etc/ssl/panel.pem"     # the certificate chain, PEM
key_file  = "/etc/ssl/panel.key"
```

```bash
systemctl kill -s HUP kariz-panel    # loads the new files for the next connections
```

A file that cannot be read is refused and the old certificate stays. `kariz-manager panel cert`
does all of this for Let's Encrypt, with renewal (see *The certificate* above); with your own
tool (certbot, acme.sh) reload as above after each renewal.

## A host without systemd

In a container there is no systemd to start the tunnels. Set `services = "process"` in
`panel.toml` (or `agent.toml`): the panel or the agent then runs each tunnel as a child process
(`kariz run`), which stops when it stops. Tunnels then do not come back after a reboot by
themselves; that is the price of having no service manager.

## Files

| Path | What |
|---|---|
| `/etc/kariz-panel/panel.toml` | the panel's settings: `listen`, `path`, `agent_listen`, `data_dir`, `kariz_dir`, `services`, `cert_file`, `key_file`, `release_api`, `release_key` |
| `/etc/kariz-panel/agent.toml` | an agent's identity (id and key), the panel's address, `kariz_dir`, `services`, `release_key` |
| `/var/lib/kariz-panel/updates/` | the releases the panel downloaded, and the result of the last update |
| `/var/lib/kariz-panel/` | the database, the certificate and its key |
| `kariz-panel.service`, `kariz-agent.service` | the systemd units |

## Updating

When a newer release is out, a notice appears in the top bar (*Kariz 0.11.0 is out*), and
*Settings*, *Updates* shows it with the release notes. **The panel never updates by itself**:
it looks (once a day, or *Check now*), and updating is your button.

- **Update the panel:** the panel downloads the release for its own CPU **once**, checks its
  signature and checksum (see below), and hands over to a helper that runs as a service of its
  own, so that it lives on while the panel is replaced. The helper keeps the old programs as
  `kariz-panel.previous` and `kariz.previous`, puts the new ones in place with a rename (never
  half written), restarts the panel, and asks it over TLS (its certificate pinned) for its
  version. **If the new panel does not answer as the new version within 30 seconds, the old
  programs are put back and the panel restarted**; the result is kept, shown in *Updates*, and
  written to the audit log. The browser waits and reloads by itself. A new **major** version
  asks you to tick a box first, and a release older than the installed one is refused (no
  downgrades).
- **Update the other servers:** *Update the servers* (in the top bar when some are behind, and in
  *Updates*). The servers never need the internet: the panel sends the release it has, over the
  link that already exists, in pieces. Each agent checks the signature **again with its own copy
  of the key**, unpacks it, and hands over to its own helper, which swaps the programs, restarts
  the agent and waits for the new agent to reach the panel, putting the old programs back if it
  does not. The servers go **one at a time**, the panel waits for each to come back before the
  next, and a server that fails stops the rest, which are left as they were.
- **Their tunnels:** the tunnel daemons keep running the old program until they are restarted.
  Tick *Restart their tunnels afterwards* and they are restarted **one at a time**, each
  waited for until it is connected again, so a pair never loses both its sides at once. A tunnel
  drops for a moment; choose your time.
- **Channel:** *Stable* (the default) or *Beta*, which also offers prereleases.
- A server whose agent is too old to be updated this way (before 0.11) shows an error for that
  server; update it once by hand with `kariz-manager update`, and it can be updated from the
  panel from then on.

### The releases are signed

Every release archive has a checksum file and a signature (`.sha256` and `.sig`): an Ed25519
signature over the checksum file, which also names the archive, so an archive cannot be swapped
for another of the same release. The public key is built into `kariz-panel` and into
`kariz-manager`; the private key is a repository secret that only the release workflow sees. A
file whose signature does not verify is never run, and is deleted. The checksum alone would only
prove the download was not damaged: it comes from the same place as the file.

To check a download by hand: `kariz-panel release-verify kariz-v0.11.0-x86_64-linux.tar.gz`
(with its `.sha256` and `.sig` beside it). To pin a key of your own (a fork), set
`release_key = "HEX"` in `panel.toml` (and in `agent.toml` for agents), and `release_api =
"https://api.github.com/repos/OWNER/REPO"` to look somewhere else.

### If the panel cannot reach GitHub

The panel needs to reach `api.github.com` and GitHub's download addresses to find and fetch a
release. If it cannot, update by hand on each server with `kariz-manager update` (the manager
checks the signature too).

## Removing

`kariz-manager panel uninstall` removes the panel (and asks before deleting its database);
`kariz-manager agent remove` removes the agent.

## Troubleshooting

- **A server does not show up:** `kariz-manager agent logs` on it. "could not connect"
  usually means the panel's agents ports (TCP and UDP, and TCP and UDP on the next port) are closed
  in a firewall between them; "connected" repeating every 20 s or so means the path stalls
  TCP: with *Auto* the agent moves to `kcp`, then `wss`, then `quic`, by itself; a join
  code that was already used or has expired is refused (make a new one).
- **The map shows no tunnel:** both servers must be connected and the tunnel must have the
  same name on both. A tunnel with one side connected is listed in the table as
  "one side only".
- **A tunnel shows as broken:** the panel reports what the entry side's daemon says
  (`kariz status`): not connected, or no daemon running. Run `kariz status -c /etc/kariz/NAME.toml`
  on the server for the details ([Status](status.md)).
- **The wizard says a port is in use:** it names the program (`sshd`, `nginx`, another
  tunnel). Pick another port, or stop that program. The check is done on the server itself, so
  a firewall rule does not matter here, but do open the port for your users.
- **A new tunnel did not connect:** the wizard shows the reason each side reported (for
  example *connection refused*: the accepting server's port is not reachable from the other, a
  firewall in between; or a timeout). Nothing is left behind; fix the cause and try again.
- **Logs are empty:** they come from `journalctl -u kariz@NAME`, so they need systemd; with
  `services = "process"` the daemons' output is not kept.
- **Locked out:** wait 15 minutes, or make a link on the server with
  `kariz-manager panel link`.
