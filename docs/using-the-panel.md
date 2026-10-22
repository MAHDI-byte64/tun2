# Using the panel

This page walks through the panel in the order you need it, from a new server to a tunnel you
can trust. You do not need any other tutorial: everything about servers and tunnels is done here,
in the browser. Try the same screens first, with sample data and nothing to install, in the
[live demo](https://mahdi-byte64.github.io/tun2/try/), take the
[guided tour](https://mahdi-byte64.github.io/tun2/docs/tour/), which opens each screen as it explains it, or
watch the [video tutorial](https://mahdi-byte64.github.io/tun2/docs/video/) (about two minutes, from a bare server to a running tunnel).

## 1. Sign in

On the server that holds the panel, the manager printed an address and a one-time link. Open the
link: it signs you in and vanishes from the address bar. The certificate is a real Let's Encrypt one, so
the browser shows no warning.

- Want a password instead of links? *Settings*, set one (10 characters or more).
- Lost the link? On the server, `kariz-manager panel link` makes another.

## 2. Add your servers

Open **Servers**, then **Add server**.

1. Give the server a name, and check the address (the panel's address as that server reaches it).
2. Leave the **link transport** on *Auto*, or pick one: *TCP*, *KCP*, *WSS* or *QUIC*. This is how the
   server talks to the panel, not how tunnels work. *Auto* tries them in turn and keeps the one that
   gets through. *QUIC* is always sealed, so it is the one to try where plain QUIC is filtered; it
   needs UDP open on the panel's port after the agents port.
3. The panel shows a **join code** and a command. On the other server, as root, run it:
   `kariz-manager --agent kz1_...`
4. Within seconds the server appears in the list, with its CPU, memory and network.

The new server opens no port: it connects to the panel. Codes work once, for 10 minutes.

## 3. Make your first tunnel

Open **Tunnels**, then **New tunnel**. The wizard asks five short things and explains each one:

| Step | You choose |
|---|---|
| **Servers** | a name, the *entry* (where your users connect) and the *exit* (which reaches the real services) |
| **Kind** | *reverse* (the exit dials the entry; the exit opens no port) or *direct*; the transport (for `quic`, whether every packet is sealed, on by default); the profile |
| **Connection** | the port the accepting side listens on, and the address the other side reaches it at |
| **Ports** | what the entry opens for your users: `443, 8080-8090, 2053=53`, TCP, UDP or both; optionally a limit of connections per user address, and *Real user IPs (PROXY protocol)* so Xray sees each user's address (only with `acceptProxyProtocol` on in Xray, see [configuration](configuration.md#real-user-addresses-proxy_protocol)) |
| **Build** | a review, then the panel builds both sides and shows every step |

The wizard picks the port for you: 3080 for the first tunnel on a server, then 3081, 3082 and so on, the
first one that none of that server's tunnels holds. You can type another.

Not sure what to pick? The default (reverse, `tcpmux`, `balanced`) is right for most paths; the
[transport chooser](https://mahdi-byte64.github.io/tun2/docs/how-it-works/) answers in four questions.

**If anything fails, both servers are put back as they were**, and the wizard tells you which
step failed and why. You cannot end with half a tunnel.

## 4. See what is happening

- **Map:** the overview. The key numbers (throughput, with a line of the last minutes),
  then the map: each server is a well; each tunnel is a channel, with its name and its rate
  now. Flowing water is traffic, a dashed empty channel is a stopped tunnel, a red pulse is a
  broken one. Hover for details, click a tunnel to open it. Under the map: the tunnels,
  **Needs attention** (a broken tunnel, a tunnel that is connected but lets no user through, one
  whose streams are nearly all taken, an offline server, a busy CPU, servers behind on the
  version, each with a button to go there) and every server's load.
- **The top bar** says *Live* while the panel answers. If it stops answering, a notice says
  so and the page keeps the last numbers until it is back.
- **Servers:** a card per server with its load, version and link. A server that is **offline**
  says since when and why, and has a **Reconnect** button: a new join code that makes the agent
  on it *that same server* again (same tunnels, nothing lost), with a choice of how it reaches
  the panel, if one protocol is filtered ([details](panel.md#a-server-that-goes-offline)). Click or tap its **IPv4** or
  **IPv6** address (or the address set for it) to copy it: the chip shows a check and a note says
  what was copied. On a phone each address is a full-width row, easy to hit.
- **Tunnels:** click a row. You see both sides, live charts of throughput and round trip (1 hour to
  30 days), and the ports it forwards with their traffic (per port: bytes up and down,
  connections and UDP flows open and total, failed opens, live from the entry). **Health** says whether a new connection
  gets through right now (checked every 15 seconds, the way a user connects) and how many of the
  tunnel's streams are in use; a tunnel that is connected but lets no one through says why, with
  the fix.
- **Terminal** (top of the Logs page, 2.10.0): a shell on the server you pick, in the browser,
  as the agent runs (root). Only servers that allow it: `terminal = true` in
  `/etc/kariz-panel/agent.toml` (`panel.toml` for the panel's own server), then restart the
  agent. Every open and close is in the audit log ([details](panel.md#terminal)).
- **Logs:** pick a tunnel and read both sides interleaved by time. Filter by level or text.
- **Events:** a server going offline, a tunnel losing its connection, and coming back.
- **Missing from their servers:** under the tunnels, the ones the panel still has a copy of
  (every create and edit leaves one) that no server lists any more. *Make again* builds one
  from its copy, with a new token; *Forget* drops the copy ([details](panel.md#make-a-tunnel)).

## 5. Change, stop, test, delete

Open the tunnel, then:

- **Edit:** the same wizard, filled in. Both sides change together; if they do not connect again,
  the old settings come back. A change to the ports alone is applied to the running entry
  without a restart (2.10.0 or newer on that server), so what is connected stays connected.
- **Start, stop, restart:** stopping also keeps it stopped at boot.
- **Speed test:** measures download, upload, latency under load and UDP through the tunnel, for
  the seconds you choose.
- **New token:** replaces the secret on both sides.
- **Traffic limit:** a volume, an end date (days or a date), or both; at the limit the panel
  stops the tunnel until the usage is reset, the limit raised or the end extended. *Make a
  link* gives whoever rents the port a page of their own with the usage, the days left, the
  state, the rate and a Restart button ([details](panel.md#traffic-limit)).
- **Auto restart:** restarts the tunnel by itself, every so many minutes, hours or days or every
  day at a time. The same on a server's card restarts all its running tunnels
  ([details](panel.md#restart-on-a-timer)).
- **Traffic limit:** a volume after which the panel stops the tunnel, with a reset by hand or
  every month on a day you pick; the usage shows on the tunnel's page and in the list
  ([details](panel.md#traffic-limit)).
- **Delete:** removes it from both servers.

## 6. Private networks

*Networks* makes private addresses between your servers (over GRE or VXLAN) that are never repeated, so a
tunnel (direct or reverse) can run over them, and the tunnel's edit page can move it on or off a network: [Private networks](networks.md).

## 7. Keep it safe

In **Settings**: the password, one-time links, and every signed-in device with a *Revoke* button.
*Download a backup* gives one file locked with a passphrase you choose; keep the passphrase.

## 8. Update

A notice appears in the top bar when a newer release is out. **Settings, Updates** shows the
release notes and two buttons: update the panel, and update the servers (one at a time, each
checked, and put back if it does not come up). The panel never updates by itself.

## 9. Proxy

When the panel's own server cannot reach some of the other servers directly, **Settings, Proxy**
takes a SOCKS5 proxy (its address, and a username/password if it needs them). Which servers go
through it is chosen per server: for a server the panel connects to (*Add server*, **The panel
connects to it**, or a server's *Edit*), tick **Through the panel proxy**. Only those servers
are dialed through the proxy; because SOCKS5 carries only TCP, such a link uses the TCP
transports (`tcpmux`, `wss`) and not the UDP ones (`kcp`, `quic`). When an agent dials the
panel instead, nothing on the panel side is proxied. A second switch, **Panel internet**, sends
the panel's own update downloads through the proxy.

Changing the proxy takes effect at once (the servers that go through it are connected again
through the new one); while the proxy is off, those servers are not connected and their cards
say so. The password is kept in the panel and never shown again. (The Telegram bot has its own
separate proxy under *Settings, Telegram*.)

## Handy things

- **Ctrl+K** opens a search for pages, commands and tunnels (type a tunnel's name to open it).
- The address follows the page, so the browser's Back button works and a bookmark opens the
  same page.
- The top bar switches **Persian / English**, **Night / Dawn**, and a **low-power** mode that
  stops the animation (also on when your browser asks for less motion).
- Everything works on a phone.

## When something is wrong

[Troubleshooting](panel.md#troubleshooting) lists the usual ones: a server that does not show up,
a port in use, a tunnel that did not connect, being locked out.

## Metrics for Prometheus

*Settings*, *Metrics (Prometheus)* switches on an address Prometheus can scrape with a token:
the servers' load, each tunnel's state and bytes, every port's counters and the traffic limits.
The section shows the address, the token and a scrape config to paste
([the metrics](panel.md#metrics)).
