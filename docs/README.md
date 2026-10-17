# Kariz documentation

For Kariz **v2.7.0**; what changed in each version is in the [changelog](../CHANGELOG.md). Start with
[Getting started](getting-started.md) and come back to the reference pages when you need a specific
setting. The same pages are a website, with search,
animated diagrams and a live demo of the panel, in English and Persian:
<https://mahdi-byte64.github.io/tun2/> (built from these files; see [`site/`](../site/README.md)).

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | The quick way (the panel), and by hand: a token, two configs, systemd |
| [Using the panel](using-the-panel.md) | A walk through the web panel: sign in, add servers, make a tunnel, watch it, keep it safe |
| [The manager script](manager.md) | One-line install of Kariz and the panel on a server, and connecting a server to a panel |
| [Configuration reference](configuration.md) | Every setting, its default and its limits |
| [Speed test](speedtest.md) | The panel's button and `kariz speedtest`: speed, latency and UDP through the live tunnel |
| [Telegram alerts](telegram.md) | A bot that tells you when a server or tunnel goes down, and answers `/status`; if Telegram is blocked |
| [The web panel](panel.md) | Install the panel, sign in, connect servers with agents, what it shows |
| [Status](status.md) | `kariz status`: connection, round trip, last error and traffic per port, on either side; the JSON document |
| [Accessibility](accessibility.md) | what is checked on every change (axe, keyboard, motion) and what is checked by hand |
| [Security review](security-review.md) | who is assumed to attack the panel, what was checked and fixed for 1.0, what is left |
| [فارسی: مستندات به زبان فارسی](fa/README.md) | every page of this documentation in Persian |
| [Private networks (GRE, VXLAN)](networks.md) | private addresses between your servers, made by the panel, never repeated |
| [Transports](transports.md) | `tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`: how each works and when to pick it |
| [Profiles](profiles.md) | `balanced`, `ultraspeed`, `gaming`, and overriding their values |
| [UDP forwarding and games](udp-and-games.md) | UDP rules, the datagram path, packet duplication, DSCP |
| [Performance](performance.md) | Measurements, tuning for speed, running the benchmarks |
| [Running behind a CDN](CDN.md) | `ws` / `wss` through Cloudflare or ArvanCloud |
| [Security](security.md) | What the token protects, encryption, what is visible on the wire |
| [Troubleshooting](troubleshooting.md) | `kariz check` warnings, common errors, logs |

How it is built: [design and protocol](ROADMAP.md). To help the project go on: [Support Kariz](support.md).

Kariz is source-available under its own [license](../LICENSE): you may read it and run the
official releases on your own servers; using the core anywhere else is not allowed.

In Persian: [README_FA.md](../README_FA.md) covers the same ground in short.
