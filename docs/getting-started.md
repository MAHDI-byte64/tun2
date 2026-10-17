# Getting started

Kariz joins two servers with a tunnel:

- The **entry** is the public server your users connect to. It owns the `[[forward]]`
  rules: "whatever arrives on this port, send it to that address".
- The **exit** is the server that reaches the real targets. It dials the addresses the
  entry asks for.

```mermaid
flowchart LR
    U[Users] -->|port 443| E[Entry server]
    E <==>|Kariz tunnel| X[Exit server]
    X --> T[Targets]
```

Which side opens the tunnel is the **mode**:

| Mode | Who dials | Pick it when |
|---|---|---|
| `reverse` | the exit dials the entry | the entry can take incoming connections from the exit |
| `direct` | the entry dials the exit | the exit can take incoming connections (or sits behind a CDN) |

The dialing side sets `tunnel.remote`, the other side `tunnel.listen`.

## The quick way: the web panel

Install the panel on one server with the manager script, connect your other servers to it, and
make tunnels in the browser. The panel does every step below for you on both servers (the
configs, a token, a systemd service, a check that it connected) and undoes it all if a step
fails:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/tun2/main/scripts/kariz.sh)
```

In the menu choose **3** (Install the web panel here) and open the link it prints. Then read
[Using the panel](using-the-panel.md); [The manager script](manager.md) explains the menu.

The rest of this page is the same thing by hand, for a server without the panel or to see what
the panel writes.

## 1. Install

Download the static Linux binary for your CPU (`x86_64`, `aarch64` or `armv7`; `uname -m`
tells) from [Releases](https://github.com/MAHDI-byte64/tun2/releases), or build it with Rust 1.80 or
newer:

```bash
cargo build --release
sudo cp target/release/kariz /usr/local/bin/
```

Do this on both servers.

## 2. Make a token

```bash
kariz token
```

The token is the tunnel's only secret: both sides use the same one, and anyone who has
it can use the tunnel. It never travels over the network.

## 3. Write the two configs

Start from a pair in [`configs/`](../configs):

| Pair | Setup |
|---|---|
| `entry-reverse.toml`, `exit-reverse.toml` | reverse mode over plain `tcp` |
| `entry-direct.toml`, `exit-direct.toml` | direct mode over plain `tcp` |
| `entry-tcpmux-reverse.toml`, `exit-tcpmux-reverse.toml` | reverse mode with mux |
| `entry-udp-reverse.toml`, `exit-udp-reverse.toml` | UDP forwarding (WireGuard, games) |
| `entry-wss-direct.toml`, `exit-wss-direct.toml` | `wss` to your own server, self-signed certificate pinned |
| `entry-wss-cdn.toml`, `exit-wss-cdn.toml` | `wss` through a CDN ([guide](CDN.md)) |
| `entry-quic-direct.toml`, `exit-quic-direct.toml` | `quic`, with WireGuard over QUIC datagrams |
| `entry-kcp-reverse.toml`, `exit-kcp-reverse.toml` | `kcp` for a lossy link |
| `entry-gaming.toml`, `exit-gaming.toml` | a game server over `kcp` with the gaming profile |

A minimal reverse-mode pair:

```toml
# /etc/kariz/config.toml on the entry
role = "entry"
mode = "reverse"

[tunnel]
transport = "tcpmux"
listen = "0.0.0.0:3080"            # the exit connects here
token = "PASTE-THE-TOKEN"

[[forward]]
listen = "0.0.0.0:443"             # users connect here
target = "127.0.0.1:443"           # dialed by the exit
```

```toml
# /etc/kariz/config.toml on the exit
role = "exit"
mode = "reverse"

[tunnel]
transport = "tcpmux"
remote = "ENTRY_IP:3080"
token = "PASTE-THE-TOKEN"
```

`target` is resolved and dialed **on the exit**, so `127.0.0.1:443` means port 443 on
the exit server itself.

## 4. Check and run

```bash
kariz check -c /etc/kariz/config.toml    # validates, prints a summary and warnings
kariz run -c /etc/kariz/config.toml
```

Start the listening side first; the dialing side retries until it can connect either
way.

## 5. Run it as a service

```bash
sudo cp systemd/kariz.service /etc/systemd/system/
sudo systemctl enable --now kariz
journalctl -u kariz -f
```

The unit reads `/etc/kariz/config.toml`, restarts Kariz if it stops, and grants the
capabilities for ports below 1024.

## Next

- Pick a transport for your path: [Transports](transports.md).
- Tune for speed or latency: [Profiles](profiles.md).
- Every setting: [Configuration reference](configuration.md).
