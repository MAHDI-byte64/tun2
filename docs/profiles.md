# Profiles

A profile sets many values at once for one kind of use. Pick it with the top-level
`profile` key; any value can still be overridden in `[tunnel.mux]`, `[tunnel.kcp]` or
`[tuning]`.

```toml
profile = "ultraspeed"            # balanced (default) | ultraspeed | gaming
```

| | `balanced` (default) | `ultraspeed` | `gaming` |
|---|---|---|---|
| For | most uses | bulk transfer, the most speed | games, voice, real-time UDP |
| Relay buffer | 64 KiB | 256 KiB | 16 KiB |
| Mux stream window | 256 KiB | 1 MiB | 64 KiB |
| Mux connections | 4 | 8 | 2 |
| Mux write coalescing | on | on | off |
| Keepalive / ping | 30 s | 30 s | 10 s |
| KCP FEC | off | off | 10 / 3 |
| KCP send window (adaptive up to) | 1024 (4096) packets | 1024 (16384) | 512 (2048) |
| UDP socket buffer | 1 MiB | 4 MiB | 1 MiB |
| UDP flow queue | 128 packets | 512 packets | 64 packets |
| UDP session buffer | 256 KiB | 1 MiB | 128 KiB |

## `balanced`

A middle ground for mixed traffic. One stream moves at most 256 KiB per round trip,
about 25-30 Mbit/s on a 60 ms path; raise `tunnel.mux.stream_window` or use `ultraspeed`
for more.

## `ultraspeed`

The most speed per connection: four times the stream window, twice the connections,
larger buffers everywhere. It costs memory per active stream (up to the window each),
and large windows let a bulk transfer fill the path's queues, which adds latency for
anything sharing it.

For the most speed, also pick the transport for the path:

- **Clean path:** `tcp` or `tcpmux`, with `encryption = "auto"` (AES-256-GCM on CPUs with
  AES instructions).
- **Lossy path:** `kcp`, or `quic` with `congestion = "bbr"`; TCP-based transports
  collapse under random loss.
- **Past the defaults:** `tunnel.mux.stream_window` goes up to 16 MiB. A stream needs
  about bandwidth x RTT: 100 Mbit/s at 100 ms is 1.25 MB.

`throughput`, its name before v0.5.1, is still accepted.

## `gaming`

Low and steady latency for small packets:

- Small buffers and windows: one download cannot fill the path, so game packets do not
  queue behind it.
- No write coalescing: each frame goes out at once.
- Pings every 10 s.
- Over `kcp`, FEC 10 / 3: most lost packets are rebuilt within one KCP interval instead
  of lost.

Use it on both sides (FEC is decided by each sending side). See
[UDP forwarding and games](udp-and-games.md) for duplication and the measurements.

## Overriding

```toml
profile = "gaming"

[tunnel.mux]
stream_window = 262144            # a larger window than gaming's 64 KiB

[tunnel.kcp]
fec_data = 0                      # FEC off despite the gaming profile
fec_parity = 0

[tuning]
keepalive_secs = 20
```

`kariz check` prints the values in effect after the profile and the overrides.
