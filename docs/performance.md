# Performance

## Localhost

User → entry → exit → echo server, 256 MiB echoed, both sides and the echo server on one
4-core Xeon (2.1 GHz) VM. Everything shares the CPU, so this compares setups. A real
link between two servers is usually limited by the network first.

| Setup | Mbit/s each way |
|---|---|
| `tcp`, no encryption | 5,200-6,600 |
| `tcp`, AES-256-GCM | 3,800-4,000 |
| `tcp`, ChaCha20-Poly1305 | 2,100-2,800 |
| `tcpmux`, AES-256-GCM | 3,200-3,300 |
| `ws` + mux, AES-256-GCM | 2,800-3,100 |
| `wss` + mux, AES-256-GCM + TLS | 2,300-2,500 |

On a GitHub Actions runner (2 vCPU): `tcpmux` 2,960-3,420, `quic` 810-950, `kcp` 600-670
Mbit/s. QUIC and KCP handle every packet in user space.

UDP through `tcpmux` (8 clients, 32 packets in flight each): about 140,000 packets per
second each way. An idle tunnel adds about 90 µs to a UDP round trip.

Memory (RSS, static musl release build with mimalloc): about 8 MiB per side idle over
`tcpmux`. 100 idle user connections over mux add about 1 MiB; 1,000 idle UDP flows about
5-9 MiB. Without mimalloc (see below) an idle side takes about 6 MiB.

### The allocator

Release builds use [mimalloc](https://github.com/microsoft/mimalloc) as the global
allocator: musl's own is built for size, not speed, and the packet path allocates a lot.
Measured on GitHub Actions runners (2 vCPU), static musl builds, with and without it, 28
setups of the throughput benchmark, 3 alternating rounds each:

| | mimalloc | musl's allocator |
|---|---|---|
| Throughput, mean over the 28 setups | **+34 %** | |
| Throughput with mux, `wss`, `quic`, `kcp` | +25 to +100 % | |
| Throughput of plain `tcp` and `ws` without mux | within 12 % either way | |
| Memory, idle | 8.1 MiB | 6.0 MiB |
| Memory, 100 idle connections | +1 MiB | +1.7 to +5 MiB (varied) |
| Memory, 1,000 idle UDP flows | +6 to +9 MiB | +4 MiB |

mimalloc commits its first arena eagerly by default, which took an idle side to 15.6 MiB;
Kariz turns that off at startup (`MIMALLOC_ARENA_EAGER_COMMIT=0`, set in
`src/allocator.rs` unless the environment sets it), which is where the 8.1 MiB comes from.

For the least memory instead, build without it:

```bash
cargo build --release --no-default-features --features quic,kcp
```

## Over a lossy path

The tests carry a link emulator: delay, random or bursty loss, and a 50 Mbit/s
bottleneck with a 50 ms queue. Its TCP side models the sender's TCP, so loss slows
`tcpmux` as on a real path. At a 60 ms round trip, with loss in both directions:

| Transport | Download at 0 / 1 / 5 % loss |
|---|---|
| `tcpmux` | 48.1 / 2.3 / 0.9 Mbit/s |
| `quic` (Cubic) | 47.9 / 2.7 / 1.0 Mbit/s |
| `quic` (BBR) | 47.5 / 47.4 / 45.7 Mbit/s |
| `kcp` | 31.4 / 28.5 / 22.5 Mbit/s |
| `kcp`, FEC 10 / 3 | 25.4 / 26.1 / 26.6 Mbit/s |

- **Loss-based congestion control collapses under random loss**, TCP and QUIC Cubic
  alike. `quic` with BBR and `kcp` keep their speed.
- **BBR fills the path's queue.** During a download, about half of the UDP packets
  sharing its connection were lost, so Cubic stays the default.
- **KCP's default window (1024 packets) overfills small paths.** A window near
  bandwidth x RTT / 1300 packets queues less, but keeps less speed under loss.

## Tuning for speed

1. **Choose the transport for the path:** `tcp` / `tcpmux` on clean paths, `kcp` or
   `quic` with BBR on lossy ones ([Transports](transports.md)).
2. **Use `profile = "ultraspeed"`,** or raise `tunnel.mux.stream_window`. One stream
   moves at most one window per round trip, so a stream needs about bandwidth x RTT
   (100 Mbit/s at 100 ms: 1.25 MB).
3. **Leave `encryption = "auto"`.** It picks AES-256-GCM on CPUs with AES instructions,
   the fastest cipher there. `none` is faster still but only authenticates.
4. **Add connections for many parallel users:** `tunnel.mux.connections` spreads streams
   over more TCP connections, each with its own congestion window.
5. **For many connections,** raise the open-file limit (the systemd unit sets
   `LimitNOFILE=1048576`).


## 2.10.0 before and after

The matrix below is 2.9.3 (`before`) against 2.10.0 (`after`) on the same 4-CPU container,
over the emulated paths of `tests/link`, so the numbers compare the two builds, not a real
line: one download stream, eight streams, and a 1200-byte UDP flow at 4000 packets a second
(38 Mbit/s) with its delay percentiles and delivered share. Each cell is ten seconds of a
single run.

How to read it. On the localhost rows, differences under about 10 % are noise. The `wan40`
and `rate50` rows are bound by the profile's window, the round trip and the 50 Mbit/s cap, so
their stream columns cannot move much; what moves there is the UDP delay. On the
`wan40-loss1` and `wan100-jitter` rows of `tcpmux`, `wss` and `quic` the UDP flow is far more
than the path carries, so the delay and delivered columns measure an overflowing queue and
swing by half or more from one run to the next, in either direction; their stream columns
depend on where the random losses fall and swing too. Only KCP, which drops instead of
queueing and rebuilds losses with FEC, gives steady numbers on those paths, and it is the
transport to use on them.

What 2.10.0 changed is the batching of datagrams on the UDP and KCP paths, the copies taken
out of the way, KCP's send window following the path (never below the profile's window), and
the larger QUIC send window of the ultraspeed profile. It shows where the CPU or the window
was the limit: the localhost rows gain up to 45 % on one stream and up to double on eight
(KCP balanced 1276 → 2494 Mbit/s, QUIC gaming 1339 → 2627), the UDP p99 on the `wan40` rows
drops by 10–35 % for the TCP-based transports and QUIC, KCP ultraspeed gains 10–16 % with
eight streams on the 40 ms and jittery paths and its p99 on the jittery path halves
(219 → 110 ms), and QUIC ultraspeed with eight streams on the 40 ms path gains 55 % from its
window. The WAN single-stream rows stay where their window puts them.

| transport, profile, path | 1 stream Mbit/s | 8 streams Mbit/s | UDP p50 ms | UDP p99 ms | UDP delivered % |
|---|---:|---:|---:|---:|---:|
| tcpmux balanced local | 3706.9 → 4412.9 (+19%) | 7835.5 → 8813.7 (+12%) | 0.4 → 0.4 (+0%) | 5.2 → 1.7 (-67%) | 100.00 → 100.00 (+0%) |
| tcpmux balanced wan40 | 48.2 → 49.1 (+2%) | 370.8 → 376.1 (+1%) | 41.6 → 41.4 (-0%) | 79.0 → 64.1 (-19%) | 99.80 → 98.65 (-1%) |
| tcpmux balanced wan40-loss1 | 4.3 → 3.4 (-21%) | 12.4 → 14.2 (+15%) | 1828.5 → 3259.8 (+78%) | 2470.7 → 4540.3 (+84%) | 9.36 → 9.40 (+0%) |
| tcpmux balanced wan100-jitter | 3.9 → 3.1 (-21%) | 19.6 → 18.3 (-7%) | 2315.4 → 1524.7 (-34%) | 3317.8 → 2322.3 (-30%) | 8.73 → 7.66 (-12%) |
| tcpmux balanced rate50 | 32.6 → 32.6 (+0%) | 46.8 → 47.5 (+1%) | 44.9 → 44.5 (-1%) | 147.2 → 208.1 (+41%) | 99.92 → 100.00 (+0%) |
| tcpmux ultraspeed local | 4765.7 → 5171.2 (+9%) | 8867.1 → 9356.4 (+6%) | 0.4 → 0.3 (-25%) | 2.8 → 2.9 (+4%) | 100.00 → 100.00 (+0%) |
| tcpmux ultraspeed wan40 | 189.3 → 182.9 (-3%) | 1487.1 → 1390.1 (-7%) | 41.7 → 41.5 (-0%) | 82.9 → 58.8 (-29%) | 100.00 → 100.00 (+0%) |
| tcpmux ultraspeed wan40-loss1 | 3.5 → 3.4 (-3%) | 29.0 → 28.9 (-0%) | 3036.8 → 4612.3 (+52%) | 3756.7 → 5800.4 (+54%) | 12.19 → 9.85 (-19%) |
| tcpmux ultraspeed wan100-jitter | 5.1 → 4.9 (-4%) | 37.2 → 32.6 (-12%) | 3760.3 → 4952.3 (+32%) | 5833.8 → 9642.6 (+65%) | 7.74 → 7.96 (+3%) |
| tcpmux ultraspeed rate50 | 48.1 → 47.8 (-1%) | 48.1 → 48.1 (+0%) | 526.3 → 355.4 (-32%) | 1082.4 → 1125.6 (+4%) | 46.20 → 67.14 (+45%) |
| tcpmux gaming local | 2691.5 → 2872.1 (+7%) | 5433.6 → 6884.3 (+27%) | 0.5 → 0.3 (-40%) | 3.5 → 1.4 (-60%) | 99.08 → 100.00 (+1%) |
| tcpmux gaming wan40 | 10.1 → 10.1 (+0%) | 82.3 → 83.2 (+1%) | 41.7 → 41.4 (-1%) | 71.0 → 49.4 (-30%) | 99.38 → 99.82 (+0%) |
| tcpmux gaming wan40-loss1 | 3.1 → 3.9 (+26%) | 8.7 → 7.2 (-17%) | 961.9 → 1815.4 (+89%) | 1439.3 → 2782.4 (+93%) | 10.04 → 9.94 (-1%) |
| tcpmux gaming wan100-jitter | 3.5 → 3.8 (+9%) | 10.0 → 8.4 (-16%) | 2717.1 → 2050.8 (-25%) | 3409.0 → 2468.1 (-28%) | 13.29 → 7.73 (-42%) |
| tcpmux gaming rate50 | 10.8 → 11.0 (+2%) | 47.9 → 47.9 (+0%) | 43.7 → 43.5 (-0%) | 83.9 → 64.1 (-24%) | 100.00 → 100.00 (+0%) |
| wss balanced local | 2516.5 → 3043.1 (+21%) | 5921.0 → 6340.8 (+7%) | 0.4 → 0.4 (+0%) | 1.6 → 1.5 (-6%) | 100.00 → 100.00 (+0%) |
| wss balanced wan40 | 43.7 → 48.0 (+10%) | 373.8 → 374.3 (+0%) | 41.8 → 41.6 (-0%) | 62.1 → 44.8 (-28%) | 100.00 → 100.00 (+0%) |
| wss balanced wan40-loss1 | 3.0 → 3.3 (+10%) | 14.4 → 13.8 (-4%) | 3145.7 → 2425.0 (-23%) | 3952.4 → 3505.7 (-11%) | 10.02 → 8.45 (-16%) |
| wss balanced wan100-jitter | 7.4 → 3.1 (-58%) | 18.1 → 17.4 (-4%) | 3343.5 → 2726.7 (-18%) | 4364.6 → 4792.6 (+10%) | 8.11 → 7.53 (-7%) |
| wss balanced rate50 | 32.6 → 32.6 (+0%) | 46.3 → 47.0 (+2%) | 44.9 → 44.6 (-1%) | 176.4 → 163.1 (-8%) | 100.00 → 100.00 (+0%) |
| wss ultraspeed local | 2942.5 → 3757.2 (+28%) | 6571.1 → 7169.2 (+9%) | 0.5 → 0.4 (-20%) | 2.0 → 2.1 (+5%) | 100.00 → 100.00 (+0%) |
| wss ultraspeed wan40 | 181.2 → 187.1 (+3%) | 1451.0 → 1479.1 (+2%) | 41.7 → 41.5 (-0%) | 95.0 → 60.8 (-36%) | 100.00 → 100.00 (+0%) |
| wss ultraspeed wan40-loss1 | 4.2 → 3.6 (-14%) | 27.7 → 28.6 (+3%) | 4042.4 → 3702.8 (-8%) | 6142.9 → 4494.1 (-27%) | 9.69 → 9.76 (+1%) |
| wss ultraspeed wan100-jitter | 5.2 → 5.6 (+8%) | 40.9 → 28.7 (-30%) | 3897.7 → 6342.0 (+63%) | 6258.4 → 7257.7 (+16%) | 9.46 → 8.65 (-9%) |
| wss ultraspeed rate50 | 47.4 → 47.8 (+1%) | 47.9 → 48.0 (+0%) | 401.9 → 99.8 (-75%) | 649.4 → 414.8 (-36%) | 65.49 → 100.00 (+53%) |
| wss gaming local | 1668.6 → 2057.1 (+23%) | 3433.3 → 4951.1 (+44%) | 0.4 → 0.4 (+0%) | 1.7 → 2.4 (+41%) | 100.00 → 100.00 (+0%) |
| wss gaming wan40 | 10.1 → 10.0 (-1%) | 82.8 → 84.8 (+2%) | 41.9 → 41.6 (-1%) | 50.6 → 43.6 (-14%) | 99.94 → 100.00 (+0%) |
| wss gaming wan40-loss1 | 4.2 → 3.8 (-10%) | 6.2 → 7.2 (+16%) | 1114.8 → 2387.7 (+114%) | 1589.6 → 3313.4 (+108%) | 9.18 → 10.22 (+11%) |
| wss gaming wan100-jitter | 3.6 → 2.8 (-22%) | 8.8 → 8.7 (-1%) | 1113.8 → 1806.0 (+62%) | 1411.6 → 2282.3 (+62%) | 6.27 → 6.31 (+1%) |
| wss gaming rate50 | 10.9 → 10.9 (+0%) | 47.7 → 47.7 (+0%) | 44.0 → 43.6 (-1%) | 76.7 → 66.6 (-13%) | 99.33 → 99.94 (+1%) |
| kcp balanced local | 800.1 → 745.4 (-7%) | 1275.6 → 2494.4 (+96%) | 0.4 → 0.5 (+25%) | 2.8 → 2.8 (+0%) | 100.00 → 100.00 (+0%) |
| kcp balanced wan40 | 46.1 → 46.6 (+1%) | 337.9 → 341.4 (+1%) | 42.9 → 42.8 (-0%) | 48.6 → 49.8 (+2%) | 100.00 → 99.77 (-0%) |
| kcp balanced wan40-loss1 | 19.7 → 21.6 (+10%) | 134.9 → 142.6 (+6%) | 42.9 → 42.9 (+0%) | 46.4 → 46.7 (+1%) | 97.96 → 98.15 (+0%) |
| kcp balanced wan100-jitter | 13.6 → 13.0 (-4%) | 82.6 → 88.3 (+7%) | 105.6 → 105.4 (-0%) | 116.5 → 108.8 (-7%) | 98.54 → 99.27 (+1%) |
| kcp balanced rate50 | 32.2 → 32.1 (-0%) | 38.9 → 41.6 (+7%) | 44.2 → 43.9 (-1%) | 90.8 → 91.1 (+0%) | 99.86 → 99.88 (+0%) |
| kcp ultraspeed local | 621.4 → 907.9 (+46%) | 2014.1 → 2694.0 (+34%) | 0.5 → 0.4 (-20%) | 2.8 → 1.9 (-32%) | 100.00 → 100.00 (+0%) |
| kcp ultraspeed wan40 | 156.0 → 160.9 (+3%) | 777.4 → 855.1 (+10%) | 43.0 → 42.7 (-1%) | 64.5 → 45.3 (-30%) | 99.92 → 100.00 (+0%) |
| kcp ultraspeed wan40-loss1 | 72.0 → 71.8 (-0%) | 470.6 → 499.8 (+6%) | 43.0 → 42.8 (-0%) | 55.2 → 47.1 (-15%) | 98.11 → 98.06 (-0%) |
| kcp ultraspeed wan100-jitter | 34.5 → 37.8 (+10%) | 254.3 → 294.8 (+16%) | 105.9 → 105.5 (-0%) | 218.7 → 109.8 (-50%) | 99.46 → 99.38 (-0%) |
| kcp ultraspeed rate50 | 29.6 → 29.5 (-0%) | 39.6 → 42.5 (+7%) | 44.4 → 44.1 (-1%) | 93.5 → 92.3 (-1%) | 99.46 → 99.50 (+0%) |
| kcp gaming local | 379.5 → 522.8 (+38%) | 1519.0 → 1869.0 (+23%) | 0.5 → 0.5 (+0%) | 2.0 → 3.0 (+50%) | 100.00 → 100.00 (+0%) |
| kcp gaming wan40 | 11.8 → 10.3 (-13%) | 92.6 → 90.5 (-2%) | 42.9 → 42.9 (+0%) | 46.3 → 45.7 (-1%) | 100.00 → 100.00 (+0%) |
| kcp gaming wan40-loss1 | 10.3 → 10.7 (+4%) | 87.4 → 87.5 (+0%) | 43.0 → 43.0 (+0%) | 46.3 → 46.4 (+0%) | 100.00 → 99.87 (-0%) |
| kcp gaming wan100-jitter | 4.4 → 4.6 (+5%) | 36.8 → 38.4 (+4%) | 105.9 → 105.7 (-0%) | 116.5 → 110.9 (-5%) | 99.64 → 99.09 (-1%) |
| kcp gaming rate50 | 10.6 → 10.6 (+0%) | 26.7 → 26.5 (-1%) | 141.3 → 141.1 (-0%) | 145.2 → 144.5 (-0%) | 98.97 → 98.80 (-0%) |
| quic balanced local | 1037.5 → 1179.8 (+14%) | 2642.5 → 2895.7 (+10%) | 0.5 → 0.5 (+0%) | 2.7 → 2.3 (-15%) | 100.00 → 100.00 (+0%) |
| quic balanced wan40 | 47.0 → 47.4 (+1%) | 369.8 → 369.6 (-0%) | 42.9 → 42.7 (-0%) | 94.1 → 85.8 (-9%) | 97.85 → 99.12 (+1%) |
| quic balanced wan40-loss1 | 3.2 → 3.5 (+9%) | 6.6 → 5.9 (-11%) | 572.0 → 372.9 (-35%) | 1264.0 → 1163.2 (-8%) | 9.56 → 6.96 (-27%) |
| quic balanced wan100-jitter | 3.7 → 3.4 (-8%) | 6.5 → 7.0 (+8%) | 229.2 → 893.1 (+290%) | 1141.7 → 1513.7 (+33%) | 7.88 → 6.35 (-19%) |
| quic balanced rate50 | 43.3 → 43.3 (+0%) | 47.3 → 47.9 (+1%) | 44.2 → 44.0 (-0%) | 95.5 → 94.3 (-1%) | 97.47 → 98.67 (+1%) |
| quic ultraspeed local | 1189.5 → 1316.8 (+11%) | 2378.1 → 2749.0 (+16%) | 0.5 → 0.4 (-20%) | 3.7 → 2.2 (-41%) | 100.00 → 100.00 (+0%) |
| quic ultraspeed wan40 | 180.3 → 183.8 (+2%) | 740.4 → 1144.4 (+55%) | 43.1 → 42.8 (-1%) | 190.8 → 163.4 (-14%) | 100.00 → 100.00 (+0%) |
| quic ultraspeed wan40-loss1 | 3.4 → 3.7 (+9%) | 6.6 → 6.0 (-9%) | 1976.8 → 1465.7 (-26%) | 2360.7 → 3244.5 (+37%) | 10.16 → 8.62 (-15%) |
| quic ultraspeed wan100-jitter | 4.6 → 4.2 (-9%) | 7.8 → 5.6 (-28%) | 2057.1 → 1849.9 (-10%) | 2569.3 → 3619.2 (+41%) | 9.88 → 9.46 (-4%) |
| quic ultraspeed rate50 | 47.9 → 47.9 (+0%) | 48.0 → 47.9 (-0%) | 44.7 → 44.3 (-1%) | 277.6 → 289.2 (+4%) | 97.94 → 99.14 (+1%) |
| quic gaming local | 1030.0 → 1066.0 (+3%) | 1338.9 → 2627.0 (+96%) | 0.4 → 0.4 (+0%) | 1.8 → 1.5 (-17%) | 100.00 → 100.00 (+0%) |
| quic gaming wan40 | 12.0 → 12.0 (+0%) | 91.3 → 95.1 (+4%) | 43.3 → 42.8 (-1%) | 88.6 → 58.5 (-34%) | 95.47 → 98.80 (+3%) |
| quic gaming wan40-loss1 | 2.8 → 3.1 (+11%) | 6.8 → 6.1 (-10%) | 280.5 → 184.7 (-34%) | 608.1 → 452.5 (-26%) | 8.07 → 7.01 (-13%) |
| quic gaming wan100-jitter | 2.6 → 2.4 (-8%) | 7.7 → 5.8 (-25%) | 458.5 → 403.7 (-12%) | 1186.3 → 584.2 (-51%) | 6.13 → 7.08 (+15%) |
| quic gaming rate50 | 11.6 → 11.5 (-1%) | 47.7 → 47.7 (+0%) | 44.1 → 43.9 (-0%) | 68.6 → 65.6 (-4%) | 96.99 → 98.52 (+2%) |

## Running the benchmarks

```bash
scripts/bench.sh run before                                                # the matrix
cargo test --release --test tunnel throughput -- --ignored --nocapture     # localhost
cargo test --release --test tunnel udp_ -- --ignored --nocapture           # UDP rates
cargo test --release --test tunnel lossy_link -- --ignored --nocapture     # lossy path
cargo test --release --test tunnel game_traffic -- --ignored --nocapture   # games, ~45 min
scripts/rss.sh tcpmux 100                                                  # memory
```

`KARIZ_BENCH_ONLY=kcp` limits `lossy_link` and `game_traffic` to rows whose name
contains `kcp`. `KARIZ_BENCH_LOSS=1` runs one loss rate.

**The matrix** (`bench_matrix`, run by `scripts/bench.sh`) is the one to compare two builds
with: four transports (`tcpmux`, `wss`, `kcp`, `quic`) × the three profiles × five paths
(localhost; 40 ms RTT; 40 ms with 1 % loss; 100 ms with 2 ms jitter and 0.3 % loss; 40 ms at
50 Mbit/s with a 50 ms queue), each measured with a one-stream download, an eight-stream
download and a UDP flow of 1200-byte packets at 4000 a second (echoed, so the table has its
round trips and delivery). `scripts/bench.sh run <label>` writes `target/bench/<label>.md`;
`scripts/bench.sh compare before after` prints the two side by side with the change.
`KARIZ_BENCH_ONLY=kcp,quic` keeps the rows whose name contains one of the parts
(`KARIZ_BENCH_ONLY="=kcp balanced local"` one exact row), `KARIZ_BENCH_SECS=5` shortens each
measurement (default 10 s; the whole matrix takes about 40 minutes at 10 s). The paths are
the userspace emulator in `tests/link`, so the numbers compare builds on one machine; they do
not predict a real path.
