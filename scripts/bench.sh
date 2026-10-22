#!/usr/bin/env bash
# The benchmark matrix (tests/tunnel.rs `bench_matrix`), kept as a markdown table so two
# builds can be compared:
#
#   scripts/bench.sh run <label>           # writes target/bench/<label>.md
#   scripts/bench.sh compare <a> <b>       # the two tables side by side, with the change
#
# `run` passes the environment through: KARIZ_BENCH_ONLY=kcp,quic (rows to run),
# KARIZ_BENCH_SECS=5 (seconds per measurement, default 10), KARIZ_BENCH_SEED, CARGO_TARGET_DIR.
# The tables are emulated-link numbers (tests/link): they compare builds on one machine, they
# do not predict a real path.
set -euo pipefail
cd "$(dirname "$0")/.."

case ${1:-} in
    run)
        label=${2:?usage: scripts/bench.sh run <label>}
        mkdir -p target/bench
        KARIZ_BENCH_OUT="$PWD/target/bench/$label.md" \
            cargo test --release --test tunnel bench_matrix -- --ignored --nocapture --exact
        echo "wrote target/bench/$label.md"
        ;;
    compare)
        a=${2:?usage: scripts/bench.sh compare <a> <b>}
        b=${3:?usage: scripts/bench.sh compare <a> <b>}
        for f in "$a" "$b"; do
            [[ -f "$f" ]] || f="target/bench/$f.md"
            [[ -f "$f" ]] || { echo "no table at $f" >&2; exit 1; }
        done
        [[ -f "$a" ]] || a="target/bench/$a.md"
        [[ -f "$b" ]] || b="target/bench/$b.md"
        python3 - "$a" "$b" <<'PY'
import sys

def table(path):
    rows = {}
    for line in open(path, encoding="utf-8"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 6 or cells[0] in ("transport profile path", "---") or cells[0].startswith("-"):
            continue
        rows[cells[0]] = cells[1:]
    return rows

def num(s):
    try:
        return float(s)
    except ValueError:
        return None

a, b = table(sys.argv[1]), table(sys.argv[2])
cols = ["1 stream Mbit/s", "8 streams Mbit/s", "UDP p50 ms", "UDP p99 ms", "UDP delivered %"]
print("| row | " + " | ".join(f"{c} ({sys.argv[1]} -> {sys.argv[2]})" for c in cols) + " |")
print("|---|" + "---:|" * len(cols))
for key in a:
    if key not in b:
        continue
    cells = []
    for x, y in zip(a[key], b[key]):
        fx, fy = num(x), num(y)
        if fx is None or fy is None or fx == 0:
            cells.append(f"{x} -> {y}")
        else:
            cells.append(f"{x} -> {y} ({(fy - fx) / fx * 100:+.0f} %)")
    print(f"| {key} | " + " | ".join(cells) + " |")
for key in b:
    if key not in a:
        print(f"| {key} | only in {sys.argv[2]}: " + " | ".join(b[key]) + " |")
PY
        ;;
    *)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
