#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
#
# One entry point for any runner: records the hardware, sizes the run to it and runs the calibration.
#
#   run-calibration.sh --scenarios smoke|reference|CONFIG.json --out DIR [--timeout-minutes N]
#                      [--workers W] [--threads T] [--memory-per-worker-gb M] [--docker IMAGE]
#
# `smoke` and `reference` are configs/smoke-m2max.json and configs/reference.example.json; a path selects any other.
# Workers default to local processes sized to the machine: T = min(11, cores), W = max(1, cores / T), memory per worker
# = 80% of available memory / W. With --docker (or without cargo), the run happens inside IMAGE (default
# rust:1.99.0-bookworm) with this checkout mounted, and the container is removed afterwards.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
scenarios=smoke out= timeout_min=170 workers= threads= mem= docker=
while [ $# -gt 0 ]; do
  case $1 in
    --scenarios) scenarios=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --timeout-minutes) timeout_min=$2; shift 2 ;;
    --workers) workers=$2; shift 2 ;;
    --threads) threads=$2; shift 2 ;;
    --memory-per-worker-gb) mem=$2; shift 2 ;;
    --docker) docker=${2:-rust:1.99.0-bookworm}; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$out" ] || { echo "--out is required" >&2; exit 2; }
mkdir -p "$out"
out=$(cd "$out" && pwd)

if [ -n "$docker" ] || ! command -v cargo >/dev/null; then
  image=${docker:-rust:1.99.0-bookworm}
  repo=$(cd "$here/../../.." && pwd)
  name="lean-calibration-$$"
  trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
  docker run --rm --name "$name" -v "$repo":/repo -v "$out":/out -w /repo/src/ffi/calibration \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$image" bash -c \
    "apt-get update -qq >/dev/null && apt-get install -y -qq python3 >/dev/null; \
     ci/run-calibration.sh --scenarios '$scenarios' --out /out --timeout-minutes $timeout_min \
       ${workers:+--workers $workers} ${threads:+--threads $threads} ${mem:+--memory-per-worker-gb $mem}; \
     rc=\$?; chown -R \$HOST_UID:\$HOST_GID /out /repo/src/ffi/target 2>/dev/null; exit \$rc"
  exit $?
fi

{
  echo "== date"; date -u; echo "== uname"; uname -a
  echo "== cpus"; (nproc 2>/dev/null || sysctl -n hw.ncpu)
  echo "== lscpu"; (lscpu 2>/dev/null || sysctl -n machdep.cpu.brand_string)
  echo "== memory"; (free -g 2>/dev/null || sysctl -n hw.memsize)
  echo "== load"; (cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg)
  echo "== rustc"; rustc -vV
  echo "== suite"; git -c safe.directory="$(cd "$here/../../.." && pwd)" -C "$here" rev-parse HEAD 2>/dev/null || true
} > "$out/host.txt" 2>&1
cat "$out/host.txt"

case $scenarios in
  smoke) config=$here/configs/smoke-m2max.json ;;
  reference) config=$here/configs/reference.example.json ;;
  *) config=$scenarios ;;
esac

cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
threads=${threads:-$(( cores < 11 ? cores : 11 ))}
workers=${workers:-$(( cores / threads > 0 ? cores / threads : 1 ))}
if [ -z "$mem" ]; then
  avail_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  [ "$avail_kb" -gt 0 ] && mem=$(( avail_kb * 8 / 10 / 1048576 / workers )) || mem=8
fi
echo "sized: $workers local workers x $threads threads, $mem GB each"

timeout --signal=TERM "$(( timeout_min * 60 ))" python3 "$here/calib.py" run --config "$config" --out "$out" \
  --set "workers={\"mode\":\"local\",\"count\":$workers,\"base_port\":47100}" --set "threads_per_worker=$threads" \
  --set "reference_workers=$workers" --set "memory_per_worker_gb=$mem"
