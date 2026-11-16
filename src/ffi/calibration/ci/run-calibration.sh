#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
#
# One entry point for any runner: records the hardware, sizes the run to it and runs the calibration.
#
#   run-calibration.sh --scenarios NAME[,NAME...] --out DIR [--timeout-minutes N] [--arch amd64|arm64]
#                      [--lean-bindings-ref REF] [--yield-to-manual-runs OWNER/REPO --runner-label LABEL]
#                      [--workers W] [--threads T] [--memory-per-worker-gb M] [--docker IMAGE]
#
# A NAME is `smoke` (configs/smoke-m2max.json), `reference` (configs/reference.example.json), another config's
# name under configs/ (e.g. `box-committed`, `gcp-flat`), or a path to a .json config. Several scenarios run in order, each into DIR/NAME, and
# share the timeout: each gets the remaining time divided by the scenarios left. Workers default to local processes
# sized to the machine: a config's `local_workers` (default max(1, cores / min(11, cores))), T = cores / W, memory per
# worker = 80% of available memory / W. With --docker (or without cargo), the run happens inside IMAGE (default
# rust:1.99.0-bookworm) with this checkout mounted, and the container is removed afterwards.
#
# --arch refuses to run on another architecture. --yield-to-manual-runs exits 0 without running when a manual
# (workflow_dispatch) run of the repository's benchmark workflows is waiting for, or running on, LABEL; it reads
# GH_TOKEN. --leanvm-revs REV[,REV] first runs upstream leanVM's README benchmarks at each revision
# (ci/leanvm-readme-bench.sh). It refuses (exit 4) with less than --min-free-gb (default 20) free for the output or docker's images, and
# removes an image it pulled. --lean-bindings-ref is recorded with the hardware; the caller checks that revision out.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
scenarios=smoke out= timeout_min=170 workers= threads= mem= docker= arch= lb_ref= yield_repo= runner_label= min_free_gb=20 leanvm_revs=
while [ $# -gt 0 ]; do
  case $1 in
    --scenarios) scenarios=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --timeout-minutes) timeout_min=$2; shift 2 ;;
    --arch) arch=$2; shift 2 ;;
    --lean-bindings-ref) lb_ref=$2; shift 2 ;;
    --yield-to-manual-runs) yield_repo=$2; shift 2 ;;
    --runner-label) runner_label=$2; shift 2 ;;
    --min-free-gb) min_free_gb=$2; shift 2 ;;
    --leanvm-revs) leanvm_revs=$2; shift 2 ;;
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

if [ -n "$arch" ]; then
  case $(uname -m) in x86_64|amd64) here_arch=amd64 ;; aarch64|arm64) here_arch=arm64 ;; *) here_arch=$(uname -m) ;; esac
  [ "$here_arch" = "$arch" ] || { echo "expected $arch, running on $here_arch" >&2; exit 3; }
fi

if [ -n "$yield_repo" ]; then
  if ! python3 "$here/ci/manual_runs.py" "$yield_repo" "${runner_label:?--runner-label is required}"; then
    echo "a manual benchmark run is waiting for or using $runner_label: yielding without running"
    exit 0
  fi
fi

{ uname -a; nproc 2>/dev/null; lscpu 2>/dev/null; free -g 2>/dev/null; df -h "$out"; } > "$out/machine.txt" 2>&1 || true

free_gb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print int($4 / 1048576)}'; }
need_free() {
  local f; f=$(free_gb "$1")
  [ -z "$f" ] || [ "$f" -ge "$min_free_gb" ] || { echo "only $f GB free on $1 ($2); need $min_free_gb" >&2; exit 4; }
}
need_free "$out" "output, builds and caches"

if [ -n "$docker" ] || ! command -v cargo >/dev/null; then
  image=${docker:-rust:1.99.0-bookworm}
  repo=$(cd "$here/../../.." && pwd)
  name="lean-calibration-$$"
  need_free "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)" "docker images"
  # An image this run pulls is removed again, so the machine keeps only what it had.
  pulled=
  docker image inspect "$image" >/dev/null 2>&1 || pulled=1
  trap 'docker rm -f "$name" >/dev/null 2>&1 || true; [ -z "$pulled" ] || docker rmi "$image" >/dev/null 2>&1 || true' EXIT
  # The library and cargo caches live under the mounted output so nothing outlives the caller's directory.
  docker run --rm --name "$name" --label lean-calibration=1 -v "$repo":/repo -v "$out":/out \
    -w /repo/src/ffi/calibration -e HOME=/out/.home -e CARGO_HOME=/usr/local/cargo \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" "$image" bash -c \
    "apt-get update -qq >/dev/null && apt-get install -y -qq python3 procps sysbench >/dev/null; \
     ci/run-calibration.sh --scenarios '$scenarios' --out /out --timeout-minutes $timeout_min \
       ${lb_ref:+--lean-bindings-ref '$lb_ref'} ${leanvm_revs:+--leanvm-revs '$leanvm_revs'} \
       ${workers:+--workers $workers} ${threads:+--threads $threads} ${mem:+--memory-per-worker-gb $mem}; \
     rc=\$?; chown -R \$HOST_UID:\$HOST_GID /out /repo/src/ffi/target 2>/dev/null; exit \$rc" && rc=0 || rc=$?
  exit $rc
fi

{
  echo "== date"; date -u; echo "== uname"; uname -a
  echo "== cpus"; (nproc 2>/dev/null || sysctl -n hw.ncpu)
  echo "== lscpu"; (lscpu 2>/dev/null || sysctl -n machdep.cpu.brand_string)
  echo "== memory"; (free -g 2>/dev/null || sysctl -n hw.memsize)
  echo "== load"; (cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg)
  echo "== rustc"; rustc -vV
  echo "== suite"; git -c safe.directory="$(cd "$here/../../.." && pwd)" -C "$here" rev-parse HEAD 2>/dev/null || true
  echo "== lean-bindings ref"; echo "${lb_ref:-unspecified}"
} > "$out/host.txt" 2>&1
cat "$out/host.txt"

if [ -n "$leanvm_revs" ]; then
  # shellcheck disable=SC2086
  "$here/ci/leanvm-readme-bench.sh" "$out" ${leanvm_revs//,/ } || echo "leanVM README benchmarks failed" >&2
fi

cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
deadline=$(( $(date +%s) + timeout_min * 60 ))
IFS=, read -r -a names <<< "$scenarios"
rc=0
for i in "${!names[@]}"; do
  name=${names[$i]}
  case $name in
    smoke) config=$here/configs/smoke-m2max.json ;;
    reference) config=$here/configs/reference.example.json ;;
    *.json) config=$name; name=$(basename "$name" .json) ;;
    *) config=$here/configs/$name.json ;;
  esac
  left=$(( (deadline - $(date +%s)) / (${#names[@]} - i) ))
  [ "$left" -gt 60 ] || { echo "no time left for $name" >&2; rc=124; continue; }
  w=${workers:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("local_workers", 0))' "$config")}
  [ "$w" -gt 0 ] || { t=$(( cores < 11 ? cores : 11 )); w=$(( cores / t > 0 ? cores / t : 1 )); }
  t=${threads:-$(( cores / w > 0 ? cores / w : 1 ))}
  m=$mem
  if [ -z "$m" ]; then
    avail_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    [ "$avail_kb" -gt 0 ] && m=$(( avail_kb * 8 / 10 / 1048576 / w )) || m=8
  fi
  echo "== $name: $w local workers x $t threads, $m GB each, $(( left / 60 )) min"
  mkdir -p "$out/$name"
  # A config with a `mode` runs one measurement set instead of the calibration: `worst` (calib/worst.py) or
  # `pq-leaves` (calib/pq_leaves.py), each on one process at a time with every thread.
  mode=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("mode", ""))' "$config")
  if [ -n "$mode" ]; then
    timeout --signal=TERM "$left" python3 "$here/calib.py" "$mode" --config "$config" --out "$out/$name" \
      --set "threads_per_worker=$cores" --set "threads=$cores" || rc=$?
    continue
  fi
  timeout --signal=TERM "$left" python3 "$here/calib.py" run --config "$config" --out "$out/$name" \
    --set "workers={\"mode\":\"local\",\"count\":$w,\"base_port\":47100}" --set "threads_per_worker=$t" \
    --set "reference_workers=$w" --set "memory_per_worker_gb=$m" || rc=$?
  pkill -f "$out/$name/bin/" 2>/dev/null || true
done
exit $rc
