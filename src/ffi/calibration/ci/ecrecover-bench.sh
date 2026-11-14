#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
#
# The gas anchor for native verification: Nethermind's ecrecover precompile (3,000 gas) per call on this machine,
# uncached (ecrecover/EcRecoverTime.cs, the anchor), and as its own BenchmarkDotNet benchmark reports it
# (Nethermind.Precompiles.Benchmark, which repeats one input and so times the precompile's last-input cache). Runs in
# a .NET SDK container that is removed afterwards (with its image, if this run pulled it).
#
#   ecrecover-bench.sh OUT [NETHERMIND_REF] [IMAGE]
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
ref=${2:-master}
image=${3:-mcr.microsoft.com/dotnet/sdk:10.0}
name="lean-calibration-ecrecover-$$"
pulled=
docker image inspect "$image" >/dev/null 2>&1 || pulled=1
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; [ -z "$pulled" ] || docker rmi "$image" >/dev/null 2>&1 || true' EXIT
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm --name "$name" --label lean-calibration=1 -v "$out":/out -v "$here/ecrecover":/harness:ro -e REF="$ref" -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" -e DOTNET_CLI_TELEMETRY_OPTOUT=1 "$image" bash -c '
    set -e
    git init -q /src && cd /src
    git remote add origin https://github.com/NethermindEth/nethermind.git
    git fetch -q --depth 1 origin "$REF" && git -c advice.detachedHead=false checkout -q FETCH_HEAD
    git rev-parse HEAD > /out/nethermind-revision.txt
    git submodule update -q --init --depth 1 src/bench_precompiles
    mkdir -p /src/ecrecover-time
    sed "s|NETHERMIND/|/src/|" /harness/EcRecoverTime.cs > /src/ecrecover-time/EcRecoverTime.cs
    (cd /src/ecrecover-time && dotnet run EcRecoverTime.cs) > /out/ecrecover-uncached.txt 2>&1 || rc=$?
    cd src/Nethermind
    dotnet run -c Release --project Nethermind.Benchmark.Runner -- \
      --filter "Nethermind.Precompiles.Benchmark.ECRecoverBenchmark*" > /out/ecrecover.txt 2>&1 || rc=$?
    cp -r BenchmarkDotNet.Artifacts /out/ 2>/dev/null || true
    chown -R "$HOST_UID:$HOST_GID" /out
    exit ${rc:-0}'
