"""EVM-execution timings for EVM-dominated blocks and mixtures, from Nethermind's own benchmark tooling.

The suite does not reimplement EVM benchmarking. It imports block-processing times (`engine_newPayload`) produced by:

- NethermindEth/gas-benchmarks (`run.sh`): `results/nethermind_results_1_<test>.txt`, whose test names carry the block
  gas size as `benchmark_<N>M`. This is what Nethermind's `gas-benchmark` agent skill drives.
- Nethermind's expb workflow (`run-expb-reproducible-benchmarks.yml`): the per-payload table
  `| payload | gas_used | processing_ms |` in the `Run expb scenarios` step log.
- A CSV `name,gas_used,ms` from anything else.

`run_gas_benchmarks` runs gas-benchmarks locally on the calibration machine (docker, bash 4+, python3 and the
release's payload assets), so the EVM figures come from the same hardware as the proving figures.
"""

from __future__ import annotations

import csv
import glob
import os
import re
import subprocess

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_gas_benchmarks(results_dir: str) -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(results_dir, "nethermind_results_*.txt"))):
        name = os.path.basename(path)[len("nethermind_results_1_"):-len(".txt")]
        text = open(path, encoding="utf-8", errors="replace").read()
        m = re.search(r"(engine_newPayloadV\d+):", text)
        size = re.search(r"benchmark_(\d+(?:\.\d+)?)M", name)
        if not m or not size:
            continue
        after = text[m.end():]
        avg = re.search(r"Average:\s*([0-9.]+)", after)
        if not avg:
            continue
        out.append({"name": name, "gas_used": float(size.group(1)) * 1e6, "ms": float(avg.group(1)),
                    "source": f"gas-benchmarks {m.group(1)} average", "gas_exact": False})
    return out


def parse_expb_log(path: str) -> list[dict]:
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = ANSI.sub("", line)
        m = re.search(r"\|\s*([0-9A-Za-z_.-]+)\s*\|\s*([0-9][0-9,]*)\s*\|\s*([0-9.]+)\s*\|", line)
        if m and not m.group(1).startswith("payload"):
            out.append({"name": m.group(1), "gas_used": float(m.group(2).replace(",", "")), "ms": float(m.group(3)),
                        "source": "expb processing_ms", "gas_exact": True})
    return out


def parse_csv(path: str) -> list[dict]:
    with open(path, newline="") as f:
        return [{"name": r["name"], "gas_used": float(r["gas_used"]), "ms": float(r["ms"]), "source": "csv",
                 "gas_exact": True} for r in csv.DictReader(f)]


def load(spec: dict) -> list[dict]:
    """`spec`: {"format": "gas-benchmarks"|"expb"|"csv", "path": ..., "note": where and on what it was measured}."""
    fmt, path = spec["format"], spec["path"]
    parse = {"gas-benchmarks": parse_gas_benchmarks, "expb": parse_expb_log, "csv": parse_csv}.get(fmt)
    if parse is None:
        raise ValueError(f"unknown EVM timing format {fmt}")
    records = parse(path)
    if spec.get("note"):
        for r in records:
            r["source"] += f"; {spec['note']}"
    return records


def evm_time_ms(records: list[dict], gas: float, tolerance: float = 0.05) -> dict:
    """The worst EVM processing time for a block of `gas`: the slowest record within `tolerance` of that gas is a
    measurement; otherwise the slowest throughput record scaled linearly, labelled extrapolated."""
    if gas <= 0:
        return {"ms": 0.0, "label": "none"}
    if not records:
        return {"ms": None, "label": "unmeasured", "detail": "no EVM timings imported"}
    near = [r for r in records if abs(r["gas_used"] - gas) <= tolerance * gas]
    if near:
        worst = max(near, key=lambda r: r["ms"])
        return {"ms": worst["ms"], "label": "measured (imported)", "detail": f"{worst['name']} ({worst['source']})"}
    worst = max((r for r in records if r["gas_used"] > 0), key=lambda r: r["ms"] / r["gas_used"])
    return {"ms": worst["ms"] / worst["gas_used"] * gas, "label": "extrapolated (linear in gas)",
            "detail": f"{worst['name']}: {worst['ms']} ms at {worst['gas_used']:.0f} gas ({worst['source']})"}


def run_gas_benchmarks(repo: str, image: str, tests: str, gas_size_m: int, fork: str, network: str = "",
                       filt: str = "", runs: int = 1) -> str:
    """Runs NethermindEth/gas-benchmarks' `run.sh` for Nethermind at one gas size; returns its results directory."""
    effective = f"{filt} and benchmark_{gas_size_m}M" if filt else f"benchmark_{gas_size_m}M"
    cmd = ["bash", "run.sh", "-t", tests, "-c", "nethermind", "-i", f'{{"nethermind":"{image}"}}', "-f", effective,
           "-r", str(runs), "-K", fork]
    if network:
        cmd += ["-n", network]
    subprocess.run(cmd, cwd=repo, check=True)
    return os.path.join(repo, "results")
