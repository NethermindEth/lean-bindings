"""Native (host, non-recursive) verification as a mempool node runs it, to price per-dependency mempool work.

Per leanSPHINCS signature; direct leanSTARK leaves (a small program, the largest this machine can prove, and an
ordinary 256-claim leaf), each verification-only and with the aggregation guest's hints; and mode-1 aggregates of
growing size, for the per-dependency amortisation. Each on one thread and on every thread, the
median of `reps` timed runs after a warm-up, behind the quiet-machine gate. The largest leaf's trace is sized to this
machine's memory (native verification depends only weakly on it) and stepped down to the verifier's bound.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from . import build as builder
from . import host
from .pipeline import TRACE_STEP, iters_for_trace, preflight
from .runner import Runner, result_line

SMALL_CODE_LOG, SMALL_TRACE_LOG, SIGS, SMALL_LEAVES = 7, 18, 256, 16
BLOCK_LEAVES, BLOCK_GROUP = 64, 16


def cpu_score(log) -> dict:
    """A reproducible CPU score to place this machine against EIP-7870's PassMark ratings: sysbench's prime test,
    events per second on one thread and on every thread. PassMark PerformanceTest is not used: its download refuses
    automated clients."""
    out = {"method": "sysbench cpu --cpu-max-prime=20000 --time=15, events/s"}
    for name, threads in (("single_thread", 1), ("multi_thread", os.cpu_count() or 1)):
        p = subprocess.run(["sysbench", "cpu", "--cpu-max-prime=20000", "--time=15", f"--threads={threads}", "run"],
                           capture_output=True, text=True)
        m = re.search(r"events per second:\s*([\d.]+)", p.stdout)
        out[name] = float(m.group(1)) if m else None
    log(f"cpu score: {out}")
    return out


def run(cfg: dict, out: str, log) -> dict:
    os.makedirs(out, exist_ok=True)
    res = {"host": host.record(), "config": cfg, "notes": []}
    path = os.path.join(out, "native.json")

    def save():
        json.dump(res, open(path, "w"), indent=1, default=str)

    b = builder.build(cfg["lib_ref"], out, log=log)
    res["build"] = b
    runner = Runner(out, cfg, log)
    rate, bounds = cfg["bounds"]["inner_log_inv_rate"], cfg["bounds"]
    sizing = preflight({**cfg, "workers": {"mode": "local", "count": 1},
                        "memory_per_worker_gb": host.memory()["available"] / 2**30}, host.memory())
    trace_log = sizing["trace_log_used"]
    res["notes"] += sizing["notes"]

    def biggest(claims: int, seed: int) -> str:
        nonlocal trace_log
        while True:
            try:
                p, meta = runner.leaf(b, bounds["code_log"], iters_for_trace(trace_log), rate, claims, seed)
                res.setdefault("leaves", {})[os.path.basename(p)] = meta
                return p
            except RuntimeError as e:
                # Past the verifier's committed-witness bound, or killed for memory: a smaller trace.
                oom = "failed (-9)" in str(e) or "failed (137)" in str(e)
                if not ("WitnessOutOfRange" in str(e) or oom) or trace_log <= 16:
                    raise
                trace_log = round(trace_log - (0.5 if oom else TRACE_STEP), 2)
                res["notes"].append(f"largest leaf lowered to 2^{trace_log:g} ({'memory' if oom else 'verifier bound'})")

    sigs = runner.sigs(b, SIGS)
    smalls = []
    for i in range(SMALL_LEAVES):
        p, meta = runner.leaf(b, SMALL_CODE_LOG, iters_for_trace(SMALL_TRACE_LOG), rate, 1, 7100 + i)
        res.setdefault("leaves", {})[os.path.basename(p)] = meta
        smalls.append(p)
    largest = biggest(1, 7001)
    # An ordinary multi-claim leaf (no payment binding): its proof's statement is the claims' batch hash.
    multi = biggest(bounds["claims"], 7002) if "batch" in b["features"] else largest
    res["trace_log_used"] = trace_log
    save()
    # The worst valid block: MAX_DEPS_PER_BLOCK = 16,384 dependencies, 64 leaves x (255 claims + their payment) in four
    # groups of 16, finalized; and a one-leaf block (one claim and its payment). Leaves of a small inner trace: the
    # block proof's verification does not depend on the leaves' size.
    blocks = []
    if "batch" in b["features"]:
        claims = bounds["claims"]
        wide = [runner.leaf(b, SMALL_CODE_LOG, iters_for_trace(SMALL_TRACE_LOG), rate, claims, 7200 + i)[0]
                for i in range(BLOCK_LEAVES)]
        blocks = [("1", "1", wide[:1]), (str(claims - 1), str(BLOCK_GROUP), wide)]
    res["cpu_score"] = cpu_score(log)
    save()
    for threads in sorted({1, os.cpu_count() or 1}):
        g = runner.gate()
        p = subprocess.run([os.path.join(b["bin"], "calib-node"), "native", str(cfg.get("reps", 5)), sigs, str(SIGS),
                            smalls[0], largest, multi, *smalls[1:]], capture_output=True, text=True,
                           env=runner.env(threads))
        r = result_line(p.stdout) or {"status": "failed", "error": p.stderr[-2000:]}
        for retain, group, leaves in blocks:
            q = subprocess.run([os.path.join(b["bin"], "calib-node"), "native-block", str(cfg.get("reps", 5)), retain, group,
                                *leaves], capture_output=True, text=True, env=runner.env(threads))
            rb = result_line(q.stdout) or {"status": "failed", "error": q.stderr[-2000:]}
            r.setdefault("items", []).extend(rb.get("items", []))
            if rb.get("status") != "ok":
                r.setdefault("errors", []).append(rb.get("error"))
        res.setdefault("runs", []).append({"threads": threads, "gate": g, "result": r})
        log(f"native verification, {threads} threads: {r.get('status')}")
        save()
    return res
