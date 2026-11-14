"""Native (host, non-recursive) verification as a mempool node runs it, to price per-dependency mempool work.

Per leanSPHINCS signature, a direct leanSTARK leaf (a small program and the largest this machine can prove), a
256-claim batch leaf with its payment binding, and a mode-1 aggregate; each on one thread and on every thread, the
median of `reps` timed runs after a warm-up, behind the quiet-machine gate. The largest leaf's trace is sized to this
machine's memory (native verification depends only weakly on it) and stepped down to the verifier's bound.
"""

from __future__ import annotations

import json
import os
import subprocess

from . import build as builder
from . import host
from .pipeline import TRACE_STEP, iters_for_trace, preflight
from .runner import Runner, result_line

SMALL_CODE_LOG, SMALL_TRACE_LOG, SIGS = 7, 18, 64


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
    small, meta = runner.leaf(b, SMALL_CODE_LOG, iters_for_trace(SMALL_TRACE_LOG), rate, 1, 7000)
    res.setdefault("leaves", {})[os.path.basename(small)] = meta
    largest = biggest(1, 7001)
    batch = biggest(bounds["claims"], 7002) if "batch" in b["features"] else largest
    res["trace_log_used"] = trace_log
    save()
    for threads in sorted({1, os.cpu_count() or 1}):
        g = runner.gate()
        p = subprocess.run([os.path.join(b["bin"], "calib-node"), "native", str(cfg.get("reps", 5)), sigs, str(SIGS),
                            small, largest, batch], capture_output=True, text=True, env=runner.env(threads))
        r = result_line(p.stdout) or {"status": "failed", "error": p.stderr[-2000:]}
        res.setdefault("runs", []).append({"threads": threads, "gate": g, "result": r})
        log(f"native verification, {threads} threads: {r.get('status')}")
        save()
    return res
