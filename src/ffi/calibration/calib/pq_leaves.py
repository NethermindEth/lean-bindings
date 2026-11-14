"""Post-quantum signature leaves (lean-bindings `examples/pq_leaves`) under the suite's measurement rules.

Each scheme's leaf is a generic program verifying N signatures with one ethereum/EIPs#12664 batch claim each. For each
scheme this records the program size, runs the leaf's own reference and negative tests, then measures a ladder of N
(cycles, time and peak memory per signature), the largest N within the verifier's committed-witness bound and the
256-claim cap, the leaf at that N, and the aggregation step that verifies it with every claim sponsored.

Every measurement is one process (`pq_leaves prove S N 1`: an untimed warm-up proof, then one timed), behind the
quiet-machine gate, `reps` times; a repetition that broke the conditions is repeated once and dropped if the repeat
also did (repeat-then-exclude). `prove_s`, cycles and the committed witness come from the program, peak RSS from
getrusage in the same process.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import time

from . import host
from .runner import SWAP_GROWTH

REPO_URL = "https://github.com/NethermindEth/lean-bindings.git"
# The largest committed witness a leaf proof may have: the calibration's maximum-resource leaf (2^29.52 at a nominal
# 2^29.5) is the largest the verifier's 2^30 stacked-witness bound admits.
MAX_LOG_COMMITTED = 29.52
MAX_CLAIMS = 256
# N ladders for the slopes, then a first guess at the bound (refined by probing).
LADDERS = {
    "slhdsa128s": [1, 16, 64, 128],
    "falcon512": [1, 2, 4, 8, 16],
    "mldsa44": [1, 2, 4],
}


def checkout(ref: str, out: str, log) -> tuple[str, str]:
    src = os.path.join(out, "pq-src")
    if not os.path.exists(os.path.join(src, ".git")):
        subprocess.run(["git", "clone", "-q", REPO_URL, src], check=True)
    subprocess.run(["git", "-C", src, "fetch", "-q", "origin", ref], check=False)
    subprocess.run(["git", "-C", src, "-c", "advice.detachedHead=false", "checkout", "-q", ref], check=True)
    sha = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    log(f"pq_leaves at {ref} ({sha[:10]})")
    return src, sha


def build(src: str, log) -> str:
    ffi = os.path.join(src, "src", "ffi")
    log("build pq_leaves")
    subprocess.run(["cargo", "build", "--release", "--locked", "--example", "pq_leaves"], cwd=ffi, check=True)
    return os.path.join(ffi, "target", "release", "examples", "pq_leaves")


class Bench:
    def __init__(self, binary: str, out: str, cfg: dict, log):
        self.bin, self.out, self.cfg, self.log = binary, out, cfg, log
        self.quiet = cfg.get("quiet", {"max_load1": 4, "timeout_s": 600})
        os.makedirs(os.path.join(out, "logs"), exist_ok=True)
        self.jsonl = open(os.path.join(out, "pq-runs.jsonl"), "a")

    def env(self) -> dict:
        e = dict(os.environ)
        e["LEANVM_NUM_THREADS"] = str(self.cfg["threads"])
        return e

    def once(self, args: list[str], tag: str, gate: bool = True) -> dict:
        g = host.wait_quiet(self.quiet["max_load1"], self.quiet["timeout_s"], log=self.log) if gate else {"quiet": True, "load1": host.load1(), "waited_s": 0}
        mem0 = host.memory()
        t0 = time.time()
        p = subprocess.run([self.bin, *args], capture_output=True, text=True, env=self.env())
        wall = time.time() - t0
        mem1 = host.memory()
        open(os.path.join(self.out, "logs", tag + ".out"), "w").write(p.stdout + "\n---stderr---\n" + p.stderr)
        lines = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
        rec = {"args": args, "tag": tag, "rc": p.returncode, "wall_s": wall, "gate": g,
               "swap_used_before": mem0["swap_used"], "swap_used_after": mem1["swap_used"],
               "result": lines[-1] if lines else None, "stdout": p.stdout[-4000:] if not lines else None}
        self.jsonl.write(json.dumps(rec) + "\n")
        self.jsonl.flush()
        return rec

    @staticmethod
    def violated(rec: dict) -> bool:
        return not rec["gate"]["quiet"] or rec["swap_used_after"] > rec["swap_used_before"] + SWAP_GROWTH

    def cell(self, scheme: str, n: int, reps: int, agg: bool) -> dict:
        args = ["prove", scheme, str(n), "1", *(["--agg"] if agg else [])]
        recs = []
        for rep in range(1, reps + 1):
            rec = self.once(args, f"{scheme}-n{n}-rep{rep}")
            if self.violated(rec):
                rec = self.once(args, f"{scheme}-n{n}-rep{rep}-retry")
            recs.append(rec)
            r = rec["result"] or {}
            self.log(f"  {scheme} n={n} rep{rep}: rc={rec['rc']} prove={r.get('prove_s')} cycles={r.get('cycles')} "
                     f"log_committed={r.get('log_committed')} rss={r.get('peak_rss', 0) / 2**30:.1f}G"
                     f"{' agg=' + str(r.get('agg_cycles')) if agg else ''}{' (unquiet)' if self.violated(rec) else ''}")
        return summarize(recs, n)


def summarize(recs: list[dict], n: int) -> dict:
    ok = [r for r in recs if r["rc"] == 0 and r["result"] and not Bench.violated(r)]
    excluded = sum(1 for r in recs if Bench.violated(r))
    if not ok:
        return {"n": n, "status": "failed", "excluded": excluded, "rc": [r["rc"] for r in recs],
                "tail": (recs[-1].get("stdout") or "")[-1000:] if recs else ""}
    res = [r["result"] for r in ok]
    pv = [x["prove_s"] for x in res]
    out = {"n": n, "status": "ok", "reps": len(ok), "excluded": excluded, "prove_s": statistics.median(pv),
           "prove_min": min(pv), "prove_max": max(pv), "cycles": statistics.median(x["cycles"] for x in res),
           "log_committed": res[0]["log_committed"], "committed": res[0]["committed"],
           "peak_rss": max(x["peak_rss"] for x in res), "witness_bytes": res[0]["witness_bytes"],
           "rows": res[0]["rows"], "load1_max": max(r["gate"]["load1"] for r in ok)}
    if "agg_cycles" in res[0]:
        out["agg_cycles"] = statistics.median(x["agg_cycles"] for x in res)
        out["agg_s"] = statistics.median(x["agg_s"] for x in res)
    return out


def fit(points: list[dict], key: str) -> tuple[float, float]:
    """Least-squares (intercept, slope) of `key` against n."""
    xs = [p["n"] for p in points]
    ys = [p[key] for p in points]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0.0
    return my - slope * mx, slope


def max_n(bench: Bench, scheme: str, ladder: list[dict]) -> tuple[int, list[dict]]:
    """The largest N that proves within MAX_LOG_COMMITTED and MAX_CLAIMS and that the aggregation guest accepts,
    found by single untimed probes started from the ladder's committed-witness slope."""
    a, b = fit(ladder, "committed")
    guess = max(1, min(MAX_CLAIMS, int((2 ** MAX_LOG_COMMITTED - a) / b))) if b > 0 else MAX_CLAIMS
    probes = []

    def fits(n: int) -> bool:
        rec = bench.once(["prove", scheme, str(n), "1", "--agg"], f"{scheme}-probe-n{n}", gate=False)
        r = rec["result"] or {}
        ok = rec["rc"] == 0 and r.get("log_committed", 99) <= MAX_LOG_COMMITTED and "agg_cycles" in r
        probes.append({"n": n, "ok": ok, "rc": rec["rc"], "log_committed": r.get("log_committed"),
                       "peak_rss": r.get("peak_rss"), "prove_s": r.get("prove_s")})
        bench.log(f"  {scheme} probe n={n}: {'fits' if ok else 'does not fit'} (rc={rec['rc']} "
                  f"log_committed={r.get('log_committed')})")
        return ok

    # The committed witness grows in power-of-two steps of the memory image, so many N share one size: bisect
    # (fits is monotone in N) rather than walk. lo always fits (0: none measured does); hi, once set, does not.
    lo = max((p["n"] for p in ladder if p["status"] == "ok" and p["log_committed"] <= MAX_LOG_COMMITTED), default=0)
    hi = MAX_CLAIMS + 1
    # From the slope's guess, gallop up (doubling the step) until a probe fails or the claim cap fits, so no probe
    # lands far above the bound, where a lattice leaf would need several times the machine's memory.
    n, step = max(lo + 1, guess), max(1, guess // 8)
    while n < hi:
        if fits(n):
            lo = n
            if n == MAX_CLAIMS:
                break
            n, step = min(MAX_CLAIMS, n + step), step * 2
        else:
            hi = n
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid
    return lo, probes
    hi = n
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid
    return lo, probes


def run(cfg: dict, out: str, log) -> dict:
    os.makedirs(out, exist_ok=True)
    src, sha = checkout(cfg["pq_ref"], out, log)
    binary = build(src, log)
    bench = Bench(binary, out, cfg, log)
    res = {"pq_ref": cfg["pq_ref"], "pq_sha": sha, "host": host.record(), "threads": cfg["threads"],
           "reps": cfg["reps"], "max_log_committed": MAX_LOG_COMMITTED, "schemes": {}}
    path = os.path.join(out, "pq-leaves.json")

    def save():
        json.dump(res, open(path, "w"), indent=1)

    ladders = {**LADDERS, **cfg.get("ladders", {})}
    for scheme in cfg.get("schemes", list(LADDERS)):
        s = res["schemes"].setdefault(scheme, {})
        size = bench.once(["size", scheme], f"{scheme}-size", gate=False)
        s["size"] = size["result"]
        test = bench.once(["test", scheme], f"{scheme}-test", gate=False)
        s["test"] = {"rc": test["rc"], "ok": test["rc"] == 0}
        log(f"{scheme}: size {s['size']}, tests {'pass' if test['rc'] == 0 else 'FAIL'}")
        save()
        s["ladder"] = [bench.cell(scheme, n, cfg["reps"], agg=False) for n in ladders[scheme]]
        ok = [p for p in s["ladder"] if p["status"] == "ok"]
        save()
        if len(ok) < 2:
            continue
        for key in ("cycles", "prove_s", "peak_rss", "committed"):
            a, b = fit(ok, key)
            s[f"{key}_fixed"], s[f"{key}_per_sig"] = a, b
        n, s["probes"] = max_n(bench, scheme, ok)
        s["max_n"] = n
        # Memory alone: the N whose extrapolated peak RSS reaches the machine's usable memory.
        usable = host.memory()["total"] * 0.95
        s["max_n_by_memory"] = int((usable - s["peak_rss_fixed"]) / s["peak_rss_per_sig"]) if s["peak_rss_per_sig"] > 0 else None
        save()
        s["at_max"] = bench.cell(scheme, n, cfg["reps"], agg=True)
        save()
    res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save()
    return res

