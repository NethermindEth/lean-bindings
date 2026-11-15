"""Does batching signatures into one leaf reduce proving cost per signature? (lean-bindings `pq_sweep`)

Measures, on one machine, post-quantum signature leaves of 1..max N signatures, the aggregation step verifying each,
16-input steps over single- and maximum-signature leaves, native verification of leaves and one-leaf (mode-1)
aggregates, and whole aggregation trees of the same signatures proved as single-signature leaves and as maximum-N
leaves on one worker.

The driver (`pq_batching/pq_sweep.rs`) is copied into the library revision's `src/ffi/examples` and built there.
Every measurement is its own process: an untimed warm-up of the same proof, then one timed, behind the quiet-machine
gate, `reps` times, with repeat-then-exclude. A tree node is a process too, but nodes run back to back as a prover
would, so between nodes only competing processes and swap growth are checked, not the load average; a tree
repetition with a violating node is repeated once and excluded if the repeat also violates.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import time

from . import host
from .runner import SWAP_GROWTH

REPO_URL = "https://github.com/NethermindEth/lean-bindings.git"
MAX_CLAIMS = 256
MAX_INPUTS = 16
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def checkout(ref: str, out: str, log) -> tuple[str, str]:
    # Under corpus/, which the CI artifact leaves out, with the build's target directory.
    src = os.path.join(out, "corpus", "pq-src")
    if not os.path.exists(os.path.join(src, ".git")):
        subprocess.run(["git", "clone", "-q", REPO_URL, src], check=True)
    subprocess.run(["git", "-C", src, "fetch", "-q", "origin", ref], check=False)
    subprocess.run(["git", "-C", src, "-c", "advice.detachedHead=false", "checkout", "-q", ref], check=True)
    sha = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    log(f"library at {ref} ({sha[:10]})")
    return src, sha


def build(src: str, log) -> str:
    ffi = os.path.join(src, "src", "ffi")
    shutil.copy(os.path.join(HERE, "pq_batching", "pq_sweep.rs"), os.path.join(ffi, "examples", "pq_sweep.rs"))
    log("build pq_sweep")
    subprocess.run(["cargo", "build", "--release", "--locked", "--example", "pq_sweep"], cwd=ffi, check=True)
    return os.path.join(ffi, "target", "release", "examples", "pq_sweep")


def med(xs: list[float]) -> dict:
    return {"median": statistics.median(xs), "min": min(xs), "max": max(xs)}


class Sweep:
    def __init__(self, binary: str, out: str, cfg: dict, log):
        self.bin, self.out, self.cfg, self.log = binary, out, cfg, log
        self.quiet = cfg.get("quiet", {"max_load1": 4, "timeout_s": 600})
        self.corpus = os.path.join(out, "corpus")
        for d in ("logs", "corpus"):
            os.makedirs(os.path.join(out, d), exist_ok=True)
        self.jsonl = open(os.path.join(out, "pq-batching-runs.jsonl"), "a")
        self.seq = 0
        self.arities = {}

    def env(self) -> dict:
        e = dict(os.environ)
        e["LEANVM_NUM_THREADS"] = str(self.cfg["threads"])
        return e

    def once(self, args: list[str], tag: str, gate: str = "full") -> dict:
        """One process. `gate`: `full` waits for a quiet machine, `busy` only records competing processes."""
        if gate == "full":
            g = host.wait_quiet(self.quiet["max_load1"], self.quiet["timeout_s"], log=self.log)
        else:
            busy = host.busy_processes({os.getpid()})
            g = {"quiet": not busy, "load1": host.load1(), "waited_s": 0, "busy": busy}
        mem0 = host.memory()
        t0 = time.time()
        p = subprocess.run([self.bin, *args], capture_output=True, text=True, env=self.env())
        wall = time.time() - t0
        mem1 = host.memory()
        self.seq += 1
        open(os.path.join(self.out, "logs", f"{self.seq:05d}-{tag}.out"), "w").write(
            " ".join(args) + "\n" + p.stdout + "\n---stderr---\n" + p.stderr[-20000:])
        lines = [json.loads(x) for x in p.stdout.splitlines() if x.startswith("{")]
        rec = {"args": args, "tag": tag, "rc": p.returncode, "wall_s": wall, "gate": g,
               "swap_used_before": mem0["swap_used"], "swap_used_after": mem1["swap_used"],
               "result": lines[-1] if lines else None}
        self.jsonl.write(json.dumps(rec) + "\n")
        self.jsonl.flush()
        return rec

    @staticmethod
    def violated(rec: dict) -> bool:
        return not rec["gate"]["quiet"] or rec["swap_used_after"] > rec["swap_used_before"] + SWAP_GROWTH

    def cell(self, args: list[str], tag: str, reps: int) -> dict:
        recs = []
        for rep in range(1, reps + 1):
            rec = self.once(args, f"{tag}-rep{rep}")
            if self.violated(rec):
                rec = self.once(args, f"{tag}-rep{rep}-retry")
            recs.append(rec)
            r = rec["result"] or {}
            t = r.get("prove_s", r.get("agg_s", r.get("median_ms")))
            self.log(f"  {tag} rep{rep}: rc={rec['rc']} t={t} cycles={r.get('cycles')} "
                     f"log_committed={r.get('log_committed')} rss={(r.get('peak_rss') or 0) / 2**30:.2f}G"
                     f"{' (excluded: unquiet)' if self.violated(rec) else ''}")
        return summarize(recs)

    # ---- leaves ----------------------------------------------------------------------------------------------
    def leaf_args(self, scheme, n, msg, key, offset=0, save=None, probe=False, cold=False):
        a = ["leaf", scheme, str(n), str(msg), str(offset), key]
        if save:
            a += ["--save", save]
        if probe:
            a.append("--probe")
        if cold:
            a.append("--cold")
        return a

    def leaf_file(self, scheme, n, msg, key, offset=0) -> str:
        return os.path.join(self.corpus, f"{scheme}-n{n}-m{msg}-{key}-o{offset}.leaf")

    def fits(self, scheme: str, n: int, msg: int, key: str) -> bool:
        """The leaf proves within the verifier's bounds, and the aggregation step accepts it."""
        f = self.leaf_file(scheme, n, msg, key, offset=900000)
        rec = self.once(self.leaf_args(scheme, n, msg, key, offset=900000, save=f, probe=True),
                        f"probe-{scheme}-m{msg}-{key}-n{n}", gate="busy")
        r = rec["result"] or {}
        ok = rec["rc"] == 0 and r.get("fits") is True
        agg = None
        if ok:
            agg = self.once(["step", key, "-", f, "--cold"], f"probe-step-{scheme}-m{msg}-{key}-n{n}", gate="busy")
            ok = agg["rc"] == 0
        if os.path.exists(f):
            os.remove(f)
        self.log(f"  probe {scheme} m{msg} {key} n={n}: {'fits' if ok else 'does not fit'} "
                 f"(log_committed={r.get('log_committed')} error={str(r.get('error'))[:80]} step_rc={agg and agg['rc']})")
        return ok

    def max_n(self, scheme: str, msg: int, key: str, guess: int) -> tuple[int, list]:
        probes = []
        cap = self.cfg.get("probe_cap", MAX_CLAIMS)

        def fits(n):
            ok = self.fits(scheme, n, msg, key)
            probes.append({"n": n, "ok": ok})
            return ok

        guess = max(1, min(cap, guess))
        if fits(guess):
            lo, hi, step = guess, cap + 1, 1
            while lo < cap:
                n = min(cap, lo + step)
                if fits(n):
                    lo, step = n, step * 2
                else:
                    hi = n
                    break
        else:
            hi, lo, step = guess, 0, 1
            while hi > 1:
                n = max(1, hi - step)
                if fits(n):
                    lo = n
                    break
                hi, step = n, step * 2
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if fits(mid):
                lo = mid
            else:
                hi = mid
        return lo, probes

    def leaf_cell(self, scheme: str, n: int, msg: int, key: str, reps: int) -> dict:
        tag = f"leaf-{scheme}-m{msg}-{key}-n{n}"
        f = self.leaf_file(scheme, n, msg, key)
        res = {"scheme": scheme, "n": n, "msg": msg, "key": key, "file": f}
        res["leaf"] = self.cell(self.leaf_args(scheme, n, msg, key, save=f), tag, reps)
        if os.path.exists(f):
            agg = f.replace(".leaf", ".wrap")
            res["wrap_file"] = agg
            res["wrap"] = self.cell(["step", key, agg, f], f"wrap-{scheme}-m{msg}-{key}-n{n}", reps)
        return res

    def verify_cell(self, path: str, reps: int) -> dict:
        return self.cell(["verify", path, str(self.cfg.get("verify_inner", 9))], "verify-" + os.path.basename(path), reps)

    # ---- trees -------------------------------------------------------------------------------------------------
    def arity(self, key: str, kind: str, files: list[str], setting) -> int:
        """Inputs per step over `files` of one `kind`: `setting` when it is a number, or with `max` the most inputs
        one step over the first of `files` proves, probed from 16 down and remembered per kind."""
        if setting != "max":
            return int(setting)
        # (largest arity that proved, smallest that failed) for this kind.
        ok, failed = self.arities.get((key, kind), (1, MAX_INPUTS + 1))
        k = min(failed - 1, len(files))
        while k > ok:
            rec = self.once(["step", key, "-", *files[:k], "--cold"], f"probe-arity-{key}-{kind}-{k}", gate="busy")
            self.log(f"  probe step {key} {kind} x{k}: rc={rec['rc']}")
            if rec["rc"] == 0:
                ok = k
            else:
                failed, k = k, k - 1
        self.arities[(key, kind)] = (ok, failed)
        return min(ok, len(files))

    def tree(self, scheme: str, msg: int, total: int, per_leaf: int, rep: int, cold: bool, label: str,
             key: str = "committed", arity=MAX_INPUTS) -> dict:
        """Proves `total` signatures as leaves of `per_leaf` signatures under `key`, then steps of up to `arity`
        inputs to one root, each node one process, back to back on this machine."""
        d = os.path.join(self.corpus, f"tree-{label}-rep{rep}")
        os.makedirs(d, exist_ok=True)
        nodes, level, files = [], 0, []
        g = host.wait_quiet(self.quiet["max_load1"], self.quiet["timeout_s"], log=self.log)
        for i, off in enumerate(range(0, total, per_leaf)):
            n = min(per_leaf, total - off)
            f = os.path.join(d, f"l{i}.leaf")
            rec = self.once(self.leaf_args(scheme, n, msg, key, offset=100000 + off, save=f, cold=cold),
                            f"tree-{label}-rep{rep}-leaf{i}", gate="busy")
            nodes.append(node_record(rec, 0, n))
            if rec["rc"] != 0:
                return {"status": "failed", "at": f"leaf {i}", "nodes": nodes}
            files.append(f)
        arities = {}
        while len(files) > 1 or level == 0:
            level += 1
            nxt = []
            a = self.arity(key, f"leaf-n{per_leaf}" if level == 1 else "agg", files, arity)
            arities[str(level)] = a
            for j in range(0, len(files), a):
                f = os.path.join(d, f"s{level}-{j // a}.agg")
                rec = self.once(["step", key, f, *files[j:j + a], *(["--cold"] if cold else [])],
                                f"tree-{label}-rep{rep}-l{level}-s{j // a}", gate="busy")
                nodes.append(node_record(rec, level, len(files[j:j + a])))
                if rec["rc"] != 0:
                    return {"status": "failed", "at": f"level {level} step {j // a}", "nodes": nodes}
                nxt.append(f)
            files = nxt
        t = [x["t"] for x in nodes]
        lv = {}
        for x in nodes:
            lv.setdefault(x["level"], []).append(x["t"])
        out = {"status": "ok", "label": label, "rep": rep, "signatures": total, "per_leaf": per_leaf,
               "leaves": sum(1 for x in nodes if x["level"] == 0), "steps": sum(1 for x in nodes if x["level"] > 0),
               "depth": level, "makespan_s": sum(t), "process_wall_s": sum(x["wall"] for x in nodes),
               "leaf_s": sum(lv[0]), "step_s": sum(sum(v) for k, v in lv.items() if k > 0),
               "per_level_s": {str(k): sum(v) for k, v in sorted(lv.items())},
               "peak_rss_max": max(x["rss"] for x in nodes), "cycles": sum(x["cycles"] for x in nodes),
               "violated": any(x["violated"] for x in nodes) or not g["quiet"], "root": files[0], "nodes": nodes,
               "cold": cold, "gate": g, "key": key, "arity": arities}
        self.log(f"  tree {label} rep{rep}: makespan {out['makespan_s']:.1f} s (leaves {out['leaf_s']:.1f} s, steps "
                 f"{out['step_s']:.1f} s), {out['leaves']} leaves + {out['steps']} steps, depth {level}, "
                 f"peak {out['peak_rss_max'] / 2**30:.1f} GB{' VIOLATED' if out['violated'] else ''}")
        return out

    def tree_cell(self, scheme, msg, total, per_leaf, reps, cold, label, key="committed", arity=MAX_INPUTS) -> dict:
        runs = []
        for rep in range(1, reps + 1):
            r = self.tree(scheme, msg, total, per_leaf, rep, cold, label, key, arity)
            if r.get("violated"):
                self.log(f"  tree {label} rep{rep} violated the quiet conditions; repeating once")
                r = self.tree(scheme, msg, total, per_leaf, rep, cold, label + "-retry", key, arity)
            runs.append(r)
        ok = [r for r in runs if r["status"] == "ok" and not r["violated"]]
        s = {"label": label, "signatures": total, "per_leaf": per_leaf, "reps": len(ok), "key": key,
             "excluded": sum(1 for r in runs if r.get("violated")), "cold": cold,
             "runs": [{k: v for k, v in r.items() if k != "nodes"} for r in runs]}
        if ok:
            for k in ("makespan_s", "leaf_s", "step_s", "process_wall_s"):
                s[k] = med([r[k] for r in ok])
            s["peak_rss_max"] = max(r["peak_rss_max"] for r in ok)
            s["leaves"], s["steps"], s["depth"] = ok[0]["leaves"], ok[0]["steps"], ok[0]["depth"]
            s["cycles"] = statistics.median(r["cycles"] for r in ok)
            s["root"] = ok[0]["root"]
            s["arity"] = ok[0]["arity"]
        return s


def node_record(rec: dict, level: int, inputs: int) -> dict:
    r = rec["result"] or {}
    return {"level": level, "inputs": inputs, "rc": rec["rc"], "t": r.get("prove_s", r.get("agg_s", 0.0)),
            "wall": rec["wall_s"], "cycles": r.get("cycles", 0), "rss": r.get("peak_rss", 0),
            "log_committed": r.get("log_committed"), "violated": Sweep.violated(rec)}


def summarize(recs: list[dict]) -> dict:
    ok = [r for r in recs if r["rc"] == 0 and r["result"] and not Sweep.violated(r)]
    excluded = sum(1 for r in recs if Sweep.violated(r))
    if not ok:
        return {"status": "failed", "excluded": excluded, "rc": [r["rc"] for r in recs]}
    res = [r["result"] for r in ok]
    out = {"status": "ok", "reps": len(ok), "excluded": excluded, "first": res[0]}
    for k in ("prove_s", "agg_s", "median_ms", "peak_rss", "cycles"):
        if k in res[0]:
            out[k] = med([x[k] for x in res])
    out["wall_s"] = med([r["wall_s"] for r in ok])
    out["load1_max"] = max(r["gate"]["load1"] for r in ok)
    return out


def run(cfg: dict, out: str, log) -> dict:
    os.makedirs(out, exist_ok=True)
    if cfg.get("pq_src"):  # a local checkout, for trying the sweep out
        src = cfg["pq_src"]
        sha = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    else:
        src, sha = checkout(cfg["pq_ref"], out, log)
    binary = build(src, log)
    sw = Sweep(binary, out, cfg, log)
    reps = cfg["reps"]
    res = {"pq_ref": cfg["pq_ref"], "pq_sha": sha, "host": host.record(), "threads": cfg["threads"], "reps": reps,
           "max_n": {}, "probes": {}, "leaves": [], "verify": [], "step16": {}, "trees": {}}
    path = os.path.join(out, "pq-batching.json")

    def save():
        json.dump(res, open(path, "w"), indent=1)

    for spec in cfg.get("leaf_cells", []):
        scheme, msg, key = spec["scheme"], spec.get("msg", 32), spec.get("key", "committed")
        mk = f"{scheme}-m{msg}-{key}"
        if "max" in spec["n"] and mk not in res["max_n"]:
            src_key = f"{scheme}-m{msg}-committed"
            guess = res["max_n"].get(src_key) or cfg.get("max_guess", {}).get(scheme, 1)
            res["max_n"][mk], res["probes"][mk] = sw.max_n(scheme, msg, key, guess)
            log(f"{mk}: max N = {res['max_n'][mk]}")
            save()
        for n in spec["n"]:
            n = res["max_n"][mk] if n == "max" else n
            if any(c["scheme"] == scheme and c["msg"] == msg and c["key"] == key and c["n"] == n for c in res["leaves"]):
                continue
            c = sw.leaf_cell(scheme, n, msg, key, reps)
            res["leaves"].append(c)
            save()
            if spec.get("verify") and (n == 1 or n == res["max_n"].get(mk)):
                for p in (c["file"], c.get("wrap_file")):
                    if p and os.path.exists(p):
                        v = sw.verify_cell(p, reps)
                        v.update({"scheme": scheme, "n": n, "msg": msg, "key": key, "file": os.path.basename(p)})
                        res["verify"].append(v)
                        save()

    t = cfg.get("tree")
    if t:
        scheme, msg, key = t["scheme"], t.get("msg", 32), t.get("key", "committed")
        per = res["max_n"].get(f"{scheme}-m{msg}-{key}") or t["per_leaf"]
        total = t.get("signatures") or t.get("groups", 16) * per
        routes = t.get("routes", ["batched", "single"])
        for route, k in (("batched", per), ("single", 1)):
            if route in routes:
                res["trees"][route] = sw.tree_cell(scheme, msg, total, k, t.get("reps", reps), t.get("cold", False),
                                                   f"{route}-{total}", key, t.get("arity", MAX_INPUTS))
                save()
        # One step over 16 leaves of each kind, as a cell: the first 16 leaves of each tree's first repetition.
        for route in ("single", "batched"):
            d = os.path.join(sw.corpus, f"tree-{route}-{total}-rep1")
            files = [os.path.join(d, f"l{i}.leaf") for i in range(MAX_INPUTS)]
            tree = res["trees"].get(route, {})
            if tree.get("arity", {}).get("1") == MAX_INPUTS and all(os.path.exists(f) for f in files):
                res["step16"][route] = sw.cell(["step", key, "-", *files], f"step16-{route}", reps)
                save()
        for route in res["trees"]:
            root = res["trees"][route].get("root")
            if root and os.path.exists(root):
                v = sw.verify_cell(root, reps)
                v.update({"route": route, "file": os.path.basename(root)})
                res["verify"].append(v)
                save()

    b = cfg.get("block")
    if b:
        scheme, msg, key = b["scheme"], b.get("msg", 32), b.get("key", "committed")
        per = res["max_n"].get(f"{scheme}-m{msg}-{key}") or b["per_leaf"]
        for route, k in (("batched", per), ("single", 1)):
            res.setdefault("block", {})[route] = sw.tree_cell(scheme, msg, b["signatures"], k, 1, b.get("cold", True),
                                                              f"block-{route}-{b['signatures']}", key,
                                                              b.get("arity", MAX_INPUTS))
            save()

    res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save()
    open(os.path.join(out, "report.md"), "w").write(report(res))
    return res


def report(res: dict) -> str:
    g = 2**30
    lines = [f"# Batching sweep, library {res['pq_sha'][:10]}", "", f"max N: {res['max_n']}", "",
             "| scheme | msg | key | N | leaf s (range) | s / sig | cycles | log2 committed | peak GB | wrap step s | wrap cycles |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c in res["leaves"]:
        l, w = c["leaf"], c.get("wrap", {})
        if l["status"] != "ok":
            lines.append(f"| {c['scheme']} | {c['msg']} | {c['key']} | {c['n']} | failed | | | | | | |")
            continue
        p = l["prove_s"]
        lines.append(f"| {c['scheme']} | {c['msg']} | {c['key']} | {c['n']} | {p['median']:.3f} ({p['min']:.3f}–{p['max']:.3f}) | "
                     f"{p['median'] / c['n']:.3f} | {l['cycles']['median']:,.0f} | {l['first']['log_committed']:.2f} | "
                     f"{l['peak_rss']['max'] / g:.1f} | {w.get('agg_s', {}).get('median', float('nan')):.3f} | "
                     f"{w.get('cycles', {}).get('median', 0):,.0f} |")
    for name, coll in (("trees", res.get("trees", {})), ("block", res.get("block", {}))):
        for route, t in coll.items():
            if "makespan_s" in t:
                m = t["makespan_s"]
                lines.append(f"\n{name} {route}: {t['signatures']} sigs, {t['leaves']} leaves + {t['steps']} steps, makespan "
                             f"{m['median']:.1f} s ({m['min']:.1f}–{m['max']:.1f}), leaves {t['leaf_s']['median']:.1f} s, steps "
                             f"{t['step_s']['median']:.1f} s, peak {t['peak_rss_max'] / g:.1f} GB, reps {t['reps']}, "
                             f"key {t.get('key', 'committed')}, most inputs per step by level {t.get('arity')}")
    for route, c in res.get("step16", {}).items():
        if c.get("status") == "ok":
            lines.append(f"\nstep16 {route}: {c['agg_s']['median']:.3f} s, {c['cycles']['median']:,.0f} cycles, "
                         f"{c['peak_rss']['max'] / g:.1f} GB")
    for v in res.get("verify", []):
        if v.get("status") == "ok":
            lines.append(f"\nverify {v.get('file')}: {v['median_ms']['median']:.2f} ms")
    return "\n".join(lines) + "\n"
