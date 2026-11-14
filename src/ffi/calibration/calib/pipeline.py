"""The calibration: preflight, builds, corpus, cells, constants, verification blocks, and the result record."""

from __future__ import annotations

import json
import math
import os
import subprocess
import time

from . import build as builder
from . import evm, gasmath, host
from .runner import Runner

# Reference points for sizing (M2 Max, 11 threads; gas-calibration REPORT.md and commitment/REPORT.md): a 2^11 leaf
# whose inner proof commits 2^27.5 field elements needed 2^18 loop iterations and peaked at these resident sizes.
REF_TRACE_LOG = 27.5
REF_ITERS_LOG = 18
INNER_GB_AT_REF = {"flat": 11.3, "committed": 8.0}
STEP_GB_FIXED = {"flat": 0.6, "committed": 0.8}
# A step verifying one 2^k-instruction leaf (M2 Max measurements): the flat key rehashes the table in the guest.
LEAF_STEP_GB = {"flat": {7: 1.2, 8: 1.4, 9: 2.0, 10: 3.1, 11: 4.7}, "committed": {k: 1.2 for k in range(7, 12)}}


TRACE_STEP = 0.1


def iters_for_trace(trace_log: float) -> int:
    return max(4, int(round(2 ** (REF_ITERS_LOG + trace_log - REF_TRACE_LOG))))


def preflight(cfg: dict, mem: dict) -> dict:
    """Sizes the maximum-resource leaf and the full step to this machine. Returns what will be used, each with a label;
    with `preflight.mode = refuse` it raises instead of scaling down."""
    key = cfg["key"]
    bounds = cfg["bounds"]
    avail_gb = mem["available"] / 2**30
    per_worker_gb = cfg["memory_per_worker_gb"]
    budget_gb = min(avail_gb * cfg.get("preflight", {}).get("usable_fraction", 0.8), per_worker_gb)
    refuse = cfg.get("preflight", {}).get("mode", "scale") == "refuse"
    out = {"available_gb": avail_gb, "budget_gb": budget_gb, "memory_per_worker_gb": per_worker_gb, "notes": []}

    # Local workers share this machine: each may hold a maximum-resource leaf step at once.
    local = cfg["workers"].get("mode", "local") == "local"
    concurrent = cfg["workers"]["count"] if local else 1
    code = want_code = bounds["code_log"]
    while code > 7 and LEAF_STEP_GB[key][code] > min(per_worker_gb, avail_gb * cfg.get("preflight", {}).get("usable_fraction", 0.8) / concurrent):
        code -= 1
    if code < want_code:
        msg = (f"code size scaled down: {concurrent} concurrent steps of a 2^{want_code}-instruction leaf need "
               f"~{concurrent * LEAF_STEP_GB[key][want_code]:.1f} GB; using 2^{code}")
        if refuse:
            raise SystemExit(f"preflight refused: {msg}")
        out["notes"].append(msg)
    out["code_log_requested"], out["code_log_used"] = want_code, code

    want = float(bounds["trace_log"])
    need = INNER_GB_AT_REF[key] * 2 ** (want - REF_TRACE_LOG)
    used = want
    while INNER_GB_AT_REF[key] * 2 ** (used - REF_TRACE_LOG) > budget_gb and used > 16:
        used -= 0.5
    if used < want:
        msg = (f"trace scaled down: 2^{want:g} needs ~{need:.0f} GB to prove, {budget_gb:.1f} GB usable; "
               f"using 2^{used:g} (estimate from the 2^{REF_TRACE_LOG} reference)")
        if refuse:
            raise SystemExit(f"preflight refused: {msg}")
        out["notes"].append(msg)
    out["trace_log_requested"], out["trace_log_used"] = want, used
    out["iters"] = iters_for_trace(used)

    max_inner = bounds["max_inner_proofs_per_step"]
    per_leaf = LEAF_STEP_GB[key][code] - STEP_GB_FIXED[key]
    k = max_inner
    while k > 1 and STEP_GB_FIXED[key] + per_leaf * k > budget_gb:
        k -= 1
    if k < max_inner:
        msg = (f"full step scaled down: {max_inner} leaves of 2^{code} instructions need "
               f"~{STEP_GB_FIXED[key] + per_leaf * max_inner:.0f} GB; measuring {k}")
        if refuse:
            raise SystemExit(f"preflight refused: {msg}")
        out["notes"].append(msg)
    out["step_leaves"] = k
    out["scaled"] = bool(out["notes"])
    return out


def _cell_time(cells: dict, name: str) -> float | None:
    c = cells.get(name, {})
    return c.get("prove_s") if c.get("status") == "ok" else None


def slope(cells: dict, small: str, large: str, dn: float) -> tuple[float | None, str]:
    """Machine-seconds per unit between two cells `dn` units apart. Small slopes drown in timing noise, so the time slope
    is floored by the cycle slope at the larger cell's seconds per cycle; the label says which one was used."""
    a, b = cells.get(small, {}), cells.get(large, {})
    if a.get("status") != "ok" or b.get("status") != "ok":
        return None, "not measured"
    by_time = (b["prove_s"] - a["prove_s"]) / dn
    by_cycles = (b["cycles"] - a["cycles"]) / dn * b["prove_s"] / b["cycles"]
    if by_time >= by_cycles:
        return max(0.0, by_time), "measured (time slope)"
    return max(0.0, by_cycles), "measured cycles x measured s/cycle (time slope within noise)"


def marginals(cells: dict, cfg: dict, mi: int | None = None) -> tuple[gasmath.Marginals, dict]:
    L = cfg["sigs_per_node"]
    fan = cfg["fanin"]
    mi = mi or cfg["bounds"]["max_inner_proofs_per_step"]
    C = cfg["bounds"]["claims"]
    labels = {}
    sig_pts = [(n, _cell_time(cells, f"sigs-{n}")) for n in sorted({max(1, L // 4), max(2, L // 2), L})]
    _, sig = gasmath.fit_line([(n, t) for n, t in sig_pts if t is not None])
    m_pts = [(c, _cell_time(cells, f"merge-{c}x1")) for c in sorted({2, fan, mi})]
    m_fixed, m_child = gasmath.fit_line([(c, t) for c, t in m_pts if t is not None])
    labels["sig"] = labels["merge_child"] = "measured (least-squares time slope)"
    carry, labels["carry_sig"] = slope(cells, "merge-2x1", f"merge-2x{L}", 2 * (L - 1))
    leaf = _cell_time(cells, "generic-leaf")
    labels["generic_leaf_step"] = "measured"
    m = gasmath.Marginals(sig=sig, merge_child=m_child, merge_fixed=m_fixed, carry_sig=carry or 0.0,
                          generic_leaf_step=leaf)
    m.claim_in_leaf, labels["claim_in_leaf"] = slope(cells, "batch-leaf-r1", f"batch-leaf-r{C}", C - 1)
    m.carry_record, labels["carry_record"] = slope(cells, "mergebatch-r1", f"mergebatch-r{C}", 2 * (C - 1))
    m.finalize_record, labels["finalize_record"] = slope(cells, "finalize-r1", f"finalize-r{C}", C - 1)
    m.labels = labels
    return m, labels


class Calibration:
    def __init__(self, cfg: dict, out: str, log=print):
        self.cfg, self.out, self.log = cfg, out, log
        os.makedirs(out, exist_ok=True)
        self.run = Runner(out, cfg, log)
        self.res: dict = {"config": cfg, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def save(self):
        json.dump(self.res, open(os.path.join(self.out, "calibration.json"), "w"), indent=1, default=str)

    # ---- setup --------------------------------------------------------------------------------------------------
    def setup(self):
        cfg = self.cfg
        self.res["host"] = host.record()
        self.res["preflight"] = pre = preflight(cfg, self.res["host"]["memory"])
        for n in pre["notes"]:
            self.log("preflight: " + n)
        base = builder.build(cfg["lib_ref"], self.out, log=self.log)
        if cfg["key"] == "committed" and "committed" not in base["features"]:
            raise SystemExit(f"{cfg['lib_ref']} has no committed key; set key=flat or another lib_ref")
        if cfg["key"] == "flat" and "committed" in base["features"]:
            raise SystemExit(f"{cfg['lib_ref']} proves under the committed key; set key=committed")
        self.base = base
        self.batch = base if "batch" in base["features"] else None
        if self.batch is None and cfg.get("batch_lib_ref"):
            b = builder.build(cfg["batch_lib_ref"], self.out, log=self.log)
            if "batch" in b["features"] and (("committed" in b["features"]) == (cfg["key"] == "committed")):
                self.batch = b
            else:
                self.res.setdefault("skipped", []).append(
                    f"{cfg['batch_lib_ref']} lacks the batch-pricing guest or the selected key ({b['features']})")
        self.res["builds"] = {"base": base, "batch": self.batch}
        self.caps = {}
        for k, b in (("base", base), ("batch", self.batch)):
            if b:
                info = subprocess.run([os.path.join(b["bin"], "calib-node"), "info"], capture_output=True, text=True).stdout
                self.caps[b["label"]] = json.loads(info)
                lib = self.caps[b["label"]]["library_max_inner_proofs_per_step"]
                if lib < cfg["bounds"]["max_inner_proofs_per_step"]:
                    self.res.setdefault("skipped", []).append(
                        f"{k} build {b['label']} enforces MAX_INNER_PROOFS_PER_STEP = {lib} < {cfg['bounds']['max_inner_proofs_per_step']}: "
                        f"its blocks are planned within {lib}")
                    if k == "base" and self.res["preflight"]["step_leaves"] > lib:
                        self.res["preflight"]["step_leaves"] = lib
                        self.res["preflight"]["notes"].append(f"full step limited to the library's {lib} inner proofs")
        self.res["capabilities"] = self.caps
        self.save()

    def max_leaf(self, build: dict, seed: int, claims: int = 1) -> str:
        pre = self.res["preflight"]
        while True:
            try:
                path, meta = self.run.leaf(build, pre["code_log_used"], pre["iters"], self.cfg["bounds"]["inner_log_inv_rate"],
                                           claims, seed)
                break
            except RuntimeError as e:
                # The verifier caps the stacked committed witness (leanVM MAX_STACKED_LOG): the largest provable trace
                # is just below the configured height, so step down until the leaf proves.
                if "WitnessOutOfRange" not in str(e) or pre["trace_log_used"] <= 16:
                    raise
                pre["trace_log_used"] = round(pre["trace_log_used"] - TRACE_STEP, 2)
                pre["iters"] = iters_for_trace(pre["trace_log_used"])
                note = (f"trace capped by the verifier's committed-witness bound: using 2^{pre['trace_log_used']:g}, "
                        f"the largest provable within 2^{TRACE_STEP:g} of 2^{pre['trace_log_requested']:g}")
                pre["notes"] = [n for n in pre["notes"] if not n.startswith("trace capped")] + [note]
                pre["scaled"] = True
                self.log("preflight: " + note)
        self.res.setdefault("leaves", {})[os.path.basename(path)] = meta
        return path

    # ---- cells --------------------------------------------------------------------------------------------------
    def cells(self):
        cfg, pre = self.cfg, self.res["preflight"]
        L, fan, C = cfg["sigs_per_node"], cfg["fanin"], cfg["bounds"]["claims"]
        mi = min(cfg["bounds"]["max_inner_proofs_per_step"], self.caps[self.base["label"]]["library_max_inner_proofs_per_step"])
        sigs = self.run.sigs(self.base, max(L, mi) * L)
        leaves = [self.max_leaf(self.base, 1000 + i) for i in range(pre["step_leaves"])]
        cells = [(f"sigs-{n}", ["sigs", sigs, str(n)]) for n in sorted({max(1, L // 4), max(2, L // 2), L})]
        cells += [(f"merge-{c}x1", ["merge", sigs, str(c), "1"]) for c in sorted({2, fan, mi})]
        cells += [(f"merge-2x{L}", ["merge", sigs, "2", str(L)])]
        cells += [("generic-leaf", ["leaves", "base", "1", leaves[0]])]
        cells += [(f"full-step-{len(leaves)}", ["leaves", "base", "1", *leaves])]
        lad = cfg.get("ladders")
        if lad:
            # Single-leaf steps over leaves of a small inner trace: the step cost of program size.
            iters, rate = iters_for_trace(lad["trace_log"]), cfg["bounds"]["inner_log_inv_rate"]
            for k in lad.get("code_logs", []):
                path, _ = self.run.leaf(self.base, k, iters, rate, 1, 60000 + k)
                cells += [(f"ladder-code-{k}", ["leaves", "base", "1", path])]
        self.log(f"cells on {self.base['label']}: {len(cells)} x {cfg['reps']} reps")
        res = self.run.cells(self.base, cells, cfg["reps"])
        if self.batch:
            bl = [self.max_leaf(self.batch, 5000 + i, C) for i in range(2)]
            mid = [n for n in (lad or {}).get("claims", []) if 1 < n < C]
            bcells = [("batch-leaf-r1", ["leaves", "batched", "1", bl[0]]),
                      *((f"batch-leaf-r{n}", ["leaves", "batched", str(n), bl[0]]) for n in mid),
                      (f"batch-leaf-r{C}", ["leaves", "batched", str(C), bl[0]]),
                      ("mergebatch-r1", ["mergebatch", "1", *bl]), (f"mergebatch-r{C}", ["mergebatch", str(C), *bl]),
                      ("finalize-r1", ["finalize", "1", bl[0]]), (f"finalize-r{C}", ["finalize", str(C), bl[0]])]
            if lad:
                # Claims per leaf need the batch-pricing guest: a leaf of n claims, all retained, at the small trace.
                iters, rate = iters_for_trace(lad["trace_log"]), cfg["bounds"]["inner_log_inv_rate"]
                for n in lad.get("claims", []):
                    path, _ = self.run.leaf(self.batch, pre["code_log_used"], iters, rate, n, 61000 + n)
                    bcells += [(f"ladder-claims-{n}", ["leaves", "batched", str(n), path])]
            self.log(f"batch cells on {self.batch['label']}: {len(bcells)} x {cfg['reps']} reps")
            res.update(self.run.cells(self.batch, bcells, cfg["reps"]))
        self.res["cells"] = res
        m, labels = marginals(res, cfg, mi)
        self.marg = m
        self.res["marginals"] = {k: v for k, v in m.__dict__.items()}
        self.save()

    # ---- constants and verification -----------------------------------------------------------------------------
    def constants(self, G: int, rate_factor: float = 1.0) -> dict:
        cfg = self.cfg
        b = gasmath.Budget(G, cfg["builder_budget_s"], cfg["reference_workers"], cfg["margin"], cfg["fanin"], cfg["sigs_per_node"])
        tx = gasmath.TxModel(**cfg.get("tx", {}))
        c = gasmath.derive(self.marg, b, depth=3)
        for _ in range(3):
            n = gasmath.blocks(c, G, tx, cfg["bounds"]["claims"])["native"]["native"]
            depth = gasmath.tree_depth(math.ceil(n / cfg["sigs_per_node"]), cfg["fanin"])
            c = gasmath.derive(self.marg, b, depth)
        if rate_factor != 1.0:
            for k in ("LEANSPHINCS_VERIFICATION_GAS", "RECURSIVE_PROOF_SHARE_GAS", "LEANSTARK_VERIFICATION_GAS",
                      "LEANSTARK_LEAF_PAYMENT_GAS", "LEANSTARK_CLAIM_GAS", "rate_gas_per_machine_s"):
                if c.get(k) is not None:
                    c[k] *= rate_factor
        c["rate_factor"] = rate_factor
        return c

    def plan_for(self, block: dict, guest: str, build: dict) -> list[str]:
        cfg = self.cfg
        mi = min(cfg["bounds"]["max_inner_proofs_per_step"], self.caps[build["label"]]["library_max_inner_proofs_per_step"])
        lines = [f"guest {guest}", f"fanin {min(cfg['fanin'], mi)}", f"max_inner {mi}",
                 f"sigs_per_node {cfg['sigs_per_node']}"]
        if block.get("native"):
            lines.append(f"sigs {self.run.sigs(build, block['native'], seed=2)}")
        for i in range(block.get("generic", 0)):
            lines.append(f"generic {self.max_leaf(build, 20000 + i)}")
        for i in range(block.get("batch_leaves", 0)):
            lines.append(f"batch {self.max_leaf(build, 40000 + i, self.cfg['bounds']['claims'])} {block['retain']}")
        return lines

    def verify(self, G: int, c: dict, it: int, records: list[dict]) -> list[dict]:
        cfg = self.cfg
        tx = gasmath.TxModel(**cfg.get("tx", {}))
        comp = gasmath.blocks(c, G, tx, cfg["bounds"]["claims"], cfg.get("evm_fraction", 0.5))
        scale = cfg.get("block_scale", 1.0)
        mem_pw = int(cfg["memory_per_worker_gb"] * 2**30)
        out = []
        for name, blk in comp.items():
            if scale != 1.0:
                blk = gasmath.scale_block(blk, scale)
            batched = "batch_leaves" in blk
            build = self.batch if batched else self.base
            row = {"block": name, "composition": blk, "iteration": it}
            evm_gas = blk.get("evm_gas", 0)
            row["evm"] = evm.evm_time_ms(records, evm_gas) if evm_gas else {"ms": 0.0, "label": "none"}
            if batched and build is None:
                row.update(status="skipped", reason="no batch-pricing build")
                out.append(row)
                continue
            if any(blk.get(k) for k in ("native", "generic", "batch_leaves")):
                label = f"g{G // 10**6}M-{name}-it{it}"
                plan = self.plan_for(blk, "batched" if batched else "base", build)
                r = self.run.block(build, label, plan)
                if r.get("status") == "ok" and not r["gate"]["quiet"]:
                    # A makespan measured under load would drive the recalibration; prove the block once more.
                    r = self.run.block(build, label + "-retry", plan)
                row["measurement"] = r
                if r.get("status") != "ok":
                    row.update(status="failed")
                    out.append(row)
                    continue
                if not r["gate"]["quiet"]:
                    row.update(status="unquiet: measured under load, not counted")
                    out.append(row)
                    continue
                v = gasmath.verdict(r["makespan_s"], cfg["builder_budget_s"], r["peak_rss_max_worker"], mem_pw)
                verify_ms = r["root_verify_ms"]
            elif evm_gas:
                v = {"time_ok": True, "memory_ok": True, "pass": True, "headroom": math.inf}
                verify_ms = 0.0
            else:
                row.update(status="empty: these constants admit no such dependency in the block")
                out.append(row)
                continue
            if row["evm"]["ms"] is not None:
                row["validator_ms"] = row["evm"]["ms"] + verify_ms
                v["validator_ok"] = row["validator_ms"] <= cfg["validator_budget_s"] * 1e3
                v["pass"] = v["pass"] and v["validator_ok"]
            else:
                v["validator_ok"] = None
            row["verdict"] = v
            row["status"] = "measured" if scale == 1.0 else f"measured at block scale {scale} (indicative)"
            out.append(row)
            self.save()
        return out

    def calibrate(self):
        cfg = self.cfg
        records = []
        if cfg.get("evm"):
            for spec in cfg["evm"].get("imports", []):
                records += evm.load(spec)
        self.res["evm_records"] = records
        self.res["gas_limits"] = {}
        for G in cfg["gas_limits"]:
            factor = 1.0
            iters = []
            for it in range(cfg.get("max_iterations", 2)):
                c = self.constants(G, factor)
                self.log(f"G={G}: iteration {it}, rate x{factor:.3f}: " + ", ".join(
                    f"{k}={c[k]:,.0f}" for k in ("LEANSPHINCS_VERIFICATION_GAS", "RECURSIVE_PROOF_SHARE_GAS",
                                                  "LEANSTARK_VERIFICATION_GAS", "LEANSTARK_CLAIM_GAS") if c.get(k) is not None))
                rows = self.verify(G, c, it, records)
                iters.append({"constants": c, "blocks": rows})
                self.res["gas_limits"][str(G)] = {"iterations": iters}
                self.save()
                failing = [r for r in rows if r.get("verdict") and not r["verdict"]["time_ok"]]
                if not failing:
                    break
                worst = max(r["measurement"]["makespan_s"] for r in failing)
                factor = gasmath.recalibrate(factor, worst, cfg["builder_budget_s"]) * 1.02
            final = iters[-1]
            measured = [r for r in final["blocks"] if r.get("verdict")]
            ok = bool(measured) and all(r["verdict"]["pass"] for r in measured)
            skipped = [r["block"] for r in final["blocks"]
                       if r.get("status") in ("skipped", "failed") or r.get("status", "").startswith("unquiet")]
            self.res["gas_limits"][str(G)]["final"] = {
                "constants": final["constants"], "pass": ok, "skipped_or_failed": skipped,
                "verdict": ("PASS" if ok and not skipped else "PASS (partial: " + ", ".join(skipped) + " not measured)"
                            if ok else "FAIL")}
            self.save()
