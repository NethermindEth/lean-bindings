"""Worst-case inputs for the ethereum/EIPs#12664 charges, as single-step cells on the batch guest.

The calibration's cells measure marginals; these measure the most expensive valid inputs a charge must cover:

- `leaf-c256-r256`: one maximum-resource leaf (2^11 instructions, the largest provable trace, 256 claims), every claim
  sponsored with its payment: what `LEANSTARK_LEAF_PAYMENT_GAS` pays for.
- `step16-c256-r1` / `-r256`: a full step of 16 such leaves with one claim each retained (the adversarial block's node:
  a leaf payment per retained claim) and with all 4,096 claims retained (the most records a step establishes).
- `mergebatch-16x1` / `-16x256` and `finalize-16x1` / `-16x256`: a merge of 16 sponsored-leaf children, and the
  finalizing step over them, at 1 and 256 retained claims a child: the per-record carry and finalization cost at
  16 x 257 = 4,112 records, the widest list a merge of full leaves carries.

Leaves are generated once (untimed) like the calibration's maximum-resource leaves; cells follow the suite's rules
(one process each, a discarded warm-up repetition, the quiet gate, repeat-then-exclude).

With `share_blocks`, it also proves one worker's share of a block at the #12664 charges (`G / W` gas, W = 16): the
largest adversarial composition of each kind within that share, on one machine (W = 1), one leaf per initial step and
fan-in 16. Each is proved `reps` times on fresh workers; the first is discarded. A W = 16 makespan is then a model:
the slowest share plus the cross-worker merge and finalization (see the report).
"""

from __future__ import annotations

import json
import os
import time

from . import build as builder
from . import host
from .pipeline import TRACE_STEP, iters_for_trace
from .runner import Runner

CLAIMS = 256
STEP = 16
# ethereum/EIPs#12664 @ 539579f7: per-dependency charges including the intrinsic proof share.
SPEC_GAS = {"native": 15_400 + 5_100, "generic": 572_000 + 5_100, "payment": 675_000, "claim": 4_200}


def share_compositions(share_gas: int) -> dict:
    """The adversarial block shares: the most of each input kind that `share_gas` buys at the spec's charges."""
    g = SPEC_GAS
    return {
        "native": {"sigs": share_gas // g["native"]},
        "generic": {"generic": share_gas // g["generic"]},
        "batch_one_claim": {"batch": share_gas // (g["payment"] + g["claim"]), "retain": 1},
        "batch_full": {"batch": share_gas // (g["payment"] + CLAIMS * g["claim"]), "retain": CLAIMS},
    }


def run(cfg: dict, out: str, log) -> dict:
    os.makedirs(out, exist_ok=True)
    res = {"host": host.record(), "config": cfg, "notes": []}
    path = os.path.join(out, "worst-cases.json")

    def save():
        json.dump(res, open(path, "w"), indent=1, default=str)

    b = builder.build(cfg["lib_ref"], out, log=log)
    res["build"] = b
    if not {"batch", "committed"} <= set(b["features"]):
        raise SystemExit(f"{cfg['lib_ref']} lacks the batch guest or the committed key ({b['features']})")
    runner = Runner(out, cfg, log)
    trace_log = float(cfg["bounds"]["trace_log"])
    leaves = []
    for i in range(cfg.get("batch_leaves", STEP)):
        while True:
            try:
                p, meta = runner.leaf(b, cfg["bounds"]["code_log"], iters_for_trace(trace_log),
                                      cfg["bounds"]["inner_log_inv_rate"], CLAIMS, 5000 + i)
                break
            except RuntimeError as e:
                if "WitnessOutOfRange" not in str(e) or trace_log <= 16:
                    raise
                trace_log = round(trace_log - TRACE_STEP, 2)
                res["notes"].append(f"trace lowered to 2^{trace_log:g} to fit the committed-witness bound")
        leaves.append(p)
        res.setdefault("leaves", []).append(meta)
        save()
    res["trace_log_used"] = trace_log
    one = leaves[:1]
    cells = [
        ("leaf-c256-r256", ["leaves", "batched", str(CLAIMS), *one]),
        ("step16-c256-r1", ["leaves", "batched", "1", *leaves]),
        ("step16-c256-r256", ["leaves", "batched", str(CLAIMS), *leaves]),
        ("mergebatch-16x1", ["mergebatch", "1", *leaves]),
        ("mergebatch-16x256", ["mergebatch", str(CLAIMS), *leaves]),
        ("finalize-16x1", ["finalize", "1", *leaves]),
        ("finalize-16x256", ["finalize", str(CLAIMS), *leaves]),
    ]
    if cfg.get("cells", True):
        log(f"worst-case cells on {b['label']}: {len(cells)} x {cfg['reps']} reps")
        res["cells"] = runner.cells(b, cells, cfg["reps"])
        save()
    if cfg.get("share_blocks"):
        res["share_blocks"] = share_blocks(runner, b, leaves, cfg, trace_log, log)
    res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save()
    return res


def share_blocks(runner: Runner, b: dict, batch_leaves: list[str], cfg: dict, trace_log: float, log) -> dict:
    share_gas = cfg["gas_limit"] // cfg["model_workers"]
    comps = share_compositions(share_gas)
    header = ["guest batched", f"fanin {STEP}", f"max_inner {STEP}", "sigs_per_node 64"]
    plans = {}
    for name, c in comps.items():
        if "sigs" in c:
            lines = [f"sigs {runner.sigs(b, c['sigs'], seed=2)}"]
        elif "generic" in c:
            lines = [f"generic {runner.leaf(b, cfg['bounds']['code_log'], iters_for_trace(trace_log), cfg['bounds']['inner_log_inv_rate'], 1, 20000 + i)[0]}"
                     for i in range(c["generic"])]
        else:
            if c["batch"] > len(batch_leaves):
                raise SystemExit(f"{name} needs {c['batch']} leaves; {len(batch_leaves)} generated")
            lines = [f"batch {p} {c['retain']}" for p in batch_leaves[:c["batch"]]]
        plans[name] = header + lines
    out = {"share_gas": share_gas, "spec_gas": SPEC_GAS, "compositions": comps, "runs": {}}
    for name, plan in plans.items():
        runs = []
        for rep in range(cfg["reps"]):
            r = runner.block(b, f"share-{name}-rep{rep}", plan)
            if rep >= 1 and not r.get("gate", {}).get("quiet", True):
                r = runner.block(b, f"share-{name}-rep{rep}-retry", plan)
            runs.append({k: v for k, v in r.items() if k not in ("node_records", "per_worker")} | {"rep": rep})
        out["runs"][name] = runs
    return out
