"""The Markdown report: every figure labelled measured, imported, extrapolated, modelled or configured."""

from __future__ import annotations

GB = 2**30

# EIPs#12654 (EIP-8288 "Activation requirements") and EIPs#12664 ("Activation requirements"), one row each: how the
# suite covers it. The status column is computed from the run.
CHECKLIST = [
    ("Calibrated block gas limit; calibration per gas limit", "gas_limits"),
    ("Builder aggregation time budget (makespan)", "builder"),
    ("Validator execution and verification time budget", "validator"),
    ("Peak-memory budgets, per worker and aggregate", "memory"),
    ("Reference revisions and configurations", "revisions"),
    ("Hardware, workers, threads and memory per worker, margins", "hardware"),
    ("Complete transaction gas accounting", "tx"),
    ("Blocks dominated by native signatures", "native"),
    ("Blocks of distinct-key singleton generic proofs (maximum resources)", "generic"),
    ("Blocks dominated by EVM execution", "evm"),
    ("Adversarial mixtures", "mix"),
    ("Measured makespan at the stated worker count, critical path, inter-worker transfers", "makespan"),
    ("Program-commitment authentication, recursion costs, total work, tree depth, transmitted bytes", "costs"),
    ("No shared-key or packed-leaf discounts", "unpacked"),
    ("Full steps at MAX_INNER_PROOFS_PER_STEP", "full_step"),
    ("Maximum-resource leaves (code 2^11, heights 2^30, rate 1/2, 256 claims)", "max_leaf"),
    ("#12664: payment binding, intermediate records, finalization", "binding"),
    ("#12664: one claim per maximum-resource leaf with its payment; full 256-claim leaves", "batch_blocks"),
    ("Constants derived from one common budget, then verified by measured blocks", "verified"),
]


def _f(x, d=3):
    return "—" if x is None else (f"{x:,.{d}f}" if isinstance(x, float) else f"{x:,}")


def _status(res: dict, key: str) -> str:
    pre = res.get("preflight", {})
    cells = res.get("cells", {})
    gl = res.get("gas_limits", {})
    blocks = [b for g in gl.values() for b in g.get("iterations", [{}])[-1].get("blocks", [])]
    measured = {b["block"] for b in blocks if b.get("verdict") and b.get("measurement")}
    scale = res["config"].get("block_scale", 1.0)
    tag = "measured" if scale == 1.0 else f"measured, blocks scaled to {scale}"
    if key == "gas_limits":
        return f"configured: {', '.join(f'{int(g):,}' for g in res['config']['gas_limits'])}"
    if key == "builder":
        return f"measured against B = {res['config']['builder_budget_s']} s"
    if key == "validator":
        ev = any(b.get("evm", {}).get("label", "none") not in ("none", "unmeasured") for b in blocks)
        return "measured (root verification) + " + ("imported EVM timings" if ev else "EVM not imported")
    if key == "memory":
        return "measured per worker (peak RSS); aggregate = sum of worker peaks"
    if key == "revisions":
        b = res.get("builds", {})
        return ", ".join(f"{k} {v['sha'][:10]} {v['features']}" for k, v in b.items() if v)
    if key == "hardware":
        h = res.get("host", {})
        return f"{h.get('cpu') or h.get('machine')}, {h.get('cpus')} CPUs, {h.get('memory', {}).get('total', 0) / GB:.0f} GB"
    if key == "tx":
        return "EIP-8141 intrinsic + per-frame + EIP-7976 triple data + signature (estimate) + EIP-7825 cap"
    if key in ("native", "generic", "evm"):
        name = {"native": "native", "generic": "generic", "evm": "evm"}[key]
        if key == "evm":
            return "imported" if any(b["block"] == "evm" and b["evm"].get("ms") for b in blocks) else "not imported"
        return tag if name in measured else "not measured"
    if key == "mix":
        got = sorted(m for m in measured if m.startswith("mix"))
        return f"{tag}: {', '.join(got)}" if got else "not measured"
    if key == "makespan":
        return "measured (wall clock across workers, transfers included)"
    if key == "costs":
        return "measured per node: cycles, prove/fetch/decode time, depth, bytes"
    if key == "unpacked":
        return "by construction: one generic leaf per initial step"
    if key == "full_step":
        n = pre.get("step_leaves")
        mi = res["config"]["bounds"]["max_inner_proofs_per_step"]
        c = cells.get(f"full-step-{n}", {})
        s = c.get("status", "not run")
        return f"{s} with {n} of {mi} leaves" + (" (scaled down)" if n != mi else "")
    if key == "max_leaf":
        return (f"code 2^{pre.get('code_log_used')} of 2^{res['config']['bounds']['code_log']}, trace 2^{pre.get('trace_log_used')} "
                f"of 2^{pre.get('trace_log_requested')}" + (" (scaled down)" if pre.get("trace_log_used") != pre.get("trace_log_requested") else ""))
    if key == "binding":
        return "measured" if cells.get("finalize-r1", {}).get("status") == "ok" else "not measured (no batch build)"
    if key == "batch_blocks":
        got = [m for m in ("batch_one_claim", "batch_full") if m in measured]
        return f"{tag}: {', '.join(got)}" if got else "not measured"
    if key == "verified":
        v = [g.get("final", {}).get("verdict") for g in gl.values()]
        return "; ".join(str(x) for x in v) or "not run"
    return ""


def render(res: dict) -> str:
    cfg = res["config"]
    L = []
    L.append(f"# Gas calibration: {cfg.get('label', 'run')}\n")
    L.append("Labels: **measured** on this machine; **imported** from another tool's measurement; **extrapolated** "
             "(a measured slope beyond its range); **modelled** (composed from measured parts, never a verdict); "
             "**configured**.\n")
    h = res.get("host", {})
    L.append("## Setup\n")
    L.append(f"- Host: {h.get('cpu') or h.get('machine')} ({h.get('system')} {h.get('release')}), {h.get('cpus')} CPUs, "
             f"{h.get('memory', {}).get('total', 0) / GB:.0f} GB; {h.get('memory', {}).get('available', 0) / GB:.1f} GB available "
             f"and {h.get('memory', {}).get('swap_used', 0) / GB:.1f} GB swap in use at start; {h.get('rustc')}.")
    w = cfg["workers"]
    wdesc = f"{w['count']} local processes" if w.get("mode", "local") == "local" else f"{len(w['hosts'])} remote hosts"
    L.append(f"- Workers: {wdesc}, {cfg['threads_per_worker']} threads each; reference W = {cfg['reference_workers']}; "
             f"memory per worker {cfg['memory_per_worker_gb']} GB; margin {cfg['margin']}; builder budget "
             f"{cfg['builder_budget_s']} s; validator budget {cfg['validator_budget_s']} s; fan-in {cfg['fanin']}; "
             f"{cfg['sigs_per_node']} signatures a step; key {cfg['key']}.")
    for k, b in res.get("builds", {}).items():
        if b:
            L.append(f"- Build `{k}`: {b['ref']} @ {b['sha'][:10]}, features {b['features'] or 'none'}.")
    for n in res.get("preflight", {}).get("notes", []):
        L.append(f"- **Preflight:** {n}.")
    for s in res.get("skipped", []):
        L.append(f"- **Skipped:** {s}.")
    if w.get("mode", "local") == "local" and w["count"] > 1:
        L.append("- Co-located workers share one machine's memory bandwidth and loopback network: transfers are measured "
                 "but are not a network's.")
    L.append("")

    L.append("## Requirements checklist (EIPs#12654, EIPs#12664)\n")
    L.append("| requirement | this run |\n|---|---|")
    for text, key in CHECKLIST:
        L.append(f"| {text} | {_status(res, key)} |")
    L.append("")

    L.append("## Cells (measured, one step per process, median of timed repetitions)\n")
    L.append("| cell | status | prove s [min–max] | cycles | committed log2 | peak RSS GB | swapped |\n|---|---|---|---|---|---|---|")
    for name, c in res.get("cells", {}).items():
        if c.get("status") == "ok":
            L.append(f"| {name} | ok ({c['reps']}) | {c['prove_s']:.3f} [{c['prove_min']:.3f}–{c['prove_max']:.3f}] | "
                     f"{c['cycles']:,.0f} | {_f(c['log_committed'], 2)} | {c['peak_rss'] / GB:.2f} | {'yes' if c['swapped'] else 'no'} |")
        else:
            L.append(f"| {name} | {c.get('status')}: {c.get('reason') or c.get('error') or ''} | | | | | |")
    leaves = res.get("leaves", {})
    if leaves:
        first = next(iter(leaves.values()))
        L.append(f"\nMaximum-resource leaf (inner proof, measured): {first.get('inner_instructions')} instructions "
                 f"(2^{first.get('inner_code_log')} padded), committed 2^{_f(first.get('inner_log_committed'), 2)}, "
                 f"witness {first.get('witness_bytes', 0) / 1024:.0f} KiB, inner proving {_f(first.get('inner_prove_s'))} s.\n")
    m = res.get("marginals", {})
    if m:
        L.append("Marginal machine-seconds (measured slopes): " + ", ".join(
            f"{k} {_f(v, 5)}" for k, v in m.items() if k != "labels") + ".\n")

    for G, g in res.get("gas_limits", {}).items():
        L.append(f"## Gas limit {int(G):,}\n")
        for i, it in enumerate(g.get("iterations", [])):
            c = it["constants"]
            L.append(f"### Iteration {i} (rate x{c['rate_factor']:.3f}, {c['rate_gas_per_machine_s']:,.0f} gas per machine-second, "
                     f"claims carried through {c['depth']} levels)\n")
            L.append("| constant | value |\n|---|---|")
            for k in ("LEANSPHINCS_VERIFICATION_GAS", "RECURSIVE_PROOF_SHARE_GAS", "LEANSTARK_VERIFICATION_GAS",
                      "LEANSTARK_LEAF_PAYMENT_GAS", "LEANSTARK_CLAIM_GAS"):
                v = c.get(k)
                L.append(f"| `{k}` | {'not measured' if v is None else f'{v:,.0f}'} |")
            L.append("")
            L.append("| block | composition | makespan s | critical path s | work s | depth | nodes | transfers MB | "
                     "peak RSS/worker GB | EVM ms | validator ms | verdict | modelled: work/W, list schedule s |")
            L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
            for b in it["blocks"]:
                comp = ", ".join(f"{k} {v:,.0f}" if isinstance(v, (int, float)) else f"{k} {v}" for k, v in b["composition"].items())
                r = b.get("measurement") or {}
                v = b.get("verdict")
                ev = b.get("evm", {})
                verdict = ("PASS" if v["pass"] else "FAIL") + ("" if b.get("status") == "measured" else " (indicative)") if v else b.get("status")
                mod = r.get("modelled", {})
                L.append(f"| {b['block']} | {comp} | {_f(r.get('makespan_s'))} | {_f(r.get('critical_path_s'))} | "
                         f"{_f(r.get('total_work_s'))} | {_f(r.get('depth'))} | {_f(r.get('nodes'))} | "
                         f"{_f((r.get('bytes_transfers', 0) + r.get('bytes_inputs', 0)) / 1e6 if r else None, 1)} | "
                         f"{_f(r.get('peak_rss_max_worker', 0) / GB if r else None, 2)} | "
                         f"{_f(ev.get('ms'), 0)} ({ev.get('label')}) | {_f(b.get('validator_ms'), 0)} | {verdict} | "
                         f"{_f(mod.get('work_over_workers_s'))}, {_f(mod.get('list_schedule_no_transfer_s'))} |")
            L.append("")
        f = g.get("final", {})
        L.append(f"**Verdict for {int(G):,} gas: {f.get('verdict')}**\n")

    L.append("## Not measured in this run\n")
    for item in unmeasured(res):
        L.append(f"- {item}")
    return "\n".join(L) + "\n"


def unmeasured(res: dict) -> list[str]:
    out = []
    pre = res.get("preflight", {})
    cfg = res["config"]
    if pre.get("trace_log_used") != pre.get("trace_log_requested"):
        out.append(f"Maximum-resource leaves at 2^{pre.get('trace_log_requested')}: measured at 2^{pre.get('trace_log_used')} (memory).")
    if pre.get("code_log_used") != pre.get("code_log_requested"):
        out.append(f"2^{pre.get('code_log_requested')}-instruction leaves: measured 2^{pre.get('code_log_used')} (memory).")
    if pre.get("step_leaves") != cfg["bounds"]["max_inner_proofs_per_step"]:
        out.append(f"Full steps of {cfg['bounds']['max_inner_proofs_per_step']} leaves: measured {pre.get('step_leaves')}.")
    if not res.get("builds", {}).get("batch"):
        out.append("#12664 payment binding and batch blocks: no batch-pricing build.")
    if not res.get("evm_records"):
        out.append("EVM execution: no timings imported; EVM-dominated blocks and EVM mixtures have no validator time.")
    if cfg.get("block_scale", 1.0) != 1.0:
        out.append(f"Full-size blocks: run at scale {cfg['block_scale']}, so verdicts are indicative only.")
    if cfg["workers"].get("mode", "local") == "local":
        out.append("Network transfers between machines: workers were local processes (loopback).")
    if cfg["reference_workers"] != (cfg["workers"].get("count") or len(cfg["workers"].get("hosts", []))):
        out.append("The reference worker count differs from the workers used: the verdicts do not apply to it.")
    out.append("Jointly maximal table heights: the generator raises one loop's trace; other tables' maxima under the "
               "final verifier resource bounds are not yet defined.")
    return out
