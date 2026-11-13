"""The Markdown report: every figure labelled measured, imported, extrapolated, modelled or configured."""

from __future__ import annotations

GB = 2**30

# The items of the benchmark methodology (ethereum/EIPs#12664, assets/eip-draft_batched_dependency_pricing/benchmarks.md),
# under its headings. The status column is computed from the run; README.md maps each item to the scenario, config key
# or output that covers it.
METHODOLOGY = {
    "Configuration": [
        ("Prover and verifier revisions and configurations, commitment construction, hashes", "revisions"),
        ("Gas schedule and gas limit", "gas_limits"),
        ("Verifier resource bounds", "bounds"),
        ("Hardware, worker count, threads and memory per worker, safety margins", "hardware"),
        ("Builder and validator time and peak-memory budgets, fixed before calibration", "budgets"),
        ("Memory per worker fixed jointly with the commitment construction and MAX_INNER_PROOFS_PER_STEP", "joint_memory"),
    ],
    "Workloads": [
        ("Maximum-resource leaf, claim count included, with support code, padding, authentication and openings", "max_leaf"),
        ("Jointly valid resource combinations", "joint"),
        ("Full steps at the proposed arity: distinct keys, recursive inputs, mixtures", "full_step"),
        ("Outer trace and proof-size bounds", "outer"),
        ("Complete transaction gas accounting", "tx"),
        ("EVM-dominated blocks", "evm"),
        ("Native-signature blocks", "native"),
        ("Unaggregated singleton generic proofs under distinct keys", "generic"),
        ("Full batch leaves; one claim per maximum-resource leaf with its payment", "batch_blocks"),
        ("Adversarial mixtures", "mix"),
        ("One leaf per initial step, no shared-key preprocessing savings", "unpacked"),
        ("Overlapping leaves, source selection, payment lookup, pruning, finalization", "batch_tree"),
        ("Intended application verifiers fit the resource bounds", "apps"),
    ],
    "Measurements": [
        ("Makespan at the stated worker count, with critical paths and inter-worker transfers", "makespan"),
        ("Authentication and recursion costs, total work, depth, critical path", "costs"),
        ("Per-worker and aggregate peak memory", "memory_measured"),
        ("Proof sizes and transmitted bytes", "bytes"),
        ("Validator execution and proof verification against their budgets", "validator"),
        ("192-byte intermediate records in memory and serialization", "records"),
        ("Own process per step, warm-up discarded, >= 3 timed repetitions, median and range", "reps"),
        ("No competing load or swap growth; violations repeated, then excluded", "conditions"),
        ("Deterministic cycle counts alongside times", "cycles"),
        ("Cumulative claim hashing and payment binding; per-record vs amortized carry", "binding"),
        ("Maximum-resource batch leaf measured separately from an ordinary generic leaf", "batch_leaf"),
        ("Measured results separated from models and extrapolations", "labels"),
    ],
    "Calibration": [
        ("Native, generic, proof-share and batch-claim charges from the same budgets", "derived"),
        ("Block workloads repeated with the proposed schedule; all must fit", "verified"),
        ("Covers only the measured gas limits, configurations and bounds", "scope"),
    ],
}


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
        return f"configured: {res['config']['memory_per_worker_gb']} GB per worker"
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
        local = res["config"]["workers"].get("mode", "local") == "local"
        return "measured (wall clock across workers, transfers included)" + (", loopback only" if local else "")
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
    if key == "unpacked":
        return "by construction: one generic leaf per initial step"
    if key == "max_leaf":
        claims = f", {res['config']['bounds']['claims']} claims" if res.get("builds", {}).get("batch") else ", claims not measured"
        return (f"code 2^{pre.get('code_log_used')} of 2^{res['config']['bounds']['code_log']}, trace 2^{pre.get('trace_log_used')} "
                f"of 2^{pre.get('trace_log_requested')}" + (" (scaled down)" if pre.get("trace_log_used") != pre.get("trace_log_requested") else "") + claims)
    if key == "binding":
        return "measured" if cells.get("finalize-r1", {}).get("status") == "ok" else "not measured (no batch build)"
    if key == "batch_blocks":
        got = [m for m in ("batch_one_claim", "batch_full") if m in measured]
        return f"{tag}: {', '.join(got)}" if got else "not measured"
    if key == "bounds":
        return "configured: " + ", ".join(f"{k} {v}" for k, v in res["config"]["bounds"].items())
    if key == "budgets":
        c = res["config"]
        return f"configured: builder {c['builder_budget_s']} s, validator {c['validator_budget_s']} s, {c['memory_per_worker_gb']} GB per worker"
    if key == "joint_memory":
        n, mi = pre.get("step_leaves"), res["config"]["bounds"]["max_inner_proofs_per_step"]
        if n is None:
            return "not run"
        return (f"fits: a full {mi}-leaf step within {res['config']['memory_per_worker_gb']} GB per worker ({res['config']['key']} key)"
                if n == mi else f"does not fit: {n} of {mi} leaves within {pre.get('budget_gb', 0):.0f} GB ({res['config']['key']} key)")
    if key == "reps":
        c = res["config"]
        timed = c.get("reps", 4) - 1
        return (f"configured: {timed + 1} runs per cell, the first discarded; median and range of {timed} timed"
                + ("" if timed >= 3 else " (fewer than the 3 required)"))
    if key == "conditions":
        ex = sum(c.get("excluded", 0) for c in cells.values())
        return (f"measured: quiet gate (load1 < {c_quiet(res)}) and swap check; {ex} cell repetitions excluded; "
                "an unquiet block is proved again, then not counted")
    if key == "cycles":
        return "measured: cycles per cell and per block node"
    if key == "batch_leaf":
        ok = all(cells.get(n, {}).get("status") == "ok" for n in ("batch-leaf-r1", "generic-leaf"))
        return "measured: batch-leaf vs generic-leaf cells" if ok else "not measured"
    if key == "joint":
        return "not covered: the generator raises one loop's trace; the other tables' joint maxima are not defined"
    if key == "outer":
        c = cells.get(f"full-step-{pre.get('step_leaves')}", {})
        return (f"measured: committed 2^{_f(c.get('log_committed'), 2)}, proof {_f(c.get('proof_bytes'))} B; "
                "not checked against a fork bound") if c.get("status") == "ok" else "not measured"
    if key == "batch_tree":
        return ("partly: source selection, payment lookup, pruning (retain) and finalization in batch blocks; overlapping leaves not exercised"
                if res.get("builds", {}).get("batch") else "not measured (no batch build)")
    if key == "apps":
        return "not covered"
    if key == "memory_measured":
        return "measured per worker (peak RSS); aggregate = sum of worker peaks"
    if key == "bytes":
        return "measured: proof bytes per cell, input/transfer/root bytes per block"
    if key == "records":
        return ("partly: included in transferred bytes, not reported separately"
                if res.get("builds", {}).get("batch") else "not measured (no batch build)")
    if key == "labels":
        return "every figure labelled"
    if key == "derived":
        return "derived from measured marginals and one budget (rate = G / (W·B/margin))"
    if key == "scope":
        return "configured gas limits only: " + ", ".join(f"{int(g):,}" for g in res["config"]["gas_limits"])
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
    L.append("## Configuration\n")
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
    for s in res.get("skipped", []):
        L.append(f"- **Skipped:** {s}.")
    if w.get("mode", "local") == "local" and w["count"] > 1:
        L.append("- Co-located workers share one machine's memory bandwidth and loopback network: transfers are measured "
                 "but are not a network's.")
    L.append("")

    _items(L, res, "Configuration")

    L.append("## Workloads\n")
    for n in res.get("preflight", {}).get("notes", []):
        L.append(f"- **Preflight:** {n}.")
    leaves = res.get("leaves", {})
    if leaves:
        first = next(iter(leaves.values()))
        L.append(f"- Maximum-resource leaf (inner proof, measured): {first.get('inner_instructions')} instructions "
                 f"(2^{first.get('inner_code_log')} padded), committed 2^{_f(first.get('inner_log_committed'), 2)}, "
                 f"witness {first.get('witness_bytes', 0) / 1024:.0f} KiB, inner proving {_f(first.get('inner_prove_s'))} s.")
    L.append("- Block compositions per gas limit and iteration are listed under Calibration.\n")
    _items(L, res, "Workloads")

    L.append("## Measurements\n")
    _items(L, res, "Measurements")
    L.append("### Steps (measured, one step per process, median of timed repetitions)\n")
    L.append("| cell | status | prove s [min–max] | cycles | committed log2 | peak RSS GB | excluded |\n|---|---|---|---|---|---|---|")
    for name, c in res.get("cells", {}).items():
        if c.get("status") == "ok":
            L.append(f"| {name} | ok ({c['reps']}) | {c['prove_s']:.3f} [{c['prove_min']:.3f}–{c['prove_max']:.3f}] | "
                     f"{c['cycles']:,.0f} | {_f(c['log_committed'], 2)} | {c['peak_rss'] / GB:.2f} | {c.get('excluded', '—')} |")
        else:
            L.append(f"| {name} | {c.get('status')}: {c.get('reason') or c.get('error') or ''} | | | | | |")
    L.append("")
    m = res.get("marginals", {})
    if m:
        L.append("Marginal machine-seconds (measured slopes): " + ", ".join(
            f"{k} {_f(v, 5)}" for k, v in m.items() if k != "labels") + ".\n")
        for k, v in (m.get("labels") or {}).items():
            L.append(f"- {k}: {v}")
        L.append("")

    L.append("Block makespans, critical paths, work, depth, transfers and memory are in the block tables under Calibration.\n")

    L.append("## Calibration\n")
    _items(L, res, "Calibration")
    for G, g in res.get("gas_limits", {}).items():
        L.append(f"### Gas limit {int(G):,}\n")
        for i, it in enumerate(g.get("iterations", [])):
            c = it["constants"]
            L.append(f"#### Iteration {i} (rate x{c['rate_factor']:.3f}, {c['rate_gas_per_machine_s']:,.0f} gas per machine-second, "
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

    L.append("## Not covered by this run\n")
    for item in unmeasured(res):
        L.append(f"- {item}")
    return "\n".join(L) + "\n"


def c_quiet(res: dict) -> float:
    return res["config"].get("quiet", {}).get("max_load1", 5)


def _items(L: list[str], res: dict, section: str):
    L.append("| methodology item | this run |\n|---|---|")
    for text, key in METHODOLOGY[section]:
        L.append(f"| {text} | {_status(res, key)} |")
    L.append("")


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
        out.append("Payment binding and batch blocks: no batch-pricing build.")
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
