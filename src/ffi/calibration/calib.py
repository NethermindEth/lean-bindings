#!/usr/bin/env python3
"""EIP-8288 / EIPs#12664 activation gas calibration. See README.md.

  calib.py run --config CONFIG --out DIR      preflight, build, cells, constants, verification blocks, report
  calib.py preflight --config CONFIG          what the machine can measure, and what would be scaled down
  calib.py build --ref REF --out DIR          build the binaries against a library revision
  calib.py report --out DIR                   re-render DIR/report.md from DIR/calibration.json
  calib.py worst --config CONFIG --out DIR    worst-case cells for the batch charges (calib/worst.py)
  calib.py pq-leaves --config CONFIG --out DIR  post-quantum signature leaves (calib/pq_leaves.py)
"""

import argparse
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from calib import build, host, pipeline, pq_leaves, report, worst  # noqa: E402


def load(path: str) -> dict:
    cfg = json.load(open(path))
    cfg.setdefault("reps", 4)
    cfg.setdefault("fanin", 4)
    cfg.setdefault("sigs_per_node", 64)
    return cfg


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--set", action="append", default=[], metavar="KEY=JSON", help="override a top-level config key")
    f = sub.add_parser("preflight")
    f.add_argument("--config", required=True)
    b = sub.add_parser("build")
    b.add_argument("--ref", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--features", help="comma-separated; default: detected from the revision")
    o = sub.add_parser("report")
    o.add_argument("--out", required=True)
    for name in ("worst", "pq-leaves"):
        w = sub.add_parser(name)
        w.add_argument("--config", required=True)
        w.add_argument("--out", required=True)
        w.add_argument("--set", action="append", default=[], metavar="KEY=JSON", help="override a top-level config key")
    a = p.parse_args()

    if a.cmd == "preflight":
        cfg = load(a.config)
        print(json.dumps({"host": host.record(), "preflight": pipeline.preflight(cfg, host.memory())}, indent=1, default=str))
    elif a.cmd == "build":
        feats = a.features.split(",") if a.features is not None else None
        print(json.dumps(build.build(a.ref, a.out, [x for x in (feats or []) if x] if feats is not None else None)))
    elif a.cmd == "report":
        res = json.load(open(os.path.join(a.out, "calibration.json")))
        open(os.path.join(a.out, "report.md"), "w").write(report.render(res))
    elif a.cmd in ("worst", "pq-leaves"):
        cfg = load(a.config)
        for kv in a.set:
            k, v = kv.split("=", 1)
            cfg[k] = json.loads(v)
        os.makedirs(a.out, exist_ok=True)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        logf = open(os.path.join(a.out, f"{a.cmd}.log"), "a")

        def log(msg):
            line = f"[{time.strftime('%H:%M:%S')}] {msg}"
            print(line, flush=True)
            logf.write(line + "\n")
            logf.flush()

        (worst if a.cmd == "worst" else pq_leaves).run(cfg, a.out, log)
    elif a.cmd == "run":
        cfg = load(a.config)
        for kv in a.set:
            k, v = kv.split("=", 1)
            cfg[k] = json.loads(v)
        os.makedirs(a.out, exist_ok=True)
        # A runner's timeout sends SIGTERM: finish through the `finally` below so the partial results and report remain.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        logf = open(os.path.join(a.out, "calib.log"), "a")

        def log(msg):
            line = f"[{time.strftime('%H:%M:%S')}] {msg}"
            print(line, flush=True)
            logf.write(line + "\n")
            logf.flush()

        c = pipeline.Calibration(cfg, a.out, log)
        try:
            c.setup()
            c.cells()
            c.calibrate()
        finally:
            c.res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            c.save()
            if "cells" in c.res:
                open(os.path.join(a.out, "report.md"), "w").write(report.render(c.res))
        for G, g in c.res.get("gas_limits", {}).items():
            log(f"G={G}: {g.get('final', {}).get('verdict')}")


if __name__ == "__main__":
    main()
