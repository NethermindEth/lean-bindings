"""Runs the binaries: corpus generation, single-step cells with repetitions, and distributed blocks on W workers."""

from __future__ import annotations

import json
import os
import secrets
import shlex
import socket
import statistics
import subprocess
import time

from . import host


def result_line(stdout: str) -> dict | None:
    for line in stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    return None


class Runner:
    def __init__(self, out: str, cfg: dict, log=print):
        self.out, self.cfg, self.log = out, cfg, log
        self.quiet = cfg.get("quiet", {"max_load1": 5, "timeout_s": 1800})
        os.makedirs(os.path.join(out, "logs"), exist_ok=True)
        self.jsonl = open(os.path.join(out, "runs.jsonl"), "a")
        # The run key authenticates every coordinator/worker frame. It lives only in this process's memory and the
        # children's environment, and in a private temporary file for remote launches; never in logs or results.
        self.token = secrets.token_hex(32)
        self.token_file = None

    def env(self, threads: int | None = None) -> dict:
        e = dict(os.environ)
        e["LEANVM_NUM_THREADS"] = str(threads or self.cfg["threads_per_worker"])
        e["CALIB_TOKEN"] = self.token
        return e

    def token_path(self) -> str:
        if self.token_file is None:
            import atexit
            import tempfile
            fd, path = tempfile.mkstemp(prefix="calib-token-")
            os.fchmod(fd, 0o600)
            os.write(fd, self.token.encode())
            os.close(fd)
            atexit.register(lambda: os.path.exists(path) and os.unlink(path))
            self.token_file = path
        return self.token_file

    def gate(self) -> dict:
        return host.wait_quiet(self.quiet.get("max_load1", 5), self.quiet.get("timeout_s", 1800))

    # ---- corpus -------------------------------------------------------------------------------------------------
    def leaf(self, build: dict, pad: int, iters: int, rate: int, claims: int, seed: int) -> tuple[str, dict]:
        d = os.path.join(self.out, "corpus", build["label"])
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"leaf-p{pad}-i{iters}-r{rate}-c{claims}-s{seed}.bin")
        meta = path + ".json"
        if os.path.exists(path) and os.path.exists(meta):
            return path, json.load(open(meta))
        p = subprocess.run([os.path.join(build["bin"], "calib-node"), "leaf", path, str(pad), str(iters), str(rate),
                            str(claims), str(seed)], capture_output=True, text=True, env=self.env())
        res = result_line(p.stdout)
        if p.returncode != 0 or res is None:
            raise RuntimeError(f"leaf generation failed ({p.returncode}): {p.stderr[-2000:]}")
        json.dump(res, open(meta, "w"))
        return path, res

    def sigs(self, build: dict, count: int, seed: int = 1) -> str:
        d = os.path.join(self.out, "corpus", "sigs")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"sigs-{count}-s{seed}.bin")
        if not os.path.exists(path):
            subprocess.run([os.path.join(build["bin"], "calib-node"), "sigs", path, str(count), str(seed)], check=True,
                           env=self.env())
        return path

    # ---- cells --------------------------------------------------------------------------------------------------
    def cells(self, build: dict, cells: list[tuple[str, list[str]]], reps: int) -> dict:
        """Runs each cell `reps` times, one process each, interleaved across cells; rep 0 is a discarded warm-up.
        Returns per-cell summaries keyed by name."""
        raw: dict[str, list[dict]] = {name: [] for name, _ in cells}
        for rep in range(reps):
            for name, args in cells:
                g = self.gate()
                mem0 = host.memory()
                t0 = time.time()
                p = subprocess.run([os.path.join(build["bin"], "calib-node"), "cell", *args], capture_output=True,
                                   text=True, env=self.env())
                wall = time.time() - t0
                mem1 = host.memory()
                tag = f"{build['label']}_{name}_rep{rep}"
                open(os.path.join(self.out, "logs", tag + ".out"), "w").write(p.stdout + "\n---stderr---\n" + p.stderr)
                rec = {"kind": "cell", "build": build["label"], "cell": name, "args": args, "rep": rep, "rc": p.returncode,
                       "wall_s": wall, "gate": g, "swap_used_before": mem0["swap_used"], "swap_used_after": mem1["swap_used"],
                       "available_before": mem0["available"], "result": result_line(p.stdout)}
                self.jsonl.write(json.dumps(rec) + "\n")
                self.jsonl.flush()
                raw[name].append(rec)
                r = rec["result"] or {}
                self.log(f"  cell {name} rep{rep}: rc={p.returncode} {r.get('status')} prove={r.get('prove_s')} "
                         f"rss={r.get('peak_rss', 0) / 2**30:.2f}G load={g['load1']:.1f}")
        return {name: summarize(recs) for name, recs in raw.items()}

    # ---- workers and blocks -------------------------------------------------------------------------------------
    def start_workers(self, build: dict) -> tuple[list[str], list[subprocess.Popen]]:
        w = self.cfg["workers"]
        if w.get("mode", "local") == "remote":
            procs = []
            for i, addr in enumerate(w["hosts"]):
                if w.get("launch"):
                    hostname, port = addr.rsplit(":", 1)
                    # Peers a worker accepts: the coordinator and the other workers, by IP.
                    allow = ",".join(dict.fromkeys([w["coordinator_ip"], *(h.rsplit(":", 1)[0] for h in w["hosts"])]))
                    cmd = w["launch"].format(host=hostname, port=port, threads=self.cfg["threads_per_worker"], index=i,
                                             token_file=self.token_path(), allow=allow)
                    procs.append(subprocess.Popen(shlex.split(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            addrs = list(w["hosts"])
        else:
            base = w.get("base_port", 47100)
            addrs = [f"127.0.0.1:{base + i}" for i in range(w["count"])]
            procs = []
            for i, a in enumerate(addrs):
                log = open(os.path.join(self.out, "logs", f"worker-{i}.log"), "a")
                procs.append(subprocess.Popen([os.path.join(build["bin"], "calib-worker"), a], stdout=log, stderr=log,
                                              env=self.env()))
        deadline = time.time() + w.get("ready_timeout_s", 300)
        for a in addrs:
            h, p = a.rsplit(":", 1)
            while True:
                try:
                    socket.create_connection((h, int(p)), timeout=2).close()
                    break
                except OSError:
                    if time.time() > deadline:
                        self.stop_workers(procs)
                        raise RuntimeError(f"worker {a} did not come up")
                    time.sleep(0.5)
        return addrs, procs

    def stop_workers(self, procs: list[subprocess.Popen]):
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()

    def block(self, build: dict, label: str, plan_lines: list[str]) -> dict:
        """Proves one block on fresh workers (so each worker's peak memory is this block's) and returns the
        coordinator's measurement."""
        d = os.path.join(self.out, "blocks")
        os.makedirs(d, exist_ok=True)
        plan = os.path.join(d, f"{label}.plan")
        result = os.path.join(d, f"{label}.json")
        open(plan, "w").write("\n".join([f"label {label}", *plan_lines]) + "\n")
        g = self.gate()
        addrs, procs = self.start_workers(build)
        try:
            p = subprocess.run([os.path.join(build["bin"], "calib-coord"), plan, ",".join(addrs), result],
                               capture_output=True, text=True, env=self.env(1))
        finally:
            self.stop_workers(procs)
        open(os.path.join(self.out, "logs", f"block-{label}.log"), "w").write(p.stdout + p.stderr)
        if p.returncode != 0 or not os.path.exists(result):
            res = {"label": label, "status": "failed", "error": (p.stderr or p.stdout)[-2000:]}
        else:
            res = json.load(open(result))
        res["gate"] = g
        self.jsonl.write(json.dumps({"kind": "block", "build": build["label"], "label": label,
                                     "result": {k: v for k, v in res.items() if k != "node_records"}}) + "\n")
        self.jsonl.flush()
        self.log(f"  block {label}: {res.get('status')} makespan={res.get('makespan_s')} work={res.get('total_work_s')}"
                 f" depth={res.get('depth')} nodes={res.get('nodes')}")
        return res


def summarize(recs: list[dict]) -> dict:
    timed = [r for r in recs if r["rep"] >= 1 and r["rc"] == 0 and r["result"] and r["result"].get("status") == "ok"]
    first = next((r["result"] for r in recs if r["result"]), None) or {}
    if first.get("status") == "skipped":
        return {"status": "skipped", "reason": first.get("reason")}
    if not timed:
        return {"status": "failed", "reps": len(recs), "error": first.get("error"),
                "rc": [r["rc"] for r in recs]}
    res = [r["result"] for r in timed]
    pv = [x["prove_s"] for x in res]
    swapped = any(r["swap_used_after"] > r["swap_used_before"] + 64 * 2**20 for r in timed)
    return {"status": "ok", "reps": len(timed), "prove_s": statistics.median(pv), "prove_min": min(pv),
            "prove_max": max(pv), "cycles": statistics.median(x["node_cycles"] for x in res),
            "log_committed": res[0].get("node_log_committed"), "proof_bytes": res[0].get("proof_bytes"),
            "peak_rss": max(x["peak_rss"] for x in res), "verify_ms": statistics.median(x["verify_ms"] for x in res),
            "swapped": swapped, "load1_max": max(r["gate"]["load1"] for r in timed),
            "quiet": all(r["gate"]["quiet"] for r in timed), "extra": {k: v for k, v in res[0].items()
                                                                      if k in ("sigs", "children", "claims_per_child", "leaves", "claims", "retain", "records")}}
