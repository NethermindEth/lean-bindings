"""Exits 1 when a manual (workflow_dispatch) benchmark run is waiting for, or running on, a self-hosted runner label.

    manual_runs.py OWNER/REPO LABEL

Only manual runs of the repository's reproducible benchmark workflows count: automated push, pull_request and
workflow_run runs queue behind this one as usual. Reads GH_TOKEN or GITHUB_TOKEN; without one, or when the API cannot
be read, it reports the runner as in use, so the caller does not run.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

WORKFLOWS = ("run-expb-reproducible-benchmarks.yml", "run-rpc-benchmarks.yml")
ACTIVE = ("queued", "waiting", "pending", "requested", "in_progress")


def get(repo: str, path: str, token: str) -> dict:
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/{path}",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def blocking_runs(repo: str, label: str, token: str, fetch=get) -> list[str]:
    found = []
    for wf in WORKFLOWS:
        for status in ACTIVE:
            runs = fetch(repo, f"actions/workflows/{wf}/runs?event=workflow_dispatch&status={status}&per_page=50", token)
            for run in runs.get("workflow_runs", []):
                jobs = fetch(repo, f"actions/runs/{run['id']}/jobs?per_page=100", token).get("jobs", [])
                # A dispatch whose resolve job has not picked a box yet may still pick this one.
                undecided = not any(lb.startswith("reproducible-benchmarks") for j in jobs for lb in j.get("labels", []))
                mine = any(label in j.get("labels", []) and j.get("status") != "completed" for j in jobs)
                if mine or undecided:
                    found.append(f"{wf} run {run['id']} ({status})")
    return found


def main() -> int:
    repo, label = sys.argv[1], sys.argv[2]
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("no GH_TOKEN: treating the runner as in use", file=sys.stderr)
        return 1
    try:
        found = blocking_runs(repo, label, token)
    except Exception as e:  # noqa: BLE001 - any API failure means we cannot tell, so yield
        print(f"cannot read {repo}'s runs ({e}): treating the runner as in use", file=sys.stderr)
        return 1
    for f in found:
        print(f"manual run in the way: {f}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
