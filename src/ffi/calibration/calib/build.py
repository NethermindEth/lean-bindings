"""Builds the suite's binaries against a lean-bindings library revision.

`.` builds in this checkout. Any other git ref is exported (`git archive`) to a cache directory, this suite is copied
over it and added to that revision's workspace, and features are detected from the revision's sources:

- `batch`: the revision's `rec_aggregation` exports `aggregate_finalized` (ethereum/EIPs#12664 leaves and payments).
- `committed`: the revision proves generic programs under a bytecode commitment (`.committed()`).

Scenarios that need a missing feature are reported as skipped.
"""

from __future__ import annotations

import os
import shutil
import subprocess

SUITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FFI = os.path.dirname(SUITE)
REPO = os.path.dirname(os.path.dirname(FFI))
BINARIES = ("calib-node", "calib-worker", "calib-coord")


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", REPO, *args], check=True, capture_output=True, text=True).stdout.strip()


def _has(ref: str, pattern: str, path: str) -> bool:
    if ref == ".":
        return subprocess.run(["grep", "-rqF", pattern, os.path.join(REPO, path)]).returncode == 0
    return subprocess.run(["git", "-C", REPO, "grep", "-qF", pattern, ref, "--", path]).returncode == 0


def detect(ref: str) -> list[str]:
    feats = []
    if _has(ref, "aggregate_finalized", "src/ffi/crates/rec_aggregation/src/lib.rs"):
        feats.append("batch")
    if _has(ref, ".committed()", "src/ffi/crates/rec_aggregation/src"):
        feats.append("committed")
    return feats


def build(ref: str, out_dir: str, features: list[str] | None = None, cache: str | None = None,
          log=print) -> dict:
    """Builds into `out_dir`/bin/<label>; returns {label, ref, sha, features, bin}."""
    if ref.startswith("origin/") and subprocess.run(["git", "-C", REPO, "rev-parse", "-q", "--verify", ref],
                                                    capture_output=True).returncode != 0:
        branch = ref[len("origin/"):]
        subprocess.run(["git", "-C", REPO, "fetch", "-q", "origin", f"{branch}:refs/remotes/{ref}"], check=True)
    sha = _git("rev-parse", "HEAD" if ref == "." else ref)
    feats = detect(ref) if features is None else features
    label = f"{sha[:10]}{'-' + '-'.join(feats) if feats else ''}"
    dest = os.path.join(out_dir, "bin", label)
    info = {"label": label, "ref": ref, "sha": sha, "features": feats, "bin": dest}
    if all(os.path.exists(os.path.join(dest, b)) for b in BINARIES):
        return info
    if ref == ".":
        ffi = FFI
    else:
        cache = cache or os.path.expanduser("~/.cache/lean-calibration")
        root = os.path.join(cache, f"lib-{sha}")
        ffi = os.path.join(root, "src", "ffi")
        if not os.path.exists(os.path.join(ffi, "Cargo.toml")):
            os.makedirs(root, exist_ok=True)
            archive = subprocess.run(["git", "-C", REPO, "archive", sha, "src/ffi"], check=True, capture_output=True).stdout
            subprocess.run(["tar", "-x", "-C", root], input=archive, check=True)
        target = os.path.join(ffi, "calibration")
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(SUITE, target, ignore=shutil.ignore_patterns("target", "__pycache__", "results*", "*.pyc"))
        cargo = os.path.join(ffi, "Cargo.toml")
        text = open(cargo).read()
        if '"calibration"' not in text:
            text = text.replace('members = ["crates/*"]', 'members = ["crates/*", "calibration"]', 1)
            if '"calibration"' not in text:
                raise RuntimeError(f"cannot add the suite to {cargo}'s workspace")
            open(cargo, "w").write(text)
    cmd = ["cargo", "build", "--release", "-p", "gas-calibration"]
    if feats:
        cmd += ["--features", ",".join(feats)]
    log(f"build {ref} ({sha[:10]}) features={feats or 'none'} in {ffi}")
    subprocess.run(cmd, cwd=ffi, check=True)
    os.makedirs(dest, exist_ok=True)
    for b in BINARIES:
        shutil.copy2(os.path.join(ffi, "target", "release", b), os.path.join(dest, b))
    return info
