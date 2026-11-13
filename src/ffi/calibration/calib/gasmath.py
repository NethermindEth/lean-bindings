"""Calibration maths: marginal machine-seconds per dependency -> gas constants, and the gas-admissible worst-case blocks
those constants allow. Pure functions; every input is a measured cell median or a configuration value.

The rate is the gas one machine-second of proving may cost under the published budget:

    rate = G / (W * B / margin)        gas per machine-second, for gas limit G, W workers, budget B seconds

and each constant is rate x the marginal machine-seconds its declaration adds to the block's aggregation (EIP-8288
"Derive native, generic and proof-share charges from this common capacity budget"). The constants are a starting point:
`verify` in calib.py proves the blocks they admit and only a measured makespan within B passes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# EIP-8141 @ the EIPs#12654 head: frame transaction intrinsic costs, and EIP-7976 calldata pricing of a 96-byte triple
# (31 zero padding bytes, a nonzero scheme byte, 64 data and key bytes).
FRAME_TX_INTRINSIC_COST = 12_000
FRAME_TX_PER_FRAME_COST = 475
STANDARD_TOKEN_COST = 4
TRIPLE_ZERO_BYTES = 31
TRIPLE_NONZERO_BYTES = 65
TRIPLE_DATA_GAS = STANDARD_TOKEN_COST * (TRIPLE_ZERO_BYTES + 4 * TRIPLE_NONZERO_BYTES)  # 1,164
MAX_DEPENDENCIES_PER_FRAME = 256
EIP7825_TX_GAS_CAP = 2**24


def fit_line(points: list[tuple[float, float]]) -> tuple[float, float]:
    """Least-squares (intercept, slope) through (x, y) points; two or more distinct x required."""
    xs = [p[0] for p in points]
    if len(set(xs)) < 2:
        raise ValueError("a slope needs two distinct sizes")
    n = len(points)
    mx = sum(xs) / n
    my = sum(p[1] for p in points) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in points) / sxx
    return my - slope * mx, slope


@dataclass
class Marginals:
    """Measured machine-seconds (one worker at the configured threads)."""

    sig: float  # one more signature in a signature step
    merge_child: float  # one more child in a merge step
    merge_fixed: float  # a merge step's fixed part
    carry_sig: float  # one more carried signature claim through one merge level
    generic_leaf_step: float  # a step verifying one maximum-resource generic leaf
    claim_in_leaf: float | None = None  # one more retained claim in a sponsored-leaf step
    carry_record: float | None = None  # one more batch record through one merge level
    finalize_record: float | None = None  # one more batch record at finalization
    finalize_fixed: float | None = None  # a finalizing step's fixed part over a plain merge
    labels: dict = field(default_factory=dict)


@dataclass
class Budget:
    gas_limit: int
    builder_s: float
    workers: int
    margin: float
    fanin: int
    sigs_per_node: int

    @property
    def machine_seconds(self) -> float:
        return self.workers * self.builder_s / self.margin

    @property
    def rate(self) -> float:
        return self.gas_limit / self.machine_seconds


def tree_depth(leaf_steps: int, fanin: int) -> int:
    """Merge levels above `leaf_steps` initial steps at fan-in `fanin` (a lone remainder rises without a step)."""
    depth = 0
    n = leaf_steps
    while n > 1:
        n = math.ceil(n / fanin)
        depth += 1
    return depth


def slot_factor(fanin: int) -> float:
    """Child slots a leaf step occupies up a full tree: 1 + 1/f + 1/f^2 + ... = f / (f - 1)."""
    return fanin / (fanin - 1)


def derive(m: Marginals, b: Budget, depth: int) -> dict:
    """The constants for budget `b`, carrying claims through `depth` merge levels. CLAIM is None without batch cells."""
    r = b.rate
    slots = slot_factor(b.fanin)
    child = m.merge_child * slots
    share_s = child / b.sigs_per_node + m.carry_sig * depth
    generic_s = m.generic_leaf_step + child
    out = {
        "rate_gas_per_machine_s": r,
        "depth": depth,
        "LEANSPHINCS_VERIFICATION_GAS": r * m.sig,
        "RECURSIVE_PROOF_SHARE_GAS": r * share_s,
        "LEANSTARK_VERIFICATION_GAS": r * (generic_s - share_s),
        "machine_s": {"sig": m.sig, "share": share_s, "generic": generic_s},
    }
    out["LEANSTARK_LEAF_PAYMENT_GAS"] = out["LEANSTARK_VERIFICATION_GAS"] + out["RECURSIVE_PROOF_SHARE_GAS"]
    if None not in (m.claim_in_leaf, m.carry_record, m.finalize_record):
        claim_s = m.claim_in_leaf + m.carry_record * depth + m.finalize_record
        out["LEANSTARK_CLAIM_GAS"] = r * claim_s
        out["machine_s"]["claim"] = claim_s
    else:
        out["LEANSTARK_CLAIM_GAS"] = None
    return out


@dataclass
class TxModel:
    """Complete transaction gas accounting for dependency-carrying frame transactions."""

    signature_gas: int = 3_000 + 16 * 65  # one secp256k1 sender signature: verification plus its bytes (estimate)
    frames_per_tx: int = 1
    tx_gas_cap: int = EIP7825_TX_GAS_CAP

    def per_tx_overhead(self) -> int:
        return FRAME_TX_INTRINSIC_COST + self.frames_per_tx * FRAME_TX_PER_FRAME_COST + self.signature_gas

    def max_deps_per_tx(self, gas_per_dep: float) -> int:
        """The most declarations one transaction holds: the frame bound, and the EIP-7825 per-transaction cap."""
        by_frames = self.frames_per_tx * MAX_DEPENDENCIES_PER_FRAME
        by_cap = int((self.tx_gas_cap - self.per_tx_overhead()) // gas_per_dep)
        return max(0, min(by_frames, by_cap))


def fill(gas: float, per_dep: float, tx: TxModel, group: int = 1) -> tuple[int, int]:
    """Groups of `group` declarations costing `per_dep` gas each (data included) that fit in `gas`, packed into as few
    transactions as the bounds allow. Returns (groups, transactions)."""
    per_group = per_dep * group
    per_tx = max(1, tx.max_deps_per_tx(per_dep) // group)
    if per_tx < 1 or tx.max_deps_per_tx(per_dep) < group:
        raise ValueError("a group exceeds one transaction")
    full_tx_gas = tx.per_tx_overhead() + per_tx * per_group
    n_tx_full = int(gas // full_tx_gas)
    groups = n_tx_full * per_tx
    rest = gas - n_tx_full * full_tx_gas - tx.per_tx_overhead()
    extra = max(0, min(per_tx, int(rest // per_group))) if rest > 0 else 0
    return groups + extra, n_tx_full + (1 if extra else 0)


def blocks(c: dict, gas_limit: int, tx: TxModel, claims_per_leaf: int, evm_fraction: float = 0.5) -> dict:
    """The worst-case gas-admissible blocks under constants `c` (EIP-8288 / EIPs#12664 benchmark requirements):
    counts of each dependency kind, and the gas left to EVM execution."""
    native = c["LEANSPHINCS_VERIFICATION_GAS"] + c["RECURSIVE_PROOF_SHARE_GAS"] + TRIPLE_DATA_GAS
    generic = c["LEANSTARK_VERIFICATION_GAS"] + c["RECURSIVE_PROOF_SHARE_GAS"] + TRIPLE_DATA_GAS
    out = {}
    n, t = fill(gas_limit, native, tx)
    out["native"] = {"native": n, "txs": t}
    n, t = fill(gas_limit, generic, tx)
    out["generic"] = {"generic": n, "txs": t}
    half = gas_limit / 2
    n1, t1 = fill(half, native, tx)
    n2, t2 = fill(half, generic, tx)
    out["mix_native_generic"] = {"native": n1, "generic": n2, "txs": t1 + t2}
    n, t = fill(gas_limit * (1 - evm_fraction), generic, tx)
    out["mix_generic_evm"] = {"generic": n, "txs": t, "evm_gas": gas_limit * evm_fraction}
    out["evm"] = {"evm_gas": gas_limit}
    if c.get("LEANSTARK_CLAIM_GAS") is not None:
        claim = c["LEANSTARK_CLAIM_GAS"] + TRIPLE_DATA_GAS
        payment = c["LEANSTARK_LEAF_PAYMENT_GAS"] + TRIPLE_DATA_GAS
        # One retained claim per maximum-resource leaf, with its payment: two declarations a leaf, each its own tx.
        per_leaf_one = claim + payment + tx.per_tx_overhead()
        out["batch_one_claim"] = {"batch_leaves": int(gas_limit // per_leaf_one), "retain": 1}
        # Full leaves: every claim in its own member transaction, as EIPs#12664 intends, plus the payment.
        per_leaf_full = claims_per_leaf * (claim + tx.per_tx_overhead()) + payment + tx.per_tx_overhead()
        out["batch_full"] = {"batch_leaves": int(gas_limit // per_leaf_full), "retain": claims_per_leaf}
        n1, _ = fill(half, native, tx)
        out["mix_native_batch"] = {"native": n1, "batch_leaves": int(half // per_leaf_one), "retain": 1}
    return out


def scale_block(block: dict, fraction: float) -> dict:
    """A block scaled to `fraction` of its dependency counts, for machines that cannot hold the full block."""
    out = dict(block)
    for k in ("native", "generic", "batch_leaves"):
        if k in out:
            out[k] = max(1 if block[k] else 0, int(round(block[k] * fraction)))
    if "evm_gas" in out:
        out["evm_gas"] = block["evm_gas"] * fraction
    out["scale"] = fraction
    return out


def verdict(makespan_s: float, budget_s: float, peak_rss: int, mem_per_worker: int) -> dict:
    """Whether one measured block meets the builder budget and the per-worker memory budget."""
    return {
        "time_ok": makespan_s <= budget_s,
        "memory_ok": peak_rss <= mem_per_worker,
        "pass": makespan_s <= budget_s and peak_rss <= mem_per_worker,
        "headroom": budget_s / makespan_s if makespan_s > 0 else math.inf,
    }


def recalibrate(rate: float, worst_makespan_s: float, budget_s: float) -> float:
    """The rate scaled so the worst measured block would just meet the budget (makespan ~ admitted work)."""
    return rate * worst_makespan_s / budget_s
