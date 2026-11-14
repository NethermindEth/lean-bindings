import math
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from calib import pq_leaves  # noqa: E402


class FakeBench:
    """Answers probes as a leaf whose committed witness grows by `per_sig` words a signature."""

    def __init__(self, fixed: float, per_sig: float):
        self.fixed, self.per_sig, self.probed = fixed, per_sig, []
        self.log = lambda m: None

    def once(self, args, tag, gate=True):
        n = int(args[2])
        self.probed.append(n)
        committed = self.fixed + self.per_sig * n
        return {"rc": 0, "result": {"log_committed": math.log2(committed), "agg_cycles": 1,
                                    "peak_rss": 1, "prove_s": 1.0}}


def ladder(fixed, per_sig, ns):
    return [{"n": n, "status": "ok", "committed": fixed + per_sig * n,
             "log_committed": math.log2(fixed + per_sig * n)} for n in ns]


class MaxN(unittest.TestCase):
    def test_largest_n_within_the_committed_bound(self):
        fixed, per_sig = 2**25, 4.3e6
        bench = FakeBench(fixed, per_sig)
        n, _ = pq_leaves.max_n(bench, "s", ladder(fixed, per_sig, [1, 16, 64]))
        bound = 2 ** pq_leaves.MAX_LOG_COMMITTED
        self.assertLessEqual(fixed + per_sig * n, bound)
        self.assertGreater(fixed + per_sig * (n + 1), bound)

    def test_capped_at_the_claim_limit(self):
        bench = FakeBench(2**16, 10)
        n, _ = pq_leaves.max_n(bench, "s", ladder(2**16, 10, [1, 64, 128]))
        self.assertEqual(n, pq_leaves.MAX_CLAIMS)

    def test_guess_above_the_bound_searches_down(self):
        # A ladder that underestimates the slope makes the first guess fail.
        fixed, per_sig = 2**25, 4.3e6
        bench = FakeBench(fixed, per_sig)
        n, probes = pq_leaves.max_n(bench, "s", ladder(fixed, per_sig / 2, [1, 16, 64]))
        bound = 2 ** pq_leaves.MAX_LOG_COMMITTED
        self.assertLessEqual(fixed + per_sig * n, bound)
        self.assertGreater(fixed + per_sig * (n + 1), bound)
        self.assertFalse(probes[0]["ok"])


if __name__ == "__main__":
    unittest.main()
