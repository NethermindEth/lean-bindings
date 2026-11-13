import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from calib import report  # noqa: E402


def minimal_run() -> dict:
    return {"config": {"label": "t", "key": "flat", "gas_limits": [60_000_000], "builder_budget_s": 6.0,
                       "validator_budget_s": 3.0, "memory_per_worker_gb": 8, "margin": 1.5, "fanin": 4,
                       "sigs_per_node": 64, "threads_per_worker": 4, "reference_workers": 1,
                       "workers": {"mode": "local", "count": 1},
                       "bounds": {"code_log": 11, "trace_log": 30, "inner_log_inv_rate": 1, "claims": 256,
                                  "max_inner_proofs_per_step": 16}}}


class Report(unittest.TestCase):
    def test_sections_follow_the_methodology_headings(self):
        text = report.render(minimal_run())
        headings = [line[3:] for line in text.splitlines() if line.startswith("## ")]
        self.assertEqual(headings, [*report.METHODOLOGY, "Not covered by this run"])
        for items in report.METHODOLOGY.values():
            for item, _ in items:
                self.assertIn(f"| {item} |", text)


if __name__ == "__main__":
    unittest.main()
