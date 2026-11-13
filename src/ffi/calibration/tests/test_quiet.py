import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from calib import host, pipeline  # noqa: E402


def block_result(makespan: float, quiet: bool) -> dict:
    return {"status": "ok", "makespan_s": makespan, "peak_rss_max_worker": 1, "root_verify_ms": 1.0,
            "gate": {"quiet": quiet, "load1": 1.0 if quiet else 12.0, "waited_s": 0 if quiet else 3600}}


class FakeRunner:
    def __init__(self, results: list[dict]):
        self.results, self.labels = list(results), []

    def block(self, build, label, plan):
        self.labels.append(label)
        return self.results.pop(0)


def calibration(results: list[dict]) -> pipeline.Calibration:
    c = pipeline.Calibration.__new__(pipeline.Calibration)
    c.cfg = {"builder_budget_s": 4.0, "validator_budget_s": 2.0, "memory_per_worker_gb": 1, "max_iterations": 2,
             "gas_limits": [60_000_000], "bounds": {"claims": 256}}
    c.res, c.base, c.batch, c.log = {}, {"label": "b"}, None, lambda m: None
    c.out = None
    c.save = lambda: None
    c.plan_for = lambda blk, guest, build: []
    c.constants = lambda G, factor=1.0: {"rate_factor": factor}
    c.run = FakeRunner(results)
    return c


class Quiet(unittest.TestCase):
    def test_gate_reports_while_it_waits_and_when_it_gives_up(self):
        logged = []
        with mock.patch.object(host, "busy_processes", return_value=[]), \
                mock.patch.object(host, "load1", return_value=12.0), mock.patch.object(host.time, "sleep"):
            g = host.wait_quiet(5, 60, poll_s=15, log=logged.append, report_every_s=30)
        self.assertFalse(g["quiet"])
        self.assertEqual(g["waited_s"], 60)
        self.assertEqual(sum("waiting for a quiet machine" in m for m in logged), 2)
        self.assertIn("marked unquiet", logged[-1])

    def test_unquiet_block_is_retried_and_counted_when_quiet(self):
        c = calibration([block_result(9.0, False), block_result(3.0, True)])
        with mock.patch.object(pipeline.gasmath, "blocks", return_value={"native": {"native": 64}}):
            c.calibrate()
        self.assertEqual(c.run.labels, ["g60M-native-it0", "g60M-native-it0-retry"])
        final = c.res["gas_limits"]["60000000"]
        self.assertEqual(len(final["iterations"]), 1)
        self.assertEqual(final["final"]["verdict"], "PASS")

    def test_block_unquiet_twice_neither_recalibrates_nor_passes(self):
        # Regression: a makespan measured after the gate timed out under load raised every constant by its overshoot.
        c = calibration([block_result(9.0, False), block_result(9.0, False)])
        with mock.patch.object(pipeline.gasmath, "blocks", return_value={"native": {"native": 64}}):
            c.calibrate()
        final = c.res["gas_limits"]["60000000"]
        self.assertEqual(len(final["iterations"]), 1)
        self.assertEqual(final["final"]["constants"]["rate_factor"], 1.0)
        self.assertFalse(final["final"]["pass"])
        self.assertTrue(final["iterations"][0]["blocks"][0]["status"].startswith("unquiet"))


if __name__ == "__main__":
    unittest.main()
