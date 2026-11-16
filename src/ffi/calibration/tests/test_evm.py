import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from calib import evm  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class Evm(unittest.TestCase):
    def test_imports_each_format(self):
        gb = evm.load({"format": "gas-benchmarks", "path": os.path.join(FIX, "gas-benchmarks")})
        self.assertEqual(sorted((r["gas_used"], r["ms"]) for r in gb), [(60e6, 812.5), (100e6, 400.0)])
        ex = evm.load({"format": "expb", "path": os.path.join(FIX, "expb-run.txt")})
        self.assertEqual([(r["name"], r["gas_used"], r["ms"]) for r in ex], [("24000001", 45e6, 310.5)])

    def test_measured_when_a_block_matches_else_extrapolated_from_the_slowest_throughput(self):
        gb = evm.load({"format": "gas-benchmarks", "path": os.path.join(FIX, "gas-benchmarks")})
        t = evm.evm_time_ms(gb, 60e6)
        self.assertEqual((t["ms"], t["label"]), (812.5, "measured (imported)"))
        t = evm.evm_time_ms(gb, 30e6)
        self.assertEqual(t["label"], "extrapolated (linear in gas)")
        self.assertAlmostEqual(t["ms"], 812.5 / 2)
        self.assertEqual(evm.evm_time_ms([], 30e6)["label"], "unmeasured")
        self.assertEqual(evm.evm_time_ms(gb, 0)["ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
