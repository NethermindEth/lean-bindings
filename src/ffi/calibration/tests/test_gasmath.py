import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from calib import gasmath as g  # noqa: E402


def marginals(**kw):
    base = dict(sig=0.0164, merge_child=0.1467, merge_fixed=0.0145, carry_sig=0.0001, generic_leaf_step=0.42,
                claim_in_leaf=0.0004, carry_record=0.0002, finalize_record=0.0001)
    base.update(kw)
    return g.Marginals(**base)


class GasMath(unittest.TestCase):
    def test_fit_line(self):
        a, b = g.fit_line([(1, 3.0), (2, 5.0), (4, 9.0)])
        self.assertAlmostEqual(a, 1.0)
        self.assertAlmostEqual(b, 2.0)
        with self.assertRaises(ValueError):
            g.fit_line([(1, 1.0), (1, 2.0)])

    def test_rate_and_depth(self):
        b = g.Budget(gas_limit=60_000_000, builder_s=6, workers=16, margin=1.5, fanin=4, sigs_per_node=64)
        self.assertAlmostEqual(b.machine_seconds, 64.0)
        self.assertAlmostEqual(b.rate, 937_500.0)
        self.assertEqual([g.tree_depth(n, 4) for n in (1, 2, 4, 5, 16, 17)], [0, 1, 1, 2, 2, 3])
        self.assertAlmostEqual(g.slot_factor(4), 4 / 3)

    def test_derive_reproduces_the_commitment_report(self):
        # commitment/REPORT.md: B = 6 s, 16 workers, margin 1.5 at 60M; tau native 16.4 ms, share 4.46 ms,
        # committed generic 0.615 s -> SPHINCS ~15.4k, share ~4.2k, STARK ~572k (rate 937.5k gas per machine-second).
        b = g.Budget(gas_limit=60_000_000, builder_s=6, workers=16, margin=1.5, fanin=4, sigs_per_node=64)
        m = marginals(sig=0.016395, merge_child=0.146729, carry_sig=0.0, generic_leaf_step=0.615118 - 0.146729 * 4 / 3)
        c = g.derive(m, b, depth=4)
        self.assertAlmostEqual(c["LEANSPHINCS_VERIFICATION_GAS"], 15_370, delta=50)
        self.assertAlmostEqual(c["RECURSIVE_PROOF_SHARE_GAS"], 937_500 * 0.146729 * 4 / 3 / 64, delta=1)
        self.assertAlmostEqual(c["LEANSTARK_VERIFICATION_GAS"] + c["RECURSIVE_PROOF_SHARE_GAS"], 937_500 * 0.615118, delta=1)
        self.assertEqual(c["LEANSTARK_LEAF_PAYMENT_GAS"], c["LEANSTARK_VERIFICATION_GAS"] + c["RECURSIVE_PROOF_SHARE_GAS"])

    def test_claim_needs_every_batch_cell_and_counts_depth(self):
        b = g.Budget(60_000_000, 6, 16, 1.5, 4, 64)
        self.assertIsNone(g.derive(marginals(carry_record=None), b, 3)["LEANSTARK_CLAIM_GAS"])
        c3 = g.derive(marginals(), b, 3)["LEANSTARK_CLAIM_GAS"]
        c4 = g.derive(marginals(), b, 4)["LEANSTARK_CLAIM_GAS"]
        self.assertAlmostEqual(c4 - c3, b.rate * 0.0002)
        self.assertAlmostEqual(c3, b.rate * (0.0004 + 3 * 0.0002 + 0.0001))

    def test_constants_scale_with_the_budget(self):
        m = marginals()
        tight = g.derive(m, g.Budget(60_000_000, 4, 16, 1.5, 4, 64), 3)
        loose = g.derive(m, g.Budget(60_000_000, 8, 16, 1.5, 4, 64), 3)
        for k in ("LEANSPHINCS_VERIFICATION_GAS", "LEANSTARK_VERIFICATION_GAS", "LEANSTARK_CLAIM_GAS"):
            self.assertAlmostEqual(tight[k], 2 * loose[k])

    def test_transaction_accounting(self):
        self.assertEqual(g.TRIPLE_DATA_GAS, 1164)
        tx = g.TxModel(signature_gas=0)
        self.assertEqual(tx.per_tx_overhead(), 12_475)
        # 576,200 + 1,164 a generic declaration: the 2^24 cap allows 29 a transaction.
        self.assertEqual(tx.max_deps_per_tx(577_364), 29)
        self.assertEqual(tx.max_deps_per_tx(20_764), 256)
        groups, txs = g.fill(10 * (12_475 + 256 * 1000), 1000, tx)
        self.assertEqual((groups, txs), (2560, 10))
        groups, txs = g.fill(12_475 + 5 * 1000 + 999, 1000, tx)
        self.assertEqual((groups, txs), (5, 1))

    def test_blocks_spend_at_most_the_gas_limit(self):
        c = {"LEANSPHINCS_VERIFICATION_GAS": 15_400, "RECURSIVE_PROOF_SHARE_GAS": 4_200,
             "LEANSTARK_VERIFICATION_GAS": 572_000, "LEANSTARK_LEAF_PAYMENT_GAS": 576_200, "LEANSTARK_CLAIM_GAS": 2_100}
        tx = g.TxModel()
        bl = g.blocks(c, 60_000_000, tx, claims_per_leaf=256)
        native = 15_400 + 4_200 + g.TRIPLE_DATA_GAS
        spent = bl["native"]["native"] * native + bl["native"]["txs"] * tx.per_tx_overhead()
        self.assertLessEqual(spent, 60_000_000)
        self.assertGreater(spent + native + tx.per_tx_overhead(), 60_000_000)
        self.assertEqual(bl["generic"]["generic"], 103)
        self.assertGreater(bl["batch_one_claim"]["batch_leaves"], bl["batch_full"]["batch_leaves"])
        self.assertNotIn("batch_one_claim", g.blocks(dict(c, LEANSTARK_CLAIM_GAS=None), 60_000_000, tx, 256))

    def test_a_dependency_above_the_transaction_cap_is_inadmissible(self):
        # Regression: a flat-key STARK charge above the EIP-7825 cap crashed the block construction.
        tx = g.TxModel()
        self.assertEqual(g.fill(60_000_000, tx.tx_gas_cap, tx), (0, 0))
        self.assertEqual(g.fill(60_000_000, 1_000_000, tx, group=tx.max_deps_per_tx(1_000_000) + 1), (0, 0))

    def test_no_sponsored_leaf_when_its_payment_exceeds_the_transaction_cap(self):
        tx = g.TxModel()
        c = {"LEANSPHINCS_VERIFICATION_GAS": 15_000, "RECURSIVE_PROOF_SHARE_GAS": 4_000, "LEANSTARK_CLAIM_GAS": 3_000,
             "LEANSTARK_VERIFICATION_GAS": 26_800_000, "LEANSTARK_LEAF_PAYMENT_GAS": 26_804_000}
        b = g.blocks(c, 60_000_000, tx, 256)
        self.assertEqual(b["generic"]["generic"], 0)
        self.assertNotIn("batch_one_claim", b)

    def test_scale_and_verdict(self):
        s = g.scale_block({"native": 3000, "generic": 1, "evm_gas": 1e6}, 0.1)
        self.assertEqual((s["native"], s["generic"], s["evm_gas"], s["scale"]), (300, 1, 1e5, 0.1))
        v = g.verdict(5.0, 6.0, 8 << 30, 12 << 30)
        self.assertTrue(v["pass"])
        self.assertFalse(g.verdict(7.0, 6.0, 1, 2)["pass"])
        self.assertFalse(g.verdict(1.0, 6.0, 3, 2)["pass"])
        self.assertAlmostEqual(g.recalibrate(1000.0, 9.0, 6.0), 1500.0)


if __name__ == "__main__":
    unittest.main()
