"""The simulation's protocol logic, run with test doubles."""
from __future__ import annotations

import unittest

from tests.node.doubles import InsecureTestSigner, MemoryLog
from tools.nodes_sim import simulate


class Simulation(unittest.TestCase):
    def test_bound_holds_and_is_deterministic(self):
        options = dict(nodes=3, runs=2, seed=7, freshness=20.0, skew=2.0, heartbeat=5.0,
                       max_delay=10.0)
        first = simulate(InsecureTestSigner(), MemoryLog, **options)
        self.assertTrue(first["bound_held"], first)
        self.assertEqual(first, simulate(InsecureTestSigner(), MemoryLog, **options))

    def test_fully_cut_off_nodes_lock_within_the_bound(self):
        report = simulate(InsecureTestSigner(), MemoryLog, nodes=3, runs=2, seed=3,
                          freshness=20.0, heartbeat=5.0, max_delay=10.0, cut_off=1.0)
        self.assertTrue(report["bound_held"], report)
        self.assertGreater(report["until_last_node"]["max"], 0)


if __name__ == "__main__":
    unittest.main()
