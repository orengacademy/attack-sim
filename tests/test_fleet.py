#!/usr/bin/env python3
"""Fleet matrix expansion — pure logic, no network."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fleet  # noqa: E402


def _args(**kw):
    base = dict(only=None, original=False, added=False, attack_sim=False,
                test_type=None, family=None, to=None, from_zone=None, direction=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


FLEET = {
    "targets": [
        {"id": "k1", "ip": "10.0.0.1", "zone": "kvdc"},
        {"id": "c1", "ip": "10.0.0.2", "zone": "cloud"},
        {"id": "s1", "ip": "10.0.0.3", "zone": "sdwan"},
    ],
    "sources": [
        {"id": "sdwan-fh", "ip": "10.9.0.1", "zone": "sdwan"},
        {"id": "kvdc-fh", "ip": "10.9.0.2", "zone": "kvdc"},
    ],
    "runs": [
        {"from": "sdwan", "to": ["kvdc", "cloud"], "direction": "a2b"},
        {"from": "kvdc", "to": ["sdwan"], "direction": "b2a"},
    ],
}


class TestFleetJobs(unittest.TestCase):
    def test_matrix_expands(self):
        jobs = fleet.build_jobs(FLEET, _args())
        # sdwan->kvdc, sdwan->cloud, kvdc->sdwan = 3 jobs
        self.assertEqual(len(jobs), 3)
        pairs = {(j["source"]["id"], j["target"]["id"], j["direction"]) for j in jobs}
        self.assertIn(("sdwan-fh", "k1", "a2b"), pairs)
        self.assertIn(("sdwan-fh", "c1", "a2b"), pairs)
        self.assertIn(("kvdc-fh", "s1", "b2a"), pairs)

    def test_filter_to_zone(self):
        jobs = fleet.build_jobs(FLEET, _args(to="cloud"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["target"]["id"], "c1")

    def test_filter_direction(self):
        jobs = fleet.build_jobs(FLEET, _args(direction="b2a"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["direction"], "b2a")

    def test_direction_both_keeps_all_jobs(self):
        # "both" means ALL directions — it must NOT filter jobs down (regression:
        # it used to drop every a2b/b2a job, yielding fewer than the no-filter run).
        all_jobs = fleet.build_jobs(FLEET, _args())
        both = fleet.build_jobs(FLEET, _args(direction="both"))
        self.assertEqual(len(both), len(all_jobs))
        self.assertGreater(len(both), 1)

    def test_no_runs_defaults_to_all_targets(self):
        jobs = fleet.build_jobs({"targets": FLEET["targets"]}, _args())
        self.assertEqual(len(jobs), 3)
        self.assertTrue(all(j["source"]["ip"] is None for j in jobs))

    def test_cloud_ports_preserved(self):
        f = {"targets": [{"id": "c", "ip": "1.2.3.4", "zone": "cloud",
                          "cloud_ports": {"445": 4445, "135": 1135}}]}
        jobs = fleet.build_jobs(f, _args())
        self.assertEqual(jobs[0]["target"]["cloud_ports"], {"445": 4445, "135": 1135})


if __name__ == "__main__":
    unittest.main()
