#!/usr/bin/env python3
"""Unit tests for the SQLite cross-run index (index.py).

Pure-stdlib, offline: builds an index from a synthetic evidence/ tree in a temp
dir and asserts the query/stats/parity behaviour. Touches no network, no real DB.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import index  # noqa: E402


def _write_run(evdir, name, meta, results):
    d = os.path.join(evdir, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "summary.json"), "w") as f:
        json.dump({"meta": meta, "results": results}, f)


class TestIndex(unittest.TestCase):
    def setUp(self):
        self.ev = tempfile.mkdtemp()
        self.db = os.path.join(tempfile.mkdtemp(), "idx.db")
        # a single-target run (baseline leg authoritative) ...
        _write_run(self.ev, "run_01__1.2.3.4",
                   {"run": "01", "started": "2026-10-05T10:00:00", "mode": "blackbox",
                    "target_ip": "1.2.3.4", "site_id": "ORG2026-70", "module_count": 2},
                   [{"iteration": 1, "attack_id": "a1", "attack": "A One", "category": "C",
                     "baseline_result": "SUCCESS", "appliance_result": "-", "appliance_ip": None,
                     "verdict": "got through", "target_ip": "1.2.3.4", "mitre": ["T1"],
                     "cwe": ["CWE-1"], "cve": "", "timestamp": "2026-10-05T10:00:01"},
                    {"iteration": 1, "attack_id": "a2", "attack": "A Two", "category": "C",
                     "baseline_result": "BLOCKED", "appliance_result": "-", "appliance_ip": None,
                     "verdict": "blocked", "target_ip": "1.2.3.4", "mitre": ["T2"],
                     "cwe": [], "cve": "", "timestamp": "2026-10-05T10:00:02"}])
        # ... and a dual-path run where the APPLIANCE leg is authoritative.
        _write_run(self.ev, "run_02__5.6.7.8",
                   {"run": "02", "started": "2026-10-05T11:00:00", "mode": "blackbox",
                    "target_ip": "5.6.7.8", "module_count": 1},
                   [{"iteration": 1, "attack_id": "a1", "attack": "A One", "category": "C",
                     "baseline_result": "OK", "appliance_result": "SUCCESS",
                     "appliance_ip": "9.9.9.9", "verdict": "finding", "target_ip": "5.6.7.8",
                     "mitre": ["T1"], "cwe": ["CWE-1"], "cve": "", "timestamp": "2026-10-05T11:00:01"}])

    def test_rebuild_counts(self):
        nr, nres = index.rebuild(self.db, self.ev)
        self.assertEqual(nr, 2)
        self.assertEqual(nres, 3)

    def test_dual_path_uses_appliance_leg_verdict(self):
        # the index's short verdict for a dual-path row is the APPLIANCE result
        # (SUCCESS), not the baseline "OK" — mirrors the reports.
        index.rebuild(self.db, self.ev)
        rows = index.query(self.db, {"target_ip": "5.6.7.8"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "SUCCESS")

    def test_filter_and_freetext(self):
        index.rebuild(self.db, self.ev)
        self.assertEqual(len(index.query(self.db, {"verdict": "SUCCESS"})), 2)
        self.assertEqual(len(index.query(self.db, {"verdict": "BLOCKED"})), 1)
        # free-text LIKE over module/mitre/cwe
        self.assertEqual(len(index.query(self.db, {}, q="A Two")), 1)

    def test_filter_whitelist_blocks_injection(self):
        # a non-whitelisted "column" is ignored, not interpolated into SQL.
        index.rebuild(self.db, self.ev)
        rows = index.query(self.db, {"target_ip; DROP TABLE results": "x"})
        self.assertEqual(len(rows), 3)   # filter ignored -> all rows, table intact

    def test_stats_rollup(self):
        index.rebuild(self.db, self.ev)
        st = index.stats(self.db)
        self.assertEqual(st["runs"], 2)
        self.assertEqual(st["overall"].get("SUCCESS"), 2)
        self.assertEqual(st["overall"].get("BLOCKED"), 1)

    def test_rebuild_is_idempotent(self):
        index.rebuild(self.db, self.ev)
        nr, nres = index.rebuild(self.db, self.ev)   # again, no duplicates
        self.assertEqual((nr, nres), (2, 3))
        self.assertEqual(len(index.query(self.db, {})), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
