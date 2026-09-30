#!/usr/bin/env python3
"""BAS (Breach & Attack Simulation) standards tests: every module carries MITRE
ATT&CK + tactic mappings, IDs are well-formed, and the run produces an ATT&CK
coverage matrix in the evidence."""
import os
import re
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core     # noqa: E402
import loader   # noqa: E402

TID = re.compile(r"^T\d{4}(\.\d{3})?$")
CID = re.compile(r"^CWE-\d+$")


class TestMappings(unittest.TestCase):
    def test_every_module_has_mitre_and_tactic(self):
        for m in loader.discover():
            meta = m.META
            with self.subTest(module=meta["id"]):
                self.assertTrue(meta.get("mitre"), f"{meta['id']} has no MITRE technique")
                for t in meta["mitre"]:
                    self.assertRegex(t, TID, f"{meta['id']}: bad technique id {t}")
                self.assertTrue(meta.get("tactic"), f"{meta['id']} has no tactic")
                for c in meta.get("cwe", []):
                    self.assertRegex(c, CID, f"{meta['id']}: bad CWE id {c}")


class TestCoverageReport(unittest.TestCase):
    def test_finalize_builds_attack_coverage(self):
        def mod(mid, mitre, tactic, cwe=None):
            m = types.SimpleNamespace()
            m.META = {"id": mid, "name": mid, "category": "Test", "requires": [],
                      "ports": [], "mitre": mitre, "tactic": tactic, "cwe": cwe or [],
                      "success_regex": r"WIN"}
            m.run = lambda t, c: "WIN" if mid == "hit" else "nope"
            return m
        mods = [mod("hit", ["T1190"], "Initial Access", ["CWE-22"]),
                mod("miss", ["T1046"], "Discovery")]
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("127.0.0.1").run(mods, 1, ev, skip_unready=False, recon=False)
        cov = ev.meta.get("attack_coverage")
        self.assertIn("T1190", cov)
        self.assertEqual(cov["T1190"]["status"], "GAP")     # hit succeeded
        self.assertIn("T1046", cov)
        self.assertIn("CWE-22", ev.meta.get("cwe_coverage", {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
