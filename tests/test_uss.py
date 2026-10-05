#!/usr/bin/env python3
"""Tests for the USS (attack-sim) additions: engine DETECTED/direction/config,
the shared _util helpers, active-establishment gating, and META sanity across all
attack_sim modules. Localhost / offline only — no external infra contacted.
    python3 -m unittest discover -s tests
"""
import importlib
import json
import os
import re
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core       # noqa: E402
import loader     # noqa: E402
from modules import _util as U   # noqa: E402

_VALID_FAMILY = set("ABCDEFG")
_VALID_DIR = {"a2b", "b2a", "both"}

# active/config-gated modules that must SKIP (not touch the network / not falsely
# pass) when neither their infra config nor --active is provided.
_GATED_SKIP = [
    "domain_fronting", "self_tunnel_vps", "ssh_over_443", "dns_tunnel",
    "nrd_category", "socks_pivot", "dlp_canary_https", "dlp_lowandslow",
    "beacon_shaping",
]


def _mods():
    return {m.META["id"]: m for m in loader.discover()}


class TestMetaSanity(unittest.TestCase):
    def test_attack_sim_meta_is_wellformed(self):
        for mid, m in _mods().items():
            meta = m.META
            if meta.get("test_type") != "attack_sim":
                continue
            self.assertIn(meta.get("family"), _VALID_FAMILY, f"{mid}: bad family")
            self.assertIn(meta.get("direction", "a2b"), _VALID_DIR, f"{mid}: bad direction")
            self.assertTrue(meta.get("mitre"), f"{mid}: no mitre mapping")
            # success/blocked regexes must compile
            for key in ("success_regex", "blocked_regex", "detected_regex"):
                pat = meta.get(key)
                if pat:
                    re.compile(pat)   # raises on a bad pattern
            self.assertTrue(callable(m.run), f"{mid}: run not callable")


class TestActiveGating(unittest.TestCase):
    def test_gated_modules_skip_without_config_or_active(self):
        ctx = core.Context(config={}, allow_active=False)   # no infra, indicator only
        mods = _mods()
        for mid in _GATED_SKIP:
            self.assertIn(mid, mods, f"{mid} not discovered")
            out = mods[mid].run("192.0.2.1", ctx)            # TEST-NET, unroutable
            self.assertIsInstance(out, str)
            self.assertIn("[SKIP]", out, f"{mid} did not SKIP when unconfigured:\n{out}")

    def test_allow_active_defaults_false(self):
        self.assertFalse(core.Context().allow_active)


class TestUtil(unittest.TestCase):
    def test_tcp_state_closed(self):
        # a port nothing listens on -> refused (or filtered), never 'open'
        self.assertNotEqual(U.tcp_state("127.0.0.1", 1, timeout=2), "open")

    def test_tcp_state_open(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            self.assertEqual(U.tcp_state("127.0.0.1", srv.getsockname()[1], timeout=2), "open")
        finally:
            srv.close()

    def test_dns_query_unreachable_is_graceful(self):
        ok, detail = U.dns_query("example.com", "192.0.2.2", timeout=1)  # TEST-NET
        self.assertIsInstance(detail, str)      # always returns gracefully, never raises
        if ok:
            # a resolver on this network answered the TEST-NET address (e.g. an
            # inline SD-WAN / captive DNS intercepting UDP/53) — can't assert
            # "unreachable" in that environment, but the graceful-return contract
            # above still held, which is what this test guards.
            self.skipTest("network has an intercepting resolver (answered TEST-NET)")
        self.assertFalse(ok)

    def test_run_transient_terminates_and_matches(self):
        out, matched = U.run_transient(
            [sys.executable, "-u", "-c", "print('connected'); import time; time.sleep(30)"],
            seconds=5, look_for=["connected"])
        self.assertTrue(matched)
        self.assertIn("connected", out)

    def test_run_transient_missing_tool(self):
        out, matched = U.run_transient(["definitely-not-a-real-binary-xyz"], seconds=2)
        self.assertFalse(matched)
        self.assertIn("[ERROR]", out)


class TestConfig(unittest.TestCase):
    def test_env_override(self):
        os.environ["HARNESS_CFG_ATTACKER_VPS"] = "203.0.113.9"
        try:
            self.assertEqual(core.load_config()["attacker_vps"], "203.0.113.9")
        finally:
            del os.environ["HARNESS_CFG_ATTACKER_VPS"]

    def test_ctx_cfg_empty_returns_default(self):
        ctx = core.Context(config={})
        self.assertEqual(ctx.cfg("attacker_vps", "fallback"), "fallback")


class TestDetections(unittest.TestCase):
    def test_load_detections_mapping_and_list(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"a": True, "b": {"note": "x", "source": "SIEM"}}, f)
            path = f.name
        os.environ["HARNESS_DETECTIONS"] = path
        try:
            d = core.load_detections()
            self.assertIn("a", d)
            self.assertEqual(d["b"]["source"], "SIEM")
        finally:
            del os.environ["HARNESS_DETECTIONS"]
            os.unlink(path)

    def test_detected_verdict_in_report_and_coverage(self):
        # a passed attack that the SOC detected must score DETECT, not GAP.
        with tempfile.TemporaryDirectory() as d:
            ev = core.Evidence(base=d)
            ev.meta["mode"] = "blackbox"
            ev.save_result(1, "x", {
                "iteration": 1, "attack": "X", "attack_id": "x", "category": "C",
                "mitre": ["T9999"], "tactic": "C2", "cwe": [], "cve": "",
                "baseline_result": "DETECTED", "appliance_result": "-",
                "appliance_ip": None, "detected_source": "SIEM",
                "control_tested": "c", "fix_location": "SD-WAN",
            })
            root = ev.finalize()
            cov = ev.meta["attack_coverage"]["T9999"]
            self.assertEqual(cov["status"], "DETECT")
            self.assertEqual(cov["detected"], 1)
            report = open(os.path.join(root, "report.txt")).read()
            self.assertIn("DETECT", report)
            nav = json.load(open(os.path.join(root, "attack_navigator_layer.json")))
            t = [x for x in nav["techniques"] if x["techniqueID"] == "T9999"][0]
            self.assertTrue(t["comment"].startswith("DETECT"))


if __name__ == "__main__":
    unittest.main()
