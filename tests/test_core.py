#!/usr/bin/env python3
"""Unit tests for the harness engine (core.py).

Pure-stdlib (unittest) so they run anywhere without pytest:
    python3 -m unittest discover -s tests        # or: python3 -m pytest tests
Only touches 127.0.0.1; contacts no external host.
"""
import os
import socket
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


def fake_module(mid, **meta):
    meta.setdefault("name", mid)
    meta.setdefault("category", "Test")
    meta["id"] = mid
    m = types.SimpleNamespace()
    m.META = meta
    m.run = lambda target, ctx: ""
    return m


class TestClassify(unittest.TestCase):
    META = {"success_regex": r"WIN", "blocked_regex": r"blocked|refused"}

    def test_success(self):
        b, a, v = core.classify(self.META, "WIN here", "WIN here")
        self.assertEqual(a, "PASSED")
        self.assertIn("FINDING", v)

    def test_blocked_through_appliance(self):
        b, a, v = core.classify(self.META, "WIN here", "connection refused")
        self.assertEqual(a, "BLOCKED")
        self.assertIn("CONTROL WORKING", v)

    def test_credential_error_not_a_control_result(self):
        meta = {"success_regex": r"WIN", "blocked_regex": r"blocked"}
        b, a, v = core.classify(meta, "STATUS_LOGON_FAILURE", "STATUS_LOGON_FAILURE")
        self.assertIn("CREDENTIAL ERROR", v)

    def test_timeout_counts_as_blocked(self):
        b, a, v = core.classify(self.META, "WIN", "[TIMEOUT] ...")
        self.assertEqual(a, "BLOCKED")


class TestRedaction(unittest.TestCase):
    def test_password_redacted(self):
        creds = {"dc_pass": "SuperSecret123", "dc_user": "Administrator"}
        out = core._redact("hydra -p SuperSecret123 ssh://x", creds)
        self.assertNotIn("SuperSecret123", out)
        self.assertIn("***", out)

    def test_short_value_not_redacted(self):
        # a 2-char value would over-redact ordinary text; guard skips it
        out = core._redact("ab cabbage", {"dc_pass": "ab"})
        self.assertEqual(out, "ab cabbage")


class TestTargetSafety(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(core.validate_target("10.0.0.1")[0])

    def test_valid_hostname(self):
        self.assertTrue(core.validate_target("dc01.lab.local")[0])

    def test_invalid(self):
        self.assertFalse(core.validate_target("not a host!!")[0])
        self.assertFalse(core.validate_target("")[0])

    def test_allowlist_enforced(self):
        os.environ["HARNESS_ALLOWLIST"] = "10.0.0.5, dc01.lab.local"
        try:
            self.assertTrue(core.target_allowed("10.0.0.5")[0])
            self.assertFalse(core.target_allowed("10.0.0.9")[0])
        finally:
            del os.environ["HARNESS_ALLOWLIST"]

    def test_no_allowlist_allows_any(self):
        os.environ.pop("HARNESS_ALLOWLIST", None)
        self.assertTrue(core.target_allowed("1.2.3.4")[0])


class TestCredentials(unittest.TestCase):
    def test_env_overrides(self):
        os.environ["HARNESS_DC_PASS"] = "from-env"
        try:
            self.assertEqual(core.load_credentials()["dc_pass"], "from-env")
        finally:
            del os.environ["HARNESS_DC_PASS"]

    def test_password_default_empty(self):
        os.environ.pop("HARNESS_DC_PASS", None)
        # (assumes no credentials.env present in the test env)
        self.assertEqual(core.load_credentials()["dc_pass"], "")


class TestGetPort(unittest.TestCase):
    def test_override_beats_default(self):
        ctx = core.Context(port_overrides={"apache_41773": 8080})
        self.assertEqual(ctx.get_port("apache_41773", 80), 8080)

    def test_default_when_no_override(self):
        self.assertEqual(core.Context().get_port("ssh_brute", 22), 22)

    def test_env_override(self):
        os.environ["HARNESS_PORT_LOG4SHELL"] = "8983"
        try:
            self.assertEqual(core.Context().get_port("log4shell", 8080), 8983)
        finally:
            del os.environ["HARNESS_PORT_LOG4SHELL"]

    def test_bad_override_falls_back(self):
        ctx = core.Context(port_overrides={"x": "notaport"})
        self.assertEqual(ctx.get_port("x", 443), 443)


class TestSudoPrefix(unittest.TestCase):
    def _patch(self, priv, has_sudo):
        self._op, self._ow = core.is_privileged, core.shutil.which
        core.is_privileged = lambda: priv
        core.shutil.which = lambda x: ("/usr/bin/sudo" if x == "sudo" and has_sudo else None)

    def tearDown(self):
        if hasattr(self, "_op"):
            core.is_privileged, core.shutil.which = self._op, self._ow

    def test_root_needs_no_prefix(self):
        self._patch(priv=True, has_sudo=True)
        self.assertEqual(core.sudo_prefix(), [])

    def test_nonroot_with_sudo_uses_noninteractive(self):
        self._patch(priv=False, has_sudo=True)
        self.assertEqual(core.sudo_prefix(), ["sudo", "-n"])   # -n = never prompts

    def test_nonroot_without_sudo_no_prefix(self):
        self._patch(priv=False, has_sudo=False)
        self.assertEqual(core.sudo_prefix(), [])


class TestSudoUnlock(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, "_op"):
            core.is_privileged = self._op
        if hasattr(self, "_ow"):
            core.shutil.which = self._ow

    def test_root_needs_no_unlock(self):
        self._op = core.is_privileged
        core.is_privileged = lambda: True
        ok, _ = core.sudo_unlock("x")
        self.assertTrue(ok)

    def test_no_sudo(self):
        self._op = core.is_privileged; self._ow = core.shutil.which
        core.is_privileged = lambda: False
        core.shutil.which = lambda n: None
        ok, msg = core.sudo_unlock("x")
        self.assertFalse(ok)
        self.assertIn("sudo", msg)


class TestProbes(unittest.TestCase):
    def test_tcp_open_then_closed(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertEqual(core.probe_tcp("127.0.0.1", port, timeout=1), "open")
        finally:
            srv.close()
        # after close, the port should refuse -> closed
        self.assertIn(core.probe_tcp("127.0.0.1", port, timeout=1),
                      ("closed", "filtered"))


class TestPreflightAndReachability(unittest.TestCase):
    def test_preflight_missing_tool(self):
        m = fake_module("x", requires=["definitely-not-a-real-binary-xyz"])
        pf = core.preflight([m])
        self.assertFalse(pf["modules"][0]["ready"])
        self.assertIn("definitely-not-a-real-binary-xyz", pf["modules"][0]["missing"])

    def test_preflight_os_gating(self):
        other = "Windows" if core.platform.system() != "Windows" else "Linux"
        m = fake_module("x", os_supported=[other])
        r = core.preflight([m])["modules"][0]
        self.assertFalse(r["os_ok"])
        self.assertFalse(r["ready"])

    def test_preflight_ready_no_tools(self):
        m = fake_module("x")  # no requires -> ready
        self.assertTrue(core.preflight([m])["modules"][0]["ready"])

    def test_reachability_categories(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            m_open = fake_module("o", ports=[("tcp", port)])
            m_none = fake_module("n", ports=[])
            rc = core.reachability("127.0.0.1", [m_open, m_none], timeout=1)
            by = {r["id"]: r for r in rc["modules"]}
            self.assertEqual(by["o"]["category"], "suggested")
            self.assertEqual(by["n"]["category"], "noport")
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
