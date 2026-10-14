"""Regression: a DoS flood that can't get raw-socket privilege (no root / no usable
sudo / no cap_net_raw) must read FLOOD-PRIV-ERROR (-> NO-RESULT), never BLOCKED.

The bug: unprivileged hping3 still prints a "100% packet loss" stats line, and the
priv-error guard used to be gated on "loss did not parse", so that 100%-loss line
slipped past it and was scored as the boundary rate-limiting the flood — a FALSE
BLOCKED that wrongly credits a control.

Pure-stdlib / offline: hping3/ping are stubbed; nothing is sent."""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import core  # noqa: E402


def _load_module(name):
    sys.modules.setdefault("core", core)
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "modules", f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


class _Ctx:
    source_ip = None
    def bind_source(self, s):
        pass
    def cfg(self, *a, **k):
        return None
    def get_port(self, *a, **k):
        return a[1] if len(a) > 1 else None


class TestIcmpFloodPrivilege(unittest.TestCase):
    def test_priv_failure_is_not_blocked(self):
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        # unprivileged hping3: the raw-socket error AND a 100% packet-loss stats line
        m._hping_flood_at = lambda t, pps, sz, sec: (
            100.0, None, 0,
            "[open_sockraw] socket(): Operation not permitted\n"
            "1 packets transmitted, 0 received, 100% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("FLOOD-PRIV-ERROR", out)
        self.assertFalse(core._match(out, m.META["blocked_regex"]),
                         "a privilege failure must NOT match blocked_regex (false BLOCKED)")
        self.assertFalse(core._match(out, m.META["success_regex"]))

    def test_real_policing_still_blocks(self):
        # a genuine policed flood (high loss, NO privilege error) must still read BLOCKED
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            95.0, 1.0, pps * sec,
            f"{pps*sec} packets transmitted, {int(pps*sec*0.05)} received, 95% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertNotIn("FLOOD-PRIV-ERROR", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]),
                        "a real policed flood should still score BLOCKED")


if __name__ == "__main__":
    unittest.main()
