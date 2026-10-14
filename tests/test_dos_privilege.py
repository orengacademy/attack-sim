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
    def test_hping_privfail_falls_back_to_python(self):
        # hping3's raw socket fails, but the Python datagram flood CAN send (like ping):
        # the module must fall back and score the REAL result (here: delivered -> PASS),
        # never a false BLOCKED and never FLOOD-PRIV-ERROR.
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            None, None, None, "[open_sockraw] socket(): Operation not permitted")
        # deliver enough volume to clear the MIN_MBPS DoS-volume floor (~152 Mbit/s)
        m._py_icmp_flood = lambda target, seconds, result: result.update(
            {"mode": "dgram(unprivileged)", "sent": 200000})

        class _CP:
            stdout = "15 packets transmitted, 15 received, 0% packet loss"
        real_run = m.subprocess.run
        m.subprocess.run = lambda *a, **k: _CP()
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.subprocess.run = real_run
            m.shutil.which = real_which
        self.assertIn("falling back to the Python", out)
        self.assertNotIn("FLOOD-PRIV-ERROR", out)
        self.assertTrue(core._match(out, m.META["success_regex"]),
                        "a delivered high-volume fallback flood should PASS")

    def test_blocked_ratelimit_verdict_renders(self):
        # REGRESSION (v1.9.61): the flat-RTT BLOCKED-RATELIMIT verdict once mixed an
        # f-string with %-formatting and crashed at runtime (ValueError: unsupported
        # format character 'v'). Force loss delta >= threshold with RTT NOT inflated and
        # assert the verdict RENDERS and reads BLOCKED (no crash).
        m = _load_module("icmp_flood")
        m._baseline = lambda t: (0.0, 15.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._sampled_loss_rtt = lambda t, samples=None: (40.0, 16.0, "flood samples")
        m._py_icmp_flood = lambda t, s, result: result.update({"mode": "raw(root)", "sent": 200000})
        real_which = m.shutil.which
        m.shutil.which = lambda x: None            # no hping3 -> Python fallback path
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))

    def test_selfcongestion_pass_verdict_renders(self):
        # the companion branch: loss up AND RTT ballooned (>= RTT_INFLATION x baseline and
        # >= RTT_ABS_FLOOR) -> self-congestion -> PASS. Must also render cleanly.
        m = _load_module("icmp_flood")
        m._baseline = lambda t: (0.0, 15.0, "15 packets transmitted, 15 received, 0% packet loss")
        big_rtt = 15.0 * m.RTT_INFLATION + m.RTT_ABS_FLOOR
        m._sampled_loss_rtt = lambda t, samples=None: (40.0, big_rtt, "flood samples")
        m._py_icmp_flood = lambda t, s, result: result.update({"mode": "raw(root)", "sent": 200000})
        real_which = m.shutil.which
        m.shutil.which = lambda x: None
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("self-congestion", out)
        self.assertTrue(core._match(out, m.META["success_regex"]))

    def _run_syn(self, base_loss, base_rtt, flood_loss, flood_rtt):
        """Drive syn_flood's verdict branches with mocked helpers (no hping3/network).
        shutil.which / time.sleep / subprocess.Popen are SHARED stdlib modules, so they are
        patched with mock.patch.object (auto-restored) — NEVER assigned directly, or they'd
        leak into other tests (that bug shipped once in v1.9.63)."""
        from unittest import mock
        m = _load_module("syn_flood")
        # module-local helpers: safe to set on the freshly re-exec'd module object
        m._connect_ok = lambda t, p, **k: True              # service up; connects stay up
        m._hping_syn = lambda *a, **k: (base_loss, base_rtt, "baseline txt")
        m._parse_loss = lambda out: flood_loss
        m._parse_rtt_avg = lambda out: flood_rtt

        class _P:
            def communicate(self, timeout=None): return ("15 packets ... 100% packet loss", None)
            def kill(self): pass
        with mock.patch.object(m.shutil, "which", lambda x: "/usr/bin/" + x), \
             mock.patch.object(m.time, "sleep", lambda *a, **k: None), \
             mock.patch.object(m.subprocess, "Popen", lambda *a, **k: _P()):
            return m.run("203.0.113.9", _Ctx())

    def test_syn_flood_verdict_branches_render(self):
        # REGRESSION: syn_flood's BLOCKED/PASS verdict strings must RENDER (same shape that
        # crashed in icmp_flood). Exercise all three: loss-delta BLOCKED, RTT-inflation
        # BLOCKED, and clean PASS.
        m = _load_module("syn_flood")
        INFL, FLOOR = m.RTT_INFLATION, m.RTT_ABS_FLOOR
        # loss-delta BLOCKED (delta >= threshold, RTT flat)
        out = self._run_syn(0.0, 10.0, 40.0, 11.0)
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))
        # RTT-inflation BLOCKED (delta small, RTT ballooned past floor)
        out = self._run_syn(0.0, 10.0, 5.0, 10.0 * INFL + FLOOR)
        self.assertIn("BLOCKED-RATELIMIT", out)
        # clean PASS (flood delivered, low loss)
        out = self._run_syn(0.0, 10.0, 0.0, 10.0)
        self.assertTrue(core._match(out, m.META["success_regex"]))

    def test_delivered_but_under_threshold_is_inconclusive(self):
        # Flood delivered (0% loss) but the achieved rate is BELOW the DoS-volume floor
        # -> INCONCLUSIVE, never a false SUCCESS (the "non-aggressive" false-finding).
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            None, None, None, "[open_sockraw] socket(): Operation not permitted")
        # ~38 Mbit/s — below the default 50 Mbit/s floor
        m._py_icmp_flood = lambda target, seconds, result: result.update(
            {"mode": "dgram(unprivileged)", "sent": 50000})

        class _CP:
            stdout = "15 packets transmitted, 15 received, 0% packet loss"
        real_run, real_which = m.subprocess.run, m.shutil.which
        m.subprocess.run = lambda *a, **k: _CP()
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.subprocess.run, m.shutil.which = real_run, real_which
        self.assertIn("INCONCLUSIVE", out)
        self.assertFalse(core._match(out, m.META["success_regex"]),
                         "an under-volume delivered flood must NOT score SUCCESS")
        self.assertFalse(core._match(out, m.META["blocked_regex"]))

    def test_priv_failure_when_both_engines_cant_send(self):
        # hping3 raw socket fails AND the Python datagram socket can't open either ->
        # FLOOD-PRIV-ERROR (-> NO-RESULT), never a false BLOCKED.
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            None, None, None, "[open_sockraw] socket(): Operation not permitted")
        m._py_icmp_flood = lambda target, seconds, result: result.update(
            {"error": "PermissionError: [Errno 1] Operation not permitted"})

        class _CP:
            stdout = "15 packets transmitted, 15 received, 0% packet loss"
        real_run = m.subprocess.run
        m.subprocess.run = lambda *a, **k: _CP()
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.subprocess.run = real_run
            m.shutil.which = real_which
        self.assertIn("FLOOD-PRIV-ERROR", out)
        self.assertFalse(core._match(out, m.META["blocked_regex"]))
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


class TestFloodPacketSize(unittest.TestCase):
    def test_flood_packet_is_full_size(self):
        # the Python fallback must send FLOOD_SIZE-byte packets (not the old 17-byte
        # payload) so the achieved-Mbit/s report is real, not ~30x overstated.
        m = _load_module("icmp_flood")
        pkt = m._flood_packet()
        # 8-byte ICMP header + FLOOD_SIZE payload
        self.assertEqual(len(pkt), 8 + m.FLOOD_SIZE)
        self.assertGreater(m.FLOOD_SIZE, 1000, "default flood payload should be bandwidth-grade")


class TestNoiseHandling(unittest.TestCase):
    def test_median_ignores_one_bad_sample(self):
        m = _load_module("icmp_flood")
        self.assertEqual(m._median([20.0, 0.0, 33.0]), 20.0)
        self.assertEqual(m._median([None, 0.0, 0.0]), 0.0)
        self.assertIsNone(m._median([None, None]))

    def _run_with_baseline(self, base_loss):
        m = _load_module("icmp_flood")
        m._baseline = lambda t: (base_loss, 30.0, "baseline")
        m._hping_flood_at = lambda *a: (None, None, None, "[open_sockraw] Operation not permitted")
        m._py_icmp_flood = lambda t, s, r: r.update({"mode": "raw(root)", "sent": 200000})

        class _CP:
            stdout = f"15 packets transmitted, 15 received, {base_loss:.0f}% packet loss"
        real_run, real_which = m.subprocess.run, m.shutil.which
        m.subprocess.run = lambda *a, **k: _CP()
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            return m.run("203.0.113.9", _Ctx())
        finally:
            m.subprocess.run, m.shutil.which = real_run, real_which

    def test_lossy_baseline_pass_is_low_confidence(self):
        out = self._run_with_baseline(18.0)   # >= NOISE_FLOOR (10)
        self.assertIn("PASS:", out)
        self.assertIn("LOW-CONFIDENCE", out)

    def test_clean_baseline_pass_has_no_caveat(self):
        out = self._run_with_baseline(0.0)
        self.assertIn("PASS:", out)
        self.assertNotIn("LOW-CONFIDENCE", out)
