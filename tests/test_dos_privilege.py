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

    def test_hping_knee_blocked_renders(self):
        # The BLOCKED-RATELIMIT verdict now lives ONLY in the hping3 raw-socket ramp (the
        # datagram fallback no longer scores BLOCKED). Drive the ramp to a knee and assert the
        # verdict renders + reads BLOCKED (also guards the v1.9.62 format-string crash).
        m = _load_module("icmp_flood")
        m._baseline = lambda t: (0.0, 15.0, "15 packets transmitted, 15 received, 0% packet loss")
        # a step that jumps loss >= RATE_LIMIT_DELTA over baseline -> _is_knee True
        m._hping_flood_at = lambda t, pps, sz, sec: (40.0, 16.0, 100000, "hping output, no priv error")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))

    def test_fallback_highloss_reads_pass_not_blocked(self):
        # The datagram fallback measures DELIVERY, not policing: high echo-reply loss with flat
        # RTT is the TARGET's own kernel reply-throttle, NOT a boundary control. It must read PASS
        # (delivered) with a kernel-reply-throttle caveat, NEVER BLOCKED (the false-BLOCKED the
        # user hit from WSL1 against a no-SD-WAN host).
        m = _load_module("icmp_flood")
        m._baseline = lambda t: (0.0, 15.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._sampled_loss_rtt = lambda t, samples=None: (60.0, 22.0, "flood samples")  # flat RTT
        m._py_icmp_flood = lambda t, s, result: result.update({"mode": "raw(root)", "sent": 143798})
        real_which = m.shutil.which
        m.shutil.which = lambda x: None            # no hping3 -> datagram fallback
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertTrue(core._match(out, m.META["success_regex"]),
                        "a delivered datagram flood must read PASS, not BLOCKED")
        self.assertFalse(core._match(out, m.META["blocked_regex"]))
        self.assertIn("kernel", out.lower())       # the reply-throttle caveat is present

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
        # TOTAL loss with a working baseline = anti-DoS blackhole -> BLOCKED, never a
        # self-congestion INCONCLUSIVE (mirrors icmp_flood's total-loss override).
        out = self._run_syn(0.0, 10.0, 100.0, 0.0)
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertFalse(core._match(out, m.META["success_regex"]))

    def test_delivered_but_under_threshold_is_pass_with_caveat(self):
        # Flood delivered (0% loss) BELOW the DoS-volume floor. DECISIVE (v1.9.65): PASS
        # (the flood reached the target = finding) WITH an under-powered / low-confidence
        # caveat — never a mute INCONCLUSIVE, and never a naive clean SUCCESS.
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
        self.assertNotIn("[INCONCLUSIVE]", out)
        self.assertTrue(core._match(out, m.META["success_regex"]),
                        "decisive: a delivered flood scores PASS (SUCCESS)")
        self.assertIn("under-powered", out,
                      "under-volume PASS must carry the low-confidence/under-powered caveat")

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
        # A genuine policer kicks in at a DoS-GRADE volume, not at a trivial rate: the
        # flood delivers clean at low steps, then loss jumps once the achieved volume is
        # >= MIN_MBPS. That reached + DoS-grade loss knee must still read BLOCKED. (Loss
        # at a sub-DoS volume is now PASS — the source's own ceiling, not a control —
        # see test_real_policing_sub_dos_volume_is_pass below.)
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        # loss jumps only at pps >= 5000, where sent=20000 over 4s => ~57 Mbit/s (>= 50 floor)
        m._hping_flood_at = lambda t, pps, sz, sec: (
            (95.0 if pps >= 5000 else 1.0), 1.0, pps * sec,
            f"{pps*sec} packets transmitted, {int(pps*sec*(0.05 if pps>=5000 else 0.99))} received, "
            f"{'95' if pps>=5000 else '1'}% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertNotIn("FLOOD-PRIV-ERROR", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]),
                        "a real DoS-grade policed flood should still score BLOCKED")

    def test_real_policing_sub_dos_volume_is_pass(self):
        # The batch-vs-solo flip fix: a PARTIAL loss knee at a trivial volume (< MIN_MBPS)
        # is the source hitting its OWN uplink ceiling, not a boundary control — it must
        # read PASS, never the vantage-dependent false BLOCKED. Here 45% loss appears at
        # target 1000 pps (~11 Mbit/s over 4s), far below the 50 Mbit/s DoS floor. (Partial,
        # NOT total — a near-total loss is the blackhole case covered below.)
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            45.0, 2.0, pps * sec,
            f"{pps*sec} packets transmitted, {int(pps*sec*0.55)} received, 45% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertTrue(core._match(out, m.META["success_regex"]),
                        "a partial sub-DoS-volume loss knee is self-congestion -> PASS, not BLOCKED")
        self.assertFalse(core._match(out, m.META["blocked_regex"]))

    def test_total_loss_is_dos_detected_blocked(self):
        # The "DOS detected" case: a WORKING baseline then ~100% loss of the flood at a
        # LOW volume (the source pushed only ~8 Mbit/s — no uplink saturates there, and
        # this source can do 300+ Mbit/s elsewhere) = an anti-DoS blackhole/ban dropped
        # the WHOLE flood. Must read BLOCKED (BLOCKED-DOS-DETECTED), not a false PASS from
        # the achieved-rate self-congestion demotion (the bug the field run hit).
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 67.0, "15 packets transmitted, 15 received, 0% packet loss")
        # step 1 (target 1000 pps): source SENT ~711 pps but 100% was dropped, RTT unmeasurable
        m._hping_flood_at = lambda t, pps, sz, sec: (
            100.0, 0.0, 711 * sec,
            f"{711*sec} packets transmitted, 0 received, 100% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("10.38.98.14", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("BLOCKED-DOS-DETECTED", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))
        self.assertFalse(core._match(out, m.META["success_regex"]),
                         "a total-loss blackhole must NOT read PASS")


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
