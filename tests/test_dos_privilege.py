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

    def _run_syn(self, base_loss, base_rtt, flood_loss, flood_rtt, sent=100000, elapsed=5.0, uplink=0):
        """Drive syn_flood's verdict branches with mocked helpers (no hping3/network).
        shutil.which / time.sleep / time.time / subprocess.Popen are SHARED stdlib modules, so
        they are patched with mock.patch.object (auto-restored) — NEVER assigned directly, or
        they'd leak into other tests (that bug shipped once in v1.9.63). `sent`/`elapsed` make
        the ACHIEVED send-rate (and thus bandwidth) deterministic; `uplink` sets the declared
        source uplink (HARNESS_SYN_UPLINK_MBPS) so the attribution branches can be exercised."""
        from unittest import mock
        m = _load_module("syn_flood")
        m.UPLINK_MBPS = uplink
        # module-local helpers: safe to set on the freshly re-exec'd module object
        m._connect_ok = lambda t, p, **k: True              # service up; connects stay up
        m._hping_syn = lambda *a, **k: (base_loss, base_rtt, "baseline txt")
        m._parse_loss = lambda out: flood_loss
        m._parse_rtt_avg = lambda out: flood_rtt
        m._parse_sent = lambda out: sent
        times = [1000.0, 1000.0 + elapsed]                  # t0, then t0+elapsed thereafter
        clock = lambda: times.pop(0) if len(times) > 1 else times[0]

        class _P:
            def communicate(self, timeout=None): return (f"{sent} packets transmitted", None)
            def kill(self): pass
        with mock.patch.object(m.shutil, "which", lambda x: "/usr/bin/" + x), \
             mock.patch.object(m.time, "sleep", lambda *a, **k: None), \
             mock.patch.object(m.time, "time", clock), \
             mock.patch.object(m.subprocess, "Popen", lambda *a, **k: _P()):
            return m.run("203.0.113.9", _Ctx())

    def test_syn_flood_verdict_branches_render(self):
        # Attribution parity with icmp_flood: a REACHED-rate loss knee (host put the rate on
        # the wire, SYN-ACKs dropped downstream) is BLOCKED by DEFAULT even at low volume; a
        # THIN declared uplink demotes it to INCONCLUSIVE; a host that could NOT transmit the
        # rate is INCONCLUSIVE; RTT shaping and TOTAL loss are BLOCKED; a clean flood is PASS.
        # (sent=100k over 5s => ~20k pps / ~6.4 Mbit/s, reached vs the 5000 pps target.)
        m = _load_module("syn_flood")
        INFL, FLOOR = m.RTT_INFLATION, m.RTT_ABS_FLOOR
        # reached-rate loss knee, no declared uplink -> BLOCKED by default (+ uplink caveat)
        out = self._run_syn(0.0, 10.0, 40.0, 11.0)
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))
        self.assertIn("ASSUMES the tester uplink", out)
        # SAME knee, but a THIN declared uplink (5 Mbit/s) is saturated by ~6.4 Mbit/s ->
        # the tester's own uplink, not the target -> INCONCLUSIVE
        out = self._run_syn(0.0, 10.0, 40.0, 11.0, uplink=5)
        self.assertIn("[INCONCLUSIVE]", out)
        self.assertFalse(core._match(out, m.META["blocked_regex"]))
        # host could NOT transmit the rate (sent=5000 over 5s => ~1000 pps << 5000) -> STILL
        # BLOCKED by default (decisive), with a threshold-at/below note
        out = self._run_syn(0.0, 10.0, 40.0, 11.0, sent=5000)
        self.assertIn("BLOCKED-RATELIMIT", out)
        self.assertIn("threshold is at/below", out)
        # RTT-inflation BLOCKED (delta small, RTT ballooned past floor) — active shaping
        out = self._run_syn(0.0, 10.0, 5.0, 10.0 * INFL + FLOOR)
        self.assertIn("BLOCKED-RATELIMIT", out)
        # clean PASS (flood delivered, low loss)
        out = self._run_syn(0.0, 10.0, 0.0, 10.0)
        self.assertTrue(core._match(out, m.META["success_regex"]))
        # TOTAL loss with a working baseline = anti-DoS blackhole -> BLOCKED regardless of
        # volume/uplink (mirrors icmp_flood's total-loss override).
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

    def test_reached_low_volume_knee_is_blocked_by_default(self):
        # The FIELD false-PASS, now fixed: a differently-tuned SD-WAN DENIED a 2,100-pps
        # flood at a LOW volume (~24 Mbit/s). The source TRANSMITTED that rate (reached) and
        # the replies were dropped downstream, so by DEFAULT (no uplink declared) it reads
        # BLOCKED — a single host doesn't saturate a remote target at these rates, so a drop
        # is the boundary. The low-volume BLOCKED carries an ASSUMES-uplink caveat.
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        # source transmits ~the target rate (reached) at every step; 45% loss (partial, low vol)
        m._hping_flood_at = lambda t, pps, sz, sec: (
            45.0, 2.0, pps * sec,
            f"{pps*sec} packets transmitted, {int(pps*sec*0.55)} received, 45% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertTrue(core._match(out, m.META["blocked_regex"]),
                        "a reached-rate loss knee is downstream -> BLOCKED by default (the field DENY)")
        self.assertFalse(core._match(out, m.META["success_regex"]),
                         "...and never the old false PASS")
        self.assertIn("ASSUMES the tester uplink", out,
                      "a low-volume BLOCKED must carry the declare-your-uplink caveat")

    def test_thin_uplink_declared_demotes_reached_knee_to_inconclusive(self):
        # SAME reached low-volume knee, but a THIN tester declares its real uplink
        # (HARNESS_ICMP_UPLINK_MBPS=10). The ~11 Mbit/s loss is AT/ABOVE that uplink's usable
        # headroom, so it's the tester's OWN uplink saturating, not the target -> INCONCLUSIVE,
        # never a false BLOCKED. This is the thin-link escape hatch.
        m = _load_module("icmp_flood")
        m.UPLINK_MBPS = 10         # declare a thin uplink (as HARNESS_ICMP_UPLINK_MBPS would)
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")
        m._hping_flood_at = lambda t, pps, sz, sec: (
            45.0, 2.0, pps * sec,                               # ~11 Mbit/s at target 1000 pps
            f"{pps*sec} packets transmitted, {int(pps*sec*0.55)} received, 45% packet loss")
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("[INCONCLUSIVE]", out)
        self.assertFalse(core._match(out, m.META["blocked_regex"]),
                         "a knee at/above the declared thin uplink is self-congestion, not BLOCKED")
        self.assertFalse(core._match(out, m.META["success_regex"]))

    def test_egress_eperm_after_clean_step_is_blocked_not_fallback(self):
        # REPRODUCED IN THE FIELD (netns + iptables OUTPUT -j DROP): a clean lower step uses the
        # raw socket fine, then a higher step is refused with EPERM at the SENDER (a local egress
        # firewall / host-based SD-WAN agent / in-path OUTPUT DROP). The old code read the
        # "operation not permitted" as a RAW-SOCKET PRIVILEGE failure, fell back to the datagram
        # flood, and printed a false PASS. It must now read BLOCKED-EGRESS-DENIED — the control
        # denied the flood, the socket demonstrably worked at the lower rate.
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")

        def _hp(t, pps, sz, sec):
            if pps <= 1000:   # clean step: raw socket works
                return (1.0, 8.0, 1000 * sec,
                        f"{1000*sec} packets transmitted, {int(1000*sec*0.99)} received, 1% packet loss")
            # higher step: egress refuses to SEND (EPERM) = the control denied the flood
            return (None, None, None, "[send_ip] sendto: Operation not permitted")
        m._hping_flood_at = _hp
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertIn("BLOCKED-EGRESS-DENIED", out)
        self.assertTrue(core._match(out, m.META["blocked_regex"]))
        self.assertFalse(core._match(out, m.META["success_regex"]),
                         "an egress EPERM after a clean step is the control, not a false PASS")
        self.assertNotIn("falling back to the Python", out,
                         "the raw socket worked at the lower step — do NOT misread EPERM as a priv failure")

    def test_not_reached_knee_is_blocked_with_threshold_note(self):
        # A clean low step then a higher step the source could NOT fully transmit (achieved
        # ~2000 pps of a 5000 target) that was dropped -> DECISIVE BLOCKED by default (no more
        # inconclusive), and the message must say the threshold is at/below the rate the host
        # DID push (don't claim the full target rate).
        m = _load_module("icmp_flood")
        m._baseline = lambda target: (0.0, 1.0, "15 packets transmitted, 15 received, 0% packet loss")

        def _hp(t, pps, sz, sec):
            if pps <= 1000:    # low step delivers CLEAN
                return (0.0, 1.0, 1000 * sec,
                        f"{1000*sec} packets transmitted, {1000*sec} received, 0% packet loss")
            # higher step: host transmits only ~2000 pps of the 5000 target, 45% dropped
            return (45.0, 2.0, 2000 * sec,
                    f"{2000*sec} packets transmitted, {int(2000*sec*0.55)} received, 45% packet loss")
        m._hping_flood_at = _hp
        real_which = m.shutil.which
        m.shutil.which = lambda x: "/usr/bin/hping3" if x == "hping3" else real_which(x)
        try:
            out = m.run("203.0.113.9", _Ctx())
        finally:
            m.shutil.which = real_which
        self.assertTrue(core._match(out, m.META["blocked_regex"]),
                        "a not-reached loss knee is still BLOCKED by default (decisive)")
        self.assertFalse(core._match(out, m.META["success_regex"]))
        self.assertIn("threshold is at/below", out)
        self.assertIn("short of the ~5,000 pps target", out)

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
