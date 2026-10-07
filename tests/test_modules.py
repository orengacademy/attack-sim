#!/usr/bin/env python3
"""Tests for the pure-socket SD-WAN modules (segmentation sweep, App-ID mismatch).
Localhost-only; no external tools required.
    python3 -m unittest discover -s tests
"""
import importlib
import os
import re
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


def _listener():
    """Start a throwaway TCP listener on 127.0.0.1; return (port, close_fn)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.sendall(b"hello\n")
                c.close()
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], (lambda: (stop.set(), srv.close()))


class TestSegmentationSweep(unittest.TestCase):
    def test_open_port_is_a_finding(self):
        seg = importlib.import_module("modules.segmentation_sweep")
        port, close = _listener()
        try:
            seg.SENSITIVE = [(port, "TEST")]           # point the sweep at our listener
            out = seg.run("127.0.0.1", core.Context())
            self.assertTrue(re.search(seg.META["success_regex"], out, re.M))
            self.assertIn("OPEN", out)
        finally:
            close()

    def test_no_open_is_blocked(self):
        seg = importlib.import_module("modules.segmentation_sweep")
        # a port nothing is listening on -> closed -> no finding
        seg.SENSITIVE = [(1, "TEST")]
        out = seg.run("127.0.0.1", core.Context())
        self.assertFalse(re.search(seg.META["success_regex"], out, re.M))
        self.assertTrue(re.search(seg.META["blocked_regex"], out, re.M))


class TestAppIdMismatch(unittest.TestCase):
    def test_mismatch_allowed_when_service_answers(self):
        appid = importlib.import_module("modules.appid_port_mismatch")
        port, close = _listener()
        try:
            appid.PAIRS = [(port, b"SSH-2.0-Test\r\n", "test-mismatch")]
            out = appid.run("127.0.0.1", core.Context())
            self.assertTrue(re.search(appid.META["success_regex"], out, re.M))
        finally:
            close()


class TestEgressModules(unittest.TestCase):
    def test_l7_not_enforced_when_peer_answers(self):
        l7 = importlib.import_module("modules.l7_enforce_443")
        port, close = _listener()   # accepts and sends bytes back
        try:
            l7.META = dict(l7.META)  # avoid mutating shared META across tests
            out = l7.run("127.0.0.1", core.Context(port_overrides={"l7_enforce_443": port}))
            self.assertTrue(re.search(l7.META["success_regex"], out, re.M))
        finally:
            close()

    def test_tls_carrier_no_tls_on_plain_listener(self):
        tls = importlib.import_module("modules.tls_carrier")
        port, close = _listener()   # plaintext listener -> TLS handshake fails
        try:
            out = tls.run("127.0.0.1", core.Context(port_overrides={"tls_carrier": port}))
            self.assertFalse(re.search(tls.META["success_regex"], out, re.M))
            self.assertIn("no-tls", out)
        finally:
            close()


class TestNtlmMd4Prereq(unittest.TestCase):
    """noPac / sAMAccountName need MD4 (ldap3 NTLM). The helper detects it and the
    modules report a clean PREREQ-MISSING (not a cryptic NO-RESULT) when it's gone."""

    def test_helper_and_hint(self):
        _util = importlib.import_module("modules._util")
        self.assertIsInstance(_util.ntlm_md4_available(), bool)
        self.assertIn("PREREQ-MISSING", _util.MD4_PREREQ_HINT)
        self.assertIn("pycryptodome", _util.MD4_PREREQ_HINT)

    def test_modules_report_prereq_when_md4_missing(self):
        _util = importlib.import_module("modules._util")
        sama = importlib.import_module("modules.samaccountname_spoof")
        orig = _util.ntlm_md4_available
        _util.ntlm_md4_available = lambda: False
        try:
            out = sama.run("10.255.255.1", core.Context(credentials={
                "domain": "lab.local", "dc_user": "Administrator", "dc_pass": "x"}))
            self.assertIn("PREREQ-MISSING", out)
            self.assertNotIn("Traceback", out)
        finally:
            _util.ntlm_md4_available = orig


class TestLog4ShellOOB(unittest.TestCase):
    """The log4shell module's --active out-of-band exploitation confirmation.
    Localhost-only: a simulated 'vulnerable target' connects back to the catcher
    with the marker (what log4j's JNDI lookup would do). No network, no curl."""

    def setUp(self):
        self.l4s = importlib.import_module("modules.log4shell")
        s = socket.socket()                      # grab a free high port for the catcher
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self._save = (self.l4s._OOB_PORT, self.l4s._OOB_WAIT, self.l4s._fire_oob)
        self.l4s._OOB_PORT = self.port
        self.l4s._OOB_WAIT = 2.0

    def tearDown(self):
        self.l4s._OOB_PORT, self.l4s._OOB_WAIT, self.l4s._fire_oob = self._save

    def test_success_regex_matches_rce_confirmed_and_served(self):
        rx = self.l4s.META["success_regex"]
        self.assertTrue(re.search(rx, "RCE-CONFIRMED: callback from 10.0.0.5"))
        self.assertTrue(re.search(rx, "HTTP_CODE:200 TIME:0.01"))

    def test_callback_host_prefers_source_ip(self):
        ctx = core.Context(source_ip="127.0.0.1")
        self.assertEqual(self.l4s._callback_host(ctx, "10.0.0.1"), "127.0.0.1")

    def test_oob_confirmed_when_target_calls_back(self):
        def fake_fire(target, web_port, host, oob_port, marker, ctx):
            # emulate log4j performing the JNDI lookup: bind, then search w/ the marker
            try:
                c = socket.create_connection((host, oob_port), timeout=2)
                c.sendall(b"\x30\x0c\x02\x01\x01`\x07\x02\x01\x03\x04\x00\x80\x00")
                try:
                    c.recv(32)               # the catcher's BIND_OK
                except OSError:
                    pass
                c.sendall(b"search:" + marker.encode())
                c.close()
            except OSError:
                pass
            return "simulated vulnerable target connected back"
        self.l4s._fire_oob = fake_fire
        ctx = core.Context(source_ip="127.0.0.1", allow_active=True)
        lines, confirmed = self.l4s._oob_confirm("127.0.0.1", 8080, ctx)
        blob = "\n".join(lines)
        self.assertTrue(confirmed, blob)
        self.assertIn("RCE-CONFIRMED", blob)

    def test_oob_inconclusive_when_no_callback(self):
        self.l4s._fire_oob = lambda *a, **k: "fired; target did not connect back"
        ctx = core.Context(source_ip="127.0.0.1", allow_active=True)
        lines, confirmed = self.l4s._oob_confirm("127.0.0.1", 8080, ctx)
        blob = "\n".join(lines)
        self.assertFalse(confirmed)
        self.assertIn("OOB-INCONCLUSIVE", blob)

    def test_run_default_is_signature_only_and_says_so(self):
        # stub run_cmd so no real curl/network is needed; default (allow_active=False)
        ctx = core.Context()
        ctx.run_cmd = lambda cmd, target: "HTTP_CODE:200 TIME:0.01"
        out = self.l4s.run("127.0.0.1", ctx)
        self.assertIn("HTTP_CODE:200", out)
        self.assertIn("OOB exploitation confirmation OFF", out)
        self.assertNotIn("RCE-CONFIRMED", out)


class TestIcmpHostLivenessBlock(unittest.TestCase):
    """ICMP 100%-loss refinement: when baseline ICMP is fully lost the verdict is
    decided by TCP liveness (a real test observation, not posture) — host up on
    TCP + ICMP gone => BLOCKED (ICMP filtered); host unconfirmable => INCONCLUSIVE.
    Localhost-only, offline."""

    def setUp(self):
        self.icmp = importlib.import_module("modules.icmp_flood")
        self._ports = self.icmp._LIVENESS_PORTS

    def tearDown(self):
        self.icmp._LIVENESS_PORTS = self._ports

    def test_open_port_confirms_up(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.icmp._LIVENESS_PORTS = (port,)
            up, how = self.icmp._host_up_via_tcp("127.0.0.1", core.Context())
            self.assertTrue(up)
            self.assertIn(str(port), how)
        finally:
            srv.close()

    def test_refused_port_confirms_up(self):
        # a closed localhost port -> RST (ECONNREFUSED) -> the host is still UP
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        self.icmp._LIVENESS_PORTS = (p,)
        up, how = self.icmp._host_up_via_tcp("127.0.0.1", core.Context(), timeout=1.0, budget=3.0)
        self.assertTrue(up)

    def test_silent_host_not_confirmed(self):
        # TEST-NET-1 (unroutable) -> connect times out -> cannot confirm up
        self.icmp._LIVENESS_PORTS = (80,)
        up, _ = self.icmp._host_up_via_tcp("192.0.2.1", core.Context(), timeout=0.4, budget=1.0)
        self.assertFalse(up)


class TestDohBypassHardened(unittest.TestCase):
    """doh_bypass now resolves a POLICY-BLOCKED canary over DoH and classifies the
    3-leg chain (direct baseline / DoH resolve / connect-by-IP). Pure helpers are
    tested offline; the network legs run via curl in the field."""

    def setUp(self):
        self.doh = importlib.import_module("modules.doh_bypass")

    def test_parse_doh_ips(self):
        j = ('{"Status":0,"Answer":[{"name":"x","type":1,"TTL":29,"data":"172.66.0.144"},'
             '{"type":1,"data":"162.159.140.146"}]}')
        self.assertEqual(self.doh._parse_doh_ips(j), ["172.66.0.144", "162.159.140.146"])

    def test_parse_doh_ips_none(self):
        self.assertEqual(self.doh._parse_doh_ips('{"Status":3,"Answer":[]}'), [])

    def test_parse_code(self):
        self.assertEqual(self.doh._parse_code("ACCESS-HTTP:403", "ACCESS-HTTP"), "403")
        self.assertEqual(self.doh._parse_code("DIRECT-HTTP:000", "DIRECT-HTTP"), "000")
        self.assertEqual(self.doh._parse_code("", "DIRECT-HTTP"), "000")

    def test_verdict_full_bypass(self):
        # direct blocked (000) + DoH resolved + access reached -> full policy bypass
        v, ok = self.doh._compose_verdict("onlyfans.com", ["172.66.0.144"], True, "000", "403")
        self.assertTrue(ok)
        self.assertIn("DOH-BYPASS", v)
        self.assertIn("BYPASSED via DoH", v)
        self.assertIn("FULL BYPASS", v)

    def test_verdict_dns_only_bypass(self):
        # direct blocked + DoH resolved but connect-by-IP blocked -> connection-layer holds
        v, ok = self.doh._compose_verdict("x.example", ["1.2.3.4"], True, "000", "000")
        self.assertTrue(ok)
        self.assertIn("connection-layer", v)

    def test_verdict_no_block_observed(self):
        # direct ALSO reached -> no DNS block on this canary from here (e.g. run off-net)
        v, ok = self.doh._compose_verdict("x.example", ["1.2.3.4"], True, "200", "200")
        self.assertTrue(ok)
        self.assertIn("no DNS block observed", v)

    def test_verdict_doh_blocked(self):
        v, ok = self.doh._compose_verdict("x.example", [], False, "000", "000")
        self.assertFalse(ok)
        self.assertIn("DOH-BLOCKED", v)

    def test_success_and_blocked_regex(self):
        self.assertTrue(re.search(self.doh.META["success_regex"], "DOH-BYPASS: resolved x -> 1.2.3.4"))
        self.assertTrue(re.search(self.doh.META["success_regex"], '  "Answer":[{"data":"1.2.3.4"}]'))
        self.assertTrue(re.search(self.doh.META["blocked_regex"], "DOH-BLOCKED: no DoH response"))


class TestIcmpRateReport(unittest.TestCase):
    """icmp_flood now reports the ACHIEVED flood rate (a single host rarely reaches
    the configured pps) and flags an under-powered run so a below-threshold PASS
    isn't read as 'no policing'."""

    def setUp(self):
        self.icmp = importlib.import_module("modules.icmp_flood")

    def test_parse_sent(self):
        self.assertEqual(
            self.icmp._parse_sent("47987 packets transmitted, 46681 received, 3% packet loss"), 47987)
        self.assertIsNone(self.icmp._parse_sent("no stats here"))

    def test_rate_report_source_limited(self):
        # 47987 sent in 15s @ target 20000 pps -> ~3200 pps, well under half -> source-limited
        rate, limited = self.icmp._rate_report(47987, 15, 1400, 20000)
        self.assertIn("ACHIEVED", rate)
        self.assertIn("Mbit/s", rate)
        self.assertTrue(limited)

    def test_rate_report_at_target_not_limited(self):
        rate, limited = self.icmp._rate_report(300000, 15, 1400, 20000)   # ~20000 pps
        self.assertFalse(limited)

    def test_rate_report_no_sent(self):
        rate, limited = self.icmp._rate_report(None, 15, 1400, 20000)
        self.assertIn("configured target", rate)
        self.assertFalse(limited)

    def test_list_env(self):
        import os as _os
        self.assertEqual(self.icmp._list_env("HARNESS_NOPE_RAMP", [1, 2, 3]), [1, 2, 3])
        _os.environ["HARNESS_TEST_RAMP"] = "200, 1000 ,5000"
        try:
            self.assertEqual(self.icmp._list_env("HARNESS_TEST_RAMP", [1]), [200, 1000, 5000])
        finally:
            _os.environ.pop("HARNESS_TEST_RAMP", None)

    def test_is_knee_loss_jump(self):
        self.assertTrue(self.icmp._is_knee(45.0, 10.0, 2.0, 9.0))    # +43 pts loss -> policed
        self.assertFalse(self.icmp._is_knee(6.0, 10.0, 2.0, 9.0))    # +4 pts -> delivered

    def test_is_knee_rtt_inflation(self):
        self.assertTrue(self.icmp._is_knee(1.0, 900.0, 1.0, 10.0))   # 90x and >=150ms -> shaped
        self.assertFalse(self.icmp._is_knee(1.0, 40.0, 1.0, 10.0))   # 4x, under the 6x/150ms floor

    def test_fmt(self):
        self.assertEqual(self.icmp._fmt(None), "?")
        self.assertEqual(self.icmp._fmt(3199.4), "3,199")
        self.assertEqual(self.icmp._fmt(12.0, 1), "12.0")


class TestDcsyncVssFallback(unittest.TestCase):
    """dcsync: DRSUAPI (real DCSync) first; for cloud/NAT'd targets where the
    dynamic RPC endpoint isn't reachable, a LABELLED VSS-over-SMB fallback. Offline
    checks: the module exposes both paths and success_regex matches a VSS krbtgt line."""

    def setUp(self):
        self.d = importlib.import_module("modules.dcsync")

    def test_has_both_paths(self):
        self.assertTrue(hasattr(self.d, "_run_in_process") and hasattr(self.d, "_dump"))

    def test_success_regex_matches_vss_krbtgt_line(self):
        line = "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:975503e819a3ffb84ee9d23749ac8d52:::"
        self.assertTrue(re.search(self.d.META["success_regex"], line))

    def test_vss_fallback_label_is_not_a_success_by_itself(self):
        note = "[VSS-FALLBACK] DRSUAPI/DCSync replication was UNREACHABLE through the cloud NAT"
        self.assertFalse(re.search(self.d.META["success_regex"], note))


class TestFloodRunsLast(unittest.TestCase):
    """icmp_flood is the DEAD-LAST attack executed (operator request, ORG2026-70):
    its flood trips this SD-WAN's PERSISTENT anti-DoS source-ban, so running it after
    everything else (incl. ssh_brute) means that ban contaminates nothing — ssh and
    all others get a clean, un-banned test first."""

    def test_icmp_flood_sorts_after_ssh_brute(self):
        icmp = importlib.import_module("modules.icmp_flood").META
        ssh = importlib.import_module("modules.ssh_brute").META
        self.assertTrue(icmp.get("run_last"))
        self.assertGreater(icmp.get("order", 0), ssh.get("order", 0))

    def test_icmp_flood_is_the_last_deferred_module(self):
        import loader
        mods = loader.discover()
        def defer(m): return bool(m.META.get("run_last") or m.META.get("trips_ips"))
        serial = [m for m in mods if defer(m) or m.META.get("serial")]
        serial.sort(key=lambda mm: (defer(mm), mm.META.get("order", 0)))
        tail = [m for m in serial if defer(m)]
        self.assertEqual(tail[-1].META["id"], "icmp_flood")


class TestFtpAnonResetBlocked(unittest.TestCase):
    """FTP anon: a session RESET right after the 220 banner (an IPS resetting the
    `USER anonymous` command — e.g. Sangfor's FTP-anonymous signature) must read
    BLOCKED, not NO-RESULT. A real 230 success must still win."""

    def setUp(self):
        self.m = importlib.import_module("modules.ftp_anonymous")

    def _run(self, canned):
        class _Ctx:
            def get_port(self, *a):
                return 21
            def run_cmd(self, *a):
                return canned
        return self.m.run("10.38.98.132", _Ctx())

    def test_reset_after_banner_marks_blocked(self):
        out = self._run("< 220 Microsoft FTP Service\n> USER anonymous\n"
                        "* Recv failure: Connection reset by peer\n* closing connection #0\n")
        self.assertIn("FTP-BLOCKED", out)
        self.assertTrue(re.search(self.m.META["blocked_regex"], out, re.I | re.M))
        self.assertFalse(re.search(self.m.META["success_regex"], out, re.I | re.M))

    def test_230_success_not_overridden(self):
        out = self._run("< 220 FTP\n> USER anonymous\n< 230 Login successful\n")
        self.assertNotIn("FTP-BLOCKED", out)
        self.assertTrue(re.search(self.m.META["success_regex"], out, re.I | re.M))


class TestSshBruteBlockedMidTest(unittest.TestCase):
    """ssh_brute: a burst that CONNECTS (tripping the signature) and then a blocked
    credential test must read BLOCKED, not NO-RESULT. Hydra's 'could not connect -
    Timeout connecting' matches neither success_regex nor blocked_regex by itself
    (that was the bug), so the module must emit a BRUTE-BLOCKED marker that does."""

    def setUp(self):
        self.m = importlib.import_module("modules.ssh_brute")

    def test_brute_blocked_marker_scores_blocked(self):
        line = ("\nBRUTE-BLOCKED: the burst CONNECTED (39 session(s), SSH reachable) and "
                "TRIPPED the brute-force signature - the credential test ... Protection works.")
        self.assertTrue(re.search(self.m.META["blocked_regex"], line, re.I | re.M))

    def test_raw_hydra_timeout_alone_matches_nothing(self):
        # the bug: this hydra line alone scored NO-RESULT; the module must classify it.
        raw = ("[ERROR] could not connect to ssh://10.35.131.79:22 - Timeout connecting "
               "to 10.35.131.79")
        self.assertFalse(re.search(self.m.META["success_regex"], raw, re.I | re.M))
        self.assertFalse(re.search(self.m.META["blocked_regex"], raw, re.I | re.M))


if __name__ == "__main__":
    unittest.main(verbosity=2)
