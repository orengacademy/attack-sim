"""Verdict-attribution regression tests for the ADDED (non-original) modules.

All localhost-only / offline: they either exercise a module's run() with the
`_util`/probe helpers monkeypatched, or assert the META regexes directly. The
rule under test: a verdict must be the TARGET's control, never a tester/
measurement artifact (false BLOCKED), and a target-side teardown of the attack
must not fall through to NO-RESULT (it is BLOCKED).
"""
import importlib
import re
import unittest

import core


def _ctx(**kw):
    return core.Context(credentials=kw.pop("creds", {}), **kw)


def _match(out, rx):
    """Engine semantics: ^/$ anchors are per-line (re.MULTILINE), as core._match does."""
    return re.search(rx, out, re.MULTILINE) is not None


class TestInProcResetTokens(unittest.TestCase):
    """The in-process impacket / kerberos modules must score a connection reset on
    the attack step as BLOCKED (reset tokens in blocked_regex), not NO-RESULT —
    while a non-network traceback (e.g. [Errno 2]) must NOT be scored BLOCKED."""

    RESET = "[ERROR] ConnectionResetError: [Errno 104] Connection reset by peer"
    PIPE = "[ERROR] BrokenPipeError: [Errno 32] Broken pipe"
    NOTNET = "[ERROR] FileNotFoundError: [Errno 2] No such file or directory"

    def test_reset_scores_blocked_notnet_does_not(self):
        for mod in ("wmiexec", "nopac", "petitpotam", "kerberoast", "kerberos_asrep"):
            m = importlib.import_module("modules." + mod)
            rx = m.META["blocked_regex"]
            self.assertRegex(self.RESET, rx, f"{mod}: reset should be BLOCKED")
            self.assertRegex(self.PIPE, rx, f"{mod}: broken pipe should be BLOCKED")
            self.assertNotRegex(self.NOTNET, rx, f"{mod}: [Errno 2] must NOT be BLOCKED")


class TestRunCmdTimeoutPreservesStdout(unittest.TestCase):
    """A slow-but-working tool killed by the watchdog must keep its streamed output
    so success_regex (checked first) can win — not be mis-scored a false BLOCKED."""

    def test_partial_stdout_preserved_on_timeout(self):
        out = core._run_cmd(
            "python3 -c \"print('krb5asrep-PROOF'); import time; time.sleep(10)\"",
            "127.0.0.1", {}, 1)
        self.assertIn("krb5asrep-PROOF", out)   # streamed proof kept
        self.assertIn("[TIMEOUT]", out)          # marker still present

    def test_empty_timeout_is_marker_only(self):
        out = core._run_cmd("python3 -c \"import time; time.sleep(10)\"", "127.0.0.1", {}, 1)
        self.assertIn("[TIMEOUT]", out)
        self.assertNotIn("PROOF", out)


class TestSwitchMgmtNoService(unittest.TestCase):
    """ports:[] disables the engine's recon NO-SERVICE gate, so the module must
    itself emit [NO-SERVICE] when every mgmt port is refused/closed (service absent)
    rather than scoring a false 'no mgmt-plane exposure' BLOCKED."""

    def setUp(self):
        self.m = importlib.import_module("modules.switch_mgmt")

    def _run(self, tcp_state, udp_state="refused"):
        orig_t, orig_u = self.m.U.tcp_state, self.m.U.udp_egress
        self.m.U.tcp_state = lambda *a, **k: tcp_state
        self.m.U.udp_egress = lambda *a, **k: udp_state
        try:
            return self.m.run("10.0.0.9", _ctx())
        finally:
            self.m.U.tcp_state, self.m.U.udp_egress = orig_t, orig_u

    def test_all_refused_is_no_service(self):
        out = self._run("refused")
        self.assertIn("[NO-SERVICE]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_filtered_is_blocked(self):
        out = self._run("filtered")
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))
        self.assertNotIn("[NO-SERVICE]", out)

    def test_open_is_success(self):
        out = self._run("open")
        self.assertTrue(_match(out, self.m.META["success_regex"]))


class TestIpv6AclParityNoEgress(unittest.TestCase):
    """A tester with no IPv6 route makes every probe 'unreachable' -> must SKIP,
    not score a false 'parity holding' BLOCKED crediting the target's ACL."""

    def setUp(self):
        self.m = importlib.import_module("modules.ipv6_acl_parity")

    def _run(self, probe_state):
        orig_r, orig_p = self.m._resolve_v6, self.m._probe6
        self.m._resolve_v6 = lambda *a, **k: "2606:4700::1111"
        self.m._probe6 = lambda *a, **k: probe_state
        try:
            return self.m.run("example.test", _ctx())
        finally:
            self.m._resolve_v6, self.m._probe6 = orig_r, orig_p

    def test_all_unreachable_is_skip(self):
        out = self._run("unreachable")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_filtered_is_parity_holding_blocked(self):
        out = self._run("filtered")
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))

    def test_open_is_finding(self):
        out = self._run("open")
        self.assertTrue(_match(out, self.m.META["success_regex"]))


class TestJa3MimicryEgressAttribution(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module("modules.ja3_mimicry")

    def _run(self, kind):
        det = {"refused": "refused", "dns": "DNS", "timeout": "timed out"}[kind]
        orig = self.m._handshake
        self.m._handshake = lambda *a, **k: (False, det, kind)
        try:
            return self.m.run("vps.test", _ctx(config={"attacker_vps": "vps.test"}))
        finally:
            self.m._handshake = orig

    def test_both_refused_is_skip_not_blocked(self):
        out = self._run("refused")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_dns_is_skip_not_blocked(self):
        out = self._run("dns")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_timeout_is_blocked(self):
        out = self._run("timeout")
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))


class TestSshOver443Attribution(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module("modules.ssh_over_443")

    def _run(self, exc):
        orig = self.m.U.connect
        def boom(*a, **k):
            raise exc
        self.m.U.connect = boom
        try:
            return self.m.run("vps.test", _ctx(config={"attacker_vps": "vps.test"}))
        finally:
            self.m.U.connect = orig

    def test_refused_is_skip(self):
        out = self._run(ConnectionRefusedError(111, "refused"))
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_timeout_is_blocked(self):
        import socket
        out = self._run(socket.timeout("timed out"))
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))


class TestSelfTunnelVpsAttribution(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module("modules.self_tunnel_vps")

    def _run(self, detail):
        orig = self.m.U.tls_reachable
        self.m.U.tls_reachable = lambda *a, **k: (False, detail)
        try:
            return self.m.run("vps.test", _ctx(config={"attacker_vps": "vps.test"}))
        finally:
            self.m.U.tls_reachable = orig

    def test_refused_is_skip(self):
        out = self._run("refused (no listener)")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_dns_is_skip(self):
        out = self._run("DNS did not resolve (blocked / forced internal resolver)")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_timeout_is_blocked(self):
        out = self._run("timed out (blocked/filtered)")
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))


class TestReverseEgressAttribution(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module("modules.reverse_egress")

    def _run(self, state):
        orig = self.m.U.tcp_state
        self.m.U.tcp_state = lambda *a, **k: state
        try:
            return self.m.run("dc.test", _ctx(config={"attacker_vps": "vps.test"}))
        finally:
            self.m.U.tcp_state = orig

    def test_unresolved_is_skip(self):
        out = self._run("unresolved")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_refused_is_skip_traversed(self):
        out = self._run("refused")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_filtered_is_blocked(self):
        out = self._run("filtered")
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))


class TestUdp443QuicAttribution(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module("modules.udp443_quic")

    def _run(self, state):
        orig = self.m.U.udp_egress
        self.m.U.udp_egress = lambda *a, **k: state
        try:
            return self.m.run("vps.test", _ctx(config={"attacker_vps": "vps.test"}))
        finally:
            self.m.U.udp_egress = orig

    def test_refused_is_skip_reached(self):
        out = self._run("refused")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_unresolved_is_skip(self):
        out = self._run("unresolved")
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_noreply_is_inconclusive(self):
        out = self._run("sent (no reply)")
        self.assertIn("[INCONCLUSIVE]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))


class TestDlpCanaryTeardown(unittest.TestCase):
    """A reset AFTER TLS is established is the DLP tearing down the exfil -> BLOCKED,
    not a mute NO-RESULT. A connect-time refused/DNS is a tester artifact -> SKIP."""

    def setUp(self):
        self.m = importlib.import_module("modules.dlp_canary_https")

    def test_connect_refused_is_skip(self):
        orig = self.m.U.connect
        self.m.U.connect = lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError(111, "refused"))
        try:
            out = self.m.run("x", _ctx(config={"canary_url": "https://canary.test/p"}))
        finally:
            self.m.U.connect = orig
        self.assertIn("[SKIP]", out)
        self.assertFalse(_match(out, self.m.META["blocked_regex"]))

    def test_post_tls_reset_is_blocked(self):
        # connect() returns a fake socket; wrap_socket's sendall raises ConnectionResetError
        import ssl

        class _FakeRaw:
            def close(self): pass

        class _FakeTLS:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def sendall(self, b): raise ConnectionResetError(104, "reset by peer")
            def recv(self, n): return b""

        orig_conn = self.m.U.connect
        orig_ctx = ssl.create_default_context
        self.m.U.connect = lambda *a, **k: _FakeRaw()

        class _C:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, raw, server_hostname=None): return _FakeTLS()
        ssl.create_default_context = lambda *a, **k: _C()
        try:
            out = self.m.run("x", _ctx(config={"canary_url": "https://canary.test/p"}))
        finally:
            self.m.U.connect = orig_conn
            ssl.create_default_context = orig_ctx
        self.assertTrue(_match(out, self.m.META["blocked_regex"]))   # "exfil blocked ... torn down"
        self.assertFalse(_match(out, self.m.META["success_regex"]))


class TestSynFloodSelfCongestion(unittest.TestCase):
    """A flood SYN-loss delta from a source that didn't reach the target send-rate is
    self-congestion -> INCONCLUSIVE, not a false BLOCKED-RATELIMIT (icmp parallel)."""

    def setUp(self):
        self.m = importlib.import_module("modules.syn_flood")

    def test_knee_verdict_constants(self):
        # target pps derived from the flood interval; the gate fraction is sane
        self.assertEqual(self.m.TARGET_PPS, 1_000_000 // self.m.FLOOD_INTERVAL_US)
        self.assertTrue(0.0 < self.m.SATURATION_FRAC <= 1.0)

    def test_parse_sent(self):
        self.assertEqual(self.m._parse_sent("50000 packets transmitted, 10 received, 99% packet loss"),
                         50000)
        self.assertIsNone(self.m._parse_sent("no stats here"))


if __name__ == "__main__":
    unittest.main()
