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


if __name__ == "__main__":
    unittest.main(verbosity=2)
