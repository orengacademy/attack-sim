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


if __name__ == "__main__":
    unittest.main(verbosity=2)
