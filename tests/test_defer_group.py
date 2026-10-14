"""Offline tests for PER-DEVICE-GROUP contamination tracking (core._defer_group_of
and the group-aware _canary/_detect_ban/_flag_if_blacklisted).

The deferred tail mixes attacks that trip DIFFERENT devices — the SD-WAN boundary
(default "boundary" group), the agency WAF on a published 443 app ("agency_waf"), and
the egress gateway ("egress"). A ban on ONE device must never flag or strand another
device's modules. These pin exactly that, with no network I/O (the group latches are
set directly so _detect_ban fast-paths without probing).

Pure-stdlib / offline."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


def _runner():
    r = core.Runner("203.0.113.10")
    r._bl_lock = threading.Lock()
    r._canary = None
    r._blacklisted = False
    r._group_canary = {}
    r._group_bl = {}
    r._group_canary_tried = set()
    return r


_NOLOG = lambda *a, **k: None


class TestDeferGroupHelpers(unittest.TestCase):
    def test_default_group(self):
        self.assertEqual(core._defer_group_of({"id": "x"}), "boundary")
        self.assertEqual(core._defer_group_of({"defer_group": "agency_waf"}), "agency_waf")

    def test_defer_group_implies_deferred(self):
        # a non-default defer_group pulls the module OUT of the parallel pool even with
        # no run_last/trips_ips flag.
        self.assertTrue(core._is_deferred({"defer_group": "agency_waf"}))
        self.assertFalse(core._is_deferred({"defer_group": "boundary"}))
        self.assertFalse(core._is_deferred({"id": "quiet"}))
        self.assertTrue(core._is_deferred({"trips_ips": True}))

    def test_url_host(self):
        self.assertEqual(core._url_host("https://app.example.gov:443/x"), "app.example.gov")
        self.assertEqual(core._url_host("app.example.gov"), "app.example.gov")
        self.assertIsNone(core._url_host(""))


class TestGroupBanIsolation(unittest.TestCase):
    def test_agency_ban_does_not_flag_boundary(self):
        r = _runner()
        # agency WAF is banned (latched, so _detect_ban fast-paths — no probe); the
        # SD-WAN boundary is clean (no canary at all).
        r._group_canary = {"agency_waf": ("tcp", 443, "198.51.100.9")}
        r._group_bl = {"agency_waf": True}
        # a boundary module's non-SUCCESS verdict is NOT tagged SUSPECT by the agency ban
        self.assertNotIn("SUSPECT", r._flag_if_blacklisted("BLOCKED — reset", _NOLOG, "boundary"))
        # the agency module's verdict IS tagged
        self.assertIn("SUSPECT", r._flag_if_blacklisted("BLOCKED — reset", _NOLOG, "agency_waf"))

    def test_boundary_ban_does_not_flag_agency(self):
        r = _runner()
        # SD-WAN boundary banned (latched); agency WAF has no canary -> never flagged.
        r._canary = ("tcp", 22)
        r._blacklisted = True
        self.assertIn("SUSPECT", r._flag_if_blacklisted("BLOCKED — timeout", _NOLOG, "boundary"))
        self.assertNotIn("SUSPECT", r._flag_if_blacklisted("BLOCKED — timeout", _NOLOG, "agency_waf"))

    def test_latch_is_per_group(self):
        r = _runner()
        r._group_canary = {"agency_waf": ("tcp", 443, "198.51.100.9"),
                           "egress": ("tcp", 53, "198.51.100.9")}
        r._bl_set("agency_waf", True)
        self.assertTrue(r._bl_get("agency_waf"))
        self.assertFalse(r._bl_get("egress"))
        self.assertFalse(r._bl_get("boundary"))
        # boundary latch still maps to the original attribute
        r._bl_set("boundary", True)
        self.assertTrue(r._blacklisted)
        self.assertTrue(r._bl_get("boundary"))

    def test_await_returns_immediately_when_group_not_banned(self):
        r = _runner()
        r._group_canary = {"agency_waf": ("tcp", 443, "198.51.100.9")}
        r._group_bl = {"agency_waf": False}
        # not banned -> returns True at once (no wait, no probe)
        self.assertTrue(r._await_unblacklist(_NOLOG, "waf_evasion", "agency_waf"))


if __name__ == "__main__":
    unittest.main()
