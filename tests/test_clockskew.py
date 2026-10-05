#!/usr/bin/env python3
"""Offline tests for the subprocess clock-skew correction (_clockskew.correction_prefix).

Pure stdlib, no network, no impacket: measure_offset + faketime_available are
monkeypatched so we exercise all four branches deterministically.
    python3 -m unittest discover -s tests
"""
import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import _clockskew  # noqa: E402  (imports fine without impacket — it's lazy)


class ClockSkewPrefixTest(unittest.TestCase):
    def setUp(self):
        self._orig_measure = _clockskew.measure_offset
        self._orig_ft = _clockskew.faketime_available

    def tearDown(self):
        _clockskew.measure_offset = self._orig_measure
        _clockskew.faketime_available = self._orig_ft

    def _stub(self, offset, faketime):
        _clockskew.measure_offset = lambda *a, **k: offset
        _clockskew.faketime_available = lambda: faketime

    def test_within_tolerance_no_prefix(self):
        self._stub(dt.timedelta(seconds=30), True)
        prefix, note = _clockskew.correction_prefix("10.0.0.1")
        self.assertEqual(prefix, "")
        self.assertEqual(note, "")

    def test_large_skew_with_faketime_wraps(self):
        self._stub(dt.timedelta(seconds=412), True)
        prefix, note = _clockskew.correction_prefix("10.0.0.1")
        self.assertEqual(prefix, "faketime -f +412s ")
        self.assertIn("[INFO]", note)
        # trailing space lets callers concatenate straight onto a run_cmd template
        self.assertTrue(prefix.endswith(" "))

    def test_negative_skew_keeps_sign(self):
        self._stub(dt.timedelta(seconds=-200), True)
        prefix, _ = _clockskew.correction_prefix("10.0.0.1")
        self.assertEqual(prefix, "faketime -f -200s ")

    def test_large_skew_without_faketime_is_prereq_missing(self):
        # No faketime + a skew past Kerberos' window means the Kerberos attack
        # can't run — a LOCAL prerequisite gap, not a control result. The note
        # must carry the [PREREQ-MISSING] marker so the classifier scores it
        # PREREQ-MISSING (not a mute NO-RESULT).
        self._stub(dt.timedelta(seconds=600), False)
        prefix, note = _clockskew.correction_prefix("10.0.0.1")
        self.assertEqual(prefix, "")
        self.assertIn("[PREREQ-MISSING]", note)
        self.assertIn("faketime", note)

    def test_kdc_unreachable_is_silent(self):
        self._stub(None, True)
        prefix, note = _clockskew.correction_prefix("10.0.0.1")
        self.assertEqual((prefix, note), ("", ""))

    def test_measure_exception_is_silent(self):
        def boom(*a, **k):
            raise RuntimeError("no impacket")
        _clockskew.measure_offset = boom
        _clockskew.faketime_available = lambda: True
        self.assertEqual(_clockskew.correction_prefix("10.0.0.1"), ("", ""))


if __name__ == "__main__":
    unittest.main()
