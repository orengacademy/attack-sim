"""Offline tests for the source-blacklist contamination handling:
  - Evidence.save_result replaces a record in place on re-run (no double-count)
  - _detect_ban latches on a canary drop and _await_unblacklist clears on recovery
  - _flag_if_blacklisted tags NO-SERVICE (not just BLOCKED) when the source is banned
  - _retry_contaminated re-runs a contaminated module and replaces its verdict

All pure-stdlib, localhost-only, offline: the canary probe and time.sleep are
monkeypatched so no network I/O or real waiting happens."""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


class _FakeMod:
    """Minimal module: a META dict + run(target, ctx) returning canned output."""
    def __init__(self, mid, output, **meta):
        self.META = {"id": mid, "name": mid, "category": "Test",
                     "success_regex": r"PWNED", **meta}
        self._output = output
        self.calls = 0

    def run(self, target, ctx):
        self.calls += 1
        return self._output(self) if callable(self._output) else self._output


def _mk_runner():
    r = core.Runner("127.0.0.1")
    r._canary = ("tcp", 22)
    r._blacklisted = False
    r._bl_lock = threading.Lock()
    r._mode = "blackbox"
    r.dual = False
    r.appliance_ip = None
    r._pol_by_id = {}
    r._port_policy = {"name": "test-policy"}
    r._detection = lambda meta, raw: None   # no detections.json interference
    return r


class TestSaveResultReplace(unittest.TestCase):
    def test_rerun_replaces_record_not_appends(self):
        d = tempfile.mkdtemp()
        ev = core.Evidence(base=d)
        ev.save_result(1, "mod", {"iteration": 1, "attack_id": "mod",
                                  "baseline_result": "INCONCLUSIVE"})
        ev.save_result(1, "mod", {"iteration": 1, "attack_id": "mod",
                                  "baseline_result": "SUCCESS"})
        same = [r for r in ev.records if r["attack_id"] == "mod" and r["iteration"] == 1]
        self.assertEqual(len(same), 1)                       # replaced, not duplicated
        self.assertEqual(same[0]["baseline_result"], "SUCCESS")

    def test_distinct_iterations_both_kept(self):
        d = tempfile.mkdtemp()
        ev = core.Evidence(base=d)
        ev.save_result(1, "mod", {"iteration": 1, "attack_id": "mod"})
        ev.save_result(2, "mod", {"iteration": 2, "attack_id": "mod"})
        self.assertEqual(len([r for r in ev.records if r["attack_id"] == "mod"]), 2)


class TestDetectBanAndRecover(unittest.TestCase):
    def test_latches_on_canary_drop(self):
        r = _mk_runner()
        r._canary_reachable = lambda: False           # canary unreachable = banned
        logs = []
        self.assertTrue(r._detect_ban(logs.append))
        self.assertTrue(r._blacklisted)
        self.assertTrue(any("BLACKLISTED" in m for m in logs))

    def test_no_canary_means_no_detection(self):
        r = _mk_runner()
        r._canary = None
        self.assertFalse(r._detect_ban(lambda m: None))

    def test_await_clears_latch_on_recovery(self):
        r = _mk_runner()
        r._blacklisted = True
        r._canary_reachable = lambda: True            # recovered
        orig_sleep = core.time.sleep
        core.time.sleep = lambda *_a, **_k: None       # no real waiting
        try:
            self.assertTrue(r._await_unblacklist(lambda m: None, "x"))
        finally:
            core.time.sleep = orig_sleep
        self.assertFalse(r._blacklisted)

    def test_await_window_sized_to_outlast_ban_expiry(self):
        # with ban_expiry=300 and no explicit wait-unblock, the wait window is
        # max(90, cooldown, 2*ban_expiry+60) = 660s — sized to ride out a real-world
        # ~600s appliance lockout in ONE halt (the halt returns the instant the canary
        # recovers, so the larger cap is free for a short ban and rescues a long one).
        r = _mk_runner()
        r._blacklisted = True
        r.ban_expiry = 300.0
        r.wait_unblock = 0.0
        r.cooldown = 0.0
        r._canary_reachable = lambda: False            # never recovers -> full window
        slept = {"total": 0.0}
        orig_sleep = core.time.sleep

        def fake_sleep(s):
            slept["total"] += s
        core.time.sleep = fake_sleep
        try:
            self.assertFalse(r._await_unblacklist(lambda m: None, "x"))
        finally:
            core.time.sleep = orig_sleep
        # it should have slept ~ the whole 660s window (in 5s steps), proving the smart
        # halt now outlasts a ~600s lockout, not just the old ban_expiry+60 = 360s.
        self.assertGreaterEqual(slept["total"], 600.0)

    def test_detected_ban_floor_is_not_the_old_30s(self):
        # Even with ban_expiry=0 (and no explicit wait), a DETECTED ban must get a
        # real pause (>= 90s floor), never the near-useless 30s that let a lockout
        # outlast the halt and dump the trailing modules as INCONCLUSIVE.
        r = _mk_runner()
        r._blacklisted = True
        r.ban_expiry = 0.0
        r.wait_unblock = 0.0
        r.cooldown = 0.0
        r._canary_reachable = lambda: False            # never recovers -> full window
        slept = {"total": 0.0}
        orig_sleep = core.time.sleep
        core.time.sleep = lambda s: slept.__setitem__("total", slept["total"] + s)
        try:
            self.assertFalse(r._await_unblacklist(lambda m: None, "x"))
        finally:
            core.time.sleep = orig_sleep
        self.assertGreaterEqual(slept["total"], 90.0)
        self.assertGreater(slept["total"], 30.0)


class TestFlagGeneralizedToNoService(unittest.TestCase):
    def test_no_service_verdict_tagged_suspect_when_banned(self):
        r = _mk_runner()
        r._blacklisted = True
        r._canary_reachable = lambda: False
        v = r._flag_if_blacklisted("NO-SERVICE — port closed", lambda m: None)
        self.assertIn("[SUSPECT:", v)

    def test_not_tagged_when_canary_reachable(self):
        r = _mk_runner()
        r._blacklisted = False
        r._canary_reachable = lambda: True
        v = r._flag_if_blacklisted("NO-SERVICE — port closed", lambda m: None)
        self.assertNotIn("[SUSPECT:", v)


class TestRetryReRunsContaminated(unittest.TestCase):
    def test_contaminated_module_is_rerun_and_replaced(self):
        d = tempfile.mkdtemp()
        ev = core.Evidence(base=d)
        r = _mk_runner()
        r.auto_retry = 1
        r._blacklisted = True                          # banned at retry entry
        r._canary_reachable = lambda: True             # ban has cleared -> recovers
        clean = _FakeMod("c", "PWNED got in", run_last=True)   # re-run => SUCCESS

        # pre-seed a CONTAMINATED result for c (as the serial loop would on quarantine)
        ev.save_result(1, "c", {"iteration": 1, "attack_id": "c",
                                 "baseline_result": "INCONCLUSIVE", "contaminated": True})
        orig_sleep = core.time.sleep
        core.time.sleep = lambda *_a, **_k: None
        try:
            r._retry_contaminated(1, ev, lambda m: None, sys.stdout, {},
                                  [clean], False, {"c"}, {})
        finally:
            core.time.sleep = orig_sleep

        recs = [x for x in ev.records if x["attack_id"] == "c" and x["iteration"] == 1]
        self.assertEqual(len(recs), 1)                 # replaced in place, no dup
        self.assertEqual(clean.calls, 1)               # actually re-ran it
        self.assertEqual(recs[0]["baseline_result"], "SUCCESS")   # clean verdict now
        self.assertFalse(recs[0]["contaminated"])      # no longer contaminated

    def test_no_retry_when_nothing_contaminated(self):
        d = tempfile.mkdtemp()
        ev = core.Evidence(base=d)
        r = _mk_runner()
        r.auto_retry = 1
        clean = _FakeMod("c", "PWNED", run_last=True)
        ev.save_result(1, "c", {"iteration": 1, "attack_id": "c",
                                 "baseline_result": "SUCCESS", "contaminated": False})
        r._retry_contaminated(1, ev, lambda m: None, sys.stdout, {},
                              [clean], False, {"c"}, {})
        self.assertEqual(clean.calls, 0)               # never re-ran a clean result


if __name__ == "__main__":
    unittest.main()
