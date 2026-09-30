#!/usr/bin/env python3
"""Robustness / exception-handling tests — prove that a faulty module, a bad
regex, a bad command template, or a failing UI callback cannot crash a run or
lose evidence. Localhost-only, recon disabled (no network)."""
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


def mod(mid, run_fn, **meta):
    meta.setdefault("name", mid)
    meta.setdefault("category", "Test")
    meta.setdefault("requires", [])
    meta.setdefault("ports", [])
    meta["id"] = mid
    m = types.SimpleNamespace()
    m.META = meta
    m.run = run_fn
    return m


class TestRunnerRobustness(unittest.TestCase):
    def _ev(self):
        return core.Evidence(base=tempfile.mkdtemp())

    def test_crashing_module_does_not_abort_run(self):
        def boom(target, ctx):
            raise RuntimeError("boom")
        good = mod("good", lambda t, c: "nothing", success_regex=r"WIN")
        bad = mod("bad", boom, success_regex=r"WIN")
        ev = self._ev()
        root = core.Runner("127.0.0.1").run([bad, good], 1, ev,
                                            skip_unready=False, recon=False)
        self.assertTrue(os.path.isdir(root))
        self.assertEqual(len(ev.records), 2)          # both recorded
        rec = {r["attack_id"]: r for r in ev.records}
        # the crash was captured (NO-RESULT + surfaced in the verdict), not raised
        self.assertEqual(rec["bad"]["baseline_result"], "NO-RESULT")
        self.assertIn("module crashed", rec["bad"]["verdict"].lower())

    def test_bad_regex_does_not_crash(self):
        m = mod("re", lambda t, c: "some output",
                success_regex="(unclosed", blocked_regex="[bad")
        ev = self._ev()
        core.Runner("127.0.0.1").run([m], 1, ev, skip_unready=False, recon=False)
        self.assertEqual(ev.records[0]["baseline_result"], "NO-RESULT")

    def test_failing_callback_does_not_crash(self):
        def bad_cb(*a, **k):
            raise ValueError("callback blew up")
        m = mod("cb", lambda t, c: "ok")
        ev = self._ev()
        r = core.Runner("127.0.0.1", on_status=bad_cb, on_output=bad_cb,
                        on_log=bad_cb, on_progress=bad_cb)
        root = r.run([m], 1, ev, skip_unready=False, recon=False)
        self.assertTrue(os.path.isdir(root))

    def test_bad_command_template_returns_error(self):
        out = core._run_cmd("{does_not_exist}", "1.2.3.4", {}, 5)
        self.assertIn("[ERROR]", out)

    def test_unparseable_command_returns_error(self):
        # unbalanced quote -> shlex raises ValueError, must be caught
        out = core._run_cmd('echo "unterminated', "1.2.3.4",
                            {"domain": "d", "dc_user": "u", "dc_pass": "p"}, 5)
        self.assertIn("[ERROR]", out)

    def test_evidence_survives_unwritable_dir(self):
        # a bogus base -> Evidence degrades to no-op writes, never raises
        ev = core.Evidence(base="/proc/nonexistent/cannot/create")
        ev.log("hello")                      # must not raise
        ev.save_run(1, "x", "target", "data")
        ev.save_result(1, "x", {"attack": "x"})
        self.assertEqual(ev.finalize(), ev.root)  # returns cleanly


if __name__ == "__main__":
    unittest.main(verbosity=2)
