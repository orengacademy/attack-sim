#!/usr/bin/env python3
"""Concurrency tests: parallel recon scan, concurrent module execution, and the
guarantee that `serial` modules (DoS/brute) never overlap other modules.
Localhost/no-network where possible; timing assertions use generous margins."""
import os
import sys
import tempfile
import threading
import time
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


class TestParallelRecon(unittest.TestCase):
    def test_recon_probes_in_parallel(self):
        # many filtered ports to a black-hole IP: sequential would be N*timeout,
        # parallel should be ~one timeout.
        ports = [("tcp", p) for p in range(9000, 9012)]  # 12 ports
        m = mod("x", lambda t, c: "", ports=ports)
        start = time.time()
        rc = core.reachability("10.255.255.1", [m], timeout=0.5)
        elapsed = time.time() - start
        self.assertLess(elapsed, 3.0)              # not 12 * 0.5 = 6s
        self.assertEqual(len(rc["probes"]), 12)    # all probed


class TestConcurrentModules(unittest.TestCase):
    def _ev(self):
        return core.Evidence(base=tempfile.mkdtemp())

    def test_parallel_execution_is_faster_and_complete(self):
        def slow(target, ctx):
            time.sleep(0.4)
            return "ok"
        mods = [mod(f"m{i}", slow) for i in range(6)]
        ev = self._ev()
        r = core.Runner("127.0.0.1")
        r.concurrency = 6
        start = time.time()
        r.run(mods, 1, ev, skip_unready=False, recon=False)
        elapsed = time.time() - start
        self.assertLess(elapsed, 1.5)              # ~0.4s, not 6*0.4=2.4s
        self.assertEqual(len(ev.records), 6)       # all recorded

    def test_serial_module_never_overlaps(self):
        state = {"active": 0, "max_parallel": 0, "serial_saw_active": None}
        lock = threading.Lock()

        def parallel_run(target, ctx):
            with lock:
                state["active"] += 1
                state["max_parallel"] = max(state["max_parallel"], state["active"])
            time.sleep(0.3)
            with lock:
                state["active"] -= 1
            return "ok"

        def serial_run(target, ctx):
            # when the serial module runs, no parallel module should be active
            with lock:
                state["serial_saw_active"] = state["active"]
            return "ok"

        mods = [mod(f"p{i}", parallel_run) for i in range(4)]
        mods.append(mod("dos", serial_run, serial=True))
        ev = self._ev()
        r = core.Runner("127.0.0.1")
        r.concurrency = 4
        r.run(mods, 1, ev, skip_unready=False, recon=False)
        self.assertGreater(state["max_parallel"], 1)      # parallels DID overlap
        self.assertEqual(state["serial_saw_active"], 0)   # serial ran alone
        self.assertEqual(len(ev.records), 5)

    def test_concurrency_one_is_sequential(self):
        order = []
        def rec(name):
            def _run(t, c):
                order.append(name)
                return "ok"
            return _run
        mods = [mod("a", rec("a")), mod("b", rec("b")), mod("c", rec("c"))]
        ev = self._ev()
        core.Runner("127.0.0.1").run(mods, 1, ev, skip_unready=False, recon=False)
        self.assertEqual(order, ["a", "b", "c"])   # default: in order, serial


if __name__ == "__main__":
    unittest.main(verbosity=2)
