#!/usr/bin/env python3
"""Unit tests for the harness engine (core.py).

Pure-stdlib (unittest) so they run anywhere without pytest:
    python3 -m unittest discover -s tests        # or: python3 -m pytest tests
Only touches 127.0.0.1; contacts no external host.
"""
import os
import socket
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


def fake_module(mid, **meta):
    meta.setdefault("name", mid)
    meta.setdefault("category", "Test")
    meta["id"] = mid
    m = types.SimpleNamespace()
    m.META = meta
    m.run = lambda target, ctx: ""
    return m


class TestClassify(unittest.TestCase):
    META = {"success_regex": r"WIN", "blocked_regex": r"blocked|refused"}

    def test_success(self):
        b, a, v = core.classify(self.META, "WIN here", "WIN here")
        self.assertEqual(a, "PASSED")
        self.assertIn("FINDING", v)

    def test_blocked_through_appliance(self):
        b, a, v = core.classify(self.META, "WIN here", "connection refused")
        self.assertEqual(a, "BLOCKED")
        self.assertIn("CONTROL WORKING", v)

    def test_credential_error_not_a_control_result(self):
        meta = {"success_regex": r"WIN", "blocked_regex": r"blocked"}
        b, a, v = core.classify(meta, "STATUS_LOGON_FAILURE", "STATUS_LOGON_FAILURE")
        self.assertIn("CREDENTIAL ERROR", v)

    def test_timeout_counts_as_blocked(self):
        b, a, v = core.classify(self.META, "WIN", "[TIMEOUT] ...")
        self.assertEqual(a, "BLOCKED")


class TestRedaction(unittest.TestCase):
    def test_password_redacted(self):
        creds = {"dc_pass": "SuperSecret123", "dc_user": "Administrator"}
        out = core._redact("hydra -p SuperSecret123 ssh://x", creds)
        self.assertNotIn("SuperSecret123", out)
        self.assertIn("***", out)

    def test_short_value_not_redacted(self):
        # a 2-char value would over-redact ordinary text; guard skips it
        out = core._redact("ab cabbage", {"dc_pass": "ab"})
        self.assertEqual(out, "ab cabbage")


class TestTargetSafety(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(core.validate_target("10.0.0.1")[0])

    def test_valid_hostname(self):
        self.assertTrue(core.validate_target("dc01.lab.local")[0])

    def test_invalid(self):
        self.assertFalse(core.validate_target("not a host!!")[0])
        self.assertFalse(core.validate_target("")[0])

    def test_allowlist_enforced(self):
        os.environ["HARNESS_ALLOWLIST"] = "10.0.0.5, dc01.lab.local"
        try:
            self.assertTrue(core.target_allowed("10.0.0.5")[0])
            self.assertFalse(core.target_allowed("10.0.0.9")[0])
        finally:
            del os.environ["HARNESS_ALLOWLIST"]

    def test_no_allowlist_allows_any(self):
        os.environ.pop("HARNESS_ALLOWLIST", None)
        self.assertTrue(core.target_allowed("1.2.3.4")[0])


class TestCredentials(unittest.TestCase):
    def test_env_overrides(self):
        os.environ["HARNESS_DC_PASS"] = "from-env"
        try:
            self.assertEqual(core.load_credentials()["dc_pass"], "from-env")
        finally:
            del os.environ["HARNESS_DC_PASS"]

    def test_password_default_empty(self):
        os.environ.pop("HARNESS_DC_PASS", None)
        # (assumes no credentials.env present in the test env)
        self.assertEqual(core.load_credentials()["dc_pass"], "")


class TestGetPort(unittest.TestCase):
    def test_override_beats_default(self):
        ctx = core.Context(port_overrides={"apache_41773": 8080})
        self.assertEqual(ctx.get_port("apache_41773", 80), 8080)

    def test_default_when_no_override(self):
        self.assertEqual(core.Context().get_port("ssh_brute", 22), 22)

    def test_env_override(self):
        os.environ["HARNESS_PORT_LOG4SHELL"] = "8983"
        try:
            self.assertEqual(core.Context().get_port("log4shell", 8080), 8983)
        finally:
            del os.environ["HARNESS_PORT_LOG4SHELL"]

    def test_bad_override_falls_back(self):
        ctx = core.Context(port_overrides={"x": "notaport"})
        self.assertEqual(ctx.get_port("x", 443), 443)


class TestSudoPrefix(unittest.TestCase):
    def _patch(self, priv, has_sudo):
        self._op, self._ow = core.is_privileged, core.shutil.which
        core.is_privileged = lambda: priv
        core.shutil.which = lambda x: ("/usr/bin/sudo" if x == "sudo" and has_sudo else None)

    def tearDown(self):
        if hasattr(self, "_op"):
            core.is_privileged, core.shutil.which = self._op, self._ow

    def test_root_needs_no_prefix(self):
        self._patch(priv=True, has_sudo=True)
        self.assertEqual(core.sudo_prefix(), [])

    def test_nonroot_with_sudo_uses_noninteractive(self):
        self._patch(priv=False, has_sudo=True)
        self.assertEqual(core.sudo_prefix(), ["sudo", "-n"])   # -n = never prompts

    def test_nonroot_without_sudo_no_prefix(self):
        self._patch(priv=False, has_sudo=False)
        self.assertEqual(core.sudo_prefix(), [])


class TestSudoUnlock(unittest.TestCase):
    def tearDown(self):
        if hasattr(self, "_op"):
            core.is_privileged = self._op
        if hasattr(self, "_ow"):
            core.shutil.which = self._ow

    def test_root_needs_no_unlock(self):
        self._op = core.is_privileged
        core.is_privileged = lambda: True
        ok, _ = core.sudo_unlock("x")
        self.assertTrue(ok)

    def test_no_sudo(self):
        self._op = core.is_privileged; self._ow = core.shutil.which
        core.is_privileged = lambda: False
        core.shutil.which = lambda n: None
        ok, msg = core.sudo_unlock("x")
        self.assertFalse(ok)
        self.assertIn("sudo", msg)


class TestServiceVsBlocked(unittest.TestCase):
    """A closed/refused port = service absent (NO-SERVICE), NOT a control block;
    a filtered/dropped port = BLOCKED (likely the SD-WAN)."""
    def _mod(self, mid, port, output):
        m = types.SimpleNamespace()
        m.META = {"id": mid, "name": mid, "category": "Test", "requires": [],
                  "ports": [("tcp", port)], "mitre": ["T1046"], "tactic": "Discovery",
                  "success_regex": r"WIN", "blocked_regex": r"timed out|refused"}
        m.run = lambda t, c, o=output: o
        return m

    def test_closed_port_is_no_service(self):
        m = self._mod("closed", 1, "Connection refused")   # 127.0.0.1:1 -> RST
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("127.0.0.1").run([m], 1, ev, skip_unready=False, recon=True)
        self.assertEqual(ev.records[0]["baseline_result"], "NO-SERVICE")

    def test_filtered_port_is_blocked(self):
        m = self._mod("filt", 9, "[TIMEOUT] no response")  # blackhole -> filtered
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("10.255.255.1").run([m], 1, ev, skip_unready=False, recon=True)
        self.assertEqual(ev.records[0]["baseline_result"], "BLOCKED")


class TestSkipNotScoredAsBlocked(unittest.TestCase):
    """A module that printed [SKIP] (did nothing) must NEVER score as BLOCKED —
    otherwise an unconfigured active module fabricates a 'control worked' verdict.
    Regression for the run_02-10 false 'OK (blocked)' on 9 egress modules."""

    def _skip_mod(self):
        m = types.SimpleNamespace()
        # blocked_regex deliberately contains the skip phrase, as the 9 real
        # modules used to, to prove the [SKIP] guard wins regardless.
        m.META = {"id": "skipper", "name": "skipper", "category": "Egress / C2",
                  "requires": [], "ports": [], "mitre": ["T1572"], "tactic": "C2",
                  "success_regex": r"REACHABLE", "blocked_regex": r"not configured"}
        m.run = lambda t, c: "# skipper\n\n[SKIP] attacker_vps not configured — nothing sent"
        return m

    def test_single_target_skip_is_SKIPPED_not_blocked(self):
        ev = core.Evidence(base=tempfile.mkdtemp())
        root = core.Runner("127.0.0.1").run([self._skip_mod()], 1, ev,
                                             skip_unready=False, recon=False)
        self.assertEqual(ev.records[0]["baseline_result"], "SKIPPED")
        # and the aggregate report must not call a uniform single bucket INCONSISTENT
        with open(os.path.join(root, "report.txt")) as f:
            rpt = f.read()
        self.assertIn("SKIPPED (not run", rpt)
        self.assertNotIn("INCONSISTENT", rpt)

    def test_classify_skip_is_not_blocked(self):
        meta = {"success_regex": r"WIN", "blocked_regex": r"not configured"}
        b, a, v = core.classify(meta, "WIN here", "[SKIP] not configured")
        self.assertEqual(a, "NO-RESULT")   # a skip is NOT a block through the appliance

    def test_skip_marker_matches_end_of_line(self):
        # ipv6_acl_parity puts the marker at the END of a line; the old ^-anchored
        # regex missed it and the skip leaked through to blocked_regex (false BLOCK).
        self.assertIsNotNone(core._SKIP_MARKER.search("no IPv6 target. [SKIP]"))
        meta = {"success_regex": r"OK", "blocked_regex": r"no .* reachable"}
        _, a, _ = core.classify(meta, "OK", "no AAAA reachable [SKIP]")
        self.assertEqual(a, "NO-RESULT")


class TestConsistencyBuckets(unittest.TestCase):
    def test_single_other_iteration_is_consistent(self):
        # one iteration landing in 'other' (e.g. NO-RESULT) is a single uniform
        # bucket -> consistent, not INCONSISTENT (the 'other'/'skipped' buckets
        # were missing from the consistency test).
        m = types.SimpleNamespace()
        m.META = {"id": "noresult", "name": "noresult", "category": "Test",
                  "requires": [], "ports": [], "success_regex": r"WIN",
                  "blocked_regex": r"refused"}
        m.run = lambda t, c: "nothing conclusive here"
        ev = core.Evidence(base=tempfile.mkdtemp())
        root = core.Runner("127.0.0.1").run([m], 1, ev, skip_unready=False, recon=False)
        with open(os.path.join(root, "report.txt")) as f:
            rpt = f.read()
        self.assertNotIn("INCONSISTENT", rpt)


class TestSourceIpBindable(unittest.TestCase):
    def test_loopback_is_bindable(self):
        self.assertTrue(core.source_ip_bindable("127.0.0.1"))

    def test_nonlocal_is_not_bindable(self):
        # TEST-NET-3 (RFC5737) — never a local interface address
        self.assertFalse(core.source_ip_bindable("203.0.113.7"))

    def test_empty_is_not_bindable(self):
        self.assertFalse(core.source_ip_bindable(""))


class TestSshBruteSkipsWithoutPassword(unittest.TestCase):
    def test_empty_password_skips(self):
        import modules.ssh_brute as sb
        ctx = core.Context(credentials={"domain": "d", "dc_user": "u", "dc_pass": ""})
        out = sb.run("127.0.0.1", ctx)
        self.assertIn("[SKIP]", out)


class TestTargetMemory(unittest.TestCase):
    def setUp(self):
        self._orig = core._TARGET_MEM
        core._TARGET_MEM = os.path.join(tempfile.mkdtemp(), "mem.json")

    def tearDown(self):
        core._TARGET_MEM = self._orig

    def test_remember_recall_roundtrip(self):
        core.remember_target("10.1.2.3", source="192.168.0.9", cloud=True,
                             smb_port="4445", rpc_port="1135",
                             domain="lab.local", dc_user="Administrator", dc_pass="NewPass123!")
        r = core.recall_target("10.1.2.3")
        self.assertEqual(r["source"], "192.168.0.9")
        self.assertTrue(r["cloud"])
        self.assertEqual(r["smb_port"], "4445")
        # per-target creds round-trip (one global cred set can't serve two targets)
        self.assertEqual(r["domain"], "lab.local")
        self.assertEqual(r["dc_user"], "Administrator")
        self.assertEqual(r["dc_pass"], "NewPass123!")

    def test_memory_file_is_owner_only(self):
        import stat
        core.remember_target("t", dc_pass="secret")
        mode = stat.S_IMODE(os.stat(core._TARGET_MEM).st_mode)
        self.assertEqual(mode & 0o077, 0)   # no group/other access (holds a password)

    def test_recall_unknown_is_empty(self):
        self.assertEqual(core.recall_target("9.9.9.9"), {})

    def test_none_fields_do_not_overwrite(self):
        core.remember_target("t", source="1.1.1.1", cloud=True)
        core.remember_target("t", source=None, cloud=False)   # None source must not wipe it
        r = core.recall_target("t")
        self.assertEqual(r["source"], "1.1.1.1")
        self.assertFalse(r["cloud"])


class TestProbes(unittest.TestCase):
    def test_tcp_open_then_closed(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertEqual(core.probe_tcp("127.0.0.1", port, timeout=1), "open")
        finally:
            srv.close()
        # after close, the port should refuse -> closed
        self.assertIn(core.probe_tcp("127.0.0.1", port, timeout=1),
                      ("closed", "filtered"))


class TestPreflightAndReachability(unittest.TestCase):
    def test_preflight_missing_tool(self):
        m = fake_module("x", requires=["definitely-not-a-real-binary-xyz"])
        pf = core.preflight([m])
        self.assertFalse(pf["modules"][0]["ready"])
        self.assertIn("definitely-not-a-real-binary-xyz", pf["modules"][0]["missing"])

    def test_preflight_os_gating(self):
        other = "Windows" if core.platform.system() != "Windows" else "Linux"
        m = fake_module("x", os_supported=[other])
        r = core.preflight([m])["modules"][0]
        self.assertFalse(r["os_ok"])
        self.assertFalse(r["ready"])

    def test_preflight_ready_no_tools(self):
        m = fake_module("x")  # no requires -> ready
        self.assertTrue(core.preflight([m])["modules"][0]["ready"])

    def test_reachability_categories(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            m_open = fake_module("o", ports=[("tcp", port)])
            m_none = fake_module("n", ports=[])
            rc = core.reachability("127.0.0.1", [m_open, m_none], timeout=1)
            by = {r["id"]: r for r in rc["modules"]}
            self.assertEqual(by["o"]["category"], "suggested")
            self.assertEqual(by["n"]["category"], "noport")
        finally:
            srv.close()


class TestInconclusiveVerdictRegistered(unittest.TestCase):
    """The INCONCLUSIVE bucket (source in IPS quarantine, attack not tested) must
    be keyed in every verdict order/colour/gloss map, or it silently drops out of
    the table/HTML the moment the engine emits it."""
    def test_in_core_orders_and_maps(self):
        self.assertIn("INCONCLUSIVE", core.Evidence._V_ORDER)
        self.assertIn("INCONCLUSIVE", core.Evidence._V_COLOR)
        self.assertIn("INCONCLUSIVE", core.Evidence._V_GLOSS_SHORT)

    def test_in_cli_orders_and_maps(self):
        import cli
        self.assertIn("INCONCLUSIVE", cli._VERDICT_ORDER)
        self.assertIn("INCONCLUSIVE", cli._VERDICT_STYLE)
        self.assertIn("INCONCLUSIVE", cli._ITER_CODE)
        self.assertIn("INCONCLUSIVE", cli._VERDICT_GLOSS)
        self.assertIn("INCONCLUSIVE", cli._VERDICT_GLOSS_SHORT)


class TestDeferLastOrdering(unittest.TestCase):
    """Quiet attacks must all run (and be recorded) BEFORE the loud ones that trip
    a blacklist / IPS signature (run_last + the new trips_ips), so a ban the loud
    ones cause can't contaminate the quiet verdicts. conc==1 => execution order ==
    record order."""
    def _mod(self, mid, **flags):
        m = fake_module(mid, requires=[], ports=[], mitre=["T1046"], tactic="Discovery",
                        success_regex=r"NEVER", blocked_regex=r"NEVER", **flags)
        m.run = lambda t, c: "benign"
        return m

    def test_trips_ips_and_run_last_sort_after_quiet(self):
        mods = [self._mod("loud_ips", trips_ips=True),
                self._mod("q1"),
                self._mod("loud_brute", run_last=True),
                self._mod("q2")]
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("127.0.0.1").run(mods, 1, ev, skip_unready=False, recon=False)
        order = [r["attack_id"] for r in ev.records]
        # both quiet modules recorded before either loud one
        self.assertLess(order.index("q1"), order.index("loud_ips"))
        self.assertLess(order.index("q1"), order.index("loud_brute"))
        self.assertLess(order.index("q2"), order.index("loud_ips"))
        self.assertLess(order.index("q2"), order.index("loud_brute"))


class TestQuarantineSkipsRemainingAsInconclusive(unittest.TestCase):
    """Once the source is in IPS quarantine and the ban doesn't clear, the engine
    must record the remaining modules as INCONCLUSIVE (not tested) rather than
    grinding out false BLOCKEDs."""
    def _mod(self, mid):
        m = fake_module(mid, requires=[], ports=[], mitre=["T1046"], tactic="Discovery",
                        success_regex=r"NEVER", blocked_regex=r"NEVER")
        m.run = lambda t, c: "benign"
        return m

    def test_remaining_modules_are_inconclusive(self):
        import threading
        r = core.Runner("127.0.0.1")
        # state normally set up by run(); we drive _iterate directly with the
        # source already quarantined and the ban held open.
        r._canary = ("tcp", 9)
        r._blacklisted = True
        r._bl_lock = threading.Lock()
        r._stop = False
        r._mode = "blackbox"
        r._await_unblacklist = lambda log, where: False   # ban never clears
        mods = [self._mod("a"), self._mod("b")]
        ev = core.Evidence(base=tempfile.mkdtemp())
        r._iterate(mods, 1, ev, skip_unready=False,
                   ready_ids={"a", "b"}, pf_by_id={}, recon_by_id={}, log=lambda *a: None)
        self.assertEqual({rr["baseline_result"] for rr in ev.records}, {"INCONCLUSIVE"})
        self.assertTrue(all(rr["passed"] is False for rr in ev.records))


class TestEvidenceConcurrencySafety(unittest.TestCase):
    """The run-dir claim must be race-safe: two runs in the same minute (two
    sessions / GUI+CLI / fleet jobs) must get DISTINCT, actually-created dirs —
    never silently share one and interleave results."""
    def test_claim_run_dir_unique_under_collision(self):
        base = tempfile.mkdtemp()
        dirs = [core._claim_run_dir(base, "run_X") for _ in range(3)]
        self.assertEqual(len(set(dirs)), 3)                 # all distinct
        for p in dirs:
            self.assertTrue(os.path.isdir(p))               # all really created
        self.assertEqual(os.path.basename(dirs[0]), "run_X")
        self.assertTrue(os.path.basename(dirs[1]).startswith("run_X-"))

    def test_two_evidences_same_minute_dont_share(self):
        base = tempfile.mkdtemp()
        e1 = core.Evidence(base=base, label="t")
        e2 = core.Evidence(base=base, label="t")
        self.assertNotEqual(e1.root, e2.root)

    def test_atomic_write_leaves_no_tmp(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.json")
        core._atomic_write(p, lambda f: f.write('{"a":1}'))
        self.assertEqual(open(p).read(), '{"a":1}')
        self.assertEqual([x for x in os.listdir(d) if ".tmp" in x], [])


class TestEvidenceMetaAndIndex(unittest.TestCase):
    """finalize() must bake run provenance + verdict/contamination counts into
    summary.json meta, and append one line per run to a sibling INDEX.md."""
    def _mod(self, mid, out):
        m = types.SimpleNamespace()
        m.META = {"id": mid, "name": mid, "category": "Test", "requires": [],
                  "ports": [], "mitre": ["T1046"], "tactic": "Discovery",
                  "success_regex": r"WIN", "blocked_regex": r"nope"}
        m.run = lambda t, c, o=out: o
        return m

    def test_meta_has_version_target_and_verdicts(self):
        import json as _j
        base = tempfile.mkdtemp()
        ev = core.Evidence(base=base, label="127.0.0.1")
        core.Runner("127.0.0.1").run([self._mod("m1", "WIN")], 1, ev,
                                     skip_unready=False, recon=False)
        meta = _j.load(open(os.path.join(ev.root, "summary.json")))["meta"]
        self.assertEqual(meta["harness_version"], core.VERSION)
        self.assertEqual(meta["target_ip"], "127.0.0.1")
        self.assertIn("verdicts", meta)
        self.assertEqual(meta["module_count"], 1)

    def test_index_md_appended(self):
        base = tempfile.mkdtemp()
        ev = core.Evidence(base=base, label="127.0.0.1")
        core.Runner("127.0.0.1").run([self._mod("m1", "WIN")], 1, ev,
                                     skip_unready=False, recon=False)
        idx = os.path.join(os.path.dirname(ev.root), "INDEX.md")
        self.assertTrue(os.path.exists(idx))
        self.assertIn(os.path.basename(ev.root), open(idx).read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
