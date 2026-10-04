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

    def test_malformed_ip_rejected(self):
        # a dotted all-numeric string that isn't a real IP must NOT pass as a
        # hostname (else every probe fails and the run falsely reports BLOCKED).
        for bad in ("192.168.1.300", "10.0.0.1.2", "999.1.1.1", "1.2.3.256"):
            ok, why = core.validate_target(bad)
            self.assertFalse(ok, f"{bad} wrongly accepted ({why})")
        # real IPs / hostnames still pass
        self.assertTrue(core.validate_target("192.168.1.30")[0])
        self.assertTrue(core.validate_target("8.8.8.8")[0])
        self.assertTrue(core.validate_target("host123.lab.local")[0])

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
        # The BUILT-IN default password must be empty — no secret baked into
        # source. A committed dummy-lab credentials.env now exists on disk, so
        # isolate the file read to prove the default (not the lab file) is empty.
        orig = core._read_cred_file
        core._read_cred_file = lambda: {}
        try:
            self.assertEqual(core.load_credentials()["dc_pass"], "")
        finally:
            core._read_cred_file = orig


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


class TestDetectionPhrasing(unittest.TestCase):
    """A DETECTED verdict must be worded by the NATURE of the note: a session-log
    ALLOW is visibility/telemetry (NOT 'detection works'), while a real IPS
    signature with prevention=yes is a genuine detection that prevention didn't stop."""

    def test_session_allow_is_visibility_not_detection(self):
        p = core._detection_phrasing("session-logged tcp/389: ALLOW (policy=Outbound_NPSA)").lower()
        self.assertIn("visibility", p)
        self.assertNotIn("detection works", p)

    def test_ips_signature_prevention_yes(self):
        p = core._detection_phrasing(
            "Sangfor IPS signature fired 'web Vulnerability' DENY x12 (prevention=yes)").lower()
        self.assertIn("signature", p)
        self.assertIn("prevention did not", p)


class TestProcessModuleExceptionBoundary(unittest.TestCase):
    """A crash in the per-module CLASSIFY/RECORD code (not just m.run()) must record
    that module NO-RESULT and let the run CONTINUE — one bad module must never abort
    the rest of the batch (CLAUDE.md guardrail)."""

    def _ok(self, mid):
        m = types.SimpleNamespace()
        m.META = {"id": mid, "name": mid, "category": "Test", "requires": [],
                  "ports": [], "mitre": ["T1046"], "tactic": "Discovery",
                  "success_regex": r"WIN", "blocked_regex": r"nope"}
        m.run = lambda t, c: "WIN"
        return m

    def test_processing_error_records_no_result_and_continues(self):
        m1, m2 = self._ok("boom"), self._ok("ok")
        ev = core.Evidence(base=tempfile.mkdtemp())
        r = core.Runner("127.0.0.1")
        orig = r._process_module_inner

        def inner(mm, *a, **k):
            if mm.META["id"] == "boom":
                raise RuntimeError("engine processing crash")
            return orig(mm, *a, **k)
        r._process_module_inner = inner
        r.run([m1, m2], 1, ev, skip_unready=False, recon=False)
        by = {rec["attack"]: rec["baseline_result"] for rec in ev.records}
        self.assertEqual(by.get("boom"), "NO-RESULT")  # recorded, not silently dropped
        self.assertIn("ok", by)                         # the run continued past the crash


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

    def test_posture_remembered_per_target(self):
        core.remember_target("wb", mode="whitebox")
        core.remember_target("bb", mode="blackbox")
        self.assertEqual(core.recall_target("wb")["mode"], "whitebox")
        self.assertEqual(core.recall_target("bb")["mode"], "blackbox")


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


class TestPortPolicy(unittest.TestCase):
    """The boundary port policy (Polisi v1.3 default) must classify service ports
    and module outcomes correctly, and a BLOCKED on a policy-DENIED port must be
    labelled as expected segmentation, not an IPS result."""
    def setUp(self):
        self.pol = core.load_port_policy()

    def test_status_allowed_denied_unlisted(self):
        self.assertEqual(core.port_policy_status("tcp", 22, self.pol), "allowed")
        self.assertEqual(core.port_policy_status("tcp", 445, self.pol), "denied")
        self.assertEqual(core.port_policy_status("tcp", 3389, self.pol), "unlisted")
        self.assertEqual(core.port_policy_status("udp", 443, self.pol), "allowed")  # VC UDP
        self.assertEqual(core.port_policy_status("udp", 161, self.pol), "unlisted")

    def test_module_outcomes(self):
        allow = {"id": "a", "ports": [("tcp", 80)]}
        block = {"id": "b", "ports": [("tcp", 445)]}
        egress = {"id": "e", "ports": []}
        partial = {"id": "p", "ports": [("tcp", 389), ("tcp", 445)]}  # one allowed
        self.assertEqual(core.module_policy(allow, self.pol)["outcome"], "allowed")
        self.assertEqual(core.module_policy(block, self.pol)["outcome"], "blocked")
        self.assertEqual(core.module_policy(egress, self.pol)["outcome"], "egress")
        self.assertEqual(core.module_policy(partial, self.pol)["outcome"], "allowed")

    def test_override_file(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "port_policy.json")
        with open(p, "w") as f:
            f.write('{"name":"Custom","allow":{"tcp":[9999]},"deny":{"tcp":[22]}}')
        old = os.environ.get("HARNESS_PORT_POLICY")
        os.environ["HARNESS_PORT_POLICY"] = p
        try:
            pol = core.load_port_policy()
            self.assertEqual(pol["name"], "Custom")
            self.assertEqual(core.port_policy_status("tcp", 22, pol), "denied")
            self.assertEqual(core.port_policy_status("tcp", 9999, pol), "allowed")
        finally:
            if old is None:
                del os.environ["HARNESS_PORT_POLICY"]
            else:
                os.environ["HARNESS_PORT_POLICY"] = old

    def test_blocked_on_denied_port_is_labelled_segmentation(self):
        m = types.SimpleNamespace()
        m.META = {"id": "smb", "name": "smb", "category": "Net", "requires": [],
                  "ports": [("tcp", 445)], "mitre": ["T1021"], "tactic": "LM",
                  "success_regex": r"WIN", "blocked_regex": r"timed out|No route"}
        m.run = lambda t, c: "[TIMEOUT] no response"
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("10.255.255.1").run([m], 1, ev, skip_unready=False, recon=False)
        r = ev.records[0]
        self.assertEqual(r["baseline_result"], "BLOCKED")
        self.assertIn("denied by", r["verdict"])
        self.assertIn("SEGMENTATION", r["verdict"])
        self.assertEqual(ev.meta["port_policy"]["blocked_by_policy"], 1)


class TestWaitUnblockFlag(unittest.TestCase):
    """--wait-unblock / HARNESS_WAIT_UNBLOCK sets how long the engine sleeps for an
    IPS quarantine to clear, independent of --cooldown. Default off (0) -> the
    engine falls back to max(30s, cooldown)."""
    def test_default_off(self):
        self.assertEqual(core.Runner("127.0.0.1").wait_unblock, 0.0)

    def test_wait_window_uses_the_flag(self):
        import time as _t, threading
        r = core.Runner("127.0.0.1")
        r._canary = ("tcp", 9); r._blacklisted = True
        r._bl_lock = threading.Lock(); r._stop = False
        r.cooldown = 0.0; r.wait_unblock = 12.0           # would be 30 without the flag
        r._canary_reachable = lambda: False               # never recovers
        slept, orig = [], _t.sleep
        _t.sleep = lambda s: slept.append(s)
        try:
            ok = r._await_unblacklist(lambda *a: None, "x")
        finally:
            _t.sleep = orig
        self.assertFalse(ok)                               # stayed banned -> False
        self.assertAlmostEqual(sum(slept), 12.0, delta=0.01)   # waited ~12s, not 30


class TestADModulesSkipWithoutPassword(unittest.TestCase):
    """noPac / sAMAccountName must SKIP (not hang on the vendored getpass
    "Password:" prompt) when no DC password is set. sudo/root does NOT supply a
    DC credential, so running elevated does not avoid this."""
    def _ctx(self):
        return core.Context(credentials={"domain": "lab.local", "dc_user": "Administrator", "dc_pass": ""})

    def test_nopac_skips_without_password(self):
        try:
            import modules.nopac as n
        except Exception as e:
            self.skipTest(f"nopac deps unavailable: {e}")
        self.assertIn("[SKIP]", n.run("127.0.0.1", self._ctx()))

    def test_samaccountname_skips_without_password(self):
        try:
            import modules.samaccountname_spoof as s
        except Exception as e:
            self.skipTest(f"samaccountname deps unavailable: {e}")
        self.assertIn("[SKIP]", s.run("127.0.0.1", self._ctx()))


class TestNmapPolicyScan(unittest.TestCase):
    """Policy-violation scan: OPEN ports outside the allow-list -> POLICY-VIOLATION;
    only-allowed-open -> POLICY-ENFORCED; no results -> SCAN-BLOCKED. Mocked nmap."""
    def _run(self, tcp_out, udp_out=""):
        import modules.nmap_policy_scan as n

        class Ctx:
            def run_cmd(self, tmpl, target):
                return tcp_out if "-sS" in tmpl else udp_out
        return n.run("10.0.0.5", Ctx())

    def test_violation_detected(self):
        out = self._run("Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 3389/open/tcp//rdp///\n")
        self.assertIn("POLICY-VIOLATION", out)
        self.assertIn("tcp/3389", out)        # 3389 not in the allow-list
        self.assertNotIn("POLICY-ENFORCED", out)

    def test_only_allowed_is_enforced(self):
        out = self._run("Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\n")
        self.assertIn("POLICY-ENFORCED", out)  # 22 + 80 are allowed -> no violation

    def test_no_results_is_scan_blocked(self):
        out = self._run("")                    # nmap returned nothing -> IPS likely blocked it
        self.assertIn("SCAN-BLOCKED", out)

    def test_stealth_time_spreads_into_batches(self):
        import os
        import modules.nmap_policy_scan as n
        env = {"HARNESS_SCAN_STEALTH": "1", "HARNESS_SCAN_BATCH_DELAY": "0",
               "HARNESS_SCAN_BATCHES": "4", "HARNESS_SCAN_TCP_PORTS": "1-100"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        calls = {"tcp": 0}

        class Ctx:
            def run_cmd(self, tmpl, target):
                if "-sS" in tmpl:
                    calls["tcp"] += 1
                    return ("Host: 10.0.0.5 ()\tPorts: 3389/open/tcp//rdp///\n"
                            if calls["tcp"] == 1 else "")
                return ""
        try:
            out = n.run("10.0.0.5", Ctx())
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        self.assertEqual(calls["tcp"], 4)          # 4 time-spread batches
        self.assertIn("STEALTH TCP", out)
        self.assertIn("POLICY-VIOLATION", out)     # 3389 violation found across batches


class TestModuleHardTimeoutMeta(unittest.TestCase):
    """A module may declare its own longer watchdog via META['hard_timeout_s']
    (e.g. a time-spread stealth scan); the engine must honour it."""
    def test_meta_hard_timeout_honoured(self):
        import time
        m = types.SimpleNamespace()
        m.META = {"id": "slow", "name": "slow", "category": "T", "requires": [],
                  "ports": [], "mitre": [], "tactic": "D",
                  "success_regex": "WIN", "blocked_regex": "x", "hard_timeout_s": 1}
        m.run = lambda t, c: time.sleep(10) or "never"
        r = core.Runner("127.0.0.1")
        start = time.time()
        out = r._safe_module_run(m, "127.0.0.1")
        self.assertLess(time.time() - start, 6)    # watchdog fired at ~1s (META), not +60
        self.assertIn("watchdog", out.lower())


class TestToolFaultNotBlocked(unittest.TestCase):
    """A harness-internal fault (module crash / watchdog-abandon) must score
    NO-RESULT even when recon shows the port filtered — crediting a crashed
    module's BLOCKED to the control fabricates a 'control worked' result."""
    def test_crash_on_filtered_port_is_no_result_not_blocked(self):
        m = types.SimpleNamespace()
        m.META = {"id": "crashy", "name": "crashy", "category": "Test", "requires": [],
                  "ports": [("tcp", 9)], "mitre": ["T1046"], "tactic": "Discovery",
                  "success_regex": r"WIN", "blocked_regex": r"NEVERMATCH"}
        def boom(t, c): raise RuntimeError("kaboom")
        m.run = boom
        ev = core.Evidence(base=tempfile.mkdtemp())
        core.Runner("10.255.255.1").run([m], 1, ev, skip_unready=False, recon=True)
        r = ev.records[0]
        self.assertEqual(r["baseline_result"], "NO-RESULT")   # was BLOCKED before the fix
        self.assertIn("tool fault", r["verdict"].lower())


class TestDirectionFilter(unittest.TestCase):
    """--direction both must run EVERY direction, not only modules tagged
    direction='both'. A one-way filter still includes 'both'-tagged modules."""
    def _args(self, direction):
        return types.SimpleNamespace(only=None, all=True, added=False,
                                     attack_sim=False, test_type=None, family=None,
                                     direction=direction)
    def _mods(self):
        return [fake_module("a", direction="a2b"),
                fake_module("b", direction="b2a"),
                fake_module("c", direction="both")]

    def test_both_keeps_all_directions(self):
        import cli
        ids = {m.META["id"] for m in cli._select(self._mods(), self._args("both"))}
        self.assertEqual(ids, {"a", "b", "c"})

    def test_a2b_keeps_a2b_and_both(self):
        import cli
        ids = {m.META["id"] for m in cli._select(self._mods(), self._args("a2b"))}
        self.assertEqual(ids, {"a", "c"})


class TestPortPolicyMalformed(unittest.TestCase):
    """A malformed port_policy.json must fall back to the built-in default (not
    raise) — and the operator is warned on stderr (verified separately)."""
    def test_malformed_falls_back_to_default(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "port_policy.json")
        with open(p, "w") as f:
            f.write("{ this is not valid json ]")
        old = os.environ.get("HARNESS_PORT_POLICY")
        os.environ["HARNESS_PORT_POLICY"] = p
        try:
            pol = core.load_port_policy()
            self.assertEqual(pol["name"], "Polisi Standard Security v1.3")
            self.assertIn(445, pol["deny"]["tcp"])   # built-in default intact
        finally:
            if old is None:
                del os.environ["HARNESS_PORT_POLICY"]
            else:
                os.environ["HARNESS_PORT_POLICY"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
