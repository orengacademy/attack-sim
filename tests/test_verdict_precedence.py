"""Regression-lock for the single-target verdict LADDER (first-match-wins) in
core.Runner._process_module_inner, and the dual-target core.classify() order.

Each rung of the ladder is a guard rail against a specific false "control works"
result; these tests pin the ORDER so a refactor can't silently reshuffle them.
Pure-stdlib / offline: the module output is crafted and the recon port-state is
INJECTED (no network, no real recon)."""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402


class _FakeMod:
    def __init__(self, mid, output, **meta):
        self.META = {"id": mid, "name": mid, "category": "Test", **meta}
        self._out = output

    def run(self, target, ctx):
        return self._out


def _verdict(raw, recon=None, success=r"WIN", blocked=r"BLOCKED-X",
             detected=None, detections=None, banned=False, unreachable=False,
             reachable_at_recon=False):
    """Drive the REAL classifier for one module and return (baseline_result, verdict).
    `recon` is the injected TCP port state ('open'/'closed'/'filtered'/...), or None
    for 'no recon'. Port policy is disabled (not under test). `banned=True` arms the
    contamination guard with an ALREADY-LATCHED source blacklist (so _detect_ban
    fast-paths and never does a real network probe) — used to verify which verdicts
    get the SUSPECT/contaminated tag. `unreachable=True` simulates the whole target
    being unreachable from this source at recon (the concurrent-tester / shared-ban
    case) so NO-SERVICE is flagged low-confidence. `reachable_at_recon=True` simulates
    the target having answered on SOME protocol at recon (host-up ground truth) so a
    liveness INCONCLUSIVE can be upgraded to BLOCKED (ICMP filtered, host up)."""
    r = core.Runner("127.0.0.1")
    if banned:
        r._canary = ("tcp", 9)            # latched: _detect_ban returns True w/o probing
        r._blacklisted = True
    else:
        r._canary = None                  # contamination guard off
        r._blacklisted = False
    r._unreachable_at_recon = unreachable
    r._host_reachable_at_recon = reachable_at_recon
    r._bl_lock = threading.Lock()
    r._mode = "blackbox"
    r.dual = False
    r.appliance_ip = None
    r._pol_by_id = {}
    r._port_policy = {"name": "t"}
    r._detections = detections or {}
    r.auto_retry = 0
    meta = {"success_regex": success, "blocked_regex": blocked}
    if detected is not None:
        meta["detected_regex"] = detected
    m = _FakeMod("t", raw, **meta)
    ev = core.Evidence(base=tempfile.mkdtemp())
    recon_by_id = {"t": {"probes": [("tcp", 80, recon)]}} if recon else {}
    r._process_module(m, 1, False, {"t"}, {}, recon_by_id, ev,
                      lambda *a: None, lambda: None)
    rec = [x for x in ev.records if x["attack_id"] == "t"][-1]
    return rec["baseline_result"], rec["verdict"]


class TestLadderPrecedence(unittest.TestCase):
    # rung 1: success_regex wins over EVERYTHING (even a matching blocked_regex +
    # a filtered port) — the attack demonstrably got through.
    def test_success_beats_blocked_and_filtered(self):
        b, _ = _verdict("WIN and also BLOCKED-X", recon="filtered")
        self.assertEqual(b, "SUCCESS")

    def test_success_beats_no_service(self):
        b, _ = _verdict("WIN", recon="closed")
        self.assertEqual(b, "SUCCESS")

    # rung 2: a credential failure is NOT a control block — it must beat blocked_regex
    # (even when blocked_regex is broad enough to match the auth-failure text).
    def test_authfail_beats_blocked(self):
        b, _ = _verdict("STATUS_LOGON_FAILURE", blocked=r"STATUS_LOGON_FAILURE", recon="open")
        self.assertEqual(b, "AUTH-FAILED")

    # rung 3: a module that did NOTHING ([SKIP]) is never a control win, even if the
    # skip text happens to match blocked_regex.
    def test_skip_beats_blocked(self):
        b, _ = _verdict("[SKIP] not configured — BLOCKED-X appears here", recon="filtered")
        self.assertEqual(b, "SKIPPED")

    # rung 4/5: a module self-declaring a missing prereq / indeterminate result wins
    # over the recon-inferred BLOCKED (never miscredited to the control).
    def test_prereq_marker_beats_filtered(self):
        b, _ = _verdict("[PREREQ-MISSING] needs faketime", recon="filtered")
        self.assertEqual(b, "PREREQ-MISSING")

    def test_inconclusive_marker_beats_filtered(self):
        b, _ = _verdict("[INCONCLUSIVE] udp probe, no handshake", recon="filtered")
        self.assertEqual(b, "INCONCLUSIVE")

    # An INCONCLUSIVE now goes through the contamination guard (icmp_flood's
    # baseline-100%-lost-and-TCP-dead is a late-ban signal): with the source
    # blacklisted it's tagged SUSPECT so it's marked contaminated for auto-retry;
    # with a healthy canary a genuine non-ban INCONCLUSIVE is left untouched.
    def test_inconclusive_flagged_suspect_when_source_banned(self):
        b, v = _verdict("[INCONCLUSIVE] baseline ICMP 100% lost, TCP liveness dead",
                        recon="filtered", banned=True)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertIn("SUSPECT", v)

    def test_inconclusive_not_flagged_when_source_clean(self):
        b, v = _verdict("[INCONCLUSIVE] udp probe, no handshake", recon="filtered", banned=False)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertNotIn("SUSPECT", v)

    # Recon disambiguation: a LIVENESS indeterminate (icmp "couldn't confirm host up")
    # with the host reachable at recon (canary set) is stated as a source quarantine,
    # not a down host. A by-design indeterminate (handshake-less UDP) gets no such note.
    def test_inconclusive_liveness_disambiguated_when_host_was_up(self):
        b, v = _verdict("[INCONCLUSIVE] TCP liveness couldn't confirm the host is up",
                        recon="filtered", banned=True)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertIn("DISAMBIGUATION", v)
        self.assertIn("quarantined", v)

    def test_inconclusive_bydesign_not_disambiguated(self):
        b, v = _verdict("[INCONCLUSIVE] udp probe, no handshake", recon="filtered", banned=True)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertNotIn("DISAMBIGUATION", v)

    def test_inconclusive_upgrades_to_blocked_when_host_up_on_another_proto(self):
        # the operator's case: ICMP 100% lost, TCP-liveness couldn't confirm, BUT recon
        # saw the host up on SOME protocol (e.g. SSH/SNMP) and the source isn't banned
        # => the boundary FILTERS ICMP (control held) => BLOCKED, not INCONCLUSIVE.
        b, v = _verdict("[INCONCLUSIVE] TCP liveness couldn't confirm the host is up",
                        recon="filtered", reachable_at_recon=True, banned=False)
        self.assertEqual(b, "BLOCKED")
        self.assertIn("FILTERS/denies ICMP", v)

    def test_inconclusive_stays_when_host_up_but_source_banned(self):
        # host was up at recon but the source is now banned => can't tell if the ICMP
        # loss is the policy or the ban => stays INCONCLUSIVE (quarantine note).
        b, v = _verdict("[INCONCLUSIVE] TCP liveness couldn't confirm the host is up",
                        recon="filtered", reachable_at_recon=True, banned=True)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertIn("quarantined", v)

    def test_inconclusive_wholly_unreachable_points_to_source_block(self):
        # whole target unreachable at recon (no canary) + a liveness indeterminate =>
        # the attack was never delivered; point at a source-side block / clean source,
        # not the generic hedge. (Matches the field case: a source banned at the
        # target's boundary while still reaching everything else.)
        b, v = _verdict("[INCONCLUSIVE] TCP liveness couldn't confirm the host is up",
                        recon="filtered", unreachable=True, banned=False)
        self.assertEqual(b, "INCONCLUSIVE")
        self.assertIn("DISAMBIGUATION", v)
        self.assertIn("BLOCKED at the boundary", v)
        self.assertIn("known-good", v)

    # rung 6: refused/closed => NO-SERVICE (service absent, NOT a control block).
    def test_refused_closed_is_no_service(self):
        b, _ = _verdict("Connection refused", recon="closed")
        self.assertEqual(b, "NO-SERVICE")

    # Concurrency / shared-source guard: when the WHOLE target was unreachable from
    # this source at recon (e.g. a concurrent tester sharing the egress/NAT got the
    # shared source banned before this run), a "closed" is flagged LOW CONFIDENCE
    # instead of a confident "service absent" — so one tester's ban can't read as
    # another's NO-SERVICE. A normally-reachable target keeps the confident verdict.
    def test_no_service_low_confidence_when_target_unreachable_at_recon(self):
        b, v = _verdict("Connection refused", recon="closed", unreachable=True)
        self.assertEqual(b, "NO-SERVICE")
        self.assertIn("LOW CONFIDENCE", v)

    def test_no_service_confident_when_target_was_reachable(self):
        b, v = _verdict("Connection refused", recon="closed", unreachable=False)
        self.assertEqual(b, "NO-SERVICE")
        self.assertNotIn("LOW CONFIDENCE", v)

    # rung 6 GUARD: an incidental "Connection refused" while the attack port is OPEN
    # must NOT rob a module of the BLOCKED its own blocked_regex earned (the noPac
    # KDC_ERR_TGT_REVOKED case).
    def test_refused_while_port_open_keeps_blocked(self):
        b, _ = _verdict("KDC_ERR_TGT_REVOKED — and a stray Connection refused",
                        blocked=r"KDC_ERR_TGT_REVOKED", recon="open")
        self.assertEqual(b, "BLOCKED")

    # rung 7: a tool crash with NO network signal => NO-RESULT, never BLOCKED (a
    # crashed module must not fabricate "the control worked").
    def test_tool_fault_beats_filtered(self):
        b, v = _verdict("[ERROR] module crashed: kaboom", recon="filtered")
        self.assertEqual(b, "NO-RESULT")
        self.assertIn("tool fault", v.lower())

    # rung 8: a silent drop (filtered / timeout) => BLOCKED (segmentation / SD-WAN).
    def test_filtered_is_blocked(self):
        b, _ = _verdict("nothing notable in output", recon="filtered")
        self.assertEqual(b, "BLOCKED")

    def test_timeout_is_blocked(self):
        b, _ = _verdict("[TIMEOUT] no response", recon="open")
        self.assertEqual(b, "BLOCKED")

    # rung 9: an explicit rejection (blocked_regex) while the port is OPEN => BLOCKED
    # (in-path IPS/WAF or host hardening — a rejection RESPONSE, not a silent drop).
    def test_blocked_regex_while_open_is_blocked(self):
        b, v = _verdict("HTTP/1.1 403 Forbidden", blocked=r"403 Forbidden", recon="open")
        self.assertEqual(b, "BLOCKED")
        self.assertIn("rejection", v.lower())

    # rung 10: no marker, no recon signal => NO-RESULT (not a guessed BLOCKED).
    def test_no_signal_is_no_result(self):
        b, _ = _verdict("just some ambiguous chatter", recon=None)
        self.assertEqual(b, "NO-RESULT")


class TestDetectedSourcing(unittest.TestCase):
    """ORG2026-70: the VERDICT is the TEST result. A FILE-sourced detection
    (detections.json / appliance log — signature, DENY or ALLOW alike) is
    REFERENCE and NEVER flips the verdict: the attack that passed stays SUCCESS
    with the correlation attached. Only a module's OWN live-observed signal
    (META['detected_regex'], seen in its own output) can score DETECTED."""

    def test_file_signature_is_reference_not_detected(self):
        dets = {"t": {"source": "Sangfor NGAF", "note": "IPS signature fired prevention=yes"}}
        b, v = _verdict("WIN", detections=dets)
        self.assertEqual(b, "SUCCESS")            # file detection does NOT flip the verdict
        self.assertIn("REFERENCE", v.upper())

    def test_file_session_allow_is_reference(self):
        dets = {"t": {"source": "Sangfor", "note": "session-logged tcp/80: ALLOW (policy=Outbound_NPSA)"}}
        b, v = _verdict("WIN", detections=dets)
        self.assertEqual(b, "SUCCESS")
        self.assertIn("REFERENCE", v.upper())

    def test_file_session_deny_is_reference_not_detected(self):
        dets = {"t": {"source": "Sangfor", "note": "session-logged tcp/80: DENY (policy=X)"}}
        b, _ = _verdict("WIN", detections=dets)
        self.assertEqual(b, "SUCCESS")            # even a DENY in the imported log is reference

    def test_module_self_report_scores_detected(self):
        # a module that self-observes a detection in its OWN output (a live test
        # result, not an imported file) IS a detection -> DETECTED.
        b, _ = _verdict("WIN\n[DETECTED] target returned a WAF block page",
                        detected=r"\[DETECTED\]")
        self.assertEqual(b, "DETECTED")

    # DETECTED only applies to attacks that PASSED: a BLOCKED attack is just BLOCKED.
    def test_detection_does_not_apply_to_blocked(self):
        dets = {"t": {"source": "Sangfor", "note": "IPS signature fired prevention=yes"}}
        b, _ = _verdict("[TIMEOUT] no response", recon="filtered", detections=dets)
        self.assertEqual(b, "BLOCKED")


class TestDetectedRegexLatentGap(unittest.TestCase):
    def test_module_detected_regex_scores_detected(self):
        """A module self-reporting a blue-team detection via META['detected_regex']
        (a LIVE observation in its own output — e.g. the target returned a block
        page) IS a real test result and scores DETECTED. This is now the ONLY way to
        score DETECTED: the verdict comes from the test, so a module's own signal
        counts, while a pre-loaded appliance-log file (detections.json) is reference
        and never flips the verdict (see TestDetectedSourcing). (Was a documented
        latent gap — detections previously gated on note wording; now gated on the
        source being the module, so this self-report is honoured.)"""
        b, _ = _verdict("WIN plus a BLOCKPAGE banner", detected=r"BLOCKPAGE")
        self.assertEqual(b, "DETECTED")


class TestClassifyDualPrecedence(unittest.TestCase):
    """The dual-target (through-appliance) classifier core.classify() mirrors the
    same precedence on its own rungs."""
    META = {"success_regex": r"WIN", "blocked_regex": r"BLOCKED-X"}

    def test_appliance_success(self):
        _, a, _ = core.classify(self.META, "WIN", "WIN")
        self.assertEqual(a, "SUCCESS")

    def test_appliance_blocked(self):
        _, a, _ = core.classify(self.META, "WIN", "BLOCKED-X")
        self.assertEqual(a, "BLOCKED")

    def test_appliance_authfail_beats_blocked(self):
        meta = {"success_regex": r"WIN", "blocked_regex": r"STATUS_LOGON_FAILURE"}
        _, a, _ = core.classify(meta, "WIN", "STATUS_LOGON_FAILURE")
        self.assertEqual(a, "AUTH-FAILED")

    def test_appliance_refused_is_no_service(self):
        _, a, _ = core.classify(self.META, "WIN", "Connection refused")
        self.assertEqual(a, "NO-SERVICE")

    def test_baseline_not_ok_is_inconclusive(self):
        # if the allow-all baseline didn't even work, the A-vs-B comparison can't
        # credit the appliance — the verdict is INCONCLUSIVE regardless of app leg.
        _, _, v = core.classify(self.META, "nothing happened", "WIN")
        self.assertIn("INCONCLUSIVE", v.upper())


if __name__ == "__main__":
    unittest.main()
