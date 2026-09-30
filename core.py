#!/usr/bin/env python3
"""
core.py — shared engine for the control-validation harness.

Provides:
  - Context      : run_cmd() helper each attack module uses
  - Evidence     : evidence/run_<ts>/ tree + JSON/TXT/CSV summaries
  - classify()   : best-effort verdict from a module's success/blocked regexes
  - Runner       : N-iteration orchestrator over selected modules

Attack logic lives in modules/<name>.py — NOT here. Each module exposes a
META dict and a run(target, ctx) function; core just drives them.

No config file — the only per-run input is the target IP (typed into the
GUI) plus ticking Rules-of-engagement confirmed. Everything else static
(lab AD credentials, per-command timeout) is preconfigured below.
"""

import os
import re
import csv
import json
import shlex
import subprocess
from datetime import datetime

# ---------------------------------------------------------------------
# Preconfigured, static settings — edit here if the lab domain/creds change.
# ---------------------------------------------------------------------
DEFAULT_CREDENTIALS = {
    "domain": "lab.local",
    "dc_user": "Administrator",
    "dc_pass": "NewPass123!",
}
DEFAULT_TIMEOUT = 300  # seconds per attack module


def _run_cmd(template, target, creds, timeout):
    cmd = template.format(target=target, **creds)
    header = f"# command: {cmd}\n# target: {target}\n\n"
    try:
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        return header + (p.stdout or "") + "\n[stderr]\n" + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return header + "[TIMEOUT] command exceeded time limit (likely blocked/filtered)"
    except FileNotFoundError:
        return header + "[ERROR] tool not found — is it installed on this Kali?"
    except Exception as e:
        return header + f"[ERROR] {e}"


# ---------------------------------------------------------------------
# Context handed to every attack module
# ---------------------------------------------------------------------
class Context:
    def __init__(self, credentials=None, timeout=DEFAULT_TIMEOUT):
        self.creds = credentials or DEFAULT_CREDENTIALS
        self.timeout = timeout

    def run_cmd(self, template, target):
        """Run an external command (curl/hydra/impacket/etc.); returns full
        raw output. Template may use {target} and any credential key
        (domain, dc_user, dc_pass)."""
        return _run_cmd(template, target, self.creds, self.timeout)


# ---------------------------------------------------------------------
# Evidence logger
# ---------------------------------------------------------------------
class Evidence:
    def __init__(self, base="evidence"):
        self.ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.root = os.path.join(base, f"run_{self.ts}")
        os.makedirs(self.root, exist_ok=True)
        self.records = []
        self.meta = {"run": self.ts, "started": datetime.now().isoformat()}
        self._log_fh = open(os.path.join(self.root, "run.log"), "a")

    def log(self, msg):
        """Persist an engine log line to run.log (the GUI's Live log panel is
        in-memory only — this is the on-disk record of the same stream, so a
        run can be reviewed after the fact without having watched the GUI)."""
        ts = datetime.now().strftime("%H:%M:%S")
        for line in str(msg).splitlines() or [""]:
            self._log_fh.write(f"[{ts}] {line}\n")
        self._log_fh.flush()

    def _dir(self, iteration, attack_id):
        d = os.path.join(self.root, f"iteration_{iteration}", attack_id)
        os.makedirs(d, exist_ok=True)
        return d

    def save_run(self, iteration, attack_id, path_name, raw):
        fn = os.path.join(self._dir(iteration, attack_id), f"{path_name}.log")
        with open(fn, "w") as f:
            f.write(raw)
        return fn

    def save_result(self, iteration, attack_id, result):
        with open(os.path.join(self._dir(iteration, attack_id), "result.json"), "w") as f:
            json.dump(result, f, indent=2)
        self.records.append(result)

    def finalize(self):
        self.meta["finished"] = datetime.now().isoformat()

        with open(os.path.join(self.root, "summary.json"), "w") as f:
            json.dump({"meta": self.meta, "results": self.records}, f, indent=2)

        cols = ["iteration", "category", "attack", "control_tested", "fix_location",
                "baseline_result", "appliance_result", "verdict", "timestamp"]
        with open(os.path.join(self.root, "summary.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in self.records:
                w.writerow({k: r.get(k, "") for k in cols})

        agg = {}
        for r in self.records:
            a = r["attack"]
            s = agg.setdefault(a, {"cat": r["category"], "fix": r["fix_location"],
                                   "blocked": 0, "passed": 0, "other": 0, "n": 0})
            s["n"] += 1
            # single-target mode never sets appliance_result (always "-"), so
            # fall back to baseline_result — otherwise every attack buckets
            # into "other" and the report always reads INCONSISTENT.
            if r.get("appliance_ip") is None:
                v = r["baseline_result"]
                bucket = "passed" if v == "SUCCESS" else "blocked" if v == "BLOCKED" else "other"
            else:
                v = r["appliance_result"]
                bucket = "blocked" if v == "BLOCKED" else "passed" if v == "PASSED" else "other"
            s[bucket] += 1

        lines = ["=" * 64, "  CONTROL VALIDATION HARNESS — REPORT",
                 f"  Run: {self.ts}", "=" * 64, ""]
        for a, s in agg.items():
            tag = "consistent" if (s["blocked"] == s["n"] or s["passed"] == s["n"]) else "INCONSISTENT"
            verdict = "OK (blocked)" if s["blocked"] == s["n"] else \
                      "GAP (passed)" if s["passed"] == s["n"] else "REVIEW"
            lines += [f"[{s['cat']}] {a}",
                      f"    blocked {s['blocked']}/{s['n']}  passed {s['passed']}/{s['n']}  "
                      f"other {s['other']}/{s['n']}  -> {verdict} ({tag})",
                      f"    fix: {s['fix']}", ""]
        lines.append(f"Evidence: {self.root}")
        with open(os.path.join(self.root, "report.txt"), "w") as f:
            f.write("\n".join(lines))
        self._log_fh.close()
        return self.root


# ---------------------------------------------------------------------
# Classification (raw logs remain the authoritative evidence)
# ---------------------------------------------------------------------
def _match(raw, pat):
    return bool(pat) and re.search(pat, raw, re.IGNORECASE | re.MULTILINE) is not None


# Convention followed by every module in this repo: a line explaining WHY
# something didn't run (missing privilege, missing tool, etc.) is either
# "[ERROR] ..."/"[WARN] ..." or "SOMETHING-ERROR: ...". When a NO-RESULT
# would otherwise just say "review raw log", surface that line right in the
# live log / verdict instead — this is what would have made the PetitPotam
# "needs root" case obvious immediately instead of after a full 3-iteration
# run with no clue why. Grep the raw log yourself for anything this misses.
_ERROR_MARKER = re.compile(r"^(?:\[ERROR\].*|\S*ERROR\S*:.*)$", re.MULTILINE)
_WARN_MARKER = re.compile(r"^\[WARN\].*$", re.MULTILINE)


def _error_hint(raw):
    # prefer an actual ERROR line (the definitive reason) over a WARN (a
    # secondary side-note) — e.g. petitpotam prints both when not root, and
    # the "RESPONDER-PRIV-ERROR: needs root" line is the one worth surfacing.
    m = _ERROR_MARKER.search(raw) or _WARN_MARKER.search(raw)
    return m.group(0).strip() if m else None


# Credential/auth failures (bad creds) are NOT a control result — checked
# before blocked_regex so a broad "STATUS_" style pattern can't misreport a
# wrong password as "control blocked it".
AUTHFAIL_REGEX = (
    r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_DISABLED|STATUS_PASSWORD_EXPIRED|"
    r"invalidCredentials|KRB_AP_ERR_MODIFIED|KDC_ERR_(?:PREAUTH_FAILED|C_PRINCIPAL_UNKNOWN)|"
    r"AcceptSecurityContext error|Authentication failure|Login incorrect"
)


def classify(meta, base_raw, app_raw):
    succ, blk = meta.get("success_regex"), meta.get("blocked_regex")
    base_ok = _match(base_raw, succ)
    base_authfail = _match(base_raw, AUTHFAIL_REGEX)
    app_ok = _match(app_raw, succ)
    app_blocked = _match(app_raw, blk) or "[TIMEOUT]" in app_raw

    baseline_result = "OK" if base_ok else "AUTH-FAILED" if base_authfail else "FAIL (inconclusive)"
    appliance_result = "PASSED" if app_ok else "BLOCKED" if app_blocked else "NO-RESULT"

    if base_authfail and not base_ok:
        verdict = "CREDENTIAL ERROR — fix core.DEFAULT_CREDENTIALS, not a control result"
    elif not base_ok:
        verdict = "INCONCLUSIVE (baseline did not succeed — check target/service)"
    elif appliance_result == "BLOCKED":
        verdict = "CONTROL WORKING (blocked)"
    elif appliance_result == "PASSED":
        verdict = "FINDING (attack passed the appliance)"
    else:
        verdict = "REVIEW (no result through appliance — block vs monitor?)"
    return baseline_result, appliance_result, verdict


# ---------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------
class Runner:
    def __init__(self, target_ip, appliance_ip=None, on_log=None, on_progress=None,
                 on_output=None, on_status=None):
        # appliance_ip is optional. If None -> single-target mode (one path).
        self.target_ip = target_ip
        self.appliance_ip = appliance_ip
        self.dual = appliance_ip is not None and appliance_ip != "" and appliance_ip != target_ip
        self.on_log = on_log or (lambda m: None)
        self.on_progress = on_progress or (lambda c, t: None)
        # on_output(attack_id, name, raw_text) — the tool's own full output,
        # for a live "what actually happened" panel (distinct from on_log's
        # short narrative lines).
        self.on_output = on_output or (lambda *a: None)
        # on_status(attack_id, name, iteration, verdict) — one call per
        # attack completion, for a live pass/fail status list.
        self.on_status = on_status or (lambda *a: None)
        self.ctx = Context()
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self, modules, iterations, ev):
        def log(msg):
            self.on_log(msg)
            ev.log(msg)

        total = iterations * len(modules)
        cur = 0
        mode = "dual-path (baseline + appliance)" if self.dual else "single-target"
        log(f"Mode: {mode}")
        log(f"Evidence dir: {ev.root}")
        for it in range(1, iterations + 1):
            if self._stop:
                break
            log(f"\n=== Iteration: {it} ===")
            for m in modules:
                if self._stop:
                    break
                meta = m.META
                log(f"  [{meta['category']}] {meta['name']}")

                target_raw = m.run(self.target_ip, self.ctx)
                ev.save_run(it, meta["id"], "target", target_raw)
                self.on_output(meta["id"], meta["name"], target_raw)

                if self.dual:
                    app_raw = m.run(self.appliance_ip, self.ctx)
                    ev.save_run(it, meta["id"], "through-appliance", app_raw)
                    b, a, verdict = classify(meta, target_raw, app_raw)
                    log(f"     baseline: [{b}]  appliance: [{a}]  -> {verdict}")
                else:
                    # single-target: classify the one path directly
                    ok = _match(target_raw, meta.get("success_regex"))
                    authfail = _match(target_raw, AUTHFAIL_REGEX)
                    blocked = _match(target_raw, meta.get("blocked_regex")) or "[TIMEOUT]" in target_raw
                    if ok:
                        b, verdict = "SUCCESS", "attack succeeded against target"
                    elif authfail:
                        b, verdict = "AUTH-FAILED", "credential error — fix core.DEFAULT_CREDENTIALS, not a control result"
                    elif blocked:
                        b, verdict = "BLOCKED", "attack blocked/unreachable"
                    else:
                        hint = _error_hint(target_raw)
                        b = "NO-RESULT"
                        verdict = f"no result — {hint}" if hint else "no result — review raw log"
                    a = "-"
                    log(f"     target: [{b}]  -> {verdict}")

                self.on_status(meta["id"], meta["name"], it, b, verdict)

                ev.save_result(it, meta["id"], {
                    "iteration": it,
                    "category": meta["category"],
                    "attack": meta["name"],
                    "attack_id": meta["id"],
                    "control_tested": meta.get("control", meta["category"]),
                    "fix_location": meta.get("fix", ""),
                    "baseline_result": b,
                    "appliance_result": a,
                    "verdict": verdict,
                    "target_ip": self.target_ip,
                    "appliance_ip": self.appliance_ip if self.dual else None,
                    "timestamp": datetime.now().isoformat(),
                })
                cur += 1
                self.on_progress(cur, total)
        return ev.finalize()
