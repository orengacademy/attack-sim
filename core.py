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
import shutil
import platform
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
# Preflight — verify each module's external tools + privileges BEFORE
# executing anything. Cross-platform (Linux/macOS/Windows): presence is
# checked with shutil.which (honours PATHEXT on Windows), and install hints
# adapt to the detected package manager. Version is NOT gated on — presence
# is what determines whether a module can run; a --versions probe is offered
# for humans but is best-effort and never blocks.
#
# A module declares its own requirements in META (all optional):
#   requires        : list[str]  external binaries it shells out to
#   needs_root      : bool       must run as root/admin (raw sockets, priv ports)
#   requires_files  : list[str]  data files that must exist (e.g. a vendored PoC)
# A module with none of these is assumed to need no external tooling.
# ---------------------------------------------------------------------

# binary -> {package-manager-key: package name}. "pip" is a fallback for tools
# with no distro package on the current OS; "note" is surfaced to the user.
INSTALL_HINTS = {
    "curl": {"apt": "curl", "dnf": "curl", "yum": "curl", "pacman": "curl",
             "zypper": "curl", "apk": "curl", "brew": "curl", "choco": "curl",
             "winget": "cURL.cURL", "scoop": "curl"},
    "snmpwalk": {"apt": "snmp", "dnf": "net-snmp-utils", "yum": "net-snmp-utils",
                 "pacman": "net-snmp", "zypper": "net-snmp", "apk": "net-snmp-tools",
                 "brew": "net-snmp", "choco": "net-snmp"},
    "hydra": {"apt": "hydra", "dnf": "hydra", "yum": "hydra", "pacman": "hydra",
              "zypper": "hydra", "brew": "hydra"},
    "ldapsearch": {"apt": "ldap-utils", "dnf": "openldap-clients",
                   "yum": "openldap-clients", "pacman": "openldap",
                   "zypper": "openldap2-client", "apk": "openldap-clients",
                   "brew": "openldap"},
    "hping3": {"apt": "hping3", "dnf": "hping3", "yum": "hping3", "pacman": "hping",
               "zypper": "hping3", "brew": "hping"},
    "ping": {"apt": "iputils-ping", "dnf": "iputils", "yum": "iputils",
             "pacman": "iputils", "zypper": "iputils", "apk": "iputils"},
    "timeout": {"apt": "coreutils", "dnf": "coreutils", "yum": "coreutils",
                "pacman": "coreutils", "zypper": "coreutils", "apk": "coreutils",
                "brew": "coreutils"},
    "python3": {"apt": "python3", "dnf": "python3", "yum": "python3",
                "pacman": "python", "zypper": "python3", "apk": "python3",
                "brew": "python", "choco": "python", "winget": "Python.Python.3"},
    "responder": {"apt": "responder", "pip": "responder",
                  "note": "Kali packages this as 'responder'; elsewhere use "
                          "pipx/pip, or clone github.com/SpiderLabs/Responder."},
    "impacket-secretsdump": {"apt": "impacket-scripts", "pip": "impacket",
        "note": "pip/pipx installs this as 'secretsdump.py' (no 'impacket-' "
                "prefix); Kali's impacket-scripts provides the 'impacket-secretsdump' "
                "name this module calls. Symlink or adjust the module if using pip."},
    "impacket-GetUserSPNs": {"apt": "impacket-scripts", "pip": "impacket",
        "note": "pip/pipx installs this as 'GetUserSPNs.py'; Kali's "
                "impacket-scripts provides 'impacket-GetUserSPNs'."},
    "impacket-psexec": {"apt": "impacket-scripts", "pip": "impacket",
        "note": "pip/pipx installs this as 'psexec.py'; Kali's impacket-scripts "
                "provides 'impacket-psexec'."},
}

# Package managers to probe per OS, in preference order. apt-get/apt both map
# to the "apt" key in INSTALL_HINTS.
_PKG_MANAGERS = {
    "Linux": ["apt-get", "apt", "dnf", "yum", "pacman", "zypper", "apk"],
    "Darwin": ["brew"],
    "Windows": ["winget", "choco", "scoop"],
}
_PM_ALIAS = {"apt-get": "apt"}
_PM_INSTALL = {
    "apt": "sudo apt-get install -y {pkgs}",
    "dnf": "sudo dnf install -y {pkgs}",
    "yum": "sudo yum install -y {pkgs}",
    "pacman": "sudo pacman -S --noconfirm {pkgs}",
    "zypper": "sudo zypper install -y {pkgs}",
    "apk": "sudo apk add {pkgs}",
    "brew": "brew install {pkgs}",
    "choco": "choco install -y {pkgs}",
    "winget": "winget install {pkgs}",
    "scoop": "scoop install {pkgs}",
}
# Tools we will NOT execute just to read a version — they need root and/or have
# side effects (Responder binds listeners; impacket wrappers try to connect).
_NO_VERSION_PROBE = {"responder", "impacket-secretsdump",
                     "impacket-GetUserSPNs", "impacket-psexec"}
_VERSION_FLAGS = ("--version", "-V", "-version", "version")


def is_privileged():
    """True if the process has root (POSIX) or Administrator (Windows) rights.
    Cross-platform: os.geteuid() doesn't exist on Windows."""
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _linux_distro():
    # /etc/os-release is the freedesktop standard across modern distros.
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return ""


def platform_info():
    sysname = platform.system()
    return {
        "system": sysname,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "distro": _linux_distro() if sysname == "Linux" else "",
    }


def detect_package_manager():
    """First available package manager for this OS, or None."""
    for cand in _PKG_MANAGERS.get(platform.system(), []):
        if shutil.which(cand):
            return cand
    return None


def _pm_key(pm):
    return _PM_ALIAS.get(pm, pm) if pm else None


def tool_version(binary, timeout=4):
    """Best-effort first-line version string, or None. Never raises; skips
    tools flagged unsafe to execute during a mere check."""
    if binary in _NO_VERSION_PROBE or shutil.which(binary) is None:
        return None
    for flag in _VERSION_FLAGS:
        try:
            p = subprocess.run([binary, flag], capture_output=True, text=True,
                               timeout=timeout)
            out = (p.stdout or p.stderr or "").strip()
            if out:
                return out.splitlines()[0][:120]
        except Exception:
            continue
    return None


def install_suggestions(missing_binaries, pm=None):
    """(commands, notes) to install the missing binaries. commands is a list of
    ready-to-run shell strings for the detected package manager (+ a pip line
    for tools with no distro package); notes carries per-tool caveats."""
    pm = pm or detect_package_manager()
    pmk = _pm_key(pm)
    sys_pkgs, pip_pkgs, notes = [], [], []
    for b in sorted(set(missing_binaries)):
        hint = INSTALL_HINTS.get(b)
        if not hint:
            notes.append(f"{b}: no known package mapping — install it manually.")
            continue
        if hint.get("note"):
            notes.append(f"{b}: {hint['note']}")
        pkg = hint.get(pmk) if pmk else None
        if pkg:
            sys_pkgs.append(pkg)
        elif hint.get("pip"):
            pip_pkgs.append(hint["pip"])
        else:
            notes.append(f"{b}: no package listed for '{pm or 'this OS'}'.")
    commands = []
    if sys_pkgs:
        tmpl = _PM_INSTALL.get(pmk, "install {pkgs}")
        commands.append(tmpl.format(pkgs=" ".join(dict.fromkeys(sys_pkgs))))
    if pip_pkgs:
        uniq = " ".join(dict.fromkeys(pip_pkgs))
        commands.append(f"pipx install {uniq}   # or: python3 -m pip install --user {uniq}")
    return commands, notes


def preflight(modules, want_versions=False):
    """Check every module's declared requirements. Returns:
      {platform, privileged, package_manager, modules: [ per-module dict ]}
    where each per-module dict has ready/missing/missing_files/priv_ok/tools."""
    priv = is_privileged()
    pm = detect_package_manager()
    out = []
    for m in modules:
        meta = m.META
        reqs = list(meta.get("requires", []))
        needs_root = bool(meta.get("needs_root", False))
        req_files = list(meta.get("requires_files", []))
        tools = []
        for b in reqs:
            path = shutil.which(b)
            tools.append({
                "binary": b,
                "found": path is not None,
                "path": path,
                "version": tool_version(b) if (want_versions and path) else None,
            })
        missing = [t["binary"] for t in tools if not t["found"]]
        missing_files = [f for f in req_files if not os.path.exists(f)]
        priv_ok = (not needs_root) or priv
        out.append({
            "id": meta["id"], "name": meta["name"], "category": meta["category"],
            "requires": reqs, "tools": tools, "missing": missing,
            "needs_root": needs_root, "priv_ok": priv_ok,
            "requires_files": req_files, "missing_files": missing_files,
            "ready": not missing and not missing_files and priv_ok,
        })
    return {"platform": platform_info(), "privileged": priv,
            "package_manager": pm, "modules": out}


def format_preflight_report(pf):
    """Human-readable multi-line report from a preflight() result (shared by the
    preflight.py CLI and the GUI's Preflight button)."""
    p = pf["platform"]
    ready_n = sum(1 for r in pf["modules"] if r["ready"])
    L = ["=" * 62, "  PREFLIGHT — tool & privilege check", "=" * 62]
    plat = f"{p['system']} {p['release']}" + (f" · {p['distro']}" if p['distro'] else "")
    L += [f"Platform : {plat}",
          f"Arch/Py  : {p['machine']} · Python {p['python']}",
          f"Privilege: {'root/admin' if pf['privileged'] else 'unprivileged'}",
          f"Pkg mgr  : {pf['package_manager'] or 'not detected'}",
          "", f"Modules ready: {ready_n}/{len(pf['modules'])}", ""]
    all_missing = set()
    for r in pf["modules"]:
        mark = "OK" if r["ready"] else "XX"
        if r["tools"]:
            parts = []
            for t in r["tools"]:
                s = t["binary"] if t["found"] else t["binary"] + " (MISSING)"
                if t.get("version"):
                    s += f" [{t['version']}]"
                parts.append(s)
            toolstr = ", ".join(parts)
        else:
            toolstr = "(no external tools)"
        L.append(f"[{mark}] {r['name']}")
        L.append(f"       tools: {toolstr}")
        if r["needs_root"]:
            L.append(f"       privilege: {'ok' if r['priv_ok'] else 'NEEDS root/admin'}")
        if r["missing_files"]:
            L.append(f"       missing files: {', '.join(r['missing_files'])}")
        all_missing.update(r["missing"])
    if all_missing:
        cmds, notes = install_suggestions(sorted(all_missing), pf["package_manager"])
        L += ["", "To install the missing tools:"]
        L += ["  " + c for c in cmds] or ["  (no package mapping — see notes)"]
        L += ["  # " + n for n in notes]
    L.append("=" * 62)
    return "\n".join(L)


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

    def run(self, modules, iterations, ev, skip_unready=True):
        def log(msg):
            self.on_log(msg)
            ev.log(msg)

        total = iterations * len(modules)
        cur = 0
        mode = "dual-path (baseline + appliance)" if self.dual else "single-target"
        log(f"Mode: {mode}")
        log(f"Evidence dir: {ev.root}")

        # ----- Preflight: verify tools/privileges BEFORE executing anything ---
        pf = preflight(modules)
        pi = pf["platform"]
        plat = f"{pi['system']} {pi['release']}" + (f" · {pi['distro']}" if pi["distro"] else "")
        log(f"Platform: {plat}  |  Python {pi['python']}  |  "
            f"privilege: {'root/admin' if pf['privileged'] else 'unprivileged'}  |  "
            f"pkg mgr: {pf['package_manager'] or 'n/a'}")
        pf_by_id = {r["id"]: r for r in pf["modules"]}
        ready_ids = {r["id"] for r in pf["modules"] if r["ready"]}
        log(f"Preflight: {len(ready_ids)}/{len(modules)} modules ready.")
        all_missing = set()
        for r in pf["modules"]:
            if r["ready"]:
                continue
            reasons = []
            if r["missing"]:
                reasons.append("missing tools: " + ", ".join(r["missing"]))
                all_missing.update(r["missing"])
            if r["missing_files"]:
                reasons.append("missing files: " +
                               ", ".join(os.path.basename(f) for f in r["missing_files"]))
            if not r["priv_ok"]:
                reasons.append("needs root/admin")
            log(f"  [NOT READY] {r['name']} — " + "; ".join(reasons))
        if all_missing:
            cmds, notes = install_suggestions(sorted(all_missing), pf["package_manager"])
            for c in cmds:
                log(f"    install: {c}")
            for n in notes:
                log(f"    note: {n}")
        if skip_unready and ready_ids != {m.META["id"] for m in modules}:
            log("  (unready modules will be skipped as PREREQ-MISSING — pass "
                "skip_unready=False to force-run them instead)")

        for it in range(1, iterations + 1):
            if self._stop:
                break
            log(f"\n=== Iteration: {it} ===")
            for m in modules:
                if self._stop:
                    break
                meta = m.META
                log(f"  [{meta['category']}] {meta['name']}")

                # Skip modules whose prerequisites aren't met, recording WHY —
                # more honest than running them blind into a tool-not-found log.
                if skip_unready and meta["id"] not in ready_ids:
                    r = pf_by_id[meta["id"]]
                    bits = []
                    if r["missing"]:
                        bits.append("missing " + ", ".join(r["missing"]))
                    if r["missing_files"]:
                        bits.append("missing file(s): " +
                                    ", ".join(os.path.basename(f) for f in r["missing_files"]))
                    if not r["priv_ok"]:
                        bits.append("needs root/admin")
                    verdict = "PREREQ-MISSING — skipped (" + "; ".join(bits) + ")"
                    b, a = "PREREQ-MISSING", "-"
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
                    continue

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
